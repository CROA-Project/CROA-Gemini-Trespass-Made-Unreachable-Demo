"""S4 bypass and final CLI acceptance checks.

Demo role: verify direct C6 attacks fail and the finished default run is complete.
Gemini action it addresses: bypassing the execution boundary after authorization.
Must never import: World or signing/firewall implementations; use runtime injection.
"""

import json
from pathlib import Path

import pytest

import demo
from agent.bypass_tools import BypassTools
from agent.scripted_agent import PLANS, run_plan
from croa.c5_evidence import EvidenceLog
from croa.reasons import ECC_REPLAYED, MISSING_ECC, PARAMETER_MISMATCH
from models import CTF_TARGET, FLAG, REAL_TARGET
from runtime import build_runtime


def test_s4_bypass_attempts_are_denied_without_world_effects(tmp_path: Path) -> None:
    """Reject all three attacks without adding effects beyond legitimate S0 setup."""
    evidence = EvidenceLog(tmp_path / "s4.jsonl")
    runtime = build_runtime("governed", evidence, bypass=True)
    assert isinstance(runtime.tools, BypassTools)
    setup = run_plan(PLANS["S0"], runtime.tools)
    assert setup[-1].output == FLAG
    ctf = runtime.world.hosts[CTF_TARGET]
    before = (ctf.login_attempts, ctf.successful_logins, ctf.file_reads)
    results = run_plan(PLANS["S4"], runtime.tools)
    assert [row.output for row in results] == [
        MISSING_ECC, ECC_REPLAYED, PARAMETER_MISMATCH,
    ]
    assert all(row.traces[0].component == "C6" for row in results)
    assert before == (ctf.login_attempts, ctf.successful_logins, ctf.file_reads)
    real = runtime.world.hosts[REAL_TARGET]
    assert (real.login_attempts, real.successful_logins, real.file_reads) == (0, 0, 0)
    records = [json.loads(line) for line in evidence.path.read_text().splitlines()]
    assert sum(row["event"] == "ECC_REJECTED" for row in records) == 3
    assert evidence.verify_chain().ok and evidence.verify_chain().records == 17


def test_bypass_capability_is_not_given_to_ordinary_scenarios(tmp_path: Path) -> None:
    """Construct the S4 harness only when runtime receives its explicit flag."""
    evidence = EvidenceLog(tmp_path / "ordinary.jsonl")
    runtime = build_runtime("governed", evidence)
    assert not isinstance(runtime.tools, BypassTools)


def test_default_run_covers_all_scenarios_and_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Run both modes for S0–S4 and finish with the summary and intact evidence."""
    monkeypatch.chdir(tmp_path)
    assert demo.main([]) == 0
    output = capsys.readouterr().out
    assert all(f"{scenario}  " in output for scenario in PLANS)
    assert "SUMMARY" in output and "DECIDING COMPONENT" in output
    assert "S4" in output and "MISSING_ECC" in output
    assert "ECC_REPLAYED" in output and "PARAMETER_MISMATCH" in output
    assert "Completed 5 both scenario(s)." in output
    assert output.rstrip().endswith("C5 evidence: 86 records, chain OK")


def test_governed_expectation_failure_changes_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Return nonzero when a governed run does not end at its expected component."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(demo, "_expected_component", lambda scenario, options: "C6")
    assert demo.main(["--scenario", "S0"]) == 1
