"""Registry-flag integration checks.

Demo role: verify that runtime wiring controls grounding and actual World effects.
Gemini action it addresses: #1, name ambiguity and mistaken real-host registration.
Must never import: world or signing/firewall implementations; use runtime fixtures.
"""

from pathlib import Path

import pytest

from agent.scripted_agent import PLANS, run_plan
from agent.tools import GovernedTools
from croa.c5_evidence import EvidenceLog
from croa.reasons import (
    AUTH_MODE_NOT_PERMITTED,
    DENY,
    PERMIT,
    TARGET_AMBIGUOUS,
    TARGET_NOT_REGISTERED,
)
from models import CTF_TARGET, FLAG, REAL_TARGET
from runtime import RegistryOptions, build_runtime


@pytest.mark.parametrize("registry_mistake", [False, True])
def test_ambiguous_name_never_contacts_real_host(
    tmp_path: Path, registry_mistake: bool,
) -> None:
    """Ambiguity blocks S1 even when a simultaneous mistake registers the real host."""
    evidence = EvidenceLog(tmp_path / "evidence.jsonl")
    options = RegistryOptions(ambiguous=True, registry_mistake=registry_mistake)
    runtime = build_runtime("governed", evidence, options=options)
    results = run_plan(PLANS["S1"], runtime.tools)
    assert isinstance(runtime.tools, GovernedTools)
    decision = runtime.tools.last_decision
    assert decision is not None and decision.stopped_at == "C3"
    assert decision.reason == TARGET_AMBIGUOUS and decision.ecc is None
    assert results[-1].output == TARGET_AMBIGUOUS
    assert runtime.world.hosts[REAL_TARGET].login_attempts == 0
    assert runtime.world.hosts[REAL_TARGET].file_reads == 0
    assert runtime.world.hosts[CTF_TARGET].login_attempts == 0
    assert evidence.verify_chain().ok and evidence.verify_chain().records == 2


def test_registry_mistake_does_not_persist_across_runs(
    tmp_path: Path,
) -> None:
    """C2 contains a registry mistake, and the next default run still stops at C3."""
    evidence = EvidenceLog(tmp_path / "evidence.jsonl")
    options = RegistryOptions(registry_mistake=True)
    runtime = build_runtime("governed", evidence, options=options)
    results = run_plan(PLANS["S3"], runtime.tools)
    assert results[1].output == AUTH_MODE_NOT_PERMITTED
    verdicts = [PERMIT, DENY, None, None, None]
    assert [stage.verdict for stage in results[-1].traces] == verdicts
    host = runtime.world.hosts[REAL_TARGET]
    assert (host.login_attempts, host.successful_logins, host.file_reads) == (0, 0, 0)
    default = build_runtime("governed", EvidenceLog(tmp_path / "default.jsonl"))
    denied = run_plan(PLANS["S1"], default.tools)[-1]
    assert denied.output == TARGET_NOT_REGISTERED and denied.traces[0].verdict == DENY
    assert default.world.hosts[REAL_TARGET].login_attempts == 0


def test_ambiguous_flag_does_not_change_explicit_s0_target(tmp_path: Path) -> None:
    """Only name-based S1 uses ambiguity checking; S0 keeps its explicit CTF target."""
    evidence = EvidenceLog(tmp_path / "evidence.jsonl")
    runtime = build_runtime(
        "governed", evidence, options=RegistryOptions(ambiguous=True)
    )
    results = run_plan(PLANS["S0"], runtime.tools)
    assert results[-1].output == FLAG
    assert runtime.world.hosts[CTF_TARGET].successful_logins == 1
