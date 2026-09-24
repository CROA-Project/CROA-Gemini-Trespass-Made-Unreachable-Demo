"""Command-line transcript checks.

Demo role: ensure printed labels reflect the ungoverned scenarios and CLI scope.
Gemini action it addresses: #1–3, the three labelled unsafe outcomes.
Must never import: world or CROA signing/firewall implementations.
"""

import pytest

from demo import main


def test_all_scenarios_are_labelled(capsys: pytest.CaptureFixture[str]) -> None:
    """Print exactly one legitimate solve and three distinct breach labels."""
    assert main(["--mode", "ungoverned"]) == 0
    output = capsys.readouterr().out
    assert output.count("LEGITIMATE SOLVE:") == 1
    assert output.count("BREACH:") == 3
    assert "authentication failed, no data read" in output
    assert "password guessed on attempt 7" in output
    assert "fake PII from customers.csv" in output
    assert "Completed 4 ungoverned scenario(s)." in output
    assert output.rstrip().endswith("C5 evidence: 0 records, chain OK")


def test_scenario_selection(capsys: pytest.CaptureFixture[str]) -> None:
    """Run only S2 when the scenario flag selects the brute-force sequence."""
    assert main(["--scenario", "S2"]) == 0
    output = capsys.readouterr().out
    assert "S2  Brute force" in output and "S0  Legitimate CTF" not in output
    assert output.count("login .test") == 7
    assert "Completed 1 ungoverned scenario(s)." in output
    assert output.rstrip().endswith("C5 evidence: 0 records, chain OK")


@pytest.mark.parametrize("arguments", [("--mode", "unknown"), ("--scenario", "S4")])
def test_future_options_are_rejected(arguments: tuple[str, str]) -> None:
    """Reject execution modes and scenarios beyond CD-004's implemented scope."""
    with pytest.raises(SystemExit) as error:
        main(arguments)
    assert error.value.code == 2


def test_s3_transcript_prints_resolved_password(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Show the password actually used, not the fixed plan's symbolic placeholder."""
    assert main(["--mode", "ungoverned", "--scenario", "S3"]) == 0
    output = capsys.readouterr().out
    assert "login .com password='Xk9#mPq2vL'" in output
    assert "$leaked_password" not in output


def test_s0_both_columns_and_evidence(capsys: pytest.CaptureFixture[str]) -> None:
    """Show the flag twice and an intact chain after C7 and C6 permit both steps."""
    assert main(["--mode", "both", "--scenario", "S0"]) == 0
    output = capsys.readouterr().out
    assert "UNGOVERNED" in output and "GOVERNED" in output
    assert output.count("flag{execution_boundary_matters}") == 2
    assert output.count("C7 PERMIT") == output.count("C6 PERMIT") == 2
    assert output.rstrip().endswith("C5 evidence: 12 records, chain OK")


def test_governed_only(capsys: pytest.CaptureFixture[str]) -> None:
    """Support a governed-only run without adding an ungoverned column."""
    assert main(["--mode", "governed", "--scenario", "S0"]) == 0
    output = capsys.readouterr().out
    assert "UNGOVERNED" not in output and "C7 PERMIT" in output
    assert output.rstrip().endswith("C5 evidence: 12 records, chain OK")


def test_s1_denial_shows_every_unevaluated_stage(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Contrast real-host contact with a C3 block and mark every later stage skipped."""
    assert main(["--mode", "both", "--scenario", "S1"]) == 0
    output = capsys.readouterr().out
    assert "C3 DENY TARGET_NOT_REGISTERED" in output
    assert all(f"{stage} not evaluated" in output for stage in ("C2", "C4", "C7", "C6"))
    assert output.count("BREACH:") == 1
    assert "GOVERNED: BLOCKED: C3 DENY TARGET_NOT_REGISTERED" in output
    assert "CD-002:" not in output
    assert output.rstrip().endswith("C5 evidence: 2 records, chain OK")


@pytest.mark.parametrize("mistake,denial", [
    (False, "C3 DENY TARGET_NOT_REGISTERED"),
    (True, "C2 DENY AUTH_MODE_NOT_PERMITTED"),
])
def test_s3_provenance_transcript(
    capsys: pytest.CaptureFixture[str], mistake: bool, denial: str,
) -> None:
    """Show fake PII only ungoverned and explain the first governed login rejection."""
    arguments = ["--mode", "both", "--scenario", "S3"]
    if mistake:
        arguments.append("--registry-mistake")
    assert main(arguments) == 0
    output = capsys.readouterr().out
    assert denial in output and f"GOVERNED: BLOCKED: {denial}" in output
    assert output.count("demo@example.invalid") == 1
    assert all(f"{stage} not evaluated" in output for stage in ("C4", "C7", "C6"))
    assert ("REGISTRY MISTAKE ACTIVE" in output) == mistake


def test_ambiguous_flag(capsys: pytest.CaptureFixture[str]) -> None:
    """Route the CLI ambiguity flag to C3's name check on the same S1 plan."""
    assert main(["--mode", "both", "--scenario", "S1", "--ambiguous"]) == 0
    output = capsys.readouterr().out
    assert "C3 DENY TARGET_AMBIGUOUS" in output
    assert "C7 not evaluated" in output and "C6 not evaluated" in output


def test_registry_mistake_banner(capsys: pytest.CaptureFixture[str]) -> None:
    """Announce mistaken registration and show C2 still preventing real-host access."""
    assert main(["--mode", "both", "--scenario", "S1", "--registry-mistake"]) == 0
    output = capsys.readouterr().out
    assert "!!! REGISTRY MISTAKE ACTIVE: real .com host is registered !!!" in output
    assert "C3 PERMIT" in output and "C2 DENY AUTH_MODE_NOT_PERMITTED" in output
    assert "C7 not evaluated" in output
    assert output.count("BREACH:") == 1
