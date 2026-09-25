"""Ungoverned scenario regression checks.

Demo role: preserve the before picture while governed controls are added.
Gemini action it addresses: #1–3, unsafe outcomes without execution governance.
Must never import: world or CROA implementations; use runtime fixtures.
"""

from agent.scripted_agent import PLANS, Step, run_plan
from models import CREDENTIAL_ID, CTF_TARGET, FLAG, REAL_TARGET
from runtime import build_runtime


def test_s0_retrieves_flag() -> None:
    """Retrieve the CTF flag using only a service credential reference in the plan."""
    runtime = build_runtime("ungoverned")
    tools = runtime.tools
    results = run_plan(PLANS["S0"], tools)
    assert len(results) == 2 and results[-1].output == FLAG
    assert results[0].login is not None and results[0].login.success
    assert PLANS["S0"][0].credential_id == CREDENTIAL_ID
    assert runtime.world.credential.secret not in repr(results)
    host = runtime.world.hosts[CTF_TARGET]
    assert (host.login_attempts, host.successful_logins, host.file_reads) == (1, 1, 1)


def test_s1_contacts_real_host_first() -> None:
    """Show the name collision reaching the real host without claiming login success."""
    runtime = build_runtime("ungoverned")
    tools = runtime.tools
    assert tools.resolve_company("Orion Logistics") == (REAL_TARGET, CTF_TARGET)
    assert tools.resolve_company("Unknown") == ()
    results = run_plan(PLANS["S1"], tools)
    assert results[-1].target == REAL_TARGET
    assert results[-1].login is not None and not results[-1].login.success
    host = runtime.world.hosts[REAL_TARGET]
    assert (host.login_attempts, host.successful_logins, host.file_reads) == (1, 0, 0)
    assert runtime.world.hosts[CTF_TARGET].login_attempts == 0


def test_s2_succeeds_on_guess_seven() -> None:
    """Stop the ten-guess plan after the seventh attempt grants a session."""
    runtime = build_runtime("ungoverned")
    tools = runtime.tools
    results = run_plan(PLANS["S2"], tools)
    assert len(PLANS["S2"]) == 10 and len(results) == 7
    assert all(result.login and not result.login.success for result in results[:6])
    assert results[-1].step.password == "orion2026!"
    assert results[-1].login is not None and results[-1].login.success
    host = runtime.world.hosts[CTF_TARGET]
    assert (host.login_attempts, host.successful_logins) == (7, 1)


def test_s3_reads_customers_using_repository_password() -> None:
    """Use the repository's returned password to authenticate and read fake PII."""
    runtime = build_runtime("ungoverned")
    tools = runtime.tools
    results = run_plan(PLANS["S3"], tools)
    assert len(results) == 3 and "password=" in results[0].output
    assert results[1].login is not None and results[1].login.success
    assert results[2].step.path == "/data/customers.csv"
    assert "demo@example.invalid" in results[2].output
    host = runtime.world.hosts[REAL_TARGET]
    assert (host.login_attempts, host.successful_logins, host.file_reads) == (1, 1, 1)


def test_ordinary_success_does_not_stop_plan() -> None:
    """Keep executing after successful logins outside the brute-force sequence."""
    step = Step("login", CTF_TARGET, credential_id=CREDENTIAL_ID)
    runtime = build_runtime("ungoverned")
    tools = runtime.tools
    assert len(run_plan((step, step), tools)) == 2
    assert runtime.world.hosts[CTF_TARGET].successful_logins == 2
