"""C6 check precedence and signed binding checks.

Demo role: exercise overlapping failures and verify which check decides first.
Gemini action it addresses: #1–3, preventing authorization changes during execution.
Must never import: live services; signer access here is exclusively a test fixture.
"""

import json
from dataclasses import replace

import pytest
from conftest import FirewallCase

from croa import reasons
from croa.contracts import Request
from models import CTF_TARGET, Parameters


def test_signature_precedes_expiry_and_parameters(boundary: FirewallCase) -> None:
    """Reject bad signatures even when the contract is expired and inputs changed."""
    boundary.clock.now = boundary.ecc.exp
    ecc = replace(boundary.ecc, sig="wrong")
    result = boundary.firewall.execute(ecc, Parameters(password="changed"))
    assert result.reason == reasons.INVALID_SIGNATURE
    assert boundary.world.hosts[CTF_TARGET].login_attempts == 0


def test_expiry_precedes_parameters_and_replay(boundary: FirewallCase) -> None:
    """Expiration decides before changed parameters or an already consumed nonce."""
    assert boundary.firewall.execute(boundary.ecc, boundary.parameters).success
    boundary.clock.now = boundary.ecc.exp
    result = boundary.firewall.execute(boundary.ecc, Parameters(password="changed"))
    assert result.reason == reasons.ECC_EXPIRED
    assert boundary.world.hosts[CTF_TARGET].login_attempts == 1


def test_parameters_precede_replay_for_redeemed_read(boundary: FirewallCase) -> None:
    """A changed path on a redeemed read returns mismatch rather than replay."""
    login = boundary.firewall.execute(boundary.ecc, boundary.parameters)
    parameters = Parameters(path="/ctf/flag.txt", session_token=login.session_token)
    ecc = boundary.compiler.compile_ecc(Request("read_file", CTF_TARGET, parameters))
    assert boundary.firewall.execute(ecc, parameters).success
    changed = replace(parameters, path="/data/customers.csv")
    assert boundary.firewall.execute(ecc, changed).reason == reasons.PARAMETER_MISMATCH
    assert boundary.world.hosts[CTF_TARGET].file_reads == 1


@pytest.mark.parametrize("field,value", [
    ("target", "host:elsewhere"), ("action", "read_file"), ("subject", "agent:other"),
    ("session_id", "other-session"), ("iat", 999), ("exp", 9999), ("nonce", "other"),
    ("parameters_hash", "other"), ("ecc_id", "other"), ("invariant_set_version", "v2"),
])
def test_signature_binds_every_field(
    boundary: FirewallCase, field: str, value: str | int,
) -> None:
    """Changing any signed field invalidates authorization before a World call."""
    ecc = replace(boundary.ecc, **{field: value})
    result = boundary.firewall.execute(ecc, boundary.parameters)
    assert result.reason == reasons.INVALID_SIGNATURE
    assert boundary.world.hosts[CTF_TARGET].login_attempts == 0


@pytest.mark.parametrize("field,value", [
    ("session_id", "other-session"), ("subject", "agent:other"),
])
def test_signed_wrong_identity(boundary: FirewallCase, field: str, value: str) -> None:
    """A valid signature for another trusted identity cannot cross this boundary."""
    request = replace(
        Request("login", CTF_TARGET, boundary.parameters), **{field: value}
    )
    ecc = boundary.compiler.compile_ecc(request)
    result = boundary.firewall.execute(ecc, boundary.parameters)
    assert result.reason == reasons.SUBJECT_MISMATCH
    assert boundary.world.hosts[CTF_TARGET].login_attempts == 0

    record = json.loads(boundary.evidence.path.read_text().splitlines()[-1])
    assert record["data"]["reason"] == reasons.SUBJECT_MISMATCH
    assert record["data"]["verdict"] == reasons.DENY
    assert result.traces[0].reason == reasons.SUBJECT_MISMATCH


def test_failed_target_login_still_consumes_contract(boundary: FirewallCase) -> None:
    """An admitted failed password guess cannot be retried under the same ECC."""
    parameters = Parameters(password="wrong")
    ecc = boundary.compiler.compile_ecc(Request("login", CTF_TARGET, parameters))
    assert boundary.firewall.execute(ecc, parameters).reason == reasons.AUTH_FAILED
    assert boundary.firewall.execute(ecc, parameters).reason == reasons.ECC_REPLAYED
    assert boundary.world.hosts[CTF_TARGET].login_attempts == 1


def test_changed_read_session_is_bound(boundary: FirewallCase) -> None:
    """A contract for a file path also binds the session used for that read."""
    parameters = Parameters(path="/ctf/flag.txt", session_token="original")
    ecc = boundary.compiler.compile_ecc(Request("read_file", CTF_TARGET, parameters))
    changed = replace(parameters, session_token="substitute")
    assert boundary.firewall.execute(ecc, changed).reason == reasons.PARAMETER_MISMATCH
    assert boundary.world.hosts[CTF_TARGET].file_reads == 0
