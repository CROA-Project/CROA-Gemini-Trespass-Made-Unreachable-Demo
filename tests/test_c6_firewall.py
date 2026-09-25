"""C6 contract admission and rejection tests.

Demo role: verify every required C6 reason against actual World effects.
Gemini action it addresses: #1–3, preventing execution without valid authorization.
Must never import: live services; test fixtures intentionally hold trusted signers.
"""

import json
from dataclasses import replace

from conftest import FirewallCase

from croa import reasons
from croa.c7_compiler import ContractCompiler
from croa.contracts import Request
from models import CTF_TARGET, FLAG, Parameters


def _assert_rejected(boundary: FirewallCase, reason: str) -> None:
    """Confirm rejection was audited without contacting the target."""
    host = boundary.world.hosts[CTF_TARGET]
    assert (host.login_attempts, host.successful_logins, host.file_reads) == (0, 0, 0)
    record = json.loads(boundary.evidence.path.read_text().splitlines()[-1])
    assert record["event"] == "ECC_REJECTED" and record["data"]["reason"] == reason
    assert boundary.evidence.verify_chain().ok


def test_happy_path_injects_secret_and_reads_flag(boundary: FirewallCase) -> None:
    """Redeem separate login and read contracts without handing out the secret."""
    login = boundary.firewall.execute(boundary.ecc, boundary.parameters)
    assert login.success and login.reason == reasons.SESSION_GRANTED
    parameters = Parameters(path="/ctf/flag.txt", session_token=login.session_token)
    ecc = boundary.compiler.compile_ecc(Request("read_file", CTF_TARGET, parameters))
    read = boundary.firewall.execute(ecc, parameters)
    assert read.success and read.data == FLAG and read.reason == reasons.FILE_READ
    assert boundary.world.hosts[CTF_TARGET].file_reads == 1
    assert boundary.world.credential.secret not in boundary.evidence.path.read_text()
    assert boundary.evidence.verify_chain().records == 4


def test_missing_ecc(boundary: FirewallCase) -> None:
    """Reject absent authorization before any World call."""
    result = boundary.firewall.execute(None, boundary.parameters)
    assert not result.success and result.reason == reasons.MISSING_ECC
    _assert_rejected(boundary, reasons.MISSING_ECC)


def test_invalid_signature(boundary: FirewallCase) -> None:
    """Reject an altered signature before any World call."""
    ecc = replace(boundary.ecc, sig="0" * 64)
    result = boundary.firewall.execute(ecc, boundary.parameters)
    assert not result.success and result.reason == reasons.INVALID_SIGNATURE
    _assert_rejected(boundary, reasons.INVALID_SIGNATURE)


def test_expired_ecc(boundary: FirewallCase) -> None:
    """Reject a correctly signed contract exactly at its expiration boundary."""
    compiler = ContractCompiler(boundary.signer, clock=lambda: 700)
    ecc = compiler.compile_ecc(Request("login", CTF_TARGET, boundary.parameters))
    result = boundary.firewall.execute(ecc, boundary.parameters)
    assert not result.success and result.reason == reasons.ECC_EXPIRED
    _assert_rejected(boundary, reasons.ECC_EXPIRED)


def test_parameter_mismatch(boundary: FirewallCase) -> None:
    """Reject altered execution inputs before injecting a secret or contacting World."""
    parameters = replace(boundary.parameters, password="extra-input")
    result = boundary.firewall.execute(boundary.ecc, parameters)
    assert not result.success and result.reason == reasons.PARAMETER_MISMATCH
    _assert_rejected(boundary, reasons.PARAMETER_MISMATCH)


def test_replayed_ecc(boundary: FirewallCase) -> None:
    """Consume a successful contract once and reject its second redemption."""
    assert boundary.firewall.execute(boundary.ecc, boundary.parameters).success
    result = boundary.firewall.execute(boundary.ecc, boundary.parameters)
    assert not result.success and result.reason == reasons.ECC_REPLAYED
    assert boundary.world.hosts[CTF_TARGET].login_attempts == 1
    record = json.loads(boundary.evidence.path.read_text().splitlines()[-1])
    assert record["event"] == "ECC_REJECTED"
    assert record["data"]["reason"] == reasons.ECC_REPLAYED
