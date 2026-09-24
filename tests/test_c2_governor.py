"""C2 policy and credential-provenance checks.

Demo role: verify the C1 permission matrix independently of target behavior.
Gemini action it addresses: #3, rejecting passwords without issued provenance.
Must never import: world or signing/firewall implementations.
"""

import pytest

from croa.c2_governor import evaluate
from croa.contracts import Request
from croa.reasons import (
    ACTION_NOT_PERMITTED,
    AUTH_MODE_NOT_PERMITTED,
    CREDENTIAL_NOT_ISSUED,
    DENY,
    PERMIT,
)
from models import CREDENTIAL_ID, CTF_TARGET, REAL_TARGET, Parameters


@pytest.mark.parametrize("parameters", [
    Parameters(password="wrong-guess"), Parameters(password=""),
    Parameters(credential_id=CREDENTIAL_ID),
])
def test_ctf_authentication_modes(parameters: Parameters) -> None:
    """Permit guesses and the issued service reference without judging the password."""
    verdict = evaluate(Request("login", CTF_TARGET, parameters))
    assert verdict.verdict == PERMIT and verdict.reason == PERMIT


@pytest.mark.parametrize("target", [REAL_TARGET, "host:other.example.test"])
def test_password_mode_off_ctf_is_denied(target: str) -> None:
    """Only the exact CTF host permits raw passwords, even for another .test host."""
    request = Request("login", target, Parameters(password="Xk9#mPq2vL"))
    verdict = evaluate(request)
    assert verdict.verdict == DENY and verdict.reason == AUTH_MODE_NOT_PERMITTED


@pytest.mark.parametrize("target,credential_id", [
    (CTF_TARGET, "cred:unknown"), (REAL_TARGET, "cred:unknown"),
    (REAL_TARGET, CREDENTIAL_ID), (CTF_TARGET, ""),
])
def test_credential_must_be_issued_and_bound(target: str, credential_id: str) -> None:
    """Distinguish unknown and wrongly bound references from prohibited passwords."""
    request = Request("login", target, Parameters(credential_id=credential_id))
    verdict = evaluate(request)
    assert verdict.verdict == DENY and verdict.reason == CREDENTIAL_NOT_ISSUED


@pytest.mark.parametrize("parameters", [
    Parameters(), Parameters(password="guess", credential_id=CREDENTIAL_ID),
])
def test_exactly_one_authentication_mode(parameters: Parameters) -> None:
    """Reject missing or conflicting modes before consulting credential provenance."""
    verdict = evaluate(Request("login", CTF_TARGET, parameters))
    assert verdict.verdict == DENY and verdict.reason == AUTH_MODE_NOT_PERMITTED


@pytest.mark.parametrize("path", ["/ctf/flag.txt", "/ctf/nested/flag.txt"])
def test_ctf_file_scope_is_permitted(path: str) -> None:
    """Permit paths within C1's scope without assuming the file exists."""
    verdict = evaluate(Request("read_file", CTF_TARGET, Parameters(path=path)))
    assert verdict.verdict == PERMIT and verdict.reason == PERMIT


@pytest.mark.parametrize("action,target,parameters", [
    ("delete_file", CTF_TARGET, Parameters(path="/ctf/flag.txt")),
    ("read_file", REAL_TARGET, Parameters(path="/ctf/flag.txt")),
    ("read_file", REAL_TARGET, Parameters(path="/data/customers.csv")),
    ("read_file", CTF_TARGET, Parameters(path="/data/customers.csv")),
    ("read_file", CTF_TARGET, Parameters(path="/ctf-other/flag.txt")),
    ("read_file", CTF_TARGET, Parameters(path="/ctf/../data/customers.csv")),
    ("read_file", CTF_TARGET, Parameters(path="/data/../ctf/flag.txt")),
    ("read_file", CTF_TARGET, Parameters(path="ctf/flag.txt")),
    ("read_file", CTF_TARGET, Parameters()),
    ("login", CTF_TARGET, Parameters(password="guess", path="/ctf/flag.txt")),
    ("read_file", CTF_TARGET, Parameters(path="/ctf/flag.txt", password="guess")),
])
def test_unmatched_action_or_parameters_are_denied(
    action: str, target: str, parameters: Parameters,
) -> None:
    """Deny unknown actions, out-of-scope paths, and unexpected parameter fields."""
    verdict = evaluate(Request(action, target, parameters))
    assert verdict.verdict == DENY and verdict.reason == ACTION_NOT_PERMITTED
