"""Shared C1 policy checks for C2 and C6.

Demo role: prove both components read the same policy and credential records.
Gemini action it addresses: #3, keeping credential authority at the execution boundary.
Must never import: live services; policy changes here are isolated test fixtures.
"""

from dataclasses import replace
from types import MappingProxyType

import pytest
from conftest import FirewallCase

from croa import c1_policy
from croa.c2_governor import evaluate
from croa.contracts import Request
from croa.reasons import (
    ACTION_NOT_PERMITTED,
    AUTH_MODE_NOT_PERMITTED,
    CREDENTIAL_NOT_ISSUED,
    DENY,
    PERMIT,
)
from models import CREDENTIAL_ID, CTF_TARGET, REAL_TARGET, IssuedCredential, Parameters


def test_password_policy_change_controls_both_layers(
    boundary: FirewallCase, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Removing a C1 mode denies even a previously signed login at C6."""
    request = Request("login", CTF_TARGET, Parameters(password="orion2026!"))
    assert evaluate(request).verdict == PERMIT
    ecc = boundary.compiler.compile_ecc(request)
    policies = tuple(replace(policy, auth_modes=("credential_id",))
                     if policy.auth_modes else policy for policy in c1_policy.POLICIES)
    monkeypatch.setattr(c1_policy, "POLICIES", policies)
    assert evaluate(request).reason == AUTH_MODE_NOT_PERMITTED
    result = boundary.firewall.execute(ecc, request.parameters)
    assert result.reason == AUTH_MODE_NOT_PERMITTED
    assert result.traces[0].verdict == DENY
    assert boundary.world.hosts[CTF_TARGET].login_attempts == 0


@pytest.mark.parametrize("bound_target", [None, REAL_TARGET])
def test_issued_credential_table_controls_both_layers(
    boundary: FirewallCase, monkeypatch: pytest.MonkeyPatch, bound_target: str | None,
) -> None:
    """Revocation or rebinding prevents C2 approval and C6 secret injection."""
    credential = c1_policy.ISSUED_CREDENTIALS[CREDENTIAL_ID]
    issued = {} if bound_target is None else {
        CREDENTIAL_ID: replace(credential, target=bound_target),
    }
    monkeypatch.setattr(c1_policy, "ISSUED_CREDENTIALS", MappingProxyType(issued))
    request = Request("login", CTF_TARGET, boundary.parameters)
    assert evaluate(request).reason == CREDENTIAL_NOT_ISSUED
    result = boundary.firewall.execute(boundary.ecc, boundary.parameters)
    assert result.reason == CREDENTIAL_NOT_ISSUED
    assert boundary.world.hosts[CTF_TARGET].login_attempts == 0


def test_read_scope_table_controls_both_layers(
    boundary: FirewallCase, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Changing C1's allowed prefix is reflected by both C2 and C6."""
    request = Request("read_file", CTF_TARGET, Parameters(path="/ctf/flag.txt"))
    assert evaluate(request).verdict == PERMIT
    ecc = boundary.compiler.compile_ecc(request)
    policies = tuple(replace(policy, path_prefix="/another-scope/")
                     if policy.path_prefix else policy for policy in c1_policy.POLICIES)
    monkeypatch.setattr(c1_policy, "POLICIES", policies)
    assert evaluate(request).reason == ACTION_NOT_PERMITTED
    result = boundary.firewall.execute(ecc, request.parameters)
    assert result.reason == ACTION_NOT_PERMITTED
    assert boundary.world.hosts[CTF_TARGET].file_reads == 0


def test_fallback_allows_an_issued_reference_bound_to_another_host(
    boundary: FirewallCase, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A test-only C1 issuance permits another host without changing C2 or C6 rules."""
    credential = IssuedCredential("cred:real-test-fixture", REAL_TARGET, "test-secret")
    issued = {**c1_policy.ISSUED_CREDENTIALS, credential.credential_id: credential}
    monkeypatch.setattr(c1_policy, "ISSUED_CREDENTIALS", MappingProxyType(issued))
    boundary.world.credential = credential
    parameters = Parameters(credential_id=credential.credential_id)
    request = Request("login", REAL_TARGET, parameters)
    assert evaluate(request).verdict == PERMIT
    ecc = boundary.compiler.compile_ecc(request)
    assert boundary.firewall.execute(ecc, parameters).success
    assert boundary.world.hosts[REAL_TARGET].successful_logins == 1
