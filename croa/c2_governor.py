"""C2 Execution Governor.

CROA component: C2 — evaluates grounded actions against C1's ordered policies.
Gemini action it addresses: #3, refusing passwords that have no issued provenance.
Fails closed: unmatched actions, prohibited authentication, and unissued or
wrongly bound credentials are denied before a contract can be compiled.
"""

import posixpath
from dataclasses import dataclass

from croa import c1_policy
from croa.contracts import Request
from croa.reasons import (
    ACTION_NOT_PERMITTED,
    AUTH_MODE_NOT_PERMITTED,
    CREDENTIAL_NOT_ISSUED,
    DENY,
    PERMIT,
)
from models import StageTrace


@dataclass(frozen=True)
class Verdict:
    """Policy verdict and its stable reason, without any execution capability."""

    verdict: str
    reason: str


def _matching_policy(request: Request) -> c1_policy.Policy | None:
    """Select C1's first applicable rule, keeping specific rules before fallbacks."""
    for policy in c1_policy.POLICIES:
        if policy.action != request.action:
            continue
        if policy.target is None or policy.target == request.target:
            return policy
    return None


def _authentication(request: Request, policy: c1_policy.Policy) -> Verdict:
    """Require one permitted authentication mode and a bound issued reference."""
    parameters = request.parameters
    has_password = parameters.password is not None
    has_credential = parameters.credential_id is not None
    if has_password == has_credential:
        return Verdict(DENY, AUTH_MODE_NOT_PERMITTED)
    mode = "password" if has_password else "credential_id"
    if mode not in policy.auth_modes:
        return Verdict(DENY, AUTH_MODE_NOT_PERMITTED)
    if parameters.credential_id is not None:
        credential = c1_policy.lookup_credential(
            parameters.credential_id, request.target
        )
        if credential is None:
            return Verdict(DENY, CREDENTIAL_NOT_ISSUED)
    return Verdict(PERMIT, PERMIT)


def evaluate(grounded_request: Request) -> Verdict:
    """Permit only the authentication modes and path scopes declared by C1.

    Args:
        grounded_request: Proposed action whose target has already passed C3.
    Returns:
        PERMIT, or the first named policy denial without contacting the World.
    """
    policy = _matching_policy(grounded_request)
    if policy is None:
        return Verdict(DENY, ACTION_NOT_PERMITTED)
    parameters = grounded_request.parameters
    if any(name not in policy.parameters for name in parameters.to_dict()):
        return Verdict(DENY, ACTION_NOT_PERMITTED)
    if policy.auth_modes:
        return _authentication(grounded_request, policy)
    if policy.path_prefix is not None and parameters.path is not None:
        if not parameters.path.startswith(policy.path_prefix):
            return Verdict(DENY, ACTION_NOT_PERMITTED)
        path = posixpath.normpath(parameters.path)
        if path.startswith(policy.path_prefix):
            return Verdict(PERMIT, PERMIT)
    return Verdict(DENY, ACTION_NOT_PERMITTED)


def check(request: Request) -> StageTrace:
    """Expose the C2 verdict as a control-plane stage trace.

    Args:
        request: Grounded proposal forwarded by the control plane.
    Returns:
        C2's structured verdict and reason for evidence and transcript rendering.
    """
    result = evaluate(request)
    return StageTrace("C2", result.verdict, result.reason)
