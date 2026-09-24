"""C1 Policy Authority.

CROA component: C1 — owns policy content and credentials used by C2 and C6.
Gemini action it addresses: #3, distinguishing an issued secret from a public leak.
Fails closed: unmatched actions have no permission, and an issued credential
can authenticate only at its bound target. Trajectory limits arrive in CD-005.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from models import CREDENTIAL_ID, CTF_TARGET, IssuedCredential


@dataclass(frozen=True)
class Policy:
    """An ordered PERMIT rule; a None target is the fallback for any target."""

    action: str
    target: str | None
    parameters: tuple[str, ...]
    auth_modes: tuple[str, ...] = ()
    path_prefix: str | None = None


ISSUED_CREDENTIALS: Mapping[str, IssuedCredential] = MappingProxyType({
    CREDENTIAL_ID: IssuedCredential(
        CREDENTIAL_ID, CTF_TARGET, "local-ctf-service-secret"
    ),
})
POLICIES: tuple[Policy, ...] = (
    Policy("login", CTF_TARGET, ("password", "credential_id"),
           auth_modes=("password", "credential_id")),
    Policy("login", None, ("password", "credential_id"),
           auth_modes=("credential_id",)),
    Policy("read_file", CTF_TARGET, ("path", "session_token"), path_prefix="/ctf/"),
)
INVARIANTS: Mapping[str, object] = MappingProxyType({})


def lookup_credential(credential_id: str, target: str) -> IssuedCredential | None:
    """Find an issued credential only when its binding matches the proposed host.

    Args:
        credential_id: Reference presented for service authentication.
        target: Host at which the credential would be used.
    Returns:
        The bound credential, or None for an unknown or wrongly bound reference.
    """
    credential = ISSUED_CREDENTIALS.get(credential_id)
    if credential is None:
        return None
    if credential.target != target:
        return None
    return credential
