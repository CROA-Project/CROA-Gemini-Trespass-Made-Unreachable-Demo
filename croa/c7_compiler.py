"""C7 Contract Compiler.

CROA component: C7 — signs a short-lived contract for a permitted proposal.
Gemini action it addresses: #1–3, allowing C6 to require explicit authorization.
Fails closed: every execution-relevant field is included in the HMAC signature.
"""

import hashlib
import hmac
import secrets
import time
from collections.abc import Callable
from dataclasses import replace
from uuid import uuid4

from croa.contracts import ECC, Request
from croa.serialization import canonical_json, parameters_hash

__all__ = ("Signer", "ContractCompiler", "canonical_json", "parameters_hash")


class Signer:
    """Shared HMAC capability given only to C7 and C6 by the composition root."""

    def __init__(self, key: bytes | None = None) -> None:
        """Use the supplied test key or generate a fresh 256-bit startup key."""
        self._key = key if key is not None else secrets.token_bytes(32)

    def sign(self, payload: dict[str, str | int]) -> str:
        """Authenticate all unsigned ECC fields using HMAC-SHA256.

        Args:
            payload: Contract fields excluding the signature.
        Returns:
            Hexadecimal signature of the canonical JSON bytes.
        """
        return hmac.new(
            self._key, canonical_json(payload).encode(), hashlib.sha256
        ).hexdigest()

    def verify(self, payload: dict[str, str | int], signature: str) -> bool:
        """Compare a presented HMAC with the expected signature in constant time.

        Args:
            payload: Presented unsigned contract fields.
            signature: Presented hexadecimal signature.
        Returns:
            Whether the signature authenticates the payload.
        """
        if not isinstance(signature, str) or not signature.isascii():
            return False
        return hmac.compare_digest(self.sign(payload), signature)


class ContractCompiler:
    """C7's signing capability and injectable clock."""

    def __init__(
        self, signer: Signer, *, clock: Callable[[], float] = time.time,
        ttl_seconds: int = 300,
    ) -> None:
        """Attach C7's signer, clock, and contract lifetime."""
        self._signer = signer
        self._clock = clock
        self._ttl_seconds = ttl_seconds

    def compile_ecc(self, request: Request) -> ECC:
        """Bind a permitted action to its identity, parameters, lifetime, and nonce.

        Args:
            request: Proposal that has passed the available control-plane checks.
        Returns:
            Signed contract carrying a fresh UUID and single-use nonce.
        """
        issued_at = int(self._clock())
        ecc = ECC(
            ecc_id=str(uuid4()), session_id=request.session_id,
            subject=request.subject, action=request.action, target=request.target,
            parameters_hash=parameters_hash(request.parameters),
            invariant_set_version="gemini-demo-policy-v1",
            iat=issued_at, exp=issued_at + self._ttl_seconds, nonce=str(uuid4()),
        )
        return replace(ecc, sig=self._signer.sign(ecc.payload()))
