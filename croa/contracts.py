"""Control-plane and execution-boundary records.

CROA component: C7/C6 — shared contract structure without a signing capability.
Gemini action it addresses: #1–3, binding execution to a specific proposed action.
Fails closed: immutable records keep the signed action and parameters stable.
"""

from dataclasses import asdict, dataclass, field
from typing import Protocol

from models import ExecutionResult, Parameters, StageTrace


@dataclass(frozen=True)
class Request:
    """An action proposed under an honest session and subject identity."""

    action: str
    target: str
    parameters: Parameters
    session_id: str = "demo-session"
    subject: str = "agent:gemini-replay"
    company_name: str | None = None


@dataclass(frozen=True)
class ECC:
    """A signed, expiring, single-use authorization for exact execution inputs."""

    ecc_id: str
    session_id: str
    subject: str
    action: str
    target: str
    parameters_hash: str
    invariant_set_version: str
    iat: int
    exp: int
    nonce: str
    sig: str = ""

    def payload(self) -> dict[str, str | int]:
        """Expose precisely the contract fields protected by the signature.

        Returns:
            Contract fields excluding the signature itself.
        """
        fields = asdict(self)
        del fields["sig"]
        return fields


@dataclass(frozen=True)
class Decision:
    """Control-plane verdict with an optional executable contract."""

    verdict: str
    reason: str
    ecc: ECC | None = None
    stopped_at: str | None = None
    traces: list[StageTrace] = field(default_factory=list)


class Proposer(Protocol):
    """Proposal capability, without exposing the compiler to agent code."""

    def propose(self, request: Request) -> Decision:
        """Decide whether a proposal can receive an execution contract.

        Args:
            request: Proposed action and its execution inputs.
        Returns:
            Verdict and a contract if permitted.
        """
        ...


class Executor(Protocol):
    """Execution capability, without exposing the firewall implementation."""

    def execute(self, ecc: ECC | None, parameters: Parameters) -> ExecutionResult:
        """Redeem a contract for its exact execution inputs.

        Args:
            ecc: Contract supplied by the control plane, if present.
            parameters: Inputs to bind against the contract.
        Returns:
            Target outcome or an execution denial.
        """
        ...
