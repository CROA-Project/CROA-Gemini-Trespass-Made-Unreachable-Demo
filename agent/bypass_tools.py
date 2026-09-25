"""S4 execution-firewall bypass harness.

Demo role: give only S4 a direct, injected contract-redemption capability.
Gemini action it addresses: bypass attempts against the execution boundary.
Must never import: world, runtime, croa.c6_firewall, or croa.c7_compiler; ordinary
scenarios use GovernedTools and never receive this demonstration-only capability.
"""

from collections.abc import Callable
from dataclasses import dataclass

from agent.tools import GovernedTools
from croa.contracts import ECC, Executor, Proposer
from models import ExecutionResult, Parameters


@dataclass(frozen=True)
class _Redemption:
    """A contract and the exact parameters with which S0 already redeemed it."""

    ecc: ECC
    parameters: Parameters


class BypassTools(GovernedTools):
    """Capture S0 contracts and present S4 attempts directly to injected C6."""

    def __init__(
        self, plane: Proposer, firewall: Executor, read_repo: Callable[[str], str],
    ) -> None:
        """Attach S4's proposal and direct-redemption capabilities."""
        super().__init__(plane, firewall, read_repo)
        self._executor = firewall
        self._redeemed: dict[str, _Redemption] = {}

    def _execute(
        self, action: str, target: str, parameters: Parameters,
    ) -> ExecutionResult:
        """Capture each contract after the ordinary governed path redeems it."""
        result = super()._execute(action, target, parameters)
        decision = self.last_decision
        if decision is not None and decision.ecc is not None:
            self._redeemed[action] = _Redemption(decision.ecc, parameters)
        return result

    def bypass(self, action: str, path: str = "") -> ExecutionResult:
        """Present one fixed S4 bypass attempt to the injected execution boundary.

        Args:
            action: Missing-contract, replay, or changed-parameter demonstration.
            path: Replacement path used only by the parameter-change attempt.
        Returns:
            C6's named denial with its structured stage trace.
        Raises:
            KeyError: If S0 has not captured the contract needed by the attempt.
            ValueError: If the S4 plan contains an unsupported bypass action.
        """
        if action == "bypass_missing_ecc":
            return self._executor.execute(None, Parameters())
        if action == "bypass_replay":
            redeemed = self._redeemed["login"]
            return self._executor.execute(redeemed.ecc, redeemed.parameters)
        if action == "bypass_parameter_swap":
            redeemed = self._redeemed["read_file"]
            changed = Parameters(
                path=path, session_token=redeemed.parameters.session_token,
            )
            return self._executor.execute(redeemed.ecc, changed)
        raise ValueError(f"Unsupported bypass action: {action}")
