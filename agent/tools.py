"""Ungoverned and governed replay tools.

Demo role: route identical agent calls through injected execution capabilities.
Gemini action it addresses: #1–3, separating proposed actions from their execution.
Must never import: world, croa.c7_compiler, or croa.c6_firewall; construction belongs
to runtime.py, which provides only the capabilities needed by each adapter.
"""

from collections.abc import Callable
from dataclasses import replace

from agent.interface import Tools
from croa.contracts import Decision, Executor, Proposer, Request
from croa.reasons import PERMIT
from models import ExecutionResult, Parameters

__all__ = ("Tools", "UngovernedTools", "GovernedTools")


class UngovernedTools(Tools):
    """Direct execution capability with no CROA proposal or contract."""

    def __init__(
        self, execute: Callable[[str, str, Parameters], ExecutionResult],
        read_repo: Callable[[str], str],
    ) -> None:
        """Attach direct execution and public repository capabilities."""
        super().__init__(read_repo)
        self._direct_execute = execute

    def _execute(
        self, action: str, target: str, parameters: Parameters,
    ) -> ExecutionResult:
        """Execute directly without asking the control plane for authorization."""
        return self._direct_execute(action, target, parameters)


class GovernedTools(Tools):
    """Proposal and execution capabilities, without access to a signer or World."""

    def __init__(
        self, plane: Proposer, firewall: Executor, read_repo: Callable[[str], str],
    ) -> None:
        """Attach proposal, redemption, and unprivileged public-source capabilities."""
        super().__init__(read_repo)
        self._plane, self._firewall = plane, firewall
        self.last_decision: Decision | None = None

    def _execute(
        self, action: str, target: str, parameters: Parameters,
    ) -> ExecutionResult:
        """Propose every host action before asking C6 to redeem its contract."""
        request = Request(action, target, parameters, company_name=self.company_name)
        decision = self._plane.propose(request)
        self.last_decision = decision
        if decision.verdict != PERMIT:
            return ExecutionResult(False, decision.reason, traces=decision.traces)
        outcome = self._firewall.execute(decision.ecc, parameters)
        traces = [trace for trace in decision.traces if trace.component != "C6"]
        return replace(outcome, traces=traces + outcome.traces)
