"""CROA control plane.

CROA component: control plane — runs C3 first and records every evaluated stage.
Gemini action it addresses: #1–3, centralizing execution authorization.
Fails closed: the first DENY prevents all later checks and contract compilation.
C2 evaluates C1 policy after C3; injected checks place C4 before C7.
"""

from collections.abc import Callable
from dataclasses import asdict

from croa.c2_governor import check as check_policy
from croa.c3_resolver import PathResolver
from croa.c5_evidence import EvidenceLog
from croa.contracts import ECC, Decision, Request
from croa.reasons import DENY, PERMIT
from models import STAGE_ORDER, StageTrace


class ControlPlane:
    """Ordered proposal checks with a trace and evidence record per decision."""

    def __init__(
        self, compile_ecc: Callable[[Request], ECC], evidence: EvidenceLog, *,
        resolver: PathResolver | None = None,
        checks: tuple[Callable[[Request], StageTrace], ...] = (),
    ) -> None:
        """Install mandatory C3 and C2 before later checks and C7 compilation."""
        self._compile_ecc = compile_ecc
        self._evidence = evidence
        self._checks = ((resolver or PathResolver()).check, check_policy, *checks)

    def propose(self, request: Request) -> Decision:
        """Ground first, record each evaluated verdict, and stop at the first denial.

        Args:
            request: Proposed action, identity, and immutable execution inputs.
        Returns:
            Decision with all stages in order, including unevaluated stages.
        Raises:
            OSError: If evidence required for authorization cannot be written.
            ValueError: If the existing evidence chain is corrupt.
        """
        self._evidence.append({
            "component": "plane", "event": "PROPOSAL_RECEIVED",
            "data": {"action": request.action, "target": request.target,
                     "session_id": request.session_id, "subject": request.subject},
        })
        traces = [StageTrace(component) for component in STAGE_ORDER]
        for check in self._checks:
            trace = check(request)
            traces[STAGE_ORDER.index(trace.component)] = trace
            self._record_stage(trace, request)
            if trace.verdict == DENY:
                assert trace.reason is not None
                return Decision(DENY, trace.reason, stopped_at=trace.component,
                                traces=traces)
        ecc = self._compile_ecc(request)
        trace = StageTrace("C7", PERMIT, PERMIT, f"ecc-{ecc.ecc_id[:8]}")
        traces[STAGE_ORDER.index("C7")] = trace
        self._record_stage(trace, request, ecc)
        return Decision(PERMIT, PERMIT, ecc, traces=traces)

    def _record_stage(
        self, trace: StageTrace, request: Request, ecc: ECC | None = None,
    ) -> None:
        """Audit successful checks and rejections before taking any next step."""
        event = "STAGE_DECISION"
        if trace.component == "C3":
            event = "GROUNDING_FAILED" if trace.verdict == DENY else "GROUNDING_PASSED"
        if trace.component == "C7":
            event = "ECC_ISSUED"
        self._evidence.append({
            "component": trace.component, "event": event,
            "data": {**asdict(trace), "action": request.action,
                     "target": request.target,
                     "ecc_id": ecc.ecc_id if ecc else None},
        })
