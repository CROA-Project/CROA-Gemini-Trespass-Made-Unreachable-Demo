"""C4 Invariant Monitor.

CROA component: C4 — reserves bounded actions against C1 trajectory invariants.
Gemini action it addresses: #2, stopping a sequence of individually permitted guesses.
Fails closed: a login whose projected count exceeds C1's limit is denied before C7.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from threading import Lock

from croa import c1_policy
from croa.contracts import Request
from croa.reasons import DENY, PERMIT, TRAJECTORY_LIMIT_EXCEEDED
from models import StageTrace


@dataclass(frozen=True)
class TrajectoryVerdict:
    """A reservation verdict with usage before and after the proposed action."""

    verdict: str
    reason: str
    current: int
    projected: int
    limit: int | None


@dataclass(frozen=True)
class _Reservation:
    """One matching invariant's counter state for an atomic decision."""

    key: tuple[str, ...]
    current: int
    projected: int
    limit: int


class TrajectoryMonitor:
    """Per-run counters that atomically evaluate and commit permitted reservations."""

    def __init__(
        self, invariants: Mapping[str, c1_policy.Invariant] | None = None,
    ) -> None:
        """Snapshot C1's invariants and initialize isolated counter state."""
        authority = c1_policy.INVARIANTS if invariants is None else invariants
        self._invariants = tuple(authority.items())
        self._counts: dict[tuple[str, ...], int] = {}
        self._lock = Lock()

    @staticmethod
    def _counter_key(
        name: str, invariant: c1_policy.Invariant,
        session: str, subject: str, target: str,
    ) -> tuple[str, ...]:
        """Build the counter identity from the scope declared by C1."""
        values = {"session": session, "subject": subject, "target": target}
        return (name, *(values[field] for field in invariant.scope.split(":")))

    def reserve(
        self, session: str, subject: str, action: str, target: str,
    ) -> TrajectoryVerdict:
        """Reserve one action only when every matching C1 invariant permits it.

        Args:
            session: Honest session identity used to scope the counter.
            subject: Honest agent identity used to scope the counter.
            action: Proposed operation matched against C1's invariant action.
            target: Grounded host used to scope the counter.
        Returns:
            The first denying invariant's usage, or the first permitted one's usage.
        """
        matching = [
            (name, invariant) for name, invariant in self._invariants
            if invariant.action == action
        ]
        if not matching:
            return TrajectoryVerdict(PERMIT, PERMIT, 0, 0, None)
        with self._lock:
            reservations = [
                self._reservation(name, invariant, session, subject, target)
                for name, invariant in matching
            ]
            denied = next(
                (item for item in reservations if item.projected > item.limit), None,
            )
            if denied is not None:
                return TrajectoryVerdict(
                    DENY, TRAJECTORY_LIMIT_EXCEEDED,
                    denied.current, denied.projected, denied.limit,
                )
            for item in reservations:
                self._counts[item.key] = item.projected
        first = reservations[0]
        return TrajectoryVerdict(
            PERMIT, PERMIT, first.current, first.projected, first.limit,
        )

    def _reservation(
        self, name: str, invariant: c1_policy.Invariant,
        session: str, subject: str, target: str,
    ) -> _Reservation:
        """Read one counter while the caller holds the evaluate-and-commit lock."""
        key = self._counter_key(name, invariant, session, subject, target)
        current = self._counts.get(key, 0)
        return _Reservation(key, current, current + 1, invariant.limit)

    def check(self, request: Request) -> StageTrace:
        """Expose an atomic reservation as a control-plane C4 stage trace.

        Args:
            request: Grounded, policy-permitted proposal carrying the counter scope.
        Returns:
            C4 verdict with accepted usage rendered as a current-limit fraction.
        """
        result = self.reserve(
            request.session_id, request.subject, request.action, request.target,
        )
        detail = "" if result.limit is None else f"{result.projected}/{result.limit}"
        return StageTrace("C4", result.verdict, result.reason, detail)
