"""C4 trajectory reservation checks.

Demo role: prove the authentication limit is atomic and scoped to its identities.
Gemini action it addresses: #2, stopping password guessing before a target succeeds.
Must never import: world or execution firewall implementations.
"""

from croa.c1_policy import INVARIANTS, Invariant
from croa.c4_trajectory import TrajectoryMonitor
from croa.contracts import Request
from croa.reasons import DENY, PERMIT, TRAJECTORY_LIMIT_EXCEEDED
from models import CTF_TARGET, REAL_TARGET, Parameters


def test_c1_owns_authentication_invariant() -> None:
    """Keep C4's action, scope, and limit in C1's immutable authority table."""
    invariant = INVARIANTS["INVARIANT-TRAJ-AUTH-001"]
    assert invariant.action == "login"
    assert invariant.scope == "session:subject:target"
    assert invariant.limit == 3


def test_limit_boundary_commits_only_permitted_reservations() -> None:
    """Permit counts one through three and keep later denials at the boundary."""
    monitor = TrajectoryMonitor()
    verdicts = [
        monitor.reserve("session-a", "agent-a", "login", CTF_TARGET)
        for _ in range(5)
    ]
    assert [result.verdict for result in verdicts] == [PERMIT] * 3 + [DENY] * 2
    assert [result.current for result in verdicts] == [0, 1, 2, 3, 3]
    assert [result.projected for result in verdicts] == [1, 2, 3, 4, 4]
    assert all(result.limit == 3 for result in verdicts)
    assert all(
        result.reason == TRAJECTORY_LIMIT_EXCEEDED for result in verdicts[3:]
    )


def test_separate_targets_do_not_share_counters() -> None:
    """Give each target an independent allowance within one session and subject."""
    monitor = TrajectoryMonitor()
    for target in (CTF_TARGET, REAL_TARGET):
        results = [
            monitor.reserve("session-a", "agent-a", "login", target)
            for _ in range(3)
        ]
        assert all(result.verdict == PERMIT for result in results)


def test_separate_sessions_and_subjects_do_not_share_counters() -> None:
    """Include both trusted identities in the configured trajectory scope."""
    monitor = TrajectoryMonitor()
    for session, subject in (
        ("session-a", "agent-a"),
        ("session-b", "agent-a"),
        ("session-a", "agent-b"),
    ):
        results = [
            monitor.reserve(session, subject, "login", CTF_TARGET)
            for _ in range(3)
        ]
        assert all(result.verdict == PERMIT for result in results)


def test_monitor_uses_scope_declared_by_c1() -> None:
    """Derive counter identity from authority data rather than a fixed local scope."""
    invariant = Invariant("login", "target", 1)
    monitor = TrajectoryMonitor({"test-invariant": invariant})
    first = monitor.reserve("session-a", "agent-a", "login", CTF_TARGET)
    second = monitor.reserve("session-b", "agent-b", "login", CTF_TARGET)
    assert first.verdict == PERMIT
    assert second.verdict == DENY


def test_non_invariant_action_passes_without_counting() -> None:
    """Leave actions outside C1's trajectory table unrestricted by C4."""
    monitor = TrajectoryMonitor()
    request = Request("read_file", CTF_TARGET, Parameters(path="/ctf/flag.txt"))
    trace = monitor.check(request)
    assert trace.verdict == PERMIT and trace.reason == PERMIT
    assert trace.detail == ""
