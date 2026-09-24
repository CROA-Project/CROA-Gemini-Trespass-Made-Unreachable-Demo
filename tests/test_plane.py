"""Control-plane stage ordering, traces, and evidence checks.

Demo role: verify real C3/C2 ordering and use a stub only for the future C4 slot.
Gemini action it addresses: #1–3, stopping and explaining the first rejection.
Must never import: live services; trusted compiler access is a test fixture.
"""

import json
from unittest.mock import Mock

from conftest import FirewallCase

from croa.contracts import Request
from croa.plane import ControlPlane
from croa.reasons import ACTION_NOT_PERMITTED, DENY, PERMIT, TARGET_NOT_REGISTERED
from models import CTF_TARGET, REAL_TARGET, Parameters, StageTrace


def test_c3_rejection_skips_later_checks_and_compilation(
    boundary: FirewallCase,
) -> None:
    """A C3 denial must leave both later check and compiler spies untouched."""
    compiler = Mock(wraps=boundary.compiler.compile_ecc)
    later = Mock(return_value=StageTrace("C4", PERMIT, PERMIT))
    plane = ControlPlane(compiler, boundary.evidence, checks=(later,))
    decision = plane.propose(Request("login", REAL_TARGET, boundary.parameters))
    assert decision.stopped_at == "C3" and decision.reason == TARGET_NOT_REGISTERED
    assert [trace.verdict for trace in decision.traces] == [DENY] + [None] * 4
    compiler.assert_not_called()
    later.assert_not_called()
    assert boundary.evidence.verify_chain().records == 2


def test_later_rejection_preserves_and_logs_earlier_verdict(
    boundary: FirewallCase,
) -> None:
    """Log a real C2 denial and retain C3's success without compiling an ECC."""
    compiler = Mock(wraps=boundary.compiler.compile_ecc)
    unused = Mock(return_value=StageTrace("C4", PERMIT, PERMIT, "2/3"))
    plane = ControlPlane(compiler, boundary.evidence, checks=(unused,))
    request = Request("read_file", CTF_TARGET, Parameters(path="/data/customers.csv"))
    decision = plane.propose(request)
    assert decision.stopped_at == "C2" and decision.reason == ACTION_NOT_PERMITTED
    assert [trace.verdict for trace in decision.traces] == [PERMIT, DENY] + [None] * 3
    lines = boundary.evidence.path.read_text().splitlines()
    records = [json.loads(line) for line in lines]
    assert [row["component"] for row in records] == ["plane", "C3", "C2"]
    assert [row["data"]["verdict"] for row in records[1:]] == [PERMIT, DENY]
    reasons = [PERMIT, ACTION_NOT_PERMITTED]
    assert [row["data"]["reason"] for row in records[1:]] == reasons
    compiler.assert_not_called()
    unused.assert_not_called()


def test_each_evaluated_stage_has_one_record(boundary: FirewallCase) -> None:
    """Keep the C4 stub detail and audit each real C3/C2 decision once."""
    trajectory = Mock(return_value=StageTrace("C4", PERMIT, PERMIT, "2/3"))
    plane = ControlPlane(boundary.compiler.compile_ecc, boundary.evidence,
                         checks=(trajectory,))
    decision = plane.propose(Request("login", CTF_TARGET, boundary.parameters))
    assert [trace.verdict for trace in decision.traces] == [PERMIT] * 4 + [None]
    assert decision.traces[2].detail == "2/3" and decision.ecc is not None
    lines = boundary.evidence.path.read_text().splitlines()
    records = [json.loads(line) for line in lines]
    assert [row["component"] for row in records] == ["plane", "C3", "C2", "C4", "C7"]
    assert all(row["data"]["verdict"] == PERMIT for row in records[1:])
    assert all(row["data"]["reason"] == PERMIT for row in records[1:])
    assert boundary.evidence.verify_chain().ok
