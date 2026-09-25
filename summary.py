"""Final scenario summary rendering.

Demo role: condense actual transcript outcomes into one comparison table.
Gemini action it addresses: #1–3 plus direct C6 bypass attempts in S4.
Must never import: world or CROA signing/firewall implementations.
"""

from dataclasses import dataclass

from agent.scripted_agent import StepResult
from croa.reasons import DENY
from transcript import scenario_outcome


@dataclass(frozen=True)
class SummaryRow:
    """One scenario's two outcomes and the governed deciding component."""

    scenario: str
    ungoverned: str
    governed: str
    component: str


def summary_row(
    scenario: str, ungoverned: list[StepResult] | None,
    governed: list[StepResult] | None,
) -> SummaryRow:
    """Summarize actual outcomes and the first governed denial component.

    Args:
        scenario: Fixed scenario identifier.
        ungoverned: Direct results, or None when that mode did not run.
        governed: Governed results, or None when that mode did not run.
    Returns:
        Compact values suitable for the final summary table.
    """
    component = "not run" if governed is None else "PERMIT path"
    if governed is not None:
        denied = next(
            (trace.component for row in governed for trace in row.traces
             if trace.verdict == DENY),
            None,
        )
        component = denied or component
    direct = "not run" if ungoverned is None else scenario_outcome(
        scenario, ungoverned
    )
    guarded = "not run" if governed is None else scenario_outcome(scenario, governed)
    return SummaryRow(scenario, direct.rstrip("."), guarded.rstrip("."), component)


def print_summary(rows: list[SummaryRow]) -> None:
    """Print the final scenario outcome and deciding-component table.

    Args:
        rows: Scenario summaries in execution order.
    """
    headers = ("SCENARIO", "UNGOVERNED", "GOVERNED", "DECIDING COMPONENT")
    values = [headers, *((r.scenario, r.ungoverned, r.governed, r.component)
                         for r in rows)]
    widths = [max(len(row[index]) for row in values) for index in range(4)]
    print("SUMMARY")
    for number, row in enumerate(values):
        print(" | ".join(value.ljust(widths[index])
                         for index, value in enumerate(row)))
        if number == 0:
            print("-+-".join("-" * width for width in widths))
    print()
