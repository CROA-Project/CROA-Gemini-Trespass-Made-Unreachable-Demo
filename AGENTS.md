# AGENTS.md — CROA Gemini Replay Demo

You are the Constructor. The spec is `docs/ARCHITECTURE.md`; the work queue is
`docs/PLAN.md`. Execute one directive per turn and stop when its Done block is true.

## Permissions
- Run `python`, `pytest`, `ruff`, and `git` freely. Everything is local, deterministic,
  and touches no network. Fix failing tests you caused; do not disable them.
- Do not add runtime dependencies. Standard library only. `pytest` and `ruff` are the
  only dev dependencies.
- Do not commit. Leave the tree for the Evaluator.

## Code clarity — this is the priority
- Obvious over clever. A reader new to CROA should follow any function without a
  debugger. If a construct needs a comment to be understood, rewrite it instead.
- One job per module, one job per function. Functions under 40 lines. Modules under
  150 lines except `world/hosts.py` and `agent/scripted_agent.py`.
- Type hints on every signature. Dataclasses for records; no dicts passed around
  when a dataclass will do.
- Every denial returns a constant from `croa/reasons.py`. Never a literal string.
- No global mutable state except the C4 counters and the C6 nonce set, and each of
  those lives inside its class.

## Documentation — write it as you build, not after
- Module header docstring, always in this shape:
  ```
  """C3 Path Resolver.

  CROA component: C3 — grounds a proposed target against the registry.
  Gemini action it addresses: #1, resolving a fictional company name to a real host.
  Fails closed: any target not in FEDERATED_CONTEXT_REGISTRY is denied before C2 runs.
  """
  ```
  Modules that are not CROA components (world, agent, demo) state their role in the
  demo and what they must never import.
- Every public function: one-line summary, then `Args:`, `Returns:`, and `Raises:`
  only for what actually exists. No `Args: None` or `Returns: None` blocks. Test
  functions and trivial constructors get the one-line summary only. Say what the
  function decides and why, not how the loop works.
- Comments explain *why*. If a comment restates the code, delete the comment.
- Every reason code in `croa/reasons.py` has a one-line comment: which component
  emits it and under what condition.
- When you change behaviour described in `README.md` or `docs/WALKTHROUGH.md`,
  update that file in the same turn.

## Completion
A directive is done only when every line of its Done block is true and you have
run the commands yourself. Report in the format at the top of `docs/PLAN.md`.
If a Done line cannot be met, say which one and why; do not redefine it.
