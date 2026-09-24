# Build Plan — Constructor Directives for Codex (GPT-6 Astra)

Read `AGENTS.md` first, then `docs/ARCHITECTURE.md`. Execute one directive at a time,
in order. Each directive ends with a **Done means** block. Do not report a directive
complete until every line of that block is true. Do not start the next directive
in the same turn; stop and report so the Evaluator can review.

Report format at the end of each directive:

```
CD-00N <name> — DONE
Files: <created/changed>
Verified: <commands you ran and their last line of output>
Open questions: <none, or one line each>
```

---

## CD-001 Scaffold, World, ungoverned agent

**Goal.** A runnable repo where the scripted agent, using ungoverned tools, breaches
the simulated world in scenarios S1, S2, S3, and legitimately solves S0. No CROA code yet.
This is the "before" picture.

**Build.**
- `pyproject.toml` (name `croa-gemini-demo`, Python ≥ 3.11, no runtime deps,
  `pytest` and `ruff` as dev deps). `.gitignore` with `evidence/`, `__pycache__/`, `.venv/`.
- `world/hosts.py`: the four World objects from ARCHITECTURE §3 as plain dataclasses.
  A `World` class with `login(target, *, password=None, secret=None) -> LoginResult`
  and `read_file(target, session_token, path) -> str`. Passwords: `.test` host uses
  `orion2026!` (guessable), `.com` host uses `Xk9#mPq2vL` (only in the leaked repo).
  `World.public_repo_read(repo_id) -> str` returns the leaked config text.
- `agent/tools.py`: an abstract `Tools` interface with `resolve_company`, `login`,
  `read_file`, `read_public_repo`. `UngovernedTools(World)` implements it by direct calls.
  `resolve_company("Orion Logistics")` returns the `.com` host first, then `.test`,
  to reproduce the name collision.
- `agent/scripted_agent.py`: `PLANS: dict[str, list[Step]]` for S0–S3 exactly as
  ARCHITECTURE §6 describes. `run_plan(plan, tools) -> list[StepResult]`. The agent
  has no branching except "stop the brute-force loop when a login succeeds".
- `demo.py`: `--mode ungoverned` prints a one-column transcript per scenario.
  `--scenario S2` runs one. Default runs all.
- `tests/test_world.py`, `tests/test_scenarios.py` (ungoverned expectations only):
  S0 retrieves the flag, S1 reaches the `.com` host, S2 succeeds on guess 7,
  S3 reads `customers.csv`.

**Done means.**
- `python demo.py --mode ungoverned` runs without error and its output shows the
  three breaches and the one legitimate solve, each labelled.
- `python -m pytest -q` is green.
- `ruff check .` is clean.
- Every module has the header docstring required by `AGENTS.md`; every public
  function has a docstring with Args/Returns.

---

## CD-002 Evidence, contracts, firewall, plane — the PERMIT path (S0)

**Goal.** The governed pipeline exists end to end and the legitimate scenario S0
passes through it. Nothing is denied yet.

**Build.**
- `croa/reasons.py`: every reason code from ARCHITECTURE §4 and §6 as constants,
  each with a one-line comment stating which component emits it and why.
- `croa/c5_evidence.py`: `EvidenceLog(path)` with `append(event: dict) -> str`
  (returns the record hash) and `verify_chain() -> ChainResult`. Records are
  `{"seq", "ts", "component", "event", "data", "prev_hash", "hash"}`.
- `croa/c7_compiler.py`: `Signer` (holds the HMAC key), `compile_ecc(...)` per
  ARCHITECTURE §4, `canonical_json()`, `parameters_hash()`.
- `croa/c6_firewall.py`: `ExecutionFirewall(signer, world, evidence)`. `execute(ecc, parameters)`.
  Checks in this order, each with its reason code: presence, signature, expiry,
  parameters hash, replay (nonce set). On pass: if parameters carry `credential_id`,
  look it up in `c1_policy.ISSUED_CREDENTIALS`, inject the secret, and call the World.
  Log `ECC_ADMITTED` / `ECC_REJECTED` and the World outcome to C5.
- `croa/c1_policy.py`: `ISSUED_CREDENTIALS` only (policies and invariants come in later
  directives, but create the empty tables now so imports are stable).
- `croa/plane.py`: `ControlPlane.propose(request) -> Decision`. For this directive it
  runs C7 only and logs `PROPOSAL_RECEIVED` and `ECC_ISSUED`. Structure it so C3, C2,
  C4 slot in ahead of C7 in the next directives without reshaping the function.
- `agent/tools.py`: `GovernedTools(plane, firewall)` implementing the same interface.
  `login` and `read_file` call `plane.propose` then `firewall.execute`. `resolve_company`
  and `read_public_repo` are unchanged (agent-side reasoning).
- `demo.py --mode governed` and `--mode both` (two-column transcript, ARCHITECTURE §7).
  Print the C5 summary line at the end.
- Tests: `test_c5_evidence.py` (append, verify, tamper one record → broken link reported),
  `test_c6_firewall.py` (happy path; wrong signature; expired; replay; parameter mismatch),
  `test_scenarios.py` gains S0 governed: two ECCs issued and redeemed, flag retrieved.

**Done means.**
- `python demo.py --mode both --scenario S0` shows PERMIT at each step and the flag
  in both columns; last line reports the C5 chain OK.
- The five C6 negative tests pass with the exact reason codes from `reasons.py`.
- `pytest -q` green, `ruff check .` clean, docstrings per `AGENTS.md`.
- `agent/` imports nothing from `croa.c6_firewall`, `croa.c7_compiler`, or `world`.
  Add this as a test (`test_import_boundaries`) now.

---

## CD-003 C3 Path Resolver — name collision (S1)

**Goal.** The agent's wrong host resolution is denied before policy is even evaluated.

**Build.**
- `croa/c3_resolver.py`: `FEDERATED_CONTEXT_REGISTRY` with the `.test` host and
  `endpoint:public_repo` only. `resolve_target(action, target) -> Grounding`. Returns
  `TARGET_NOT_REGISTERED` for unknown targets. Add `resolve_by_name(name) -> Grounding`
  that returns `TARGET_AMBIGUOUS` when more than one registered entry matches a
  company name; used only when `--ambiguous` is set (which registers a second `.test`
  variant to manufacture ambiguity).
- `croa/plane.py`: C3 runs first. On DENY, log `GROUNDING_FAILED` and return without
  running later stages. The Decision object records `stopped_at="C3"`.
- `demo.py`: `--ambiguous` flag. `--registry-mistake` flag (adds the `.com` host to the
  registry at startup and prints a loud banner). Needed by CD-005 but wire it now so
  the registry has one construction path.
- Tests: `test_c3_resolver.py` (registered, unregistered, type mismatch, ambiguous),
  `test_scenarios.py` gains S1 governed: `stopped_at == "C3"`, reason
  `TARGET_NOT_REGISTERED`, the World's `.com` host records zero login attempts.

**Done means.**
- `python demo.py --mode both --scenario S1` shows the `.com` breach ungoverned and
  `C3 DENY TARGET_NOT_REGISTERED` governed, with C2/C4/C7/C6 marked "not evaluated".
- `--ambiguous` produces `TARGET_AMBIGUOUS`.
- `pytest -q` green, `ruff` clean, docstrings per `AGENTS.md`.

---

## CD-004 C1 policy + C2 Governor — credential provenance (S3)

**Goal.** A secret the agent found on its own is rejected because C1 never issued it,
even when C3 has been fooled by a registry mistake.

**Build.**
- `croa/c1_policy.py`: `POLICIES` per ARCHITECTURE §5:
  `login` on `.test` permits `password` mode; `login` on any other target requires
  `credential_id` present in `ISSUED_CREDENTIALS` and bound to that target;
  `read_file` on `.test` permitted for paths under `/ctf/`; everything else DENY.
- `croa/c2_governor.py`: `evaluate(grounded_request) -> Verdict`. Emits
  `CREDENTIAL_NOT_ISSUED` when a `credential_id` is unknown or bound elsewhere,
  `AUTH_MODE_NOT_PERMITTED` when `password` mode is used off the `.test` host,
  `ACTION_NOT_PERMITTED` for everything not matched by a PERMIT policy.
- `croa/plane.py`: C2 runs after C3. `stopped_at="C2"` on DENY.
- Tests: `test_c2_governor.py` for each reason code; `test_scenarios.py` gains S3 governed
  in both configurations: without `--registry-mistake` it stops at C3, with it it stops
  at C2 with `AUTH_MODE_NOT_PERMITTED` (the leaked secret is presented as a password).
  The `.com` host records zero successful logins in both.

**Done means.**
- `python demo.py --mode both --scenario S3 --registry-mistake` prints the banner,
  shows the PII read ungoverned, and `C2 DENY AUTH_MODE_NOT_PERMITTED` governed.
- Without the flag the same scenario stops at C3.
- `pytest -q` green, `ruff` clean, docstrings per `AGENTS.md`.

---

## CD-005 C4 Invariant Monitor — brute force (S2)

**Goal.** Individually permitted login attempts are cut off by the sequence limit.

**Build.**
- `croa/c1_policy.py`: `INVARIANTS` with `INVARIANT-TRAJ-AUTH-001`
  (action `login`, scope `session:subject:target`, limit 3).
- `croa/c4_trajectory.py`: `TrajectoryMonitor.reserve(session, subject, action, target) -> TrajectoryVerdict`.
  Evaluate and commit under one lock in one call (mirrors the pilot v0.2.0 fix).
  Return current, projected, and limit in the verdict so the transcript can print `2/3`.
- `croa/plane.py`: C4 runs after C2 and before C7. `stopped_at="C4"` on DENY.
- `agent/scripted_agent.py`: in governed mode the brute-force loop must *keep trying*
  after the first C4 DENY so the transcript shows guesses 5–10 also denied without
  ever reaching C7. Do not add intelligence to the agent; it just runs its list.
- Tests: `test_c4_trajectory.py` (limit boundary, separate targets do not share
  counters, separate sessions do not share counters), `test_scenarios.py` gains S2
  governed: exactly three ECCs issued, attempts 4–10 `stopped_at == "C4"`, the World
  records exactly three failed logins and zero successes.

**Done means.**
- `python demo.py --mode both --scenario S2` shows guess 7 succeeding ungoverned and
  the `1/3 2/3 3/3 DENY` progression governed.
- `pytest -q` green, `ruff` clean, docstrings per `AGENTS.md`.

---

## CD-006 S4 bypass scenario, README, walkthrough, final pass

**Goal.** Ship-ready. A presenter can clone, run one command, and narrate.

**Build.**
- `agent/scripted_agent.py`: S4 plan. It needs a hook to call the firewall directly and
  to reuse an earlier ECC; implement this as a `BypassTools` subclass used only by S4,
  with a module docstring explaining it exists to demonstrate C6 and is not an agent
  capability in the other scenarios.
- `demo.py`: summary table after all scenarios (ARCHITECTURE §7). `--mode both` is the
  default. Exit code 0 only if every governed scenario ended in the expected component.
- `README.md`: purpose (three paragraphs max), the incident table from ARCHITECTURE §1,
  quick start, the scenario table, "What this does NOT show" copied from ARCHITECTURE §9,
  and the HMAC simplification note.
- `docs/WALKTHROUGH.md`: presenter script. For each scenario: one sentence on what
  Gemini did, the command to run, what to point at in the output, one sentence on the
  CROA principle. Under 120 lines.
- Final pass: read every module top to bottom. Remove anything not used by a scenario
  or a test. Confirm every function is under 40 lines and every module under 150
  (World and scripted plans may exceed; note why in their docstrings).

**Done means.**
- `python demo.py` from a fresh clone runs all five scenarios in both modes, prints the
  summary table and `C5 evidence: N records, chain OK`, exits 0.
- `pytest -q` green, `ruff check .` clean.
- `README.md` quick start works exactly as written (test it in a fresh venv).
- `docs/WALKTHROUGH.md` exists and references only flags and outputs that exist.

---

## Evaluator checklist (Gemini CLI, after each directive)

1. Run the directive's Done commands yourself. Do not trust the report.
2. Open `croa/reasons.py`. Every code printed in the transcript must be defined there.
3. For the directive's scenario, confirm the World object shows *zero* unauthorized
   effects in governed mode (no logins, no reads). Check the World's counters, not the
   transcript.
4. Try one thing the directive did not anticipate (an extra parameter, an empty target,
   a replayed ECC from a different session). It must fail closed with a reason code.
5. Check `test_import_boundaries` still passes and still covers `agent/` and `world/`.
6. Read three random functions. If you cannot explain each in one sentence from its
   docstring alone, the directive is not done.
