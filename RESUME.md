# Resume the CROA Gemini Replay Demo

Checkpoint recorded 2026-09-24, after CD-004 acceptance and publication.
This file is the handoff for fresh Codex and Claude sessions on another computer.
Chat history, Zellij sessions, local paths, and virtual environments are not needed.
Reading this file alone does not authorize starting a directive or publishing work.

## Read first

Read `AGENTS.md`, `docs/ARCHITECTURE.md`, and `docs/PLAN.md`, in that order,
then use this handoff for the accepted checkpoint and next assignment.
AGENTS is the Constructor's operating rules; ARCHITECTURE is the spec; PLAN is
the six-directive queue. Some early PLAN descriptions predate accepted architecture
changes below. Do not undo accepted changes to match those older descriptions.
The user's current instructions take precedence.

## Repository and branch

- Repository: https://github.com/CROA-Project/CROA-Gemini-Trespass-Made-Unreachable-Demo
- Working branch: `feat/cd-001-to-004`. Keep using it for CD-005 unless told otherwise.
- Draft PR: https://github.com/CROA-Project/CROA-Gemini-Trespass-Made-Unreachable-Demo/pull/1
- Accepted implementation commit: `adb53c4b9afeaa9583103ed6da7dd62c5124d990`.
- Bootstrap `main`: `f5f142016f7deafa8cc11b240a25cfd69d762c4d`, containing only
  a stub README and the three license files copied unchanged from Pilot-001.
- Handoff documentation commits may follow the implementation checkpoint.
  Check Git state rather than assuming the branch tip still equals `adb53c4`.
- Implementation belongs on the feature branch, never directly on `main`.
  Do not merge the draft PR or force-push as part of resuming.

## Roles and review workflow

- Codex normally acts as Constructor: implement one explicitly assigned directive,
  run every Done command, report, and stop. Do not commit or push Constructor work.
- Claude acts as Architect/reviewer in the current workflow: independently inspect
  the implementation and run acceptance checks before accepting, committing, and
  pushing. Do not infer acceptance from the Constructor's report.
- An Evaluator may also run the checklist at the end of PLAN. No fresh agent should
  claim another agent has reviewed work it has not actually reviewed.
- The user temporarily assigned Codex an Architect review for CD-004. Codex reviewed
  it and accepted the C6 extension; Claude subsequently reported an independent
  review, acceptance, and publication. That temporary assignment does not change
  the default Constructor role for CD-005.
- Every departure from ARCHITECTURE or PLAN, even an improvement, must appear as a
  separate line under `Open questions` in the Constructor's report. The Architect
  resolves it and updates the spec when accepting it.
- Update this handoff after each reviewed checkpoint with actual state and evidence.
  Distinguish implemented, verified, accepted, committed, and pushed work.

## Accepted state through CD-004

CD-001 through CD-004 are complete and accepted. CD-005 and CD-006 have not started.

| Scenario | Ungoverned now | Governed now |
| --- | --- | --- |
| S0 legitimate CTF | Retrieves flag | C3/C2 permit; C7 issues two ECCs; C6 executes both; retrieves flag |
| S1 name collision | Contacts `.com`; login fails | C3 `TARGET_NOT_REGISTERED`; with registry mistake, C2 `AUTH_MODE_NOT_PERMITTED` |
| S2 brute force | Guess 7 succeeds | Guess 7 still succeeds; C4 is not implemented yet |
| S3 leaked credential | Reads fake customer data | C3 denies by default; with registry mistake, C2 denies login with `AUTH_MODE_NOT_PERMITTED` |

S3's fixed plan still attempts a read after login denial; with the registry mistake,
that read separately receives C2 `ACTION_NOT_PERMITTED`. The summary shows the first
denial. For governed S1 and S3 in either registry configuration, the `.com` World's
login attempts, successful logins, and file reads are all zero.

`--ambiguous` adds another `.test` registration and makes S1 return
`TARGET_AMBIGUOUS`. `--registry-mistake` registers `.com` and prints a loud banner.
Both are constructed only through `runtime.py` with per-run registry state.

The default CLI mode remains ungoverned. C4 prints `not evaluated`.
S4, the final summary table, the both-mode default, and `docs/WALKTHROUGH.md`
belong to CD-006; their absence is intentional at this checkpoint.

## Decisions and constraints to preserve

- Runtime dependencies: standard library only. Dev tools: pytest and Ruff only.
  Prefer clear small functions, type hints, dataclasses, and named reason constants.
- Docstrings follow current AGENTS: omit nonexistent Args/Returns sections;
  tests and trivial constructors use a one-line summary. Apply this when touching
  existing files; do not perform a separate documentation sweep.
- All reason codes live in `croa/reasons.py`, with emitter/condition comments.
- `runtime.py` is the composition root. `agent/` never imports `world`, `runtime`,
  `croa.c6_firewall`, or `croa.c7_compiler`. Production World imports are restricted
  to runtime and C6; `test_import_boundaries` enforces the static boundaries.
- Signer uses standard-library HMAC-SHA256 and is passed only to C7 and C6.
  This is a local scripted simulation, not a live model or a Python sandbox.
- C1 owns policy content and issued credentials. C2 and C6 use those same tables;
  C6 retains its bound-credential lookup immediately before secret injection.
- C6 checks presence, signature, subject/session identity, expiry, parameters hash,
  replay, then current C1 policy through C2's evaluator before admission.
  `SUBJECT_MISMATCH` is distinct from `INVALID_SIGNATURE`. The policy recheck was an
  explicitly accepted CD-004 extension, now recorded in ARCHITECTURE section 4.
- Read ECCs bind both `path` and `session_token`. Nonces are consumed before World
  execution. Evidence records do not expose injected service secrets.
- Decision carries ordered C3/C2/C4/C7/C6 traces. Every evaluated stage logs its
  verdict and reason to C5; later stages after a denial print `not evaluated`.
- PLANS is an immutable mapping of tuples, an accepted departure from the early
  dict/list sketch to comply with the no-mutable-globals rule.
- S3's transcript prints the resolved fake leaked password, not `$leaked_password`.
- `croa_example.kdl` is a personal, ignored Zellij layout. It is not required to run
  this project. Start fresh panes in the clone directory; no old absolute path is needed.
- `.venv`, caches, and `evidence/` are ignored. Recreate them; do not copy or commit them.
  Demo invocations regenerate the evidence log.

## Fresh computer setup and baseline

Use Python 3.11 or newer. These commands assume a Bash-compatible shell (e.g. WSL).

```sh
git clone --branch feat/cd-001-to-004 https://github.com/CROA-Project/CROA-Gemini-Trespass-Made-Unreachable-Demo.git
cd CROA-Gemini-Trespass-Made-Unreachable-Demo
git status --short --branch
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pytest ruff
python -m pytest -q
ruff check .
python demo.py --mode both --scenario S3 --registry-mistake
```

On native Windows, activate with `.venv\Scripts\Activate.ps1` in PowerShell instead.
Installing dev tools needs package-index access; running the demo needs no network.
For an existing clone, inspect local changes before updating; do not discard them.

The reviewed CD-004 baseline had 116 passing tests and `All checks passed!` from
Ruff. S3 with the registry mistake ended `C5 evidence: 6 records, chain OK`;
without it, 4 records; S1 with it, 3 records; S0, 12 records. These are recorded
results from the prior review, not claims of fresh-machine verification.
Tests also cover signature/expiry/identity/parameter/replay failures, policy
consistency, import boundaries, evidence tampering, and World counters.

## Next assignment: CD-005 only

Start only after the user assigns CD-005. Re-read its complete block in PLAN.

- Put `INVARIANT-TRAJ-AUTH-001` in C1 INVARIANTS: action `login`, scope
  `session:subject:target`, limit 3. C4 must read the authority's invariant data.
- Add `croa/c4_trajectory.py` with
  `TrajectoryMonitor.reserve(session, subject, action, target) -> TrajectoryVerdict`.
  Evaluate and commit under one lock in one call. Include current, projected, and
  limit so the transcript can show `1/3`, `2/3`, `3/3`, then denial.
- Run C4 after C2 and before C7; return `stopped_at="C4"` on denial. Preserve C5
  records and traces. `ControlPlane` already accepts additional ordered checks;
  construct and inject per-run monitor state through runtime.
- Governed S2 must try all ten guesses: attempts 4–10 receive
  `TRAJECTORY_LIMIT_EXCEEDED` without reaching C7. Do not add agent intelligence.
  Ungoverned S2 still stops on successful guess 7.
- Test the limit boundary and independent targets/sessions (the scope also includes
  subject). Prove exactly three ECCs issued and exactly three failed World logins,
  with zero successful logins. Check World counters, not just transcript text.
- Update README behavior in the same directive; keep S0/S1/S3 working.
- Run `python demo.py --mode both --scenario S2`, `python -m pytest -q`, and
  `ruff check .` yourself, and satisfy every CD-005 Done line. Report in PLAN's
  exact format, including all deviations under Open questions. Stop; no CD-006.

## Prompts for new panes

Codex, when ready to begin implementation:

> Read AGENTS.md, docs/ARCHITECTURE.md, docs/PLAN.md, and RESUME.md. You are the
> Constructor. CD-004 is accepted and published. Stay on feat/cd-001-to-004;
> do not commit or push. Execute CD-005 only, including the requirements in
> RESUME.md. Run its Done commands yourself, report in PLAN's format with every
> deviation under Open questions, and stop for review.

Claude, when restoring the reviewer pane:

> Read CLAUDE.md and RESUME.md, then the referenced operating rules, architecture,
> and plan. You are the Architect/reviewer. Restore context and inspect Git state;
> do not implement CD-005 in parallel. Wait for the Constructor's CD-005 report.
> Independently verify the Done block and World counters before accepting it.
> Commit and push only reviewed work on feat/cd-001-to-004, update RESUME.md,
> and leave PR #1 a draft. Report actual validation and publication results.
