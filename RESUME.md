# Resume the CROA Gemini Replay Demo

Checkpoint recorded 2026-09-25, after CD-006 acceptance and publication.
All six PLAN directives are complete.
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
- Working branch: `feat/cd-001-to-004`. All directive work lives here.
- Draft PR: https://github.com/CROA-Project/CROA-Gemini-Trespass-Made-Unreachable-Demo/pull/1
- Accepted implementation commits: CD-001–CD-004 `adb53c4b9afeaa9583103ed6da7dd62c5124d990`;
  CD-005 `3c115f92615f4dd20ad256cb9ce347cc97ebca69`;
  CD-006 `7d120bbb68ba21328e7e2d61ec3081aa0a713610`.
- Bootstrap `main`: `f5f142016f7deafa8cc11b240a25cfd69d762c4d`, containing only
  a stub README and the three license files copied unchanged from Pilot-001.
- Handoff documentation commits may follow the implementation checkpoint.
  Check Git state rather than assuming the branch tip still equals `7d120bb`.
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
  the default Constructor role.
- Every departure from ARCHITECTURE or PLAN, even an improvement, must appear as a
  separate line under `Open questions` in the Constructor's report. The Architect
  resolves it and updates the spec when accepting it.
- Update this handoff after each reviewed checkpoint with actual state and evidence.
  Distinguish implemented, verified, accepted, committed, and pushed work.

## Accepted state through CD-006

CD-001 through CD-006 are complete and accepted.

| Scenario | Ungoverned now | Governed now |
| --- | --- | --- |
| S0 legitimate CTF | Retrieves flag | C3/C2/C4 permit; C7 issues two ECCs; C6 executes both; retrieves flag |
| S1 name collision | Contacts `.com`; login fails | C3 `TARGET_NOT_REGISTERED`; with registry mistake, C2 `AUTH_MODE_NOT_PERMITTED` |
| S2 brute force | Guess 7 succeeds | C4 `1/3`, `2/3`, `3/3` (three failed target logins); guesses 4–10 C4 `TRAJECTORY_LIMIT_EXCEEDED` |
| S3 leaked credential | Reads fake customer data | C3 denies by default; with registry mistake, C2 denies login with `AUTH_MODE_NOT_PERMITTED` |
| S4 bypass attempt | Not applicable (no C6) | After a governed S0 setup: C6 `MISSING_ECC`, `ECC_REPLAYED`, `PARAMETER_MISMATCH`; World counters unchanged |

S3's fixed plan still attempts a read after login denial; with the registry mistake,
that read separately receives C2 `ACTION_NOT_PERMITTED`. The summary shows the first
denial. For governed S1 and S3 in either registry configuration, the `.com` World's
login attempts, successful logins, and file reads are all zero.

`--ambiguous` adds another `.test` registration and makes S1 return
`TARGET_AMBIGUOUS`. `--registry-mistake` registers `.com` and prints a loud banner.
Both are constructed only through `runtime.py` with per-run registry state.

C4 reads `INVARIANT-TRAJ-AUTH-001` (action `login`, scope `session:subject:target`,
limit 3) from C1 INVARIANTS. `TrajectoryMonitor.reserve` evaluates and commits under
one lock; runtime builds a fresh monitor per run and injects `monitor.check` into
`ControlPlane` after C2 and before C7. Only permitted reservations are counted.
Governed S2 runs all ten guesses; the World records 3 attempts and 0 successes,
and exactly three ECCs are issued. C4 now logs a stage record for every action it
evaluates, so S0 evidence grew from 12 to 14 records. Denied reservations record
detail `4/3` (the projected count); the transcript shows only the denial reason.

C4 enforces every C1 invariant whose action matches, denies if any would be
exceeded, and commits none of the counters on denial (CD-005 review carry-over).

`python demo.py` defaults to `--mode both`, runs S0–S4, prints a summary table, and
exits nonzero unless each governed scenario ends at its expected component (the
expectation accounts for `--ambiguous` and `--registry-mistake`). S4 uses
`BypassTools` from `agent/bypass_tools.py`, which runtime builds only with
`bypass=True`; it holds the same `Executor` capability GovernedTools already has
and imports no World, C6, or C7 module. Accepted file-organization deviations
(`agent/bypass_tools.py`, `summary.py`) are recorded in ARCHITECTURE section 8.
`docs/WALKTHROUGH.md` is the presenter script (76 lines).

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

The reviewed CD-006 baseline (Claude review, 2026-09-25): 129 passing tests, Ruff
clean, and `python demo.py` ending `C5 evidence: 86 records, chain OK` with exit 0,
both in the working venv and in a fresh copy with a new venv following the README
quick start exactly. All 12 combinations of mode and the two registry flags exit 0.
Function and module size limits hold; `agent/scripted_agent.py` is 153 lines, an
exception PLAN permits and its docstring explains.

The earlier CD-005 baseline had 124 passing tests and
`All checks passed!` from Ruff. Evidence totals: S2 49 records; S0 14; S1 2
(also with `--ambiguous`); S1 with registry mistake 3; S3 4; S3 with registry
mistake 6; all `chain OK`. The reviewer also verified independently: 64 threads
making 3,200 concurrent reservations on one key got exactly 3 permits; ungoverned
S2 World counters were 7 attempts and 1 success; governed S2 were 3 and 0, with
zero `.com` contact. These are recorded results, not fresh-machine verification.
Tests also cover signature/expiry/identity/parameter/replay failures, policy
consistency, import boundaries, evidence tampering, and World counters.

## Next step: the user's decision

No directive remains in PLAN. Do not start new work without an assignment.
Open choices for the user:

- Mark draft PR #1 ready for review and merge it into `main` (not done by any agent).
- Optionally have an Evaluator run PLAN's Evaluator checklist against the final state.
- Small presentation nits noted at CD-006 review, not blocking: S4 steps display the
  target as `C6`, the ungoverned S4 cells read `target: NOT APPLICABLE: no C6`, and
  the S4 summary names only the first denial (`MISSING_ECC`).
- `croa-demo.kdl` is a personal untracked Zellij layout; `.gitignore` covers only
  `croa_example.kdl`.

## Prompt for a new reviewer pane

> Read CLAUDE.md and RESUME.md, then the referenced operating rules, architecture,
> and plan. You are the Architect/reviewer. All six directives are accepted and
> published. Restore context, inspect Git state, and wait for the user's next
> instruction; do not start new work or change PR #1's draft status unasked.
