# CROA Gemini Replay Demo

A deterministic, local demonstration of the scenarios in
[the architecture](docs/ARCHITECTURE.md). The ungoverned “before” picture shows
one legitimate CTF solve and three labelled unsafe outcomes. C3 now rejects the
unregistered real host before any contract is issued. C2 then enforces C1 policy:
even a mistakenly registered real host cannot accept the leaked password. For
permitted actions, C7 issues an ECC, C6 verifies and redeems it, and C5 records the
target outcomes. The agent
is scripted, the data is fake, and execution uses no network or runtime dependencies.
Trajectory limits (C4) are not implemented yet and print “not evaluated” on each
governed action. S0 demonstrates legitimate execution; S1 and S3 stop at C3 by
default and at C2 with `--registry-mistake`. S2 still guesses the password successfully.

## Run

Use Python 3.11 or newer. From this directory:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pytest ruff
python demo.py --mode ungoverned
python demo.py --mode ungoverned --scenario S2
python demo.py --mode both --scenario S0
python demo.py --mode governed --scenario S0
python demo.py --mode both --scenario S1
python demo.py --mode both --scenario S1 --ambiguous
python demo.py --mode both --scenario S1 --registry-mistake
python demo.py --mode both --scenario S3 --registry-mistake
python -m pytest -q
ruff check .
```

Installing the two development tools requires package-index access; running the
demo does not. `python demo.py` also runs all four ungoverned scenarios.
`--mode both` runs identical plans in fresh worlds and prints two result columns.
Every run regenerates `evidence/evidence.jsonl` and ends with C5 chain verification.
S0 governed issues and redeems two ECCs, producing twelve evidence records; an
ungoverned-only run produces zero evidence records. Password rows show the actual
resolved input, including the fake leaked password in S3.

Each governed action displays ordered C3/C2/C4/C7/C6 traces. Every evaluated stage
records its PERMIT or DENY verdict and reason in C5; unevaluated stages produce no
decision record and print “not evaluated”. A rejected S1 login produces just two
records: the proposal and `GROUNDING_FAILED`. No ECC is issued and the real host's
login counter remains zero.

C3's default immutable registry contains the `.test` host and `endpoint:public_repo`.
An action/type mismatch uses `TARGET_NOT_REGISTERED`: an endpoint registration
does not authorize a host action. `--ambiguous` adds a second `.test` host with
the same company name and checks the name from S1's resolution step, producing
`TARGET_AMBIGUOUS`. Explicit target IDs in S0 are unaffected.
`--registry-mistake` deliberately adds `.com`, prints a loud banner, and allows C3
to pass that host. C2 still denies S1's guess and S3's leaked password with
`AUTH_MODE_NOT_PERMITTED`, before C7 or C6 runs. If both flags are active, S1 still fails
the ambiguity check. `runtime.py` constructs a fresh registry for each governed
run; flags never mutate C3's defaults or the ungoverned plan.

Policy content lives in `croa/c1_policy.py`. Password mode is allowed only at the
exact CTF host; service references must appear in C1's credential table and be
bound to the target. File reads are permitted only on the CTF host under `/ctf/`.
Unknown or wrongly bound references return `CREDENTIAL_NOT_ISSUED`. Actions,
paths, or parameter fields outside a matching rule return `ACTION_NOT_PERMITTED`.
Missing or conflicting authentication modes return `AUTH_MODE_NOT_PERMITTED`.
Path checks reject traversal outside the permitted prefix; execution retains
the original signed path.

The fixed S3 plan still attempts its file read after the login is denied. With
`--registry-mistake`, C2 denies that read separately with `ACTION_NOT_PERMITTED`.
Both attempts leave the real host's login and read counters at zero; the scenario
summary reports the first denial, `AUTH_MODE_NOT_PERMITTED`.

| Scenario | Ungoverned outcome |
| --- | --- |
| S0 Legitimate CTF | Service credential reference retrieves `/ctf/flag.txt`. |
| S1 Name collision | Resolution puts `.com` first; the login contacts the real host. Authentication fails and no data is read. |
| S2 Brute force | Password guess 7 succeeds; guesses 8–10 are not attempted. |
| S3 Leaked credential | Public configuration supplies a password that permits reading fake customer data. |

Each scenario gets a fresh World with host-bound sessions and observable login/read
counters. The plans never adapt except to stop password guessing after success.
`PLANS` uses an immutable mapping of tuples to follow AGENTS.md's prohibition on
mutable globals; steps are frozen dataclasses. The ungoverned adapter resolves S0's
credential reference to a World fixture secret, which the scripted plan never sees.

All reason codes, including World authentication outcomes, live in `croa/reasons.py`.
`runtime.py` constructs the worlds and injects capabilities; `agent/` imports no
World, C7 compiler, or C6 firewall implementation, as specified in Architecture §10.
Only `runtime.py` and `croa/c6_firewall.py` import World
in production; the import-boundary test also checks that World cannot import agent
or CROA implementations beyond the shared reason constants.

This is a simulation, not a live-model experiment or a sandbox. Import separation
is checked by tests and review, not enforced by Python at runtime. Session and
subject are trusted strings; C6 checks that they match its configured identity.
A bad signature yields `INVALID_SIGNATURE`; after signature verification, either
a subject or session mismatch yields `SUBJECT_MISMATCH` before expiry is checked.
C6 additionally rechecks C1 policy after replay validation, using C2's same
evaluator. It keeps the bound-credential lookup immediately before secret injection.
This extension was accepted at the CD-004 architecture review and is recorded in
Architecture §4; no target, mode, or path policy is duplicated in C6.
Read contracts bind the session token as well as the path so neither can be
substituted after signing.

Signing deliberately uses standard-library HMAC-SHA256 with a fresh startup key
held by C7 and C6. See **CROA Enterprise Reference Pilot 001** for the asymmetric
RS256 version, whose private key stays in the control plane, and the
[architecture signing note](docs/ARCHITECTURE.md#signing-simplification).
The replay cache is in memory and the demo runs in one process. C5's append-only
SHA-256 chain detects broken stored links; it has no external anchor that could
detect wholesale chain rewriting or removal of the final records.
