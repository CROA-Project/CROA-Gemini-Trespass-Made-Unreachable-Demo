# CROA Gemini Trespass Made Unreachable — Demo

A deterministic, local replay of the September 2026 Google Gemini trespass incident,
run twice with the same scripted agent: once ungoverned, once through the CROA
control plane (C1–C7). The second run shows each of Gemini's three unauthorized
actions made structurally unreachable, with the reason code and the component that
stopped it.

Pure Python, standard library only. No network, no live model, no Docker.

The implementation lands through reviewed pull requests from feature branches.
See the open pull requests for the current state and `docs/ARCHITECTURE.md` on
the feature branch for the design.

Part of the [CROA Project](https://github.com/CROA-Project/CROA). Sibling of the
[Enterprise Reference Pilot 001](https://github.com/CROA-Project/CROA-Enterprise-Reference-Pilot-001)
and the [Minimal Reference Harness](https://github.com/CROA-Project/croa-reference-harness).

## Licensing

Code: Apache-2.0 (`LICENSE-CODE`). Documentation: CC-BY-4.0 (`LICENSE-DOCS`).
See `LICENSE` for the combined notice.
