# FCP-002-CORE-001 — Foundational dependency boundary

Status: DRAFT
Last Updated: 2026-11-01

## Scope

This review-only guard protects the current `palaco-foundation` and
`palaco-constitution` crates from dependencies on other workspace crates.
It checks normal, development, build, target-specific and renamed dependencies.

## Rationale

The FCP-001 design names conceptual core components that do not map one-to-one
to the existing Genesis workspace. This guard does not rename crates or assert
that the full FCP-001 architecture is implemented.

## Evidence and limitations

Run `python3 scripts/verify_core_boundaries.py` and
`python3 -m unittest discover -s tests -p 'test_architecture_boundaries.py'`.
The verifier reads workspace Cargo manifests and fails closed on parse errors.
It is not a substitute for cargo build/tests, a complete dependency DAG review,
or formal architectural approval. A CI PASS must be linked to an exact SHA and
workflow run ID before this control is marked verified.

## Decision boundary

DRAFT / REVIEW ONLY. No change to runtime, admission, authorization, release,
or production state. A human reviewer must approve policy expansion.
