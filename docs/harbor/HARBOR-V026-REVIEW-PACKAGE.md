# Harbor v0.26 — machine-readable review package

## Purpose

This document and the adjacent JSON manifest freeze the review package for the
Harbor key-bound floor candidate. The package records exact dependency heads,
reproducible CI evidence, review claims and unresolved gates.

It is a preparation record only. It is not a security approval, authority
token, release record, runtime authorization or activation decision.

## Frozen candidate

- repository: `Maurits-pixe/palaco-genesis`
- candidate PR: #186
- candidate head: `d7a00da579276ef669fa1e95e4f27bb2ede0284f`
- candidate base: PR #168 head `ccf785858406bbc4f83e9008feb6e5e991b87c89`
- package decision: `NOT_REVIEWED`
- authorization: `NONE`

The dependency chain is:

`v0.22 signed floor verifier`
→ `v0.23 governed bridge`
→ `v0.24 review dossier`
→ `v0.25 key-bound envelope`
→ `v0.26 boundary hardening`

The exact SHA values and CI run IDs are in
`HARBOR-V026-REVIEW-PACKAGE.json`.

## Evidence boundary

The manifest records CI conclusions exactly as observed. For PR #186 the
relevant evidence is:

- PALACO CI run `41192279197`: success;
- Citadel A1 interoperability run `41192279192`: success;
- Harbor unit tests: 124 passed, 0 failed.

This evidence supports the tested code and workflow runs only. It does not prove
that the registry, time source, key binding, source authority or storage
environment is independently trusted.

## Human-only fields

The JSON manifest deliberately leaves these fields unfilled:

- reviewer identity;
- review timestamp;
- review decision;
- findings;
- reviewer signature.

A human reviewer must create a new append-only review record rather than
overwriting this preparation manifest.

## Open gates

The review remains blocked until the independent reviewer assesses, at minimum:

1. key enrollment and source-to-key authority mapping;
2. durable monotone time and anti-rollback recovery;
3. replay, quorum and external checkpoint semantics;
4. tenant isolation and production storage;
5. Windows filesystem and recovery behavior;
6. separate merge, release, runtime-authorization and activation gates.

## Status

> REVIEW PACKAGE PREPARED / EXACT HEADS PINNED / CI EVIDENCE RECORDED /
> HUMAN REVIEW NOT EXECUTED / NOT AUTHORIZED / NOT ACTIVATED
