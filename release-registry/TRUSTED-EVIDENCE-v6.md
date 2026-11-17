# PALACO Trusted Evidence v6 — Independent Trust Contract

**DRAFT / GO-13 HOLD.** This is a standalone Python evidence-inspection contract in the release registry, not a live browser verifier. The v4/v5 HTML files remain unchanged.

## What the candidate does

`trusted_evidence_v6.py` accepts:
1. Canonical metadata-only v2 backup and matching checkpoint.
2. A v6 detached attestation with exact fields `schema`, `scope`, `key_id`, `signature`.
3. Three **externally supplied**, required trust callbacks:
   - `verify_checkpoint(statement, receipt)` verifies the checkpoint independently.
   - `get_trusted_anchor(scope)` returns an independently secured *monotonic* exact `(sequence, head)`.
   - `verify_attestation(statement, signature, key_id)` verifies detached attestation using independently trusted keys, policies, signer identity, freshness and revocation information.

Each callback must be provided by an implementation that is *independent of the uploaded package*. Missing, offline, exceptional or non-Boolean results are denied. `get_trusted_anchor` must not simply read its answer out of the checkpoint file. A callback returning `True` is NOT proof that the underlying operation was implemented correctly.

The signed-attestation statement is domain-separated and binds scope, key ID, backup bytes SHA-256 and the digest of the canonical v2 checkpoint statement.

The output is a redacted diagnostic report with `EXTERNAL_CALLBACK_ACCEPTED`, `authorization: DENY`, `release: HOLD` and `production_release_enabled: false`. It **never** returns `PROVEN` or permission to restore, execute, release or authorize. Receipt and signature values are excluded.

## Threat boundaries

This candidate **does not implement a real public-key signature validator, a trustworthy key registry, a current revocation oracle, a trusted clock, signed anchor rotation, durable external monotonic anchoring or an actual human review service**. The three callbacks are a strict integration boundary, not a substitute for any of these systems.

This code alone cannot establish provenance or source authenticity, and cannot detect fully coordinated rollback if the independent anchor is compromised. It does not protect the source files from TOCTOU, and it does not introduce encryption or secure device identity.

No live account data or credentials must be used. Do not wire synthetic tests or permissive callbacks into production. The existing Recovery Cockpit v5 remains read-only; it is not coupled to this module.

## Review / test

```sh
python -m unittest discover -s release-registry -p 'test_trusted_evidence_v6.py' -v
```

17 cases cover complete synthetic fixture, missing verifiers, missing/stale/malformed anchor, exceptions, invalid fields/scope, false/truthy responses, bad receipt, damaged backup, attestation binding and redacted report output.

A real deployment would additionally require independently published key policies, Ed25519 or another approved signature scheme through a vetted library, strict canonical cross-language test vectors, timestamp and policy checks, revocation/freshness verification, independently controlled monotonic head persistence, negative integration tests, mobile-browser QA and an explicit human GO-13 review. No deployment, merge, publication, shared login or automatic recovery is authorized.
