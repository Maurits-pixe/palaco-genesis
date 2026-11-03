# ORCH-033 — Offline Memory Catalog (Vacation Mode)

**Candidate:** DRAFT, stacked on ORCH-032 PR #199.  
**Purpose:** make a deterministic, network-independent metadata search primitive available to the ORCHEASTRA runtime.

## Delivered in this candidate

- Bounded Rust in-memory index (100,000 maximum records and 100 search results).
- Stable identifier order and non-overwriting duplicate handling.
- Rejects malformed IDs, control characters, empty titles/sources, zero sizes and invalid query input.
- Stores only public/synthetic preview metadata: identifier, short title, unverified source label, estimated bytes and classification.
- No network calls, no required cloud dependencies and no credential authority.

This is **not** a durable on-disk catalog, encrypted vault, personal storage, indexing of document bodies, offline AI, verified provenance or 56-day availability proof. The `source_label` is an unverified descriptive label.

## Scope and privacy gate

- Only `PublicReference` and `SyntheticFixture` classes exist.
- Do not place real names, personal documents, private filenames, secrets, authorization grants, or sensitive labels in this plaintext index.
- The catalog is in-process memory; it disappears on shutdown.
- Personal metadata, thumbnails and full-text indexes must be encrypted together with personal content under a separately reviewed vault policy.
- No offline grant issuance, revocation override, authority creation or silent synchronization.

## Acceptance

1. Case-insensitive offline search produces stable ordering.
2. Duplicate ID is rejected while keeping the original record.
3. Path-like IDs, control characters, empty/invalid metadata are rejected.
4. Non-ASCII or blank query is rejected explicitly.
5. Results are bounded to prevent unbounded result materialization.
6. Project CI: format, lint, tests, architecture validation as configured.
7. Human security review before any real personal data is indexed.

## Next independent slices

1. Verified content-hash manifest and quarantined corruption handling (no private content).
2. Durable crash-safe local catalog generation with rollback tests.
3. Approved encrypted personal vault (ORCH-031C), actor isolation, recovery and key lifecycle.
4. Airplane-mode acceptance, full-disk tests, multi-week clock/failure simulation and explicit reconciliation.

**Decision:** engineering candidate only; merge, sensitive data and production remain HOLD.
