# Archive Sampling Evidence Ledger v0.1 — DRAFT / GO-13 HOLD

The offline-only module `tools/archive_sampling_evidence_ledger.py`
revalidates independently seeded and signed multi-chunk availability
challenges, then indexes their derived nonces and an evidence digest
using **one SQLite `BEGIN IMMEDIATE` transaction**. A sequence-indexed,
domain-separated SHA-256 ledger links every batch to its predecessor.
Each entry binds manifest SHA-256, independent seed, exact chunk
population, deterministic selected indices, ordered nonces and the
digest of all submitted evidence. The ledger rechecks the complete
hash chain and exact nonce index on each append or read-only inspection.

Both append and inspection require a **separately authenticated** previous
head and minimum batch count; a missing or rolled-back local database
must not be trusted as fresh. A consumed nonce or duplicate sample
cannot be accepted as a new successful batch. A corrupted chain or
nonce index is quarantined without appending a new event. The caller
must independently retain external pins after every confirmed commit.

**Threat model limitations:** Local SQLite is not immutable and does
not independently prove external custody, file availability, remote
storage location, or legal organizational identity. The verifier
does not generate randomness, issue challenges, provide trusted time,
update a remote replay authority, or durably publish its head.
A caller supplying a stale or forged trusted head can defeat rollback
protection. Multi-device global replay protection requires an
independently managed shared authority. All successful outcomes
remain `pending-review`; GO-13 HOLD prohibits merge, restore, release,
deployment and operational authorization.

Run: `python3 -m unittest discover -s tests -p 'test_archive_sampling_evidence_ledger.py' -v`.
