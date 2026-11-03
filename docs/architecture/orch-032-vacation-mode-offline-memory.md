# ORCH-032 — VACATION MODE: Offline Personal Memory

**Status:** DRAFT candidate — capacity planning only  
**Mission:** provide weeks or months of meaningful PALACO operation without internet, including large locally available knowledge, work history and personal drafts after a separately approved encrypted vault exists.  
**Authority:** none. Offline preparation does not issue credentials, reactivate grants or mutate protected world/system state.

## Experience

Before departure, the user chooses a duration (for example 56 days), storage budget and content categories. A preflight estimates required space and generates a reviewable packing plan. The future client downloads and verifies content **before** disconnecting, creates an offline search index, records signed manifests and shows an explicit readiness report. A device may additionally use a removable encrypted drive for larger archives, but must not assume one exists.

During vacation, the user can:
- read PALACO manuals, reference material and approved cached knowledge;
- search a local index with provenance and freshness labels;
- draft, plan, annotate and simulate without sending data to the internet;
- create local event receipts, checkpoints and non-authoritative staged intents;
- view last-known project status with its timestamp and explicit STALE/UNKNOWN markers;
- optionally run an on-device AI model only if that capability is installed and verified on the actual hardware.

The user must never be falsely told that live status, new revocations, remote content or remote authorization is available offline.

## Storage architecture

1. **Small hot tier:** recent notes, active plans, schedules, task queue and current indexes.
2. **Large warm tier:** downloaded books, documents, media and language/knowledge packs.
3. **Cold archive tier:** older snapshots and backups on user-controlled removable or secondary local storage.
4. **Metadata index:** versioned content manifest, hashes, source identifiers, timestamps, classifications and estimated/actual sizes.
5. **Private tier:** personal history and drafts only inside the separately approved encrypted vault (ORCH-031C).
6. **Authority tier:** grants and execution credentials are not ordinary content packs; never silently add them to the offline archive.

Storage capacities are hardware- and filesystem-dependent, not a fixed PALACO promise. The planner must preserve free space for the OS, recovery, logs and future local work.

## Preparation workflow

1. Select time horizon, storage destination and categories.
2. Estimate download sizes, search-index overhead, local-edit reserve and backup reserve.
3. Run quota, supported filesystem, device health and available-energy preflight.
4. Download into staging with resumable chunks; verify hash and source provenance.
5. Build deterministic local search indexes and metadata catalogs.
6. Encrypt personal material with an approved local key custody policy.
7. Perform a real airplane-mode rehearsal with no DNS/network access.
8. Produce a report: READY_FOR_OFFLINE_USE / PARTIAL / HOLD, with exact missing packs.
9. Keep previous known-good pack generation until the replacement is verified.

## Offline runtime

- Network-independent navigation and file access.
- No hidden online dependency for core read/draft functions.
- Local journal and checkpoint with explicit durability/space/error states.
- Safe fallbacks when a model, pack, locale or asset is absent.
- Background network detection must never interrupt active local work.
- A user may choose strict airplane mode with network interfaces disabled.
- Sensitive search indexes and cached thumbnails are treated as private data.
- Every cached assertion shows its last trusted verification time.

## Reconnection

Reconnection is a separate, explicit transition: authenticate, obtain trusted time, policy and revocation evidence, compare manifests, reconcile idempotent local edits, show conflicts, obtain required approvals, then synchronize. Staged intents are not executed merely because connectivity returns.

## Acceptance scenarios

- ORCH032-N01: 56 days offline, public pack preflight succeeds with sufficient local space.
- ORCH032-N02: requested pack exceeds safe quota -> HOLD.
- ORCH032-N03: private pack without reviewed encrypted vault -> HOLD.
- ORCH032-N04: authority-bearing pack -> DENY.
- ORCH032-N05: invalid/duplicate pack ID -> DENY.
- ORCH032-N06: cumulative size overflow -> DENY.
- ORCH032-N07: interrupted preflight/download -> resumable, no false READY.
- ORCH032-N08: corrupted pack or index -> quarantined / unreadable, no silent substitution.
- ORCH032-N09: airplane-mode cold start -> read/draft functions work without network.
- ORCH032-N10: full disk -> clean failure, prior content preserved.
- ORCH032-N11: absent on-device model -> clear unavailable state, never claim live AI.
- ORCH032-N12: user switches actor -> no cross-user private data.
- ORCH032-N13: time rollback -> no authority resurrection.
- ORCH032-N14: recovery from old backup -> fresh authorization required.
- ORCH032-N15: reconnect with conflicting edits -> explicit review, no silent overwrite.
- ORCH032-N16: replay of staged intent -> bounded idempotent handling.

## Build phases

- A. Pure Rust vacation pack capacity planner and negative tests (**this PR**).
- B. Download manifest, resumable chunk staging and content integrity (**not implemented**).
- C. Local search index and offline language packs (**not implemented**).
- D. Encrypted personal vault integration, key recovery and actor isolation (**not implemented**).
- E. On-device model adapter with hardware capability detection (**not implemented**).
- F. Airplane-mode acceptance, battery/storage stress and weeks-long fault simulation (**not implemented**).
- G. Authenticated reconciliation and audit receipt generation (**not implemented**).

The 56-day goal is an acceptance target, not a demonstrated runtime guarantee.

**Gate:** `ORCH-032 = DRAFT / NO_PERSONAL_STORAGE / NO_LIVE_OFFLINE_PACK / HOLD`.
