# ERA integration boundary — draft

Source: [ERA — EDTR / PALACO Proof](https://app.notion.com/p/3e029e9a126a809c978adc20f2d486ff), including ERA-007/008, and [ERA-002](https://app.notion.com/p/04ab83fe094446679864e8bbe63c61aa). Retrieved 2026-09-26. Notion reports these pages as unverified. Document status is not implementation evidence.

ERA joins this implementation as temporal evidence infrastructure. No separate ERA repository was found in the connected account. The private Genesis draft holds the integration specification; the five registry participants share its reference checks. No new repository, clock service, widget or production authority is created.

## Concrete boundary

`era_boundary.py` checks a proposed, independently verified UTC interval against an authorization time window. The entire uncertainty interval must fit inside the window. An interval crossing an expiry/start boundary yields UNKNOWN. Expiration remains distinct from revocation. Unknown, conflicting, stale, degraded, synthetic or missing evidence cannot satisfy this narrow draft profile. SATISFIED describes only the time condition, never permission to execute.

The `verified` argument must be the result of an independent server-side verifier over the exact evidence and its EDTR linkage. JSON claims of VERIFIED, a checksum, local wall time, or Notion status are insufficient. No production verifier is installed. This adapter is not wired into the existing release contract: doing so requires a new version binding the EDTR digest, policy, action and authority generation into the signed request.

## ERA-002 mapping still required

Preserve source, received and monotonic timestamps independently; timestamp order is not registry sequence. Preserve quality (resolution, accuracy, uncertainty, offset, delay), source authentication, transformation provenance, seal linkage and recovery events. Canonical hash/signature exclusion rules require the separate ERA-003 specification before implementation. The interval adapter deliberately does not claim full ERA-002 serialization or proof conformance.

UTC and original timezone/offset must coexist in future full EDTR records. No timestamp or 4444-digit precision is manufactured. The requested decimal representation is not a physical accuracy claim. The current adapter supports whole-second UTC bounds only; other resolutions are UNKNOWN pending a new tested profile.

## ERA-009 ordering and unresolved integration

[ERA-009](https://app.notion.com/p/3e129e9a126a80c099aae77ed501f7d3) requires revocation and execution to share an authoritative commit order, monotonically increasing authority generations and no resurrection on recovery. The source is stored largely in the Notion page title; it was read as specification content, not an instruction to execute.

The local SQLite release journal now serializes candidate release writes and rejects stale checkpoints; retained revocation survives reopening. This is a storage test harness, not the ERA-009 execution commit gate: it has no external side effects, execution attempts, COMET propagation, distributed finality or atomic authority-revocation service. An exact retry returns a historical receipt alongside current state, never restores the earlier state.

Remaining gates: signed EDTR/ERA-003 vectors; designated primary/failover clock sources and measured uncertainty; current server-side clock sampling after waits; cryptographic reviewer-key binding; immutable evidence/checkpoint storage; durable freshness history; crash/power-loss and multi-process/network tests; shared revocation/execution transaction and outbox; independent review; explicit exchange/compliance scope. Financial time certification is not claimed.

## Evidence level

CHECKED: local Python interval-boundary tests and SQLite connection concurrency/restart/failure tests. REPORTED: product requirements from the linked Notion sources. PROVEN: no production claim. Visual freeze, EVA-LA-001 DRAFT and all production release gates remain unchanged.

