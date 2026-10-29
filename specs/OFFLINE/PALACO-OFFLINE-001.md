# PALACO-OFFLINE-001 — Grand Overview & Continuity Contract

**Status:** DRAFT — cross-repository implementation candidate; not authorization or release  
**Last Updated:** 2026-10-29  
**Decision owner:** PALACO HOOFDKANTOOR / Maurits Benjamin (human review required)  
**Scope:** Seven Wonders, RIO, Citadel, ELIXERS, MUNDO, ERA, local archives and operational surfaces

## 1. Outcome

PALACO must remain useful when the internet is unavailable, slow or interrupted. A user who has *previously installed or loaded* the relevant offline-capable app can continue reading previously downloaded public information, creating WORLD drafts, working with OR6IT and fictional ERA calendars, writing RIO drafts, accessing permitted local archives and exporting backups.

This does **not** make external services work offline: hosted AI, GitHub, email, payments, Supabase, remote identity verification, revocation sources, server-rendered content and delivery to other devices still need a connection or a separately distributed local implementation.

**Constitutional invariants:** `NO SILENT WORLD STATE CHANGE`; `NO SILENT TIME`; `ACCESS ≠ AUTHORIZATION`; `QUEUED ≠ DELIVERED`; `LOCAL SAVE ≠ SERVER SYNC`; `CACHE ≠ CURRENT REVOCATION`; invented ERA time cannot be used as trusted authorization time. Offline availability must never elevate authority.

## 2. GitHub inventory and responsibility matrix

Observed from the connected GitHub installation on 29 October 2026. Seven accessible repositories are the complete **observed** set, not proof that other unconnected repositories do not exist. Baseline SHA identifies the read-only inventory, not later changes.

| Repository | Observed `main` SHA | Observed technology / evidence | Work package |
| --- | --- | --- | --- |
| `Maurits-pixe/PALACO` | `93a490f01cae0ec5c28f587506dd37fb86fc147d` | Rust core; [`RIO-SYNC-001`](https://github.com/Maurits-pixe/PALACO/blob/main/docs/standards/rio/sync/RIO-SYNC-001.md) is **Draft v0.1** | P-01: align Quay events, RIO outbox, trusted-time and revocation limits |
| `Maurits-pixe/palaco-genesis` | `a1a92d6552299208717ea4d22f8e75deee867e94` | Rust workspace, 23 members, CI/gates and contracts | P-02: shared offline operation envelope, integration harness, cross-repo policy |
| `Maurits-pixe/PALACO-Citadel` | `9962fbe04e66d59b987866dc85f8fd5d9e8126e1` | Existing PWA manifest + service worker `palaco-rio-shell-v5` | P-03: public offline shell v6, fallback, offline indicator, protected route exclusions, tests |
| `Maurits-pixe/PALACO-INDUSTRIE` | `57e5169a193f4b442e440b3969eecd4ab3f7b500` | Node server, SQLite, authenticated sessions, GitHub discovery | P-04: locally deployable workstation/server mode, safe session restoration, backup |
| `Maurits-pixe/PALACO-BOOK-1` | `c27e3f25b892d6ec6e90655f2104be8b64ad1bad` | Next.js 15 and SQLite require server availability | P-05: explicit exportable offline reader, local notes, reconnection conflict review |
| `Maurits-pixe/PALACO-NEO` | `5d9b50fbe25cb2bc0e41877ffc14dbab61246074` | Initial README only; no runtime evidenced | P-06: AETHER/BASTION/NEO offline resource and key-custody contract before implementation claims |
| `Maurits-pixe/desktop-tutorial` | `0f7d27b921b2a6f54289a0f882c13fcb1736bbb8` | Private tutorial, no PALACO production dependency evidenced | P-07: inventory only; no production mutation |

The published MUNDO and RIO Sites are **additional application surfaces**, not extra GitHub repositories in this inventory. MUNDO's current browser-local creative storage is useful offline *after loading*, but not a protected account backup. Their release/evidence states must be checked independently.

## 3. Offline capability tiers

| Tier | Local capability | While offline | On reconnect |
| --- | --- | --- | --- |
| L0 | Public shell/assets/help | Read versioned allowlist cache | Update only from a valid package; no private caching |
| L1 | Personal WORLD/OR6IT/ERA drafts, sketches, images, logs | Continue editing with explicit local save, quota notice and export | Review import/merge separately; never auto-promote to official WORLD |
| L2 | RIO message drafts / proposals | Durable local outbox labelled `QUEUED_LOCAL` | Idempotent send only after renewed session and policy review; server ACK or rejection visible |
| L3 | Private accounts and archives | Only if explicitly unlocked and encrypted on this device; otherwise `LOCKED` | Fresh identity, consent, policy, revocation and device binding check |
| L4 | Spending, access/grants, publication, admission, authoritative WORLD changes | `HOLD_OFFLINE` / `DENY`; no effect | Fresh trusted time and revocation **within the same authorization decision** plus human-approved transition |
| L5 | Cloud AI, GitHub, email, payments, remote queries and delivery | `UNAVAILABLE_OFFLINE`; local model only if packaged separately | Resume on explicit action; do not invent remote output or receipts |

## 4. Three independent state axes

Never flatten these into one `online` boolean:

1. **Transport:** `UNREACHABLE`, `REACHABLE_UNVERIFIED`, `CONNECTED`, `RECONNECTING`.
2. **Data:** `NOT_CACHED`, `LOCAL_DRAFT`, `QUEUED_LOCAL`, `SYNCING`, `ACKNOWLEDGED`, `REJECTED`, `CONFLICT_REVIEW`, `RECOVERY_UNCERTAIN`.
3. **Authority:** `UNKNOWN`, `HOLD_OFFLINE`, `DENIED`, `VALIDATED_FOR_SCOPE`, `REVOKED`, `EXPIRED`.

For each grant generation, `REVOKED` and `EXPIRED` are terminal. The trust epoch and highest accepted trusted time never decrease. Local wall-clock rollback, stale snapshots or a custom ERA clock cannot renew or resurrect authority.

## 5. Proposed durable operation envelope — not frozen

```json
{
  "schema": "palaco.offline.operation.v0.1",
  "client_operation_id": "stable-random-id",
  "citadel_ref": "citadel-reference",
  "subject_ref": "account-or-local-profile-reference",
  "operation_class": "RIO_MESSAGE_PROPOSAL",
  "payload_ref": "encrypted-local-blob-reference",
  "base_revision": "last-acknowledged-server-cursor",
  "local_created_at": "untrusted-display-time",
  "trusted_epoch_ref": "last-accepted-epoch-or-UNKNOWN",
  "policy_ref": "policy-version-known-at-draft-time",
  "authorization_ref": null,
  "status": "QUEUED_LOCAL",
  "attempt_count": 0,
  "acknowledgment_ref": null
}
```

Required invariants:

- Stable operation ID survives crash, restart and retries. Replays reuse the **same** ID.
- Local journal is append-only for transitions and receipts; edits append lineage instead of overwriting evidence.
- `QUEUED_LOCAL` never implies `DELIVERED`, `PUBLISHED`, `AUTHORIZED` or `VERIFIED`.
- On reconnect: session, consent, scope, policy, trusted time and revocation must be revalidated together, before effect. No queued action inherits stale rights.
- Server cursor and operation ID reconcile one outcome: `ACKNOWLEDGED`, `REJECTED`, or `CONFLICT_REVIEW`. Timeout after possible effect becomes `RECOVERY_UNCERTAIN` until resolved.
- No duplicate effects on repeated transport frames; no false time or delivery receipt.
- Sensitive payloads do not enter Cache Storage, plaintext localStorage or the public PWA shell. Require bounded encrypted local storage and device/account isolation.
- A missing key means `LOCKED`, never plaintext fallback; a corrupt/out-of-quota store must explain export/recovery possibilities without false success.

## 6. Storage and deployment design

**Browser:** versioned service worker caches explicitly public static files only. IndexedDB can support creative drafts and bounded local artifacts; a separately reviewed encrypted store is needed for sensitive records. Browser data can be evicted. A local copy is neither an account backup nor ownership proof.

**Desktop/mobile:** produce signed downloadable packages with bundled UI/assets, local transactional database (e.g. SQLite), migration/backup tests and OS-protected keys. A browser PWA does not prove native app resilience or availability without an initial online install.

**Local node/LAN:** a locally running PALACO service can work without external internet only when code, compute, database, permissions and keys are actually available locally. Protect ports, LAN exposure and storage with explicit security controls.

**Reconnect:** visible pending count, bounded exponential retry, explicit review before submission, deterministic idempotent replay, cursor verification, rejection reasons and no automatic private archive uploads.

**Inclusivity:** the experience must remain understandable from age eight, support twelve PALACO languages (including Arabic RTL), keyboard and screen readers, and a calm state indicator. Example: “Je werkt offline. Je werk staat op dit apparaat. Niets is verstuurd.”

## 7. Program gates

| Gate | Exit evidence required | Current assessment |
| --- | --- | --- |
| G0 — Inventory | Accessible repositories, branches and observed dependencies | INVENTORIED — seven accessible repos |
| G1 — Public shell | Online install → unplug → public reload, non-public negative access, multilingual fallback | Citadel PR #50: automated Chromium offline-context test PASS on `b6cd066e2afc191e6cae8b19be4cd415f1442a67` (run `40969979920`); physical-device and human release review pending |
| G2 — Creative local core | OR6IT/MUNDO/ERA drafts after restart, storage quota, export and corruption tests | PROGRAM-WIDE NOT EXECUTED |
| G3 — Durable outbox | Crash pre/post first effect, duplicate delivery, reconnect, conflict and replay | NOT EXECUTED |
| G4 — Private/identity | Revocation, expiry, trusted clock rollback, old snapshot, shared device and logout | HOLD — security evidence required |
| G5 — Native/offline node | Signed bundles, offline cold restart, migration, backup and restore | NOT EXECUTED |
| G6 — Federation/ELIXERS | Scoped cross-Citadel reconciliation, safe delegation expiry and receipts | HOLD — authority gates required |
| G7 — Release | CI binding, human review, threat model, accessibility, rollback and source provenance | NOT AUTHORIZED |

**No scope inflation:** G1 browser-shell success cannot authorize G2–G7, new runtime authority, a merge or a production release.

## 8. Domain ownership

- **Foundation / Quay:** durable journal, evidence and causal replay; independent trusted time.
- **Harbor:** offline proposals only, no invented remote admission.
- **Citadel:** device isolation, consent, local keys and allowlisted shell.
- **Federation:** cursor reconciliation, no shadow authority.
- **Intelligence:** optional local model only with separate package and explicit uncertainty.
- **Evolution:** read local event lineage for visual playback, never silently rewrite history.
- **RIO:** conversational status and user control; **not** policy or authority.
- **OR6IT / MUNDO / ERA:** local creative work, custom planetary time separate from trusted time.
- **WISDOM / BANK CARLOS / 5CRIPTIE:** protect key custody, vault and identity records; no plaintext cache fallback.

## 9. Human decisions and AI triadereview

Decisions required before later gates: encrypted-device/account model; trusted-time/revocation freshness; retention and backup policy; supported native packages/local AI resources; child/shared-device safeguards; explicitly scoped review/merge/release authority.

- **TRIAS (AI lens):** offline continuity cannot weaken consent, authority or monotone expiry. G4–G7 HOLD.
- **ORACLE (AI lens):** seven GitHub HEADs, `RIO-SYNC-001` draft and Citadel v5 service worker were observed; no production airplane-mode or device-security validation is yet established.
- **MENTOR (AI lens):** first deliver public-shell fallback with honest status, then local backups, then guarded RIO outbox and private storage.

**Next legitimate transition:** `G1 implementation candidate → human-reviewed browser airplane-mode pilot`, followed independently by `G2 local creative durability`. This is a coordination proposal, not canon sealing, a release permit or three independent human reviews.
