# OFFLINE-001 — Verification & Evidence Register

**Status:** DRAFT — limited local test evidence; no system-wide verification  
**Last Updated:** 2026-10-29  
**Parent:** [`PALACO-OFFLINE-001`](../../specs/OFFLINE/PALACO-OFFLINE-001.md)

## Evidence levels

| Level | Meaning |
| --- | --- |
| `SPECIFIED` | Normative design or draft proposal exists; no test implied |
| `IMPLEMENTED_CANDIDATE` | Code has been created on a separate branch; no merge or deployment implied |
| `LOCAL_SIMULATION_PASS` | Named local harness assertions passed against that candidate |
| `BROWSER_OFFLINE_PASS` | Actual installed client resumed with network disabled and requested feature succeeded |
| `SERVER_RECONCILIATION_PASS` | Outbox and server receipts verified under disconnect, retry and crash |
| `AUTHORIZED_RELEASE` | Explicit human review, policy gate and deployment decision separately recorded |

## Initial Citadel slice — limited evidence

Code candidate: [`PALACO-Citadel` PR #50](https://github.com/Maurits-pixe/PALACO-Citadel/pull/50) service worker public shell v6, self-contained offline fallback in 12 languages, explicit connectivity label and honest no-sync status. Candidate branch `feature/offline-continuity-g1`, browser-evidence HEAD `b6cd066e2afc191e6cae8b19be4cd415f1442a67`.

| ID | Test | Local simulated result | Remaining evidence |
| --- | --- | --- | --- |
| OFF-001 | Public files and fallback included in installation | PASS (Node mock) | Real install over HTTPS and cache storage inspection |
| OFF-002 | Public shell responds after network failure | PASS (Node mock) | Real airplane-mode reload in browser |
| OFF-003 | Unknown public navigation shows self-contained fallback | PASS (Node mock) | Browser navigation and screen reader |
| OFF-004 | Guarded routes, write methods and foreign origins bypass worker | PASS (Node mock) | Browser negative auth/account/API request |
| OFF-005 | Private, no-store, redirected and opaque responses never refresh shell cache | PASS (Node mock) | Integrated response header test |
| OFF-006 | Activate removes only older PALACO caches | PASS (Node mock) | Browser upgrade/rollback test |
| OFF-007 | Offline page has 12 language texts and Arabic RTL | PASS (static assertion) | 12-language visual and keyboard QA |
| OFF-008 | Mock sync timestamps/false receipts removed from public prototype | PASS (static assertion) | Browser test of offline/online toggling |

Reproducible command on the candidate checkout: `npm run test:offline`. This validates eight bounded offline-shell contracts, **not** RIO delivery, private storage, cross-app data, account security, true offline runtime or deployment.

### Automated browser evidence, separately scoped

- **Source:** [`Citadel offline-browser workflow run 40969979920`](https://github.com/Maurits-pixe/PALACO-Citadel/actions/runs/40969979920), HEAD `b6cd066e2afc191e6cae8b19be4cd415f1442a67`, **PASS** on 2026-10-29.
- **Execution:** GitHub-hosted Chromium on mobile and desktop viewport projects. The test opens the public app, waits for the active worker, sets the browser context offline, reloads the allowlisted public routes, and checks the Arabic RTL fallback for an unknown route.
- **Boundary:** This is `BROWSER_OFFLINE_PASS` for the scoped public shell under automated browser network emulation. It is **not** a physical disconnected-device trial, cold native installation, durable private-archive proof, an authorization/security attestation, or production availability.
- **Separate work:** OFF-004 simulated negative access passed, but integrated browser/network authorization negative tests are still required. The two Vercel preview statuses are distinct from this offline-browser job and do not constitute release evidence.

## Required adversarial harness before wider rollout

| ID | Test scenario | Expected safe outcome | Status |
| --- | --- | --- | --- |
| OFF-101 | First visit without network and without shell installed | Explicit cannot-start; no false offline readiness | NOT EXECUTED |
| OFF-102 | Previously installed shell, disable connection, hard reload | Public shell and safe cached pages render; no private contents | NOT EXECUTED |
| OFF-103 | Network drops halfway through IndexedDB write | Transaction or recoverable journal; no partial accepted state | NOT EXECUTED |
| OFF-104 | Local storage quota reached/evicted/private mode | Honest error, recovery/export path, no false save claim | NOT EXECUTED |
| OFF-105 | Reconnect sends queued RIO operation twice | Stable idempotency ID, one accepted server effect | NOT EXECUTED |
| OFF-106 | Crash before vs after first external effect | Replay distinguishes NOT STARTED from RECOVERY_UNCERTAIN | NOT EXECUTED |
| OFF-107 | Old grant, revoked permit, old snapshot and backward clock | HOLD/DENY; never resurrect authority | NOT EXECUTED |
| OFF-108 | Policy/scope/participant changes during disconnect | CONFLICT_REVIEW or REJECTED, no silent merge | NOT EXECUTED |
| OFF-109 | Invalid/corrupt local journal, tampered archive | Fail closed for authority; personal drafts recover/export when possible | NOT EXECUTED |
| OFF-110 | Open app on shared device with another local profile | Strong isolation, no private cross-profile leakage | NOT EXECUTED |
| OFF-111 | User logs out while offline | Local session locked; never claim remote revocation complete | NOT EXECUTED |
| OFF-112 | Change creative ERA clock from past to future | No change in trusted time, policy validity or server cursor | NOT EXECUTED |
| OFF-113 | Cross-device conflict, offline attach image, then reconnect | User reviews upload/merge; consent maintained | NOT EXECUTED |
| OFF-114 | PWA update, rollback, corrupt/incomplete install | Previous working version or honest unavailable state; no stale private grant | NOT EXECUTED |
| OFF-115 | Native signed bundle with all network interfaces disabled | Local functionality continues without DNS, cloud or embedded credentials | NOT EXECUTED |

## Release review envelope

Each repo-specific PR must freeze `repository`, `PR`, `head_sha`, `base_branch`, `base_sha`, workflow/config SHA, checks/run IDs/jobs, test artifacts or logs, reviewer identity and date. Cross-repository tests must name *both* source commits. No CI result from another head or repository counts as a PASS for this candidate. G1 may advance only to a real browser pilot under human review. G4–G7 remain held until their separate authority/security evidence exists.
