# PALACO Trusted Recovery v4 — Offline Recovery Cockpit

**Status: DRAFT / GO-13 HOLD.** Standalone browser inspection surface, not wired to live PALACO One, RIO, MUNDO, Citadel, NEO OS or production release controls.

Open `recovery-cockpit-v4.html` locally in a browser. The page uses system fonts, no remote libraries, no external resource requests, no service worker, no telemetry, and no application credentials. Visual styling follows the draft PALACO dark-green/gold direction without replacing existing Sites designs.

## Functions
- Local file chooser accepts only JSON input, up to 8 MiB; no upload.
- Inspects the **structure only** of v2 checkpoint `{schema,scope,sequence,head,receipt}` or v2 backup `{schema,scope,sequence,head,events}`.
- Rejects unexpected fields, missing keys, invalid digest formats and malformed event metadata; renders file data through `textContent` only.
- Displays scope, declared sequence, head, document type, record count, and explicit **UNKNOWN** external verification.
- Exports a local report tagged `STRUCTURE_ONLY`, `HOLD`, `DENY` and `productionReleaseEnabled:false`, without copying event payloads or receipt values into the report.
- Clears displayed inspection state on reset or new selection.

## Not implemented (important)
This browser page does **not** calculate or verify the SHA-256 event chain, check canonical JSON encoding, verify signatures or trusted checkpoints, establish provenance, inspect source authenticity, prove independent review or grant approvals. Structural plausibility is not evidence of a valid backup. The exported report is SELF-REPORTED / STRUCTURE_ONLY, not CHECKED or PROVEN in the release registry's evidence vocabulary.

The page does not restore files, mutate journals, obtain permissions, create keys, release code or synchronize real data. There is no independent signer, consent system, revocation service, crash-safe restore or multi-device integration.

## Manual inspection checks
1. Open locally with the network disabled; UI renders.
2. Upload a valid-shape v2 checkpoint; observe `STRUCTUUR PLAUSIBEL · NIET GEVERIFIEERD` and `HOLD`.
3. Supply malformed JSON, unknown keys, wrong digest length, excessive size or incorrect event order; observe rejection.
4. Confirm no restoration or authorization action exists. Export report and verify `authorization: DENY`.
5. Reset and confirm previous identifiers are no longer displayed.
6. Inspect network requests: no external calls should occur.

Do not import secret receipts, credentials, account records or personal backups into this prototype. Real security review, device/browser tests and CI are required before any production wiring.

**No merge, deployment, publication or activation. GO-13 HOLD.**
