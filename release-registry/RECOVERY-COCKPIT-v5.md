# PALACO Recovery Cockpit v5 — Evidence & Verification Candidate

**Status: DRAFT / GO-13 HOLD.** The original v4 cockpit is retained unchanged; v5 is a separate self-contained offline HTML candidate. It is NOT deployed or connected to any live PALACO surface.

## Added local checks
- v2 back-up: validates exact event fields, known modules, sequence, previous hash syntax, metadata digests and duplicate event IDs.
- Recomputes genesis SHA-256 and each event SHA-256 using the Python `offline_stage.py` domain-separated profile: `PALACO-OFFLINE-STAGE-v1:EVENT` plus a NUL byte followed by sorted-key ASCII JSON (no spaces).
- Rejects a broken predecessor link or a computed head that differs from the back-up's supplied head.
- If WebCrypto SHA-256 is unavailable, denies chain inspection instead of falling back to a fake or weaker check.
- Prevents a stale asynchronous file selection from replacing the results of a newer selection or reset.
- Reports `CHAIN_VALID_UNTRUSTED` for a locally consistent back-up; a standalone checkpoint is only `STRUCTURE_ONLY`.
- Export remains local and explicitly declares `HOLD`, `DENY`, and `productionReleaseEnabled:false`. No back-up events or receipt strings are included in export.

## Security boundaries

Matching hashes from a file and its own claimed head do **not** independently verify the source or detect a forged but internally consistent back-up. There is no independently anchored checkpoint, verified author signature, identity binding, trust-provider integration, trusted clock, freshness, revocation, policy enforcement, or authorization. The raw event **payload bytes are absent**, so `payload_sha256` format is checked but actual payload integrity cannot be established. Browser WebCrypto availability depends on a secure context, browser implementation and device. This is a static-review candidate, NOT a verified cross-language cryptographic test.

The JavaScript canonicalization uses `JSON.stringify` over sorted, ASCII-restricted event fields to match the constrained Python event profile. Future event types or Unicode fields require cross-language vectors and separate versioning. Back-up byte-level canonicality is not checked by this UI. Do not connect this browser result to `secure_restore.py` as a trust verifier.

## Review checks
```sh
python -m unittest discover -s release-registry -p 'test_recovery_cockpit_v5.py' -v
```
Then perform real manual browser tests with known Python-generated fixture vectors: valid chain; modified event, previous hash, head, duplicate IDs; absent WebCrypto; offline operation; reset during file reading; large file; malformed JSON; export. Verify runtime network activity is absent. Independent CI must execute the tests and security reviewers must assess origin, rollback and canonicalization risks.

**No deployment, merge, publication, release switch, login or account activation. GO-13 HOLD.**
