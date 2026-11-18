# PALACO Trusted Evidence v18 — Distributed Replay Coordination

**Draft only — GO-13 HOLD.** `distributed_replay_v18.py` is an offline-first *coordination contract*, not a running distributed replay service.

## Candidate transport model

- `candidate(sender_id, recipient_id, message_id, package_sha256, device_id)` produces strict metadata. Offline devices may queue a candidate but **must not treat it as globally accepted**.
- `prepare_batch(claims)` / `read_batch(payload)` serialize or parse canonical JSON, reject malformed records and byte-for-byte duplicate candidates. Different devices may present the same global message tuple; those records remain distinct to expose conflicts rather than silently overwriting them.
- A separate, atomic central coordinator must ensure a globally unique `(sender_id, recipient_id, message_id)`, durable first-use and monotonic authority sequencing. **That coordinator is NOT implemented.**
- `receipt_statement(claim, authority_sequence, decision)` defines v18 domain-separated bytes for authenticating a specific candidate, sequence and central decision (`first-claim`, `duplicate`, `conflict`).
- `inspect_decisions` demands `verify_authority(statement, receipt)` and a separately authenticated `get_trusted_watermark()` callback. It rejects missing providers, non-Boolean verification, duplicate authority sequences, unanchored decisions and multiple `first-claim` decisions for the same global tuple inside the inspected batch, regardless of order.
- The external watermark callback must be independently secured and monotonic. A malicious self-supplied watermark is not trusted. Authenticity of a receipt requires a real coordinator signature validator and current revocation policy outside this module.
- Inspections are always diagnostics: `authorization: DENY`, `release: HOLD`, `production_release_enabled: false`. A first-claim report **does not** acknowledge a v16 message for processing. Decrypted data still requires v14 proof verification.

## Regression scenarios

```sh
python -m unittest discover -s release-registry -p 'test_distributed_replay_v18.py' -v
```

22 committed test scenarios cover canonical offline batches, empty queues, duplicates, malformed metadata and encodings, missing/rejecting/exceptional verifier, invalid and rolled-back watermark, duplicate authority sequence, altered decision binding, conflicting candidates, duplicate first-use decisions, permanent HOLD, receipt byte binding and invalid proof. These tests have not yet been independently confirmed as run.

## Security and operational limits

No production implementation of a trusted central registry, authenticated receipt signing, durable global database, transport channel, trusted timestamp, offline-to-online retry, reconciliation state persistence, Byzantine-fault tolerance, per-tenant scope or distributed consensus exists. Offline recipients cannot safely assume globally unique first use. The v17 local SQLite registry remains only a single-machine replay defense.

Before deployment: implement a truly atomic central first-use database, authenticated quorum or equivalent appropriate consistency guarantees, secure key management and revocation, durable monotonic receipts, device enrollment, privacy protections, convergence/fork audits, failure-injection and multi-device concurrency tests.

**No auto-merge, publication, user account modification, recovery activation, issuance or production authorization.**
