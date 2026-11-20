# PALACO Offline Recovery & Persistent Journal — Candidate v1

This candidate provides **local, read-only replay and transactional append** of the metadata-only events defined by `offline_stage.py`. It does **not** connect applications or store user payloads. It is not an authority verifier, synchronization service, identity provider, or production database.

## Local behavior

- One SQLite database file; event rows have unique, monotonic sequences and IDs.
- `BEGIN IMMEDIATE` serializes local writers. A caller supplies an expected head; a stale writer is rejected instead of silently overwriting an event.
- On restart, every stored event is decoded and replayed using the existing staging hash-chain validation. Changed history and row/sequence mismatches fail closed.
- Exact duplicate requests return the same history and head. Changed duplicates raise `IDEMPOTENCY_CONFLICT`.
- SQLite triggers reject ordinary event `UPDATE` and `DELETE`. Failed appends roll back.
- No production release, account authority or device sync occurs.

## Tests

```sh
python -m unittest discover -s release-registry -p 'test_offline_journal.py' -v
```

Twelve tests cover empty reads, restart replay, exact retry, stale writer, changed retry, incorrect chain predecessor, corrupted event bytes, append-only triggers, rollback, independent DB connections, corrupt sequence and invalid Boolean sequence.

A local reproduction passed 12/12 tests on 17 November 2026 with a manually reconstructed copy of the upstream staging module; the GitHub/CI run must independently execute tests against the checked-in module.

## Unresolved security and release gates

**GO-13: HOLD.** An expected head supplied by a client is not a trusted external checkpoint. If an attacker can rewrite the database and its claimed checkpoint, this code cannot reliably detect rollback. SQLite triggers are not protection from privileged tampering. There is no independent attestation, trusted device or user identity, signature/key binding, encrypted storage, distributed consensus, crash/power-loss fault-injection coverage, backup/restore procedure or revocation verification. The module must not be used with actual customer records or credentials. Cross-process transactional writes are locally serialized, but no distributed synchronization is provided.

**No merge, deployment, authorization, account activation or issuance is implied.**
