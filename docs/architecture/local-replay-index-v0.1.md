# PALACO Local Replay Index v0.1 — Draft / HOLD

This prototype builds an **untrusted candidate-ID index** in a caller-selected
SQLite file. It is not an authority store or a verified evidence store.

## Usage

```bash
python3 tools/local_replay_index.py ./candidate-index.sqlite ./candidate-records.json
python3 -m unittest discover -s tests -p 'test_local_replay_index.py' -v
```

It first validates candidate records using the deterministic intake module.
Candidates with valid payload hashes are still only `pending-review`.
Malformed or duplicated records in one batch are quarantined. The module uses
`BEGIN IMMEDIATE` and a primary-key uniqueness constraint so a later attempt
to index the same record ID in that **same SQLite database** is quarantined,
including an attempt with changed payload. It stores only record ID, lineage ID
and payload SHA-256; it does not store evidence payloads.

## Critical non-guarantees

- An integrity hash is **not** a cryptographic signature or authenticated provenance.
- The local file is mutable, deletable, replaceable and rollbackable. There is
  no authenticated durable server, attested storage, independent auditor, or
  cross-device consensus.
- SQLite coordinates writers sharing one database; it does **not** establish
  global atomicity or server-side replay protection.
- Successful indexing is **not** verified evidence and grants no identity,
  authorization, trust or execution authority.
- No synchronization, network calls, migrations or deployments are performed.
- DB file location, backup, permissions, crash recovery, operational monitoring
  and threat model require independent review before any deployment.

**Release gate: HOLD. GO-13 HOLD. Authorization: DENY.**
