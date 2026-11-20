# PALACO offline candidate staging v1

**Draft, no runtime authority.** This is a pure in-memory demonstration of metadata-only synchronization staging. It cannot sync across devices, persist data, authenticate accounts, confirm signatures, check trusted checkpoints, verify revocation, or resolve application data conflicts. It must not be deployed as a credential, release or execution gate.

`offline_stage.py` accepts events with exactly: `schema`, `module`, `event_id`, `sequence`, `previous`, `payload_sha256`. Module must be one of `palaco-one`, `rio`, `mundo`, `citadel`, `neo-os`. Only a digest of test payload bytes is stored; no user records, tokens, or credentials are stored.

For an append, the caller provides its expected head, the history is replayed and sequence/previous digest verified. Exact duplicate events return an unchanged history. Changed retries, missing/extra fields, duplicate IDs, stale checkpoints, forks, out-of-order events and tampering are rejected. Hashes use SHA-256 with a distinct event domain prefix.

Run tests:

```sh
python -m unittest discover -s release-registry -p 'test_offline_stage.py' -v
```

**Important limitations:** Hash chains and caller-supplied heads do not prove authenticity or protect against rollback of both history and the checkpoint. Determinism is only validated within this Python candidate profile. There is no durable, transactional storage, trusted clock, device identity, encryption, provenance, network replication, consent mapping, access control, or independent verification. No real account data must be passed through this module. GO-13 remains **HOLD**; deployment, activation, key issuance and shared login remain blocked.
