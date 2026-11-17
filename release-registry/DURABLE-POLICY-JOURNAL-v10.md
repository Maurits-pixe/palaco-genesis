# PALACO Trusted Evidence v10 — Durable Policy Journal (candidate)

**DRAFT. GO-13 HOLD. No production authorization.**

This candidate stores v9 key-policy ledger events in a local SQLite file. It is a transaction/recovery harness, not a trusted policy authority or production-grade distributed log. The existing v7-v9 contracts remain unchanged.

## Local implementation

`durable_policy_journal_v10.py` implements `DurablePolicyJournal`:

- An `events`-style SQLite journal table named `policy_events`, with unique positive sequence numbers and canonical JSON event bytes.
- `append(before, after, expected_head=...)` starts `BEGIN IMMEDIATE`, replays all stored events, checks the expected head, delegates version/immutability/revocation checks to v9 `propose_event`, writes exactly one event and commits atomically.
- SQLite triggers reject ordinary updates/deletions. This is a guard against accidental mutation, not protection against an SQLite administrator or direct file tampering.
- `read(expected_head=...)` reconstructs the chain after process restart in a read transaction, rejecting changed bytes, noncanonical JSON, wrong sequences, stale heads and broken history.
- `inspect_trusted(get_trusted_anchor=..., verify_policy=...)` requires independently implemented external trust checks. The function rejects empty journals and returns only an inspection report with `HOLD` and `DENY`.

## Test commands

```sh
python -m unittest discover -s release-registry -p 'test_durable_policy_journal_v10.py' -v
python -m unittest discover -s release-registry -p 'test_policy_ledger_v9.py' -v
```

16 additional tests were committed for restart, competing sequential writers, rollback, two-event replay, append-only triggers, malformed or renumbered stored events, stale reads, absent or mismatched external trust, negative policy response and input immutability. **Test execution has not been independently confirmed here.**

## Security boundaries and unresolved gates

- A caller-supplied expected head is not a trusted checkpoint; a malicious operator can replace both journal and claimed head. Only an independently authenticated **monotonic** anchor can detect such rollback.
- No external anchor service, attested policy engine, live revocation authority, trusted clock, signing-key custody or authenticated device identity has been connected.
- Transactions protect against ordinary concurrent local append calls, not distributed forks, privileged file replacement or malicious concurrent writers.
- SQLite `synchronous=FULL` does not prove crash durability across filesystems, storage drivers, or power loss. Fault injection, backups, restore review and recovery testing remain necessary.
- The current model accepts public-key registry snapshots as data; it does not perform trusted admissions for new keys. Key-management governance must be independently established.
- No user payloads, credentials, account changes, cross-device synchronization or deployment are introduced.

**No merge to main, live publication, key issuance, shared login, account activation, recovery execution or policy authorization.**
