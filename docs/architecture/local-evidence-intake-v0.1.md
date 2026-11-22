# PALACO Local Evidence Intake v0.1 — HOLD

`tools/local_evidence_intake.py` is a **local, non-persistent inspection prototype**. It accepts a JSON array of candidate records and produces a JSON report with per-record status.

It checks canonical JSON SHA-256 payload integrity, supported schema, record/lineage identifiers, duplicate record IDs, malformed data and an input size bound. Every locally intact candidate remains `pending-review`; malformed, conflicting and repeated identifiers are `quarantined`. It makes no database, network or credential calls.

Run:

```bash
python3 tools/local_evidence_intake.py ./candidate-records.json
python3 -m unittest discover -s tests -p 'test_local_evidence_intake.py' -v
```

**Trust limitations:** SHA-256 equality is not signature verification, signer authentication, authorization, replay protection across batches, server-side reconciliation, clock validation, or durable evidence storage. It should not be wired directly into authoritative workflows. The output always says `authorization_granted: false`, `persisted: false`, and `release_gate: HOLD`.

Next engineering steps require a persistent duplicate index, signed canonical envelopes, authenticated reviewers, provenance verification, bounded streaming validation, audit logging, and adversarial tests before any live integration.

## Cross-batch duplicate screening (prototype)

Supply an optional JSON array of previously observed record IDs:

```sh
python3 tools/local_evidence_intake.py ./candidate-records.json --seen-ids ./previous-ids.json
```

A candidate whose ID is in that snapshot is quarantined with reason
`previously-seen-record-id`. This input is a **caller-supplied, untrusted
snapshot**, not a durable authoritative index. An omitted or stale list cannot
detect cross-batch replay, and separate concurrent processes may race.
Neither list nor evidence is modified. Actual replay protection requires
authenticated durable state and atomic uniqueness checks at the server boundary.
