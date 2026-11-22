# Offline Custody Anchor Handoff v0.1 — DRAFT / GO-13 HOLD

`tools/custody_anchor_handoff.py` packages a previously verified Ed25519
custody-statement ledger anchor into a bounded canonical JSON envelope,
addressed to an expected recipient. It returns a domain-separated SHA-256
digest without writing files, contacting a service or sending a message.

The recipient may submit a detached Ed25519-signed acknowledgement restricted
to the disposition `received-for-independent-review`. The verifier requires
an **independently obtained** expected package digest, authenticated custodian
public keys and key allowlist, revocation set, witness roots/revocations and a
trusted minimum ledger count. It verifies the recipient binding, both
signatures, the full local custody chain and the package digest.

`register_ack` uses a separate SQLite register with a transactionally unique
receipt ID, and one acknowledgement per custodian key/recipient/package digest.
Identical receipt replay, statement-ID conflict and duplicate acknowledgement
are quarantined. It stores metadata hashes only; signing private keys and raw
receipt text are not persisted.

**No proof of actual off-device custody is asserted.** Local SQLite data can
be rewritten by an attacker. The receiving custodian and its roots, independently
pinned package hash, revocation freshness and external minimum must be secured
outside this module. It does not deliver packages, issue signatures, provide
trusted time, operate an immutable archive, coordinate global replay checks,
merge, authorize, restore or deploy. All valid states are pending-review/HOLD.

Tests: `python3 -m unittest discover -s tests -p 'test_custody_anchor_handoff.py' -v`.
