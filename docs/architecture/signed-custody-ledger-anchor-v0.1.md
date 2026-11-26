# Signed Custody Ledger Anchor v0.1 — DRAFT / GO-13 HOLD

`tools/signed_custody_ledger_anchor.py` verifies a detached Ed25519
witness for the local custody-statement hash chain. A strict canonical
statement binds the ledger event count and exact last SHA-256 event hash,
with `PALACO-SIGNED-CUSTODY-LEDGER-ANCHOR-V1` domain separation.

The verifier **requires externally authenticated** witness public keys,
a revoked-witness set and a minimum event count stored outside the ledger.
A signed anchor with a count below this floor is stale. The signature is
verified before opening the ledger in read-only mode. A ledger inspection
checks the complete chain and all index rows against the signed head.

The module does not generate signing keys, sign checkpoints, store them
off-device, publish them, or prove that any independent custodian actually
received or retained evidence. A compromised signing key, compromised
caller-supplied roots or stale external minimum defeats this assurance.
Every result remains HOLD, never an authorization, restoration or release.

Tests: `python3 -m unittest discover -s tests -p 'test_signed_custody_ledger_anchor.py' -v`.
