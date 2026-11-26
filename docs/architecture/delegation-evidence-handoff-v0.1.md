# Offline Delegation Evidence Handoff v0.1 — DRAFT · GO-13 HOLD

`tools/delegation_evidence_handoff.py` exports a **logical** canonical JSON
handoff package only after verifying the complete signed delegation-status
history and an organizational witness quorum. A domain-separated SHA-256 digest
binds all witness envelopes in the package and an explicit recipient ID.

A separately signed Ed25519 acknowledgement can only assert
`received-for-independent-review`. Verification checks a separately pinned
package hash, expected recipient, trusted recipient public-key roots,
allowlist, revocations and a distinct key from the witness roster, then
re-validates the entire upstream delegation/witness evidence. A small
SQLite register prevents identical receipt replay and a second receipt
for the same recipient-key/package pair.

**Security boundary:** the package is not sent, saved to remote custody,
or signed here. A signed acknowledgement does not prove reliable physical
storage, operational independence, legal entitlement or delivery. The
local replay index is not immutable and cannot detect reuse across separate
databases. External hash pinning and trusted key ownership are caller duties.
The only valid state is `pending-review`; release, merge, deploy, recovery
and operational authorization stay DENY under GO-13 HOLD.

Run `python3 -m unittest discover -s tests -p 'test_delegation_evidence_handoff.py' -v`.
