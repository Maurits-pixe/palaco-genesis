# Signed Delegation Receipt Audit Anchor v0.1 — DRAFT / GO-13 HOLD

`tools/signed_delegation_receipt_audit_anchor.py` checks a multi-organization
Ed25519 witness quorum about the *complete* delegation receipt audit chain.

A strict canonical checkpoint commits to the audit head SHA-256 and exact
receipt event count, using domain separator
`PALACO-DELEGATION-RECEIPT-WITNESS-V1`.
All 2–16 submitted witness statements must be signature-valid and match
the same externally pinned head and locally verified count. One key can
never count twice; distinct keys assigned to the same organization never
satisfy organizational independence. Submitted authentic contradictions,
revoked or untrusted keys and recipients acting as witnesses are rejected.
The verifier reads the underlying SQLite database without writing to it,
revalidates the audit chain and receipt index, and checks the separately
provided trusted head and lower count floor.

Trust roots, organizational affiliation, current revocations and the
external head/count floor must be independently authenticated **outside**
the code. This module cannot detect a withheld contradictory statement,
prove a witness organization is legally independent, sign or transmit
checkpoints, or establish durable off-device custody. An invalid or missing
trust policy is quarantined. Even successful verification is only
`pending-review`; GO-13 remains HOLD, with authorization, recovery,
release, merge, and deployment prohibited.

Run `python3 -m unittest discover -s tests -p 'test_signed_delegation_receipt_audit_anchor.py' -v`.
