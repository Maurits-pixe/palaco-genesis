# ORCH-049 — Signature-byte binding for offline recovery receipts

Status **DRAFT / HOLD**. Stacked on ORCH-048 (#215).

This pure Rust slice recomputes the exact ORCH-047 domain-separated SHA-256 statement from a matching ORCH-046 review and receipt, then passes the digest, 32-byte key reference and 64-byte signature bytes to a separately supplied `SignedReceiptVerifier`.

The built-in `DenyAllSignedReceiptVerifier` always refuses. Test-only mocks are **not** cryptographic verification. No production Ed25519 library, public-key registry, key revocation, trusted time, durable anti-replay ledger, durable recovery, or operator authentication is implemented.

Even an external verifier acceptance returns only `VerifiedForSeparateReview`, which cannot modify filesystem contents. An eventual authorized executor must separately validate signature algorithm and bytes, epoch/revocation, trusted clock, actor identity, one-time nonce and exact refreshed disk observations.

Five unit tests cover default denial, mock-only accepted review classification, forged digest, sequence/execution mismatch, blank or refused signatures.

TRIAS: no execution authority. ORACLE: signature-byte interface is not real cryptographic verification. MENTOR: integrate audited Ed25519 verification and durable nonces with explicit separate human review before enabling recovery.
