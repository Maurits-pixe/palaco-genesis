# Detached Review History Anchor v0.1 — DRAFT / HOLD

`tools/signed_review_history_anchor.py` verifies a **detached, Ed25519-signed
review history anchor** containing the review-history issuer key fingerprint,
history entry count, final SHA-256 chain hash and cumulative record count.
It binds a previously witnessed history state with domain separation
`PALACO-REVIEW-HISTORY-ANCHOR-V1`.

Verifier inputs are a separate local history SQLite path, a signed envelope,
authenticated witness public-key roots, an authenticated revoked-key set,
and an independently maintained minimum history entry count.

The verifier checks exact schema, witness signature, issuer key fingerprint,
revocation, freshness floor, complete local history chain and the precise
counters/head. Every possible success returns `pending-review`, never a
restore or authorization grant. No databases or artifacts are written.

**Critical limitations:** the tool neither issues a checkpoint nor publishes
it to any external system. The issuer keys and revocation status are caller
assertions, not automatically established trust. A stolen valid signing key,
stale external floor or compromised witness store can defeat the protection.
No trusted time, freshness service, immutable ledger, cryptographic key custody
or reconciliation quorum is implemented. Strict GO-13 HOLD.

Tests: `python3 -m unittest discover -s tests -p 'test_signed_review_history_anchor.py' -v`.
