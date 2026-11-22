# PALACO Reviewer-Gated Replay Pipeline v0.1 — DRAFT / HOLD

`tools/reviewer_gated_replay.py` composes the preexisting layers:

1. Ed25519 issuer-signed reviewers registry snapshot (with caller-provided trust roots).
2. Reviewer key-fingerprint match, revocation, UTC validity and minimum revision.
3. Evidence payload integrity and Ed25519 signature verification.
4. SQLite local replay index, only for candidates passing earlier checks.

This *does not* grant reviewer authority, validate a real human identity, provide
a trusted time source, authenticate root keys, or establish an authoritative
revocation/revision store. The caller-provided key maps, evaluation timestamp and
minimum revision are not safe to trust without external controls. All candidate
results remain pending review or quarantined. The return values for
authorization, evidence verification and signer authority are always false.

The local database is mutable/rollbackable and is not cross-device replay
protection. Further hardening requires a server-backed trust anchor, immutable
audit trail, atomic replay admission, and reviewer identity/permission policy.

Test: `python3 -m unittest discover -s tests -p 'test_reviewer_gated_replay.py' -v`

GO-13 HOLD; no merge, deployment, issuance or authority change.
