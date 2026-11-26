# PALACO Signed Recovery Review v0.1 — DRAFT / HOLD

The read-only module `tools/signed_recovery_review.py` verifies an Ed25519
signature on a canonical decision declaration containing the exact
`dossier_sha256`, reviewer ID, a bounded review decision/reason and declared
UTC time. Domain separation: `PALACO-RECOVERY-REVIEW-V1`.

The declaration must match the original dossier's manual-review claim and its
recomputed canonical digest. Reviewer key fingerprint, validity and revocation
are checked against a separate issuer-signed reviewer registry snapshot and an
additional caller-provided revoked-key list. Signature and external revision
policy are checked fail-closed. A real key registry, authenticated identity,
trusted time, external revocation/freshness source, secure quorum and
independently stored dossier hashes are still missing.

**Allowed decisions:** request-review, defer, reject. No approve or restore
decision exists. The result never grants recovery, authorization or automated
restoration; even a valid signature remains pending-review. It does NOT write
to the databases or issue any credential. GO-13 HOLD.

Run: `python3 -m unittest discover -s tests -p 'test_signed_recovery_review.py' -v`
