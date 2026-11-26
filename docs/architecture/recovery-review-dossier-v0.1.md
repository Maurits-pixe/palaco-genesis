# Recovery Review Dossier v0.1 — DRAFT / HOLD

`tools/recovery_review_dossier.py` produces a deterministic, canonical SHA-256
review *dossier*, built on `checkpoint_recovery_assessment.assess`. It records
the local assessment state/reason, signed-checkpoint bytes fingerprint, issuer
key fingerprint (when valid), witnessed sequence/head, an explicit human review
**claim**, and the required further independent investigation.

Review claims only accept `request-review`, `defer` and `reject`. There
is intentionally **no** `approve` option. A human's declared name and UTC
timestamp are caller-controlled, not authenticated credentials or secure time.
The dossier SHA-256 detects accidental or unauthorized changes **only when its
expected hash has been stored independently**. A digest alone is not a
signature, external anchor, or authority certificate.

The tool is read-only with respect to both SQLite databases and performs no
restoration. Even a matching assessment can at most be `pending-review`; the
response permanently sets `authorization_granted=false`,
`recovery_approved=false`, `automatic_restore=false` and
`release_gate=HOLD`. Trust roots, revocations, witness provenance,
immutability, cross-file snapshot consistency and review identity are not
established here.

Tests: `python3 -m unittest discover -s tests -p 'test_recovery_review_dossier.py' -v`.
