# Signed Review Register Checkpoint v0.1 — DRAFT / HOLD

The module `tools/signed_review_register_checkpoint.py` reads the entire local
signed recovery-review replay index in an SQLite read transaction. It hashes a
canonical, sorted list of identifier/digest rows and verifies an issuer's
Ed25519 signature over the row count and rows hash, using domain separation.

Missing, modified or extra rows are rejected against a previously signed
checkpoint. Issuer keys must come from independent trusted roots, with an
authenticated revocation set and an externally protected minimum row-count
floor. Verification never creates or mutates a database.

Important: the module does **not** create or publish checkpoints, authenticate
issuer authority, guarantee freshness, or provide any external write-once store.
Row count is not a secure monotonic sequence; even a valid signature does not
prove that the entire register was captured by a trustworthy issuer. Multiple
database snapshots may be signed independently. The caller must independently
anchor checkpoints and enforce monotonic identity and history policy before
using this for security. There is no recovery, authorization or release.

Tests: `python3 -m unittest discover -s tests -p 'test_signed_review_register_checkpoint.py' -v`.
