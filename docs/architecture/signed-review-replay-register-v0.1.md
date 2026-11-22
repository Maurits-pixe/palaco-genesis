# Signed Review Replay Register v0.1 — DRAFT / HOLD

`tools/signed_review_replay_register.py` verifies Ed25519 reviewer declarations
and their exact recovery dossier hash **before** opening a local SQLite index.
The register stores per-(dossier SHA-256, reviewer ID) uniqueness and hashes of
the canonical signed declaration/envelope. Identical signed declarations are
quarantined on replay; conflicting declarations for the same dossier/reviewer
are rejected. Valid first observations remain `pending-review` only.

SQLite `BEGIN IMMEDIATE` and primary/unique keys serialize local competing
writers to the same database file. No review text, raw dossier, private key
or raw evidence is retained in the index. A separate read-only inspector
allows local diagnosis without creating a database.

**Limits:** an attacker can replace/roll back the entire file; key maps, issuer
roots, reviewer status, trusted time, min revision and signature validity
are not a substitute for authenticated authorization. This is not a distributed
replay defense. No independent immutable storage or sign-off exists.
Nothing approves recovery, executes restoration, merges or deploys.
GO-13 HOLD; authorization DENY.

Tests:
`python3 -m unittest discover -s tests -p 'test_signed_review_replay_register.py' -v`.
