# PALACO Review Checkpoint History v0.1 — DRAFT / HOLD

`tools/review_checkpoint_history.py` records verified review-register
checkpoints in a separate local SQLite database. Each issuer has a sequential
local history with an SHA-256 chain, an increasing row count, and a domain
separator. Identical snapshots are idempotent; lower counts and conflicting
same-count hashes are rejected. Invalid signatures or revoked issuers never
reach the history database. Writes are serialized with `BEGIN IMMEDIATE`.

A read-only inspector verifies continuity against a caller-supplied
**independently authenticated** prior head and minimum history length. Without
an externally protected head, a malicious local writer can replace or recompute
the whole history. The history database is NOT a remote witness, immutable
ledger, trusted counter or signed release approval. Row counts are not
equivalent to reliable monotonic checkpoint generations, and writes to the
review register and history use distinct transactions. All observations and
verdicts are advisory: authorization DENY, GO-13 HOLD.

Tests: `python3 -m unittest discover -s tests -p 'test_review_checkpoint_history.py' -v`
