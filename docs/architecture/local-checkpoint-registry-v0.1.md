# Local Checkpoint Registry v0.1 — DRAFT / HOLD

`tools/local_checkpoint_registry.py` provides a **separate** SQLite register of
the highest observed **signed** audit checkpoint per issuer. Before writing,
it verifies issuer signature, supplied key fingerprint, external minimum
sequence and the local evidence audit chain. It rejects explicitly revoked
issuer fingerprints supplied by the caller. `BEGIN IMMEDIATE` and a UNIQUE
issuer key give atomic local monotonic updates; equal sequence with different
content is rejected as equivocation.

Example contract: `record(checkpoint_db, evidence_db, envelope, trusted_roots,
revoked_issuers, minimum_sequence)`. The revocation collection and minimum
sequence MUST come from an independently authenticated policy source. The
separate store offers no guarantee against file replacement, deletion, rollback
or a malicious local process. Verification of the evidence chain and writing
the checkpoint store are **not** one atomic cross-database operation, so
concurrent evidence changes can race. A signed checkpoint itself does not
establish issuer identity or permit issuance, trusted recovery, or execution.

There is **no external anchoring service**, key revocation service, secure
clock, trusted remote database, or production deployment. The register is a
local engineering prototype; successful results are `pending-review` only.
All authorization flags remain false. GO-13 HOLD.

Test: `python3 -m unittest discover -s tests -p 'test_local_checkpoint_registry.py' -v`
