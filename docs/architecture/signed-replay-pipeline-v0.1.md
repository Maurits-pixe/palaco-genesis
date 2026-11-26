# Signed replay pipeline v0.1 — DRAFT / HOLD

Module `tools/signed_replay_pipeline.py` composes the existing local prototypes
in the required order: **candidate integrity + metadata binding → Ed25519
signature verification → local SQLite replay index**.

The pipeline never indexes an invalid signature. Repeated IDs are quarantined
using the local SQLite unique constraint. Even with valid signatures, candidates
are only `pending-review`. Returned flags are permanently
`authorization_granted: false`, `evidence_verified: false`,
`signer_authority_verified: false`; release remains `HOLD`.

The caller MUST supply an independently authenticated key map; this prototype
does not authenticate reviewers, check revocation/validity windows, prevent
file rollback or provide cross-host replay safety. A valid signature does not
make the key owner trustworthy or authorized. No production registration,
backend deployment or identity issuance is enabled.

Run tests:

```sh
python3 -m unittest discover -s tests -p 'test_signed_replay_pipeline.py' -v
```

Requires the pinned Python cryptography dependency used by CI.
