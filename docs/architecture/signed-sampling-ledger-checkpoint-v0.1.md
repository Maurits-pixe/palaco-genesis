# Signed Sampling Ledger Checkpoint v0.1 — DRAFT · GO-13 HOLD

The offline verifier `tools/signed_sampling_ledger_checkpoint.py` authenticates
2–16 detached Ed25519 witness declarations about one exact sampling
ledger head, batch count, latest manifest SHA-256 and evidence SHA-256.
Canonical message domain: `PALACO-SIGNED-ARCHIVE-SAMPLING-LEDGER-V1`.

The verifier opens the local SQLite sampling ledger in read-only mode
and validates the entire batch-chain and nonce index in a consistent
read transaction, before comparing its head against a separately
authenticated external head and minimum batch count. Submitted
signatures must be valid and refer to that exact checkpoint; duplicate
keys, repeated witness organizations, revoked signers, unknown trust
roots, conflicting statements and privileged fields fail closed.

Independent callers must supply and protect Ed25519 trust roots, an
authenticated key-to-organization roster, current revocations, and
out-of-band latest head/count pins. The program does not generate
witness signatures, establish actual legal or operational organizational
independence, sign remote receipts or preserve external pins. The
underlying local ledger stores evidence digests but does not retain
full sampled content, so a signed checkpoint does not prove remote
archival custody or long-term content availability.

Every successful verification remains **pending-review**;
`release_gate=HOLD`, `authorization_granted=false`,
`automatic_restore=false`, `recovery_approved=false`.
No merge, release, public deployment or restoration is performed.

Test: `python3 -m unittest discover -s tests -p 'test_signed_sampling_ledger_checkpoint.py' -v`.
