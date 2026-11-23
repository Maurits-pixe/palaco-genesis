# Witness Registry Succession v0.1 — DRAFT / GO-13 HOLD

`tools/witness_registry_succession.py` verifies a bounded chain of
governance-signed organization witness registry snapshots. Each
separately signed succession record commits to the exact hash of the
registry envelope, its contiguous revision number, and the preceding
succession-record hash. The first snapshot's digest and the final
record digest MUST be pinned through independent trusted governance
channels; a minimum accepted revision MUST be independently supplied.

The verifier ensures strict consecutive revisions, signature validity,
key-to-organization stability, monotonic revocations, and no removal of
historical keys. A replacement key can become active under an existing
organization only after the old key is marked revoked. Distinct domain
separators protect registry snapshot hashes and succession signatures.

This is an OFFLINE integrity and succession checker, not issuance of
witness identities, a trust-on-first-use protocol or evidence of actual
organizational independence. Trust bootstrap, immutable off-device
storage, independent signer custody, trusted timestamps and authoritative
real-world legal identity checks are not implemented. Valid output is
`pending-review` and GO-13 remains HOLD; no recovery, deployment, merge,
release or authorization occurs.

Test: `python3 -m unittest discover -s tests -p 'test_witness_registry_succession.py' -v`.
