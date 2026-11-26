# Sampling Succession Evidence Handoff v0.1 — DRAFT / GO-13 HOLD

The offline `tools/sampling_succession_evidence_handoff.py` module prepares a
canonical, recipient-bound JSON handoff only after verifying the **entire**
signed sampling checkpoint succession against the local SQLite sampling
ledger and independently authenticated external history pins.

Package hashes use SHA-256 domain separation
`PALACO-SAMPLING-SUCCESSION-HANDOFF-V1`. A separately signed Ed25519
receipt acknowledges `received-for-independent-review` only, and binds
the expected recipient, a caller-pinned package digest and an independent
caller-managed receipt nonce. Recipient signing keys must be allowlisted,
trusted, unrevoked and distinct from the witnesses. Verification reruns
the complete historical chain and its witness signatures, including
current revocations, after checking receipt integrity.

The code does not deliver or store packages, retain nonce consumption,
authenticate organizations beyond the caller-managed roster, or create
trusted external pins. A signed acknowledgement proves only that the
recipient private key signed a claim, **not** delivery, independent
review, reliable external custody or legal authority. Global replay
protection requires a separately managed durable consumed-nonce index.

Success is exclusively `pending-review`; GO-13 HOLD prohibits release,
merge, recovery, deployment and operational authorization.

Run `python3 -m unittest discover -s tests -p 'test_sampling_succession_evidence_handoff.py' -v`.
