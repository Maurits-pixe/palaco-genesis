# Signed evidence envelope v0.1 — Draft / HOLD

The validator `tools/signed_evidence_envelope.py` verifies Ed25519 signatures over
a strictly canonicalized subset of record metadata: schema version, record ID,
lineage ID and SHA-256 payload digest. `verify_candidate` separately verifies
the candidate payload SHA-256 and equality of signed metadata.

Requires `cryptography==44.0.3` in the verification environment. No signing
service, private keys, live trust registry, database migrations or production
deployments are included. The fixed private key in the test suite is **public
test material only**, never an issuance key.

## Trust boundary

A caller-supplied map of key fingerprints to Ed25519 public keys is required.
The caller must authenticate, govern, revoke and rotate those keys independently.
Passing a key supplied by an adversary is **not** establishing trust. Even a
valid signature only returns `pending-review`, never authorization or a
verified human identity.

The replay index remains separate: integrating both modules needs an atomic
server-side sequence, evidence signer authorization, durable revocation state,
trusted clocks and further review. **Authorization DENY; GO-13 HOLD.**
