# Organization Delegation Status History v0.1 — DRAFT / GO-13 HOLD

The module `tools/organization_delegation_history.py` verifies a bounded,
offline, Ed25519-signed history for one exact signed assessor-delegation
envelope. Every status record binds its organization, assessor key, delegation
envelope SHA-256, strict sequential revision, and previous signed-record hash.

Only `active` and `revoked` are recognized. The first record must be active.
Once revoked, the same delegation digest can never become active again.
Every record must be signed by an independently trusted and allowlisted
status issuer that is not a witness, assessor, governance issuer, or delegator.
An external revocation list excludes bad status issuers.

The caller MUST pin the first and latest record SHA-256 externally and provide
an independent minimum history revision. Without these pins a local attacker
could replace or rewind the chain. The verifier first rechecks the complete
signed organization registry succession, identity assessor claim and signed
narrow delegation. Valid results remain `pending-review`, not actual
delegation or authorization.

**Limitations:** no independent legal representation evidence, trusted time,
remote key management, immutable off-device storage, automatic amendment,
global replay monitoring or recovery/merge/release authority is provided.
This verifies cryptographic statements, not real-world legal powers.

Run: `python3 -m unittest discover -s tests -p 'test_organization_delegation_history.py' -v`.
