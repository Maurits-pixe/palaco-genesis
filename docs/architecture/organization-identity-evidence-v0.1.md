# Organization Identity Evidence v0.1 — DRAFT / GO-13 HOLD

The verifier in `tools/organization_identity_evidence.py` accepts a detached
Ed25519-signed *assessor claim* concerning a witness organization and its
currently active witness key. It commits to the exact latest signed registry
envelope hash, contiguous registry revision and an evidence-document SHA-256.

Before accepting the assessor signature, it re-verifies the entire signed
witness-registry succession against independently pinned genesis/head hashes
and the minimum revision. It checks the current organization/key mapping,
current assessor allowlist and revocations, key fingerprint, signature and
separation between assessor and witness/governance issuer roles.

A valid claim returns `pending-review`, never permission. It is not a legal
identity check: actual evidence documents, registered organizations, beneficial
ownership, assessor independence, key ceremonies and external immutable custody
must be authenticated by separate processes. No private evidence documents
are written to the repository or included in verifier output. No release,
recovery, merge, public hosting or deployment is authorized.

Test: `python3 -m unittest discover -s tests -p 'test_organization_identity_evidence.py' -v`.
