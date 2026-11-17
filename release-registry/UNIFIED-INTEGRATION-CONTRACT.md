# PALACO Unified Integration Contract v1 — candidate only

This contract extends the read-only offline package integrity check. It does **not** connect the five actual apps, authenticate source origins, load code, sync user data, grant roles or enable deployment.

Candidate package contents:

```text
candidate/
  package-integrity.json      # SHA-256 list for EVERY other file
  module-contract.json        # MUST be included in that list
  palaco-one/index.html
  rio/index.html
  mundo/index.html
  citadel/index.html
  neo-os/index.html
```

Example `module-contract.json` (no entrypoint is executed):

```json
{
  "schema": "palaco-unified-integration/v1",
  "modules": [
    {"id": "palaco-one", "entrypoint": "palaco-one/index.html", "requires": []},
    {"id": "rio", "entrypoint": "rio/index.html", "requires": ["palaco-one"]},
    {"id": "mundo", "entrypoint": "mundo/index.html", "requires": []},
    {"id": "citadel", "entrypoint": "citadel/index.html", "requires": ["palaco-one"]},
    {"id": "neo-os", "entrypoint": "neo-os/index.html", "requires": []}
  ]
}
```

All five IDs are required exactly once; each entrypoint must be a listed, hash-matching local file under that module's namespace. Dependencies must reference known modules, have no duplicates and form a directed acyclic graph. Extra fields are rejected. The SHA-256 manifest must include the contract and every other file. Empty directories are ignored.

Run `python release-registry/integration_contract.py /path/to/candidate`. Run tests with `python -m unittest discover -s release-registry -p 'test_*integrit*.py' -v` and `python -m unittest discover -s release-registry -p 'test_integration_contract.py' -v`.

**Security boundary:** All package contents, including manifests, remain untrusted. Matching hashes do not establish source authenticity, signature validity, trusted time, revocation state, permission to execute or user identity. Runtime integration, genuine dependency linkage, secure offline synchronization, replay protection and immutability between check and use remain unimplemented. GO-13: **HOLD**. No merge, deployment, activation, key issuance or shared login.
