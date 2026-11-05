# PVC-001 G8 Security Checklist

**Scope:** PALACO Core Alpha  
**Status:** OPEN — no security certification is asserted by this checklist.

The validator reads the table below. `PASS` requires a repository evidence
reference in the form `path@<sha256>` whose digest matches the checked-in
artifact. `OPEN` and `HOLD` are blockers; `FAIL` is a demonstrated mandatory
control failure. A checklist status is a recorded claim, not independent
reviewer authentication.

| Control | Status | Evidence |
|---|---|---|
| SEC-THREAT-MODEL | OPEN | release-registry/THREAT-MODEL.md |
| SEC-SUPPLY-CHAIN | OPEN | - |
| SEC-SECRETS-CONFIG | OPEN | - |
| SEC-ADVERSARIAL | OPEN | - |
| SEC-INDEPENDENT-REVIEW | OPEN | - |

The threat-model draft explicitly records unresolved production risks and
requires independent review. Supply-chain, secrets/configuration, adversarial
and independent-review controls remain open until current, revision-bound
evidence is supplied and reviewed.
