# PALACO Trusted Evidence v14 — Governance Proof Bundle (candidate)

**DRAFT / GO-13 HOLD.** This is a portable review-evidence *candidate* with no recovery authorization or production role.

## Scope

`governance_proof_bundle_v14.py` creates and validates canonical portable JSON bytes containing:
- The exact v12 governance proposal, review list and calculated review head.
- The SHA-256 digests of the original v11 backup bytes and independent evidence bytes.
- The declared review count and v14 schema version.

The bundle is bounded to 2 MiB and rejects unknown fields, invalid JSON, noncanonical encoding, invalid review links, changed evidence or backup bytes, changed proposal binding, and incorrect count/head. The v12 review verifier checks the reviewer receipts through an **independent** `verify_role` callback and an externally pinned audit head from `get_trusted_audit_anchor`. A matching internal hash is not a trusted identity or provenance source.

`make_bundle` does NOT attest anything. `verify_bundle` returns only a redacted diagnostic: `authorization: DENY`, `release: HOLD`, and `production_release_enabled: false`. The diagnostic does not include opaque receipt strings.

## Sensitive-data handling

**Warning:** The exported proof bundle itself includes the raw opaque reviewer receipts and actor identifiers copied from v12, because external verification depends on them. It is **not encrypted or redacted**. Do not upload, email, publish, log or distribute real-user review bundles. Use synthetic evidence only until encryption, retention, data minimization and authorized reviewer access have been designed and independently reviewed.

## Tests

```sh
python -m unittest discover -s release-registry -p 'test_governance_proof_bundle_v14.py' -v
```

20 scenarios committed: synthetic full two-role acceptance with permanent DENY/HOLD, byte-level canonicality, changed backup and evidence, changed review head, reordering, modified receipt, unknown fields, missing fields, changed count and Boolean count, stale audit anchor, false or non-Boolean role approval, missing trust provider, rejection veto, report receipt redaction, and empty reviews.

The tests have not been independently confirmed as executed; GitHub CI outcomes must be checked. Synthetic callbacks that return True are fixtures, **not** verification providers.

## Non-implemented production gates

External monotonic trust anchors, cryptographically authenticated reviewer roles, revocation/freshness, trusted time, controlled evidence custody, encryption and recipient authorization, portable signatures over the complete bundle, browser/mobile review UX, version migration, independent security review, real-world integration and disaster recovery fault tests are pending.

No automatic call to v11 restoration, no account/role change, no key issuance, no deployment and no release-switch behavior. A positive bundle inspection is **never** permission to execute anything.

**No merge to main; GO-13 HOLD.**
