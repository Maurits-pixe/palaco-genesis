# Receipt Custody Policy v0.1 — DRAFT / GO-13 HOLD

`tools/receipt_custody_policy.py` defines a signed, bounded, canonical
offline custody policy. An independent governance key signs the permitted
witness key fingerprints, minimum receipt event count, and policy revision.
The verifier requires an **externally authenticated** governance key map,
a minimum revision pinned outside the database, distinct witness roots and
separate revoked-key lists. The event threshold is the maximum of the signed
policy and the external trusted threshold.

The verifier first verifies the policy and its signer; it then allows only
listed witness keys to pass the existing Ed25519 signed receipt-chain anchor
verifier. It checks the full local audit chain and reconciles the receipt
index. Invalid policy, tampered signatures, stale minimums, revoked keys and
unrecognized witnesses all quarantine. Successful output remains
`pending-review`, `authorization_granted=false`, `automatic_restore=false`.

**Unimplemented trust requirements:** no governance issuance process,
real custodian authentication, external immutable publication, remote
freshness, independently anchored key rotations, physical receipt custody or
trusted time exists in this module. An attacker supplying every trust root,
policy and minimum can trivially fabricate a seemingly valid local result.
The policy is not an execution authorization or recovery approval.

Run `python3 -m unittest discover -s tests -p 'test_receipt_custody_policy.py' -v`.
