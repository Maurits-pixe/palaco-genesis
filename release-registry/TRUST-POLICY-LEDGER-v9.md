# PALACO Trusted Evidence v9 — Trust Anchor & Policy Ledger (draft)

**GO-13 HOLD — not a production trust root, revocation service or release control.**

The v9 candidate implements an append-only, in-memory *proposal and replay contract* for changes to versioned v8 key-registry snapshots. Existing v7/v8 signature verification remains separate and unchanged.

## Candidate semantics

- Each event carries exactly the v9 schema, a 1-based sequence, a previous event digest, SHA-256 hashes of its before/after v8 snapshots, and the two complete snapshots.
- Domain-separated SHA-256 hashes link events. Replay checks exact sequential order, predecessor digest, snapshot hashes and continuity between the after-state of one event and the before-state of the next.
- Every registry update increments its registry version by exactly one.
- Existing public-key bytes are immutable and existing scope lists cannot be changed in place; an updated key/scope requires a **new key ID** and the independent transition policy that is still to be defined.
- Key removal is forbidden; revocation is terminal for the existing key ID. A revoked key cannot be reactivated.
- Proposals freeze caller input, reject stale expected heads and do not modify the supplied history.
- External trust inspection requires **both** `get_trusted_anchor()` and `verify_policy(sequence, head)`. The anchor must be independently maintained, authenticated and monotonic; caller-supplied history must never supply its own trusted anchor.
- Empty histories are rejected by the trust-inspection function. Positive synthetic callbacks still produce only `HOLD`, `DENY` and `production_release_enabled: false`.

## Negative checks

```sh
python -m unittest discover -s release-registry -p 'test_policy_ledger_v9.py' -v
```

20 test cases were committed, covering candidate revocation, prohibited reactivation, scope widening, key replacement/deletion, skipped versions, stale heads, tampered events, broken links and sequences, unknown authority fields, cross-event discontinuity, missing/rollback anchors, policy exceptions, non-Boolean approvals, frozen proposals, invalid sequences and empty-ledger trust refusal.

The existence of test code is **not** proof of test execution. Independent GitHub CI confirmation and adversarial review are required.

## Explicit limitations

The ledger is a **local pure Python model**, not durable append-only storage. It has no independent signature verification over ledger entries, no real trusted monotonic checkpoint, no live revocation oracle, no trusted time, no key-rotation ceremony, no concurrency control, no deployment or account integration. SHA-256 detects changes relative to a trustworthy external anchor; it cannot establish that the history was created by an authorized issuer.

The transition contract is intentionally conservative: it does not remove revoked records, retroactively authorize active keys, or change existing key scopes. Adding a brand-new key is not by itself authenticated onboarding. Any production acceptance of newly introduced key IDs requires separate independently signed admission policy and reviewer authorization.

**No merge to main, site publication, credential creation, key issuance, recovery activation, production data, or release authorization.**
