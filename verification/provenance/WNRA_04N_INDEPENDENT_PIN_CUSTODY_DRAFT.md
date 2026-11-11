# WNRA-04N — Independent pin custody contract (DRAFT / TEST ONLY)

Status: **PROPOSED**, **GO-13 HOLD**, **AUTHORIZATION DENY**.

Parent evidence: WNRA-04M DRAFT #289, immutable head
`fed36db041f242c96ee6cec6620e99316246e775`.
The parent demonstrates a disposable SQLite snapshot digest under one read transaction;
it does **not** establish an authenticated issuer or independent pin custodian.

## Security objective and trust boundary

A verifier may compare a test snapshot's deterministic digest with a separately
held expected value. The comparison has integrity meaning only if the expected
value was acquired and retained independently of every actor who can rewrite
the test ledger. An attacker controlling both sources can substitute both.

This document does not authorize production pin issuance, key use, signing,
release, runtime activation, trusted time, cross-host fencing or any governed
state change. A digest, test PASS, and custody receipt are not permissions.

## Proposed actors and separation

| Actor | May do in the hypothetical test design | Must not do |
| --- | --- | --- |
| Fixture writer | Modify isolated disposable SQLite data | Create or replace an accepted external pin |
| Pin custodian | Accept a candidate digest into an isolated review register | Edit lease or audit rows; self-approve an issued identity |
| Verifier | Read only the pinned digest and snapshot; produce PASS/FAIL | Write ledger or pin; authorize redemption |
| Reviewer | Inspect immutable evidence and explicit custody decision | Infer production authority from a green fixture |

These roles are conceptual interfaces. No real service, person, credential,
separation of duties or independent approval is evidenced here.

## Proposed pin record v0.1

Required fields (candidate schema, not canonical):

- `schema`: fixed `WNRA-04N-PIN-v0.1`
- `fixture_id`: non-empty opaque test fixture identity
- `snapshot_digest`: lowercase 64-character SHA-256 hex
- `algorithm`: fixed `sha256`
- `snapshot_domain`: fixed `PALACO-WNRA-04L-TEST-SNAPSHOT-v1`
- `source_commit`: exact 40-character Git commit ID used for the test
- `sequence`: positive integer, monotonically increasing per fixture
- `predecessor_digest`: prior accepted pin digest, null only for genesis
- `evidence_ref`: immutable source/run reference supplied by the reviewer
- `custody_status`: `PROPOSED` or `REVIEWED` or `REJECTED`

The record itself is **not** an authentication mechanism. Its storage, access
policy and immutability must be independently established before any trust claim.

## Fail-closed acceptance invariants (proposed)

1. **No self-pin**: the verifier cannot calculate a new expected digest from the
   same database and then treat the comparison as independent evidence.
2. **No silent replacement**: an existing accepted pin cannot be overwritten by
   an ordinary fixture writer or by a failed review.
3. **No rollback**: an older sequence or predecessor mismatch is rejected.
4. **No cross-fixture replay**: fixture and domain must match exactly.
5. **No unproven custody**: absent or unverifiable custodian identity, signature,
   isolation evidence, or trusted channel means `UNKNOWN` or `DENY`, not PASS.
6. **No authority escalation**: successful pin verification never moves an
   authorization, release, signing, identity issuance, or redemption gate.
7. **No implicit time**: timestamps, if later introduced, need a separately
   verified clock authority. Local wall-clock labels have no authority.
8. **No partial acceptance**: a storage error, crash or missing predecessor
   leaves the previous accepted review record untouched.
9. **No circular attestation**: an evidence artifact signed or supplied solely
   by the party that can rewrite both ledger and pin cannot close the trust root.

## Negative test plan for a future isolated candidate

- DB and proposed digest both rewritten by one actor -> no independent proof.
- Accepted pin substituted with equal-length different hex -> DENY.
- Sequence decreases or predecessor differs -> DENY.
- Fixture identity or snapshot domain differs -> DENY.
- Custodian unavailable or ambiguous -> UNKNOWN/DENY.
- Simulated interrupted pin replacement -> prior accepted pin persists.
- A valid pinned fixture digest with `AUTHORIZATION: DENY` stays DENY.

## Decision gates

**Current**: DRAFT SPECIFICATION, no pin service, no trusted external anchor,
no independent custodian evidence, no credential provisioning. Prior test-only
CI results do not satisfy these missing trust requirements.

**Next admissible step**: create a *separate disposable test-only* custody
state-machine fixture with negative tests for substitution, rollback,
cross-fixture replay and interrupted replacement. Review exact-head CI.
Any move beyond fixtures requires governance and explicit authority evidence.

## AI-review by three lenses

- **TRIAS:** separation of custody and execution is required; no promotion to
  canonical identity or runtime gate.
- **ORACLE:** existing hash comparison is tested; independence of its pin is
  currently **UNVERIFIED**.
- **MENTOR:** keep the first implementation deterministic, offline, disposable,
  and visibly distinct from real-world signing or credential operations.
