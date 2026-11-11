# WNRA-04D — Trusted source statement issuer and one-shot lease (DRAFT)

**Date:** 2026-11-11 (Europe/Amsterdam)  
**Repository:** `Maurits-pixe/palaco-genesis`  
**Parent candidate:** PR #279, pinned-digest test head `5587f3112d714c52e37a51aa1c4f15e930dfd169`  
**Classification:** DERIVED DESIGN / NOT IMPLEMENTED / NOT AUTHORIZED  
**Gates:** GO-13 HOLD; AUTHORIZATION DENY. No signing, release, production runtime, key provisioning, merge or deployment.

## 1. Evidence boundary and problem

The native Windows metadata workflow for PR #279 (run `42960353063`, job `130325146375`) completed successfully on its specified head. The five `test_windows_test_pinned_digest.py` cases logged `ok` (none skipped), including a **hardlink with a matching attacker-supplied digest**. A successful caller-pinned SHA-256 comparison proves consumed-byte equality to an expectation, **not** producer authenticity, trustworthy origin or immutable storage. The earlier hardlink and in-place mutation limitations remain open.

**Goal of this candidate:** specify the smallest independently reviewable contract for obtaining the expected digest from an authenticated, controlled producer statement and for granting a narrowly scoped, short-lived, one-use worker capability. This file grants no live capabilities.

## 2. Actors and explicit trust boundary

| Actor / object | Proposed responsibility | Forbidden inference |
| --- | --- | --- |
| Controlled build producer | Create output in worker-owned staging; report digest of exact finalized bytes and immutable artifact identity | An arbitrary path or filename is not proof of origin |
| Trusted statement issuer | Verify producer/workflow identity and completed-artifact event against a pinned policy; issue authenticated source statement | A test harness, arbitrary manifest, PR label or CI green check cannot self-issue |
| Lease authority / verifier | Verify issuer authenticity, claim bindings, time interval, revocation and one-use redemption in controlled state | A JSON boolean `revoked:false` or local cache does not prove current revocation |
| Native Windows reader | Consume only a worker-owned root-handle capability and approved basename; stage exact bytes, compute observed digest | An NT handle, file ID, same-volume hardlink or matching digest alone is not an authorization |
| Governance / evidence reviewer | Review bound evidence and make any separately authorized transition | `MATCH_OBSERVED` never means `AUTHORIZED` |

Issuer and lease services are conceptual; **none is present or trusted merely because this contract exists**. Production identity, issuer keys, roots, revocation stores, OS ACLs and deploy topology require separate human design review.

## 3. Proposed source-statement contract v0 (noncanonical)

Illustrative logical fields, not a signed receipt:

```json
{
  "schema": "WNRA-04D/source-statement-v0",
  "issuer_id": "policy-pinned-issuer-id",
  "issuer_key_id": "key-version",
  "producer_subject": "authenticated-build-worker-identity",
  "workflow_ref": "approved-workflow-and-revision",
  "build_id": "unique-build",
  "attempt_id": "unique-attempt",
  "artifact_role": "approved-role",
  "artifact_instance_id": "unique-output",
  "expected_sha256": "64-lowercase-hex",
  "byte_length": 0,
  "storage_binding_ref": "worker-owned-immutable-staging-object",
  "issued_at": "trusted-UTC-time",
  "not_before": "trusted-UTC-time",
  "expires_at": "trusted-UTC-time",
  "statement_id": "unique-nonce",
  "authenticator": "detached-cryptographic-proof"
}
```

The verifier must check a **policy-pinned issuer key/identity external to the statement**, its approved algorithm and key status, canonical encoding and domain-separated signature/MAC verification, all required claims and exact artifact bindings. Reject unknown/retired keys, duplicate claims, unknown fields that could alter interpretation, noncanonical digests, unsigned or self-signed statements, wrong audience, producer/workflow mismatch and unapproved roles. An authenticated identity claim must be validated against a trusted identity provider / build control plane; copying a producer name into JSON is insufficient.

The expected digest must be generated from finalized controlled output and bound to an immutable worker-owned staging object before issuance. The statement's authenticator is not designed or calculated here; there are **no example private keys or mock trust roots** to accidentally elevate.

## 4. Proposed one-shot BuildSourceLease v0

Lease issuance only follows successful source-statement verification and a validated current build context. The lease binds:

- `lease_id` (unguessable, unique), `statement_id`, `build_id`, `attempt_id`, `artifact_instance_id`, `artifact_role`, `consumer_identity`, `audience`, `issuer_id`.
- A strict `not_before` / `expires_at` interval with bounded maximum lifetime; monotonic server-side expiry accounting for live redemption, and explicit rejection of backward-clock anomalies. No client-controlled clock extends a lease.
- A **worker-local, non-serializable handle capability** for an already validated root directory; expected volume/file identity and exact single-component leaf name. Never encode raw handles, filesystem paths, key material or bearer tokens in evidence logs.
- Single-use redemption stored in an authoritative, atomic compare-and-set state keyed by `lease_id` (not browser storage or a process-local flag), plus an explicit issuer/lease revocation check at redemption **and again at governed handoff**.
- An idempotency policy: a repeated request returns a `REPLAY_DENIED`/existing-result reference, never a fresh read permit, even across crash/restart or concurrent workers. If durable state is unavailable, fail closed.

**State machine (proposed):** `REQUESTED -> ISSUED -> REDEEMING -> CONSUMED`; `EXPIRED`, `REVOKED`, `DENIED` are terminal. Expiry/revocation wins over a pending operation before handoff. An interrupted `REDEEMING` remains denied unless a separately specified recovery protocol can prove no reuse. Issuance and redemption are distinct, auditable events. Treat a lost audit write or indeterminate lease state as HOLD/DENY.

## 5. Reader handoff, immutable bytes and evidence

1. Verify statement cryptographically and independently against pinned policy. Validate build attempt, role, scope, byte bound, immutable staging binding and time window.
2. Atomically redeem a lease to an approved reader. Fail closed on missing/expired/revoked/replayed lease, clock uncertainty, identifier mismatch or unavailable state.
3. Open one basename relative to the trusted live root handle; reject reparse and namespace escape. Check opened-handle file/volume identity; do **not** mistake hardlink count for provenance.
4. Copy/read into strictly bounded, worker-owned immutable staging inaccessible to untrusted writers. Do not expose staged bytes until the complete snapshot and its integrity checks succeed. Abandon and clean up on any partial read, mutation, mismatch or ownership ambiguity.
5. Compute SHA-256 of exactly the staged bytes; use constant-time comparison against the authenticated expected digest and verify length/identity. Revalidate statement/lease revocation at the governed handoff.
6. Emit a `SourceReadEvidence` record referencing the statement, lease and policy revision with `MATCH_OBSERVED`, `MISMATCH`, `DENY` or `HOLD`. Bind producer, byte count, observed digest, attempt, read trace and reasons. **Never output a production permit or authority from this path**.

Offline mode may retain evidence for later review, but must **not** redeem previously unknown, expired or uncheckably revoked leases. No silent time advancement, trust-root switch or world-state change.

## 6. Negative and positive review matrix (NOT EXECUTED)

| Fixture | Expected decision |
| --- | --- |
| Valid signed producer event, matching finalized immutable bytes, fresh lease, atomic redemption | `MATCH_OBSERVED` evidence only |
| Matching hash of outside-root hardlink without authenticated producer statement | `DENY` |
| Caller chooses digest and self-signs a plausible manifest | `DENY` |
| Valid signature from unpinned/retired key or wrong domain/audience | `DENY` |
| Producer identity, workflow, build/attempt, role or artifact binding mismatch | `DENY` |
| Digest, length, canonical encoding, signature or immutable staging identity modified | `DENY` |
| Lease replay, concurrent redemption, restart replay or stale revocation | `DENY` |
| Expired/not-yet-valid lease, backward clock or unavailable trusted time | `DENY/HOLD` |
| File changes in place between source open and staging digest | `DENY` unless exact trusted immutable snapshot remains validated |
| Partial staging write, crash, permission failure or lost audit event | `DENY/HOLD`, no published bytes |
| Reparse root/child, volume identity drift or unknown filesystem semantics | `DENY` |

These are required future fixtures, not green tests. No native Windows lease issuer, signer, authoritative revocation service or immutable staging is implemented by this DRAFT.

## 7. Security review questions before any implementation

- Who operates/attests the build worker and issuer, and where are identity proof and issuer public keys pinned **outside untrusted repository metadata**?
- What exact durable transactional store enforces one-use redemption across crashes and concurrent workers?
- Which filesystem/ACL and file-creation mechanism makes finalized staging truly writer-inaccessible, and how is this demonstrated against hardlinks and in-place modification?
- What is the explicit maximum lease TTL, clock-skew policy, key rotation, revocation lag, replay retention and disaster recovery behavior?
- How are sensitive capabilities redacted from logs, while nonsecret audit and StateProof lineage remain reviewable?
- Which real governance actor can approve moving past test-only evidence and with what independent evidence? GO-13 currently prevents such a move.

## 8. AI triadereview and next admissible slice

- **TRIAS:** issuer != verifier != governance; a source statement and lease can bind evidence but confer no runtime, merge or release authority. GO-13 HOLD / AUTHORIZATION DENY is unchanged.
- **ORACLE:** PR #279 Windows run `42960353063` and job `130325146375` show five new digest tests executed successfully, no skips in that suite. They do not validate a trusted producer; all issuer/lease/immutable-staging controls above remain **NOT EXECUTED**.
- **MENTOR:** next, build a **separate test-only lease state-machine simulator** with negative expiry/revocation/replay/concurrency fixtures and no real key material, file access or production issuer; then conduct a separate native Windows immutable-staging review. Human security review is required before any production trust root.

This is one assistant's three-lens AI review, not independent approval. **Transition:** `WNRA-04D DRAFT design` -> `separate DRAFT test-only lease simulator` after exact-head review; production integration, signing, merge, release and deployment remain **HOLD/DENY**.
