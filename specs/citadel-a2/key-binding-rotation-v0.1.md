# EVA-LA-001 — Reviewer key binding and rotation procedure v0.1

Status: DRAFT PROCEDURE / NOT EXECUTED / HUMAN REVIEW REQUIRED
Date: 2026-09-30
Governance intent: release-policy-v0.3.json
Inspected implementation: ef5ec5bff93730f72c06de81b5845c14b3457889
Scope: the two designated reviewers of EVA-LA-001 only.

## 1. Current readiness

| Item | State |
|---|---|
| Reviewer appointments | Recorded in governance-intent v0.3 |
| Maurits public key and identity/key binding | MISSING / UNVERIFIED |
| Second reviewer person/account identity, acceptance and distinctness | UNVERIFIED |
| Second reviewer public key and identity/key binding | MISSING / UNVERIFIED |
| Release-authorizing actor and scope | UNASSIGNED |
| Current-policy distribution channel and freshness/rollback protection | UNESTABLISHED |
| Durable atomic release-continuity state | NOT IMPLEMENTED |

These are operational prerequisites, not fields to fill with synthetic values. No production private key is to be created by this procedure's author or supplied to chat, Notion, GitHub, logs or test fixtures.

## 2. Binding each reviewer

1. Confirm acceptance of the reviewer role through an independently established contact channel. Record the person, designated reviewer ID, confirmed GitHub account if applicable, verifier and evidence reference. An email address alone proves neither distinct personhood nor key ownership.
2. Each reviewer generates and retains their own Ed25519 signing key in their chosen protected signing environment. Record the custody method and recovery custodian; do not collect private key material. Key-generation and signing tooling must be selected and reviewed before ceremony execution.
3. Collect only the public key (32 raw bytes represented by 64 lowercase hexadecimal characters) and a unique key ID. Compute the fingerprint as SHA-256 of the 32 raw public-key bytes, with that format explicitly named. Do not reuse a test key.
4. Obtain proof of possession using a fresh one-use random challenge bound to purpose REVIEWER_KEY_BINDING, EVA-LA-001, WORLD-EVA-001, reviewer ID, key ID, full public key and ceremony reference. Preserve the exact challenge bytes and detached signature; record independent signature verification and consume the challenge once. The challenge format/tool is not implemented by the release verifier and must be reviewed before use. Never reuse release-approval bytes as an identity-binding challenge.
5. Compare the full public key or its explicitly computed fingerprint through the independently established channel. Record who checked it and how. A signature establishes possession; it does not establish the human identity by itself.
6. Check that the two reviewers are different people and have different key IDs and public keys. Record acceptance and evidence references for both. Only after all checks may identity_key_binding_verified become true in a new, traceable policy revision.

Required per-reviewer evidence: reviewer ID, accepted role, person/account verification reference, public key, key ID, fingerprint and algorithm, custody description, challenge bytes/digest, possession signature, verification result, independent-channel confirmation, checker identity, ceremony reference and observed time. Observed time alone is not trusted-time evidence.

## 3. Bootstrap the current trusted policy

An explicitly appointed policy/release authority must approve the initial trust anchor. Reviewer appointment does not appoint that authority.

After bindings are verified, construct an executable policy with exactly the fields required by verify_approvals.py: policy_version "0.2", signature_profile "ED25519-A2-APPROVALS-0.1", governance_phase "INTERIM", required_distinct_reviewers 2, citadel_id, world_id, reviewers. Each reviewer entry contains exactly reviewer_id, key_id, public_key_hex and status ACTIVE.

Governance-intent v0.3 and executable schema version 0.2 are different documents. Do not feed the intent document to the verifier or add ceremony metadata to the executable policy. Retain binding evidence separately and bind its digest in the authority's transition record.

Use policy_digest() from the inspected verifier to compute the digest. Distribute that digest and policy through an authenticated channel independently established from the incoming release bundle. Record a monotonically increasing policy revision, predecessor digest, effective release boundary, authority decision and acknowledgement from each consumer. The current verifier does not enforce policy revisions or freshness: that control remains an integration blocker. A copied policy file beside its own digest is not an independent trust anchor.

## 4. Planned rotation

1. Prepare the replacement key and repeat the complete identity/possession binding ceremony.
2. Produce a new policy revision and digest; preserve the previous policy and key history unchanged.
3. Obtain the currently required two-person review of the transition and an explicit decision from the appointed authority. The transition binds old/new policy digests, old/new key IDs, replacement binding evidence, scope and effective boundary.
4. Do not insert both old and new keys as extra reviewers: the current executable policy requires exactly two entries, one per designated reviewer. Retain retired key history outside the executable snapshot.
5. Authenticate and atomically install the new current anchor with rollback-resistant revision state at each consumer. Quarantine consumers that cannot confirm the current revision. New release approvals must bind the new policy digest.
6. Record retirement of the old key and retain prior signatures for historical verification. Never translate historical signature validity into current release permission.

Automated transition verification and anchor installation are not implemented. Until reviewed tooling and durable state exist, rotation is a documented procedure only.

## 5. Compromise or loss

Immediately hold new releases when compromise or key loss is reported. An operator may reduce service availability to hold releases; this does not grant permission to resume them.

Preserve the report and last trusted state. Mark the affected key REVOKED in a new authenticated policy revision when the appointed authority can authorize that revision. The verifier then rejects that key; two-person releases cannot proceed with only the remaining reviewer. Do not lower the threshold, reuse an old policy anchor or accept a replacement key based only on a compromised-key signature.

Recovery requires a separately established authority process, fresh binding evidence and authenticated replacement anchors. No recovery authority is appointed by this document. If authority or current state cannot be established, remain on HOLD. Do not require the compromised or lost key to authorize its own emergency removal. Preserve historical policies and distinguish historical integrity from current validity.

## 6. Evidence and release checks

| Check | Existing implementation / remaining action |
|---|---|
| Two signatures and distinct key material | Existing candidate tests; not human-identity evidence |
| Missing approval, revoked key, copied signature | Existing candidate rejection tests |
| Threshold downgrade against unchanged anchor | Existing candidate rejection test |
| Old policy accepted as current after rotation | Current-anchor distribution/freshness integration required |
| Concurrent acceptance, crash, restored snapshot | Durable atomic state and recovery tests required |
| Binding challenge replay or wrong person | Ceremony tool and independent verification required |
| Changed source commit, descriptor or context | Existing candidate checks; source provenance still separately required |

Run and preserve tests against the exact review head before technical approval. This change adds no runtime test result. A successful verifier receipt still has production_release=false.

Each human review record must identify repository, PR, head SHA, base SHA, reviewed paths, test evidence, assumptions, findings and decision. Any subsequent change requires review of a new explicit revision.

## 7. Separate release authority decision

Before any merge/release, record the authorizing actor, appointment evidence, permitted actions (merge, tag, release and activation separately), repository/Citadel scope, exact target commits/artifacts, revocation route and decision reference. No actor is automatically assigned here.

Closure requires verified bindings, approved custody/rotation/recovery procedure, authenticated current-policy distribution, durable continuity controls, recorded human reviews and explicit release authority. Until then: DRAFT / RELEASE BLOCKED.
