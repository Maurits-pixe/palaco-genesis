# A2 — verification and release contract candidate v0.1

Status: DRAFT design for review, before B1 PostgreSQL. This document does not activate authorization or declare a signed release. A1 remains the executable envelope-integrity baseline.

## VerificationResult v0.1

Receipt fields: `result`, `reason`, `scope`, `identity`, `authority`, `current_validity`, `signatures`, `archive_inclusion`. In A1, scope is exactly `A1_ENVELOPE_INTEGRITY`; the last five fields remain `UNKNOWN`. Consumers must check scope and dimensions and must never treat a VALID A1 receipt as permission to execute. The receipt itself is not signed evidence.

| Result | Meaning | Consumer behavior |
|---|---|---|
| VALID | All implemented checks match externally supplied anchors | Accept only the stated integrity scope |
| INVALID | Malformed data or a violated supported rule | Reject; never repair silently |
| INCOMPLETE | Required anchor, chain segment or referenced source is absent | Reject pending the missing material |
| CONFLICT | Duplicate identity or resource/anchor context conflicts | Reject and investigate context |
| UNKNOWN | Unsupported version/profile/signature or no records | Reject; no fallback to a weaker profile |

No non-VALID result is success. A1 returns the first issue in the documented validation order; it is not an exhaustive diagnosis. A2 must preserve this order or introduce a new verification profile with new vectors.

## Rules and stable reason-code candidate

| Stage | Reason codes |
|---|---|
| Parsing | MALFORMED_JSON_PROFILE, BUNDLE_OBJECT_REQUIRED, BUNDLE_FIELDS |
| Manifest | MANIFEST_SCHEMA, UNSUPPORTED_MANIFEST_PROFILE, MANIFEST_FIELDS, MANIFEST_DIGEST |
| External anchors | EXTERNAL_ANCHORS_REQUIRED, ANCHOR_FORMAT, MANIFEST_ANCHOR_CONFLICT |
| Records | RECORDS_ARRAY_REQUIRED, NO_RECORDS, ENVELOPE_FIELDS, ENVELOPE_SCHEMA, UNSUPPORTED_RECORD_VERSION, ENVELOPE_VALUES, ENVELOPE_ENUM |
| Context and chain | RESOURCE_CONTEXT_CONFLICT, DUPLICATE_ID_OR_SEQUENCE, SEQUENCE_GAP, CHAIN_ORDER, RECORD_DIGEST |
| Dependencies | REFERENCE_FORMAT, SELF_REFERENCE, DEPENDENCY_MISSING_OR_NOT_PRIOR, REFERENCE_TYPE, DUPLICATE_REFERENCE |
| Final checks | ANCHORED_HEAD_NOT_PRESENT, SIGNATURE_PROFILE_NOT_IMPLEMENTED, A1_INTEGRITY_MATCHES_EXTERNAL_ANCHORS |

Reason strings become stable only when A2 is approved and frozen. A1 tests already compare full receipts across Rust and Python. Missing source means an unresolved envelope reference, not proof that an external source exists or is truthful. Payload schemas, evidence content validity and constitutional rules need separate versioned verification profiles.

## Threat model and trust boundaries

An attacker can supply any bundle field, rewrite/reorder/truncate exports, replay a record into another Citadel/world, invent actor IDs, timestamps and signatures, or substitute both content and untrusted anchors. Domain-separated full-envelope hashes and trusted external anchors address byte integrity and context substitution. Size/depth limits bound individual parsing inputs; deployment rate limits remain separate.

Compromised release keys, a compromised anchor channel, malicious but correctly hashed evidence, rollback to an old valid release and unauthorized writes are not solved by A1. Fail closed for unsupported trust material. Do not infer authenticated identity or tenant access from `actor_ref`, `citadel_id`, a matching digest or another PALACO repository's login.

## Schema and profile evolution

Published vectors, schema/profile identifiers and baseline tags are append-only release artifacts. A change to canonical bytes, allowed values, digest domain, verification meaning or precedence requires a new explicit profile/schema and new vectors. Old verifiers must reject unsupported versions with UNKNOWN. Unknown fields remain INVALID; omission and null remain distinct. Migration produces new records with explicit provenance to old records; it must not rewrite historical digests. Retain old verifier versions to reproduce historical results.

## Verifiable manifest release process

1. Authorized maintainers approve the exact commit, profile IDs, vectors, checksum inventory and resolved semantic review. Record who approved what; CI alone is insufficient.
2. Build a release descriptor binding commit, manifest digest, fixture head, schema/profile IDs and file checksums. Choose and freeze a signature profile and canonical descriptor schema before implementation; no ad hoc signature format is approved here.
3. Sign that descriptor with an authorized release key. Distribute its verification key and authority scope through an independently trusted channel. A public key embedded only in the bundle is not a trust anchor.
4. Publish descriptor, detached signature, immutable artifacts and verification instructions under a unique baseline tag. Verify from a clean download with both independent implementations. Verify tag/commit and file checksums as well as signature.
5. Define release sequence/rollback policy, key rotation, key revocation and compromised-release withdrawal. Signature validity does not imply present authorization. Preserve withdrawn artifacts for audit, clearly recording their status.

Open A2 decisions: authorized release owners/key custody, signature algorithm/profile, descriptor schema, trusted distribution channel, rollback and revocation policy. Until these are decided and implemented, releases are checksum-verifiable candidates only, not authenticated production manifests.

## Exit gate before B1

A2 is complete only after receipt/schema and reason-code vectors are frozen, threat assumptions approved, evolution rules accepted, and the chosen signed-release process passes negative tests (wrong key/context, altered artifact, unknown profile, revoked key and rollback). Then B1 can implement append-only transactions, idempotency and expected previous digest; authorization and tenant isolation require their own explicit gate before exposing writes.
