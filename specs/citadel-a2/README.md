# A2 — verification and release contract candidate v0.1

Status: DRAFT implementation candidate for review, before B1 PostgreSQL. A1 remains the executable envelope-integrity baseline. A2 adds a machine-readable receipt schema, reason registry, 30 differential reason vectors, an unsigned release-candidate checksum gate and an optional Ed25519 approval-verification profile. It does not declare a production release or activate the Citadel.

## Interim governance and later handover

Current user decision (2026-09-29): **two designated interim reviewers**, Maurits (`github:Maurits-pixe`) and the second reviewer recorded in `release-policy-v0.3.json`. The second reviewer's contact was supplied by the owner; their person identity, distinctness, acceptance, GitHub account and identity-to-key binding remain unverified. Both production public keys remain missing. The second reviewer's local designation ID is not a verified identity. Production release remains disabled and release authority is unassigned. Versions 0.1 and 0.2 are retained as historical governance intent and are superseded by v0.3. These governance-intent documents are not executable cryptographic trust stores. The executable approval-profile version remains 0.2; this documentation update does not install a trusted policy or change verifier semantics.

Email and GitHub handles do not count as separate people or prove key ownership. A bot or automated agent review does not count as Maurits' approval. The current two-reviewer requirement cannot be satisfied by signatures from the same person or key. The handover to Ambassadors requires a new policy version, an explicit effective release boundary and recorded authorization by the then-current authority. Do not silently relabel existing keys or treat the word Ambassador as a credential. Retain historical policies and approvals for reproducibility. The Ambassadors' approval threshold remains a future policy decision; do not inherit the interim threshold implicitly.

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

`verification-result.schema.json` forbids unknown/omitted fields, fixes the A1 scope and UNKNOWN authority dimensions, and couples each reason to exactly one result. `reason-codes-v0.1.json` is the candidate registry. `tools/citadel_a2/contracts.py` provides the corresponding receipt boundary check. `verification/citadel-a2/reason-vectors-v0.1.json` covers every registered reason, runs both implementations and compares complete receipts and exit codes. These are separate A2 vectors; A1 vectors remain untouched.

## Threat model and trust boundaries

An attacker can supply any bundle field, rewrite/reorder/truncate exports, replay a record into another Citadel/world, invent actor IDs, timestamps and signatures, or substitute both content and untrusted anchors. Domain-separated full-envelope hashes and trusted external anchors address byte integrity and context substitution. Size/depth limits bound individual parsing inputs; deployment rate limits remain separate.

Compromised release keys, a compromised anchor channel, malicious but correctly hashed evidence, rollback to an old valid release and unauthorized writes are not solved by A1. Fail closed for unsupported trust material. Do not infer authenticated identity or tenant access from `actor_ref`, `citadel_id`, a matching digest or another PALACO repository's login.

### Closure checklist — 2026-09-29

Threat model status: **OPEN / REVIEW REQUIRED**. The following is a closure checklist, not evidence that controls were executed or approved. Existing tests described above do not establish production readiness.

| Threat / boundary | Required closure evidence | Current gap |
|---|---|---|
| Reviewer impersonation or one person counted twice | Independently confirmed person/account/public-key binding and acceptance for each reviewer; two distinct people | Second identity and both key bindings unverified |
| Stolen, replaced or revoked signing key | Reviewed custody, rotation and emergency revocation procedure; authenticated current policy anchor; negative stale-policy test | Production procedure and anchor distribution open |
| Replay, concurrent acceptance or restored old snapshot | Atomic compare-and-advance of release sequence/digest; concurrent-writer, crash and restore tests against durable state | Offline verifier does not persist state |
| Local clock rollback or expired authorization reuse | Trusted-time policy where expiry is used; terminal revocation/expiry; rollback and stale-snapshot negative tests | Current signature profile does not establish current authorization |
| Altered, reordered or truncated export / replaced anchors | Both verifiers check exact exported bytes against independently acquired current anchors; missing dependencies fail closed | Full constitutional export case not implemented |
| Unauthorized writes or tenant/context substitution | Authentication plus explicit resource/action authorization at the transaction boundary; deny and cross-tenant tests | Ledger/API flow not implemented |
| False or malicious but correctly hashed evidence | Explicit assessment, decision threshold, authorization and reassessment; integrity never treated as truth or authority | Full constitutional flow not implemented |
| Source/artifact substitution or unapproved release | Exact commit, descriptor and artifact inventory bound to approvals; reviewed provenance and explicit release actor | Release authority, source attestation and baseline open |

The two designated reviewers must record their assessment against an exact commit and identify accepted assumptions and unresolved blockers. A test run or this checklist cannot count as their approval. No reviewer invitation or acceptance is implied.

## Schema and profile evolution

Published vectors, schema/profile identifiers and baseline tags are append-only release artifacts. A change to canonical bytes, allowed values, digest domain, verification meaning or precedence requires a new explicit profile/schema and new vectors. Old verifiers must reject unsupported versions with UNKNOWN. Unknown fields remain INVALID; omission and null remain distinct. Migration produces new records with explicit provenance to old records; it must not rewrite historical digests. Retain old verifier versions to reproduce historical results.

## Verifiable manifest release process

1. Authorized maintainers approve the exact commit, profile IDs, vectors, checksum inventory and resolved semantic review. Record who approved what; CI alone is insufficient.
2. Build a release descriptor binding commit, manifest digest, fixture head, schema/profile IDs and file checksums. Review and freeze the candidate signature profile and approval envelope before production use; implementing the profile does not approve it.
3. Sign that descriptor with an authorized release key. Distribute its verification key and authority scope through an independently trusted channel. A public key embedded only in the bundle is not a trust anchor.
4. Publish descriptor, detached signature, immutable artifacts and verification instructions under a unique baseline tag. Verify from a clean download with both independent implementations. Verify tag/commit and file checksums as well as signature.
5. Define release sequence/rollback policy, key rotation, key revocation and compromised-release withdrawal. Signature validity does not imply present authorization. Preserve withdrawn artifacts for audit, clearly recording their status.

Open A2 gates: both reviewers' verified identity/key bindings and key custody; explicit release authority; approval of the candidate signature profile; trusted policy distribution and durable continuity-state storage; key revocation/rotation procedure and Ambassador handover. Cryptographic approval checks and rollback/revocation negative tests are implemented in the candidate profile, but authentic production trust configuration and integration are not.

## Optional signed-approval profile

See [approval-profile-v0.1.md](approval-profile-v0.1.md) for exact signed bytes, policy pinning, identity/key uniqueness and continuity semantics. `verify_approvals.py` supports a trusted, explicitly pinned interim policy requiring one or two distinct reviewers. The current governance choice is two; threshold-one support is retained only for historical/profile compatibility and must not be selected as the current production policy. Threshold reduction changes the signed policy digest and cannot be accepted against an unchanged trusted policy anchor. A signature self-supplied by an untrusted key never counts.

The profile uses the [PyCA Ed25519 API](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/), pinned to `cryptography==50.0.1` for these tests. Tests generate synthetic private keys in memory; no production keys, signed production artifacts or secrets are created. A successful scoped signature result is not an instruction to merge, tag, deploy or activate.

## Executable unsigned candidate gate

`release_candidate.py` accepts an externally anchored descriptor digest and source commit, and an artifact directory. The descriptor binds DRAFT status, version, commit, Citadel/world, manifest/head digests, canonical/hash profiles and an ordered, exact inventory of the three A1 reference files. SHA-256 hashes are over raw file bytes. Descriptor hash is SHA-256 of `PALACO:CITADEL:RELEASE-DESCRIPTOR:A2` plus NUL plus PALACO-JSON-A1 canonical descriptor bytes, including its explicit null signature. No signature exclusion is defined for this unsigned profile.

The checker validates reference file bytes, manifest consistency, resource context and the A1 chain. It rejects dropped, duplicated or traversal filenames and linked/missing/oversized files. It compares the declared commit to the external expected commit; it does **not** prove Git ancestry, ownership or that a tag resolves to that commit. Use a fixed offline export directory, not one concurrently modified by untrusted writers. Repository/source attestation remains part of the signed release process.

For intact unsigned material the result is `INCOMPLETE`, `artifact_integrity: VALID`, `release_authority: UNKNOWN`, `signatures: UNKNOWN`, `production_release: false`. A supplied signature produces UNKNOWN because no signature profile is implemented. Self-declared approvals are rejected as unknown fields. The CLI always exits nonzero; it has no production approval path. This A2_RELEASE_CANDIDATE receipt is deliberately outside the A1 receipt schema.

The committed candidate anchors original A1 source commit `c84ecde45dd3221b4d6c99efe2201971a3e6a14a`; its descriptor digest is `c14586730eac6f44d809adc346d86488cd99f58c50cf01ee236b32e447b4659f`. This checked-in example is a reproducibility fixture, not an independently authenticated channel.

```sh
cargo build --locked -p palaco-citadel-contracts --bins
CITADEL_A1_BINARY="$PWD/target/debug/citadel-a1" python3 tools/citadel_a2/test_contracts.py
python3 tools/citadel_a2/test_release.py
python3 tools/citadel_a2/release_candidate.py verification/citadel-a2/release-candidate-v0.1.json verification/citadel-a1 c14586730eac6f44d809adc346d86488cd99f58c50cf01ee236b32e447b4659f c84ecde45dd3221b4d6c99efe2201971a3e6a14a
# Last command intentionally exits 1: intact artifacts do not approve a release.
```

## Exit gate before B1

A2 is complete only after receipt/schema and reason-code vectors are frozen, threat assumptions approved, evolution rules accepted, and the chosen signed-release process passes negative tests (wrong key/context, altered artifact, unknown profile, revoked key and rollback). Then B1 can implement append-only transactions, idempotency and expected previous digest; authorization and tenant isolation require their own explicit gate before exposing writes.
