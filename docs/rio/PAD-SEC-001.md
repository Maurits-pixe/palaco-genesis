# PAD-SEC-001 — Security and mutation-boundary contract

Status: SPECIFICATION COMPLETE — NOT EXECUTED

Base: PAD-MIG-001 at 9d81babfbbcc8a7dee6c2f1df93aa99645523838

This contract defines the security boundary for the PAD-RECORD-001 schema. It separates database capability from PALACO authorization and specifies the minimum role, mutation, temporal, revocation, and signature rules for a future adapter.

No role, grant, RLS policy, key registry, or cryptographic operation is executed by this document or by repository CI.

## Security axioms

The following distinctions are normative:

- database capability is not PALACO authorization;
- access is not authorization;
- a valid signature is not permission;
- a verified receipt is not permission;
- a migration identity is not a runtime identity;
- a verifier may establish a result but may not mutate the evidence basis;
- a projection may be derived from canonical records but may not rewrite them.

Authorization must fail closed when identity, scope, purpose, lifecycle, trusted time, revocation state, key state, or provenance is unknown, stale, contradictory, or unverifiable.

## Protected surfaces

The following PAD-MIG-001 tables are canonical and append-only:

- rio_verification_runs;
- rio_verification_run_manifests;
- rio_verification_run_unresolved;
- rio_observations;
- rio_evidence;
- rio_verifications.

The migration ledger is separately protected: only the migration boundary may append a migration record, and only after exact artifact, predecessor, and validation checks succeed.

For canonical PAD records, the normal operating contract is:

- INSERT may occur only through the role and lifecycle permitted for that record type;
- UPDATE is denied;
- DELETE is denied;
- TRUNCATE is denied;
- canonical bytes, identifiers, provenance, sequence values, and digests are never rewritten;
- corrections are new records with new identities and explicit provenance.

Database-owner or superuser capability does not create PALACO authorization. Any emergency break-glass operation is outside the runtime path, requires independent human governance, and must produce a separately attributable security record. Break-glass is not a normal correction mechanism.

## Role separation

Role names below are contract identities, not claims that PostgreSQL roles already exist.

| Contract role | Permitted capability | Explicit prohibition |
| --- | --- | --- |
| Owner / security authority | Approves role, key, policy, and break-glass governance changes | No implicit runtime write authority; no silent historical rewrite |
| Migrator | Applies the exact ordered migration and appends its migration-ledger record | No canonical PAD-record INSERT, UPDATE, DELETE, TRUNCATE, GRANT, or role escalation |
| Runtime writer | Appends lifecycle-valid runs, observations, and closed evidence | No schema change, privilege change, historical mutation, or verification-basis rewrite |
| Verifier | Reads the run, observation, and evidence basis and appends verification results | No observation/evidence mutation, no deletion, no grant or key change |
| Projector | Reads canonical records and writes only explicitly derived projections | No source-table mutation and no authority elevation through a projection |
| Reader / auditor | Reads the permitted scope and provenance | No write, DDL, grant, role, key, or lifecycle mutation |
| PUBLIC / unknown identity | No capability | No default allow, discovery-based authority, or anonymous write |

The runtime identity must not own canonical tables, manage roles, grant privileges, bypass row-level security, or hold migration authority. The verifier identity must not be trusted as the source of the evidence it verifies.

## Scope and authorization decision

Every authorization decision must bind all of the following in one decision record:

1. subject identity and authenticated session;
2. contract role and current grant state;
3. requested operation and purpose;
4. target record, tenant, world, citadel, project, or authorization scope;
5. record lifecycle state and allowed transition;
6. trusted time and trust epoch;
7. revocation state and revocation sequence;
8. key identity and signer state where a receipt or signature is required;
9. provenance and decision identifier.

The decision is DENY or HOLD if any required input is absent, stale, contradictory, out of scope, or unverifiable. A database permission check is only one input; it is never the complete authorization decision.

## Default deny and RLS boundary

The future database adapter must provide default-deny behavior for PUBLIC and unknown identities. Application roles must not receive BYPASSRLS. Row-level security is defense in depth and must not be treated as a replacement for PALACO authorization, provenance, revocation, or lifecycle validation.

Any RLS policy must be scoped to an authenticated subject and an explicit authorization scope supplied by the trusted runtime boundary. A client-controlled identifier, a projection row, a receipt alone, or a stale session value is insufficient to establish scope.

The exact claim transport, role names, grants, RLS statements, and deployment ownership remain implementation work. This contract intentionally does not invent executable PostgreSQL policy text before those interfaces are specified.

## Temporal and revocation invariants

Authorization validity is monotonic:

- REVOKED and EXPIRED are terminal grant states;
- the highest accepted trusted time may never decrease;
- trust_epoch may never decrease;
- a local clock rollback produces TEMPORAL_UNCERTAIN and DENY or HOLD;
- an old snapshot may not restore a grant, role, key, or revocation state;
- a stale authorization snapshot is rejected rather than refreshed by the client;
- trusted-time and revocation checks are bound to the same authorization decision;
- a grant cannot become valid again merely because wall-clock time moved backwards.

The recovery boundary must durably retain the highest accepted trusted time, trust epoch, revocation sequence, and relevant authorization head before accepting a new decision. In-memory state alone is not sufficient evidence of monotonic security state.

## Receipt and signer boundary

Where a security receipt is used, its canonical signed domain must be explicit. For the temporal receipt boundary this domain is PALACO-ERA-V1-TEMPORAL-RECEIPT.

A receipt is accepted only when all of the following bind to the same canonical payload:

- signer identity;
- bound key identifier and algorithm;
- domain and schema version;
- subject, purpose, and authorization scope;
- record or decision identifier;
- digest and sequence/head values;
- trusted timestamp and trust epoch;
- revocation and validity state;
- signature bytes.

The following must reject:

- wrong-key verification;
- cross-domain substitution;
- payload or digest mutation;
- signer substitution;
- revoked or expired signer;
- stale sequence or head;
- missing scope or purpose;
- malformed or non-canonical serialization.

SIGNATURE VALID is not AUTHORIZED. RECEIPT VERIFIED is not PERMISSION. Production key custody, HSM/KMS operation, rotation service, and external trust anchors are not established by this contract.

## Mandatory denial matrix

The future implementation and independent review must cover at least these cases:

| Case | Required result |
| --- | --- |
| PUBLIC or unknown identity attempts any canonical write | DENY |
| Runtime attempts UPDATE, DELETE, or TRUNCATE | DENY |
| Runtime attempts DDL, GRANT, role escalation, or BYPASSRLS | DENY |
| Migrator attempts canonical record write | DENY |
| Verifier attempts observation or evidence mutation | DENY |
| Projector attempts source-table mutation | DENY |
| Reader or auditor attempts any write | DENY |
| Scope does not match the target record | DENY |
| Grant is expired or revoked | DENY |
| Trusted time or trust epoch moves backwards | TEMPORAL_UNCERTAIN → DENY or HOLD |
| Old snapshot omits a later revocation | DENY |
| Receipt has wrong key, domain, signer, sequence, or payload | DENY |
| Signature verifies but authorization is absent | DENY |
| Required provenance or lifecycle input is unknown | DENY or HOLD |
| Valid append has an existing identity or digest conflict | DENY without mutation |

Negative results must leave canonical PAD records, digests, migration state, and authorization heads unchanged.

## Enforcement boundary

This contract is the security and mutation boundary for PAD-MIG-001. It does not implement:

- PostgreSQL roles, grants, RLS policies, triggers, or transaction hooks;
- an authentication or session service;
- key generation, custody, rotation, or revocation infrastructure;
- trusted-time acquisition or external clock consensus;
- a dispatcher, outbox, or exactly-once delivery mechanism;
- production deployment, authorization evidence, or conformance execution.

The future adapter must prove the separation between database capability and PALACO authorization, and must record enough evidence to distinguish a denied operation from an unavailable runtime.

## Status boundary

This repository state contains a reviewable security contract and denial matrix only. It does not prove that a database enforces the contract, that keys are bound correctly, that clock rollback is detected, that revocation survives recovery, or that a runtime identity cannot escalate.

PAD-SEC-001 remains SPECIFICATION COMPLETE — NOT EXECUTED. The next boundary is PAD-OUTBOX-001, followed by PAD-VER-001.
