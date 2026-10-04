# PAD-AUTHGATE-001 — Fail-closed authorization gate contract

Status: SPECIFICATION COMPLETE — NOT EXECUTED

Base: PAD-ENVGATE-001 at e8f0b8b48a251f1b3631930db95997a2462a8c6f

PAD-AUTHGATE-001 is the second gate in the execution sequence. It determines whether one explicitly identified authority may authorize one exact, bounded run after the environment prerequisite has reached READY.

This contract does not create an authority, infer permission from identity, execute a command, open PostgreSQL, create observations, close evidence, or establish conformance. Authorization is a separate decision from environment readiness and from execution.

## Gate sequence and boundary

The required order remains:

PAD-ENVGATE → PAD-AUTHGATE → EXEC-ENVELOPE → REVALIDATE → COMMIT → EXEC → RECORD

The gate meanings are distinct:

| Gate | Owns |
| --- | --- |
| PAD-ENVGATE | Whether the exact environment prerequisites are observable and compatible |
| PAD-AUTHGATE | Whether an identified authority explicitly permits the exact declared scope |
| EXEC-ENVELOPE | Whether all execution identifiers, commands, fixtures, limits, and expected material are frozen |
| REVALIDATE | Whether environment, authority, scope, revision, time, and provenance still match |
| COMMIT | Whether the envelope and pending run state are accepted atomically before the first effect |

PAD-AUTHGATE may be evaluated only after a current PAD-ENVGATE READY result is available. BLOCKED, STALE, or UNVERIFIED environment state prevents authorization. A PAD-ENVGATE READY result is necessary but never sufficient.

An AUTHORIZED result permits only the next contract boundary. It does not start a run, commit an effect, contact a service, or make a conformance claim.

## Authorization decision

The authorization gate answers one bounded question:

Has an explicitly identified and eligible authority, using a traceable decision, permitted this exact actor, target, scope, revision, environment, test pack, validity window, and evidence boundary?

The only positive result is AUTHORIZED. The following fail-closed results do not permit the next gate:

- NOT AUTHORIZED: no valid authorization decision exists or an explicit deny/hold is present;
- BLOCKED: a prerequisite or required authorization fact cannot be evaluated;
- STALE: a previously evaluated decision no longer matches the declared revision, environment, scope, or trust state;
- REVOKED: the authorization has been explicitly withdrawn;
- EXPIRED: the validity window has ended;
- UNVERIFIED: a decision, identity, signature, provenance, or binding cannot be independently checked.

Unknown, missing, contradictory, ambiguous, or unverifiable facts never become AUTHORIZED through defaulting, inference, retry, or substitution.

## Authority identity and basis

Every authorization decision must bind:

- a stable authority identifier and authority class;
- the decision-maker identity and authentication method;
- the constitutional, governance, or delegated basis for authority;
- the actor or service that will perform the declared action;
- the subject, tenant, project, world, target, or resource boundary;
- the purpose and reason for the decision;
- the reviewer or approver identity when a second-person review is required;
- the authorization decision identifier and canonical decision version.

Identity is not authority. An external identifier, account possession, RIO message, event, successful login, or repository permission must not be treated as a grant unless the declared authority policy explicitly binds it to this decision.

RIO remains a consumer and communication interface. It cannot create, enlarge, delegate, revive, or bypass authorization. Implementation, federation, automation, or a green CI result cannot create authority.

## Scope and prohibited operations

The authorization must state the smallest permitted scope and the operations that are prohibited. It must bind, at minimum:

- exact run and test-pack identifiers;
- exact repository, implementation head, base, workflow, and configuration revisions;
- exact environment and toolchain references;
- exact fixtures, services, database class, endpoints, and network policy;
- allowed commands, arguments, working directory, resource limits, and exit classifications;
- permitted subject, tenant, project, world, and data boundary;
- evidence destination, retention class, and append-only record boundary;
- named external effects, if any;
- explicit prohibited operations and excluded production resources.

No authority may be inferred for an adjacent branch, newer commit, alternate toolchain, different database, broader tenant, live credential, undeclared endpoint, or changed test pack. A material scope change creates a new decision; it does not amend the old decision silently.

Least privilege is mandatory. Anything not explicitly permitted is denied.

## Validity and temporal trust

The decision must carry a canonical temporal validity window:

- issued_at;
- not_before, when used;
- expires_at;
- trusted sequence and trust_epoch;
- temporal evidence source and observation locator.

UTC is the canonical representation. Wall-clock timestamps do not replace monotonic ordering. The highest accepted trusted time and trust_epoch must not decrease. A rollback, leap ambiguity, source disagreement, or stale temporal proof results in BLOCKED, STALE, or UNVERIFIED.

Expiration and revocation are monotone terminal conditions. An expired or revoked decision cannot be restored by a clock rollback, old snapshot, cache replay, branch reset, or database restore. If current time or revocation state cannot be established, execution is denied.

The timestamp of a decision is evidence metadata. It is not permission by itself.

## Provenance and exact decision binding

The authorization record must be canonical, digestible, and independently locatable. It must bind:

- source policy and policy version;
- authority, actor, target, purpose, and scope;
- environment, implementation, base, workflow, test-pack, and fixture identities;
- validity, revocation, expiration, and trust state;
- isolation, network, service, secret, and evidence boundaries;
- decision reason, reviewer, and approval requirements;
- predecessor or superseded-decision relation, when applicable;
- canonical serialization and authorization digest.

The integrity rule is:

WHAT IS SIGNED SHALL BE EXACTLY WHAT IS VERIFIED.

Changing any signed or digested field changes the authorization identity and requires a new decision. Rendered summaries, mutable labels, branch names without commit identity, or an unbound database row are not sufficient proof of the decision.

## Consent, identity, and delegation

Where a run acts for a subject, tenant, project, world, or data owner, the authorization must bind:

- the canonical subject and ownership relation;
- purpose limitation;
- required consent or delegated mandate;
- consent/mandate version and provenance;
- expiration and withdrawal state;
- the exact data and operation boundary.

Consent is not interchangeable with authority, and authority is not interchangeable with ownership. A missing, withdrawn, conflicting, or stale consent or mandate blocks the decision. Delegation must identify both delegator and delegate, the delegated scope, validity window, and non-delegable operations.

Identity merge, split, substitution, or aliasing cannot silently transfer authority. External IDs and imported records do not grant permission.

## Revocation, expiration, and conflict handling

Before returning AUTHORIZED, the gate must evaluate the current revocation and expiration state for:

- the authority;
- the decision;
- the actor or delegated credential;
- the subject consent or mandate;
- the environment and implementation binding;
- the test pack and evidence destination.

Any explicit revoke, terminal deny, expiration, unresolved conflict, or trust downgrade wins over an earlier allow. A later allow must not erase the history of a revoke or reactivate a terminal state without a new, separately governed decision.

If the revocation source is unavailable or cannot be bound to the current trust sequence, the result is BLOCKED or UNVERIFIED, never AUTHORIZED.

## Isolation and external-effect boundary

Authorization must bind the isolation boundary established by PAD-ENVGATE:

- dedicated working directory and process boundary;
- service and database identity;
- tenant, subject, project, or world scope;
- network allowlist and endpoint class;
- credential and secret policy;
- evidence destination and retention boundary;
- allowed external effects and their limits.

Authorization cannot enlarge an environment that PAD-ENVGATE did not validate. Production-like endpoints, live authority, undeclared credentials, cross-tenant access, and unlisted external effects are denied unless explicitly and separately governed; this contract does not open them.

## Replay, uniqueness, and idempotency

Each authorization must have a unique authorization_id and must bind to one declared run_id or an explicitly declared, bounded reuse policy. It must include:

- a unique decision sequence or nonce;
- the exact environment and revision binding;
- the expected next gate;
- replay detection state;
- an idempotency key for the authorization decision.

Replaying an old decision against a new head, base, workflow, environment, time window, scope, or run is denied. Duplicate delivery may return the same recorded decision, but it must not create a second authorization side effect or permit a broader action.

Replay validation happens before the first execution effect and is repeated at REVALIDATE and COMMIT.

## Decision record and review

A future authorization record must be append-only and contain:

- authorization_id and run_id;
- authority, decision-maker, actor, target, subject, tenant, and purpose;
- scope and prohibited operations;
- repository, head, base, workflow, test pack, fixture, environment, and toolchain references;
- validity, sequence, trust_epoch, revocation, expiration, and consent state;
- isolation, network, service, credential, and evidence boundaries;
- reviewer/approver identity and decision reason;
- canonical decision bytes and authorization digest;
- provenance locators and policy/ruleset version;
- status, failure reason, and supersedes/superseded-by relation;
- observed_at and record sequence.

The record must preserve the distinction between a draft request, a review, an allow, a deny, a hold, a revoke, and an expiration. A human or policy decision must be attributable; an implementation must not self-authorize.

This document defines the review requirements but does not constitute an approval, signature, permit, or authorization record.

## Transition rules

The next gate may open only under all of the following conditions:

1. PAD-ENVGATE has a current READY result bound to the exact declared revisions and environment.
2. Authority identity, authority basis, actor, target, scope, and prohibited operations are explicit.
3. Validity, trusted temporal state, revocation, expiration, consent, and delegation are current.
4. The decision is canonical, provenance-bound, independently verifiable, and attributable.
5. Isolation, service, network, credential, external-effect, and evidence boundaries match the environment.
6. Replay and idempotency checks pass for the exact run and decision.
7. Required review and approval conditions are satisfied.
8. The authorization status is AUTHORIZED and no higher-priority deny, hold, revoke, expiry, or conflict exists.

After AUTHORIZED, the sequence must continue to EXEC-ENVELOPE. It must not jump directly to EXEC. The envelope, revalidation, and commit gates remain mandatory.

## Required negative matrix

The future authorization checker and independent review must cover at least:

| Case | Required result |
| --- | --- |
| Environment is BLOCKED, STALE, or UNVERIFIED | No authorization; PAD-AUTHGATE remains closed |
| Authority identity or authority basis is missing | NOT AUTHORIZED |
| Actor differs from the declared actor | NOT AUTHORIZED or BLOCKED |
| Scope, target, tenant, or purpose is broader than declared | DENY; no substitution |
| Head, base, workflow, test pack, fixture, or environment differs | STALE or BLOCKED |
| Validity window is absent, expired, or not yet active | EXPIRED or NOT AUTHORIZED |
| Trusted time rolls back or trust_epoch differs | BLOCKED or UNVERIFIED |
| Authority, credential, consent, or mandate is revoked | REVOKED; no execution |
| Revocation state cannot be read or bound | BLOCKED or UNVERIFIED |
| Signature/digest does not verify the canonical decision | UNVERIFIED; no execution |
| Reviewer/approval requirement is unmet | NOT AUTHORIZED |
| Authorization is replayed for another run or revision | DENY; create a new decision |
| Duplicate request arrives for the same decision | Idempotent read; no second side effect |
| External effect is not explicitly named | DENY |
| RIO, CI, implementation, or federation attempts to grant authority | DENY; no implicit permission |
| Authorization is valid but EXEC-ENVELOPE is absent | No execution; next gate remains closed |

## Current status and non-claims

PAD-AUTHGATE-001 remains SPECIFICATION COMPLETE — NOT EXECUTED.

The current repository state is:

| Boundary | Status |
| --- | --- |
| PAD-ENVGATE-001 | BLOCKED in the observed local environment under TUR-016 |
| PAD-AUTHGATE-001 | NOT OPENED / NOT AUTHORIZED |
| EXEC-ENVELOPE | NOT OPENED |
| RUN 002 | NOT AUTHORIZED |
| Runtime execution | NOT EXECUTED |
| PostgreSQL/service execution | NOT EXECUTED |
| Observation/evidence generation | NOT CREATED |
| Independent verification | NOT PERFORMED |
| Conformance | NOT CLAIMED |

No authorization, permit, signature, evidence record, runtime result, PostgreSQL result, or conformance result is created by this contract or by repository CI.

PAD-ENVGATE READY, when eventually observed, will remain necessary but insufficient. The next valid transition after this specification is a separately reviewable authorization decision, followed by EXEC-ENVELOPE, REVALIDATE, COMMIT, EXEC, and RECORD.
