# WNRA-04Y — Independent Pin Anchor Interface (proposal v0.1)

**Classification:** DERIVED PROPOSAL / SPECIFICATION ONLY.  
**Repository scope:** ORCHEASTRA Windows provenance test lineage after WNRA-04X.  
**Gate:** GO-13 HOLD; production authorization DENY.  
**Status:** No independent custodian is enrolled, implemented, operated, or verified by this document.

## Purpose and hard boundary

WNRA-04N through WNRA-04X exercise disposable in-memory and SQLite pin custody, process crashes, corruption, replacements, and local file identity. Those fixtures are controlled by the test actor. They do not establish independence or authenticate a substituted, structurally valid database.

An eventual independent anchor MUST be owned and administered separately from the actor that writes the SQLite ledger and its test pin history. Its trust root, endpoint, security policy, and actual operator require an explicit governance decision. Local filesystem metadata, a self-issued signature, a CI artifact, or a simulated reviewer are NOT qualifying anchors.

## Proposed interface

This is an abstract protocol boundary, not a deployed endpoint or a wire standard. All fields are required unless explicitly noted.

### Anchor request

| Field | Meaning |
| --- | --- |
| protocol | Exact identifier `WNRA-04Y-ANCHOR-PROPOSAL-v0.1` |
| request_id | Unique replay-protection identifier |
| fixture_domain | Explicit non-production or approved domain identifier |
| source_commit | Full source commit identifier |
| record_digest | Canonically computed SHA-256 of the governed record |
| predecessor_anchor_id | Anchor reference or explicit genesis marker |
| sequence | Strictly increasing per domain |
| evidence_ref | Reference to evidence material, never an authorization claim |
| actor_id | Authenticated requesting actor, subject to independent custody policy |

### Anchor response

| Field | Meaning |
| --- | --- |
| request_id | Exact echo of the request |
| decision | `ACCEPTED`, `DENIED` or `UNAVAILABLE` |
| anchor_id | Stable unique ID, only for `ACCEPTED` |
| anchor_digest | Digest bound to the exact request fields, only for `ACCEPTED` |
| predecessor_anchor_id | Independently recorded predecessor reference |
| custodian_id | Separately verified custodian identity |
| key_id | Independently trusted verification-key reference |
| signature | Verifiable authenticator over canonical response plus bound request |
| policy_version | Applied independent policy identifier |
| evidence_ref | Custodian-side immutable audit reference |

Any omitted, conflicting, malformed or unverifiable response MUST yield **DENY**. A response from the same local actor must not count as independent attestation.

## Proposed operations

1. `anchor(record, prior_reference)`: request acceptance; never overwrite an existing anchor.
2. `verify(record, anchor_reference)`: independently retrieve and authenticate the anchored record, its domain, predecessor, sequence and current policy.
3. `health()`: read-only availability observation. Healthy is not authorization.
4. `revoke(anchor_reference, reason)`: only through separately authorized policy; preserve prior evidence and revocation lineage.

No operation silently alters WORLD state, grants an identity, issues an ELIXER, or elevates an authorization gate.

## Mandatory denial matrix

| Condition | Result |
| --- | --- |
| Custodian absent, unreachable, unprovisioned, or timed out | DENY |
| Unknown, rotated-without-proof, or locally self-issued key | DENY |
| Different domain, source commit, sequence, digest or predecessor | DENY |
| Missing trusted timestamp or conflicting freshness policy | DENY |
| Duplicate request with conflicting payload | DENY and auditable conflict |
| Replay, rollback, fork or attempted history rewrite | DENY |
| No independent review/ownership evidence | DENY |
| Valid CI or local SQLite structural check but no independent anchor | DENY |
| Revoked, expired, or unreviewed anchor | DENY |

The requesting system must treat DENY, UNAVAILABLE, malformed data and an exception as non-authorizing. No cached ACCEPTED value may bypass freshness or revocation rules.

## Required evidence before implementation or authority review

- Named, approved external custody operator and proof of separation of duties.
- Threat model for key custody, compromise, recovery, revocation, replay, substitution and availability.
- Versioned canonical serialization and digest test vectors, independently reproduced.
- Signed response verification with a governed trust root; audited key rotation and revocation.
- Negative fixture suite across process, machine and privilege boundaries, including disconnected/offline states.
- Evidence that every request is bound to the exact reviewed source head, policy, environment and domain.
- Independent human governance review, operational controls, and explicitly authorized enrollment.
- Separate runtime authorization gate evidence. Passing the above tests does not by itself authorize production.

## Acceptance stages

1. **SPECIFICATION:** this reviewable proposal exists; no runtime claims.
2. **TEST ADAPTER:** an isolated fake response provider may exercise DENY semantics; MUST be labeled simulated.
3. **INDEPENDENT VERIFICATION:** an approved independently operated provider is integrated and external checks are witnessed and recorded.
4. **AUTHORIZATION REVIEW:** separately authorized governance evaluates the complete evidence, revocations and risks.
5. **PRODUCTION:** only after explicit applicable authority and release gates; not implied by any earlier stage.

## TRIAS / ORACLE / MENTOR AI-review notes

- **TRIAS:** trust-root control and authority must remain outside the test writer. GO-13 HOLD.
- **ORACLE:** current WNRA-04X local inode/ctime observations provide no cryptographic proof of provenance; operator, key and external evidence are UNKNOWN.
- **MENTOR:** next permissible slice is a fail-closed test adapter with negative fixtures, without claiming that a real custodian exists.

**Non-decision:** This proposal is not a canon amendment, a security certification, a merge approval or an authorization permit.
