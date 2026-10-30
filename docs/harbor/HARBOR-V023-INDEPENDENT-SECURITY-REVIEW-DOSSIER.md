# Harbor v0.23 — independent security review dossier

## Purpose

This dossier prepares the human security review for PR #160. It is a review
instrument, not a review result, approval, authorization, release record or
activation record.

The review must assess the exact code and exact CI evidence below. A green
workflow is evidence that the configured checks ran; it is not evidence that a
key registry, clock, source mapping or runtime authority is trusted.

## Frozen predecessor baseline

| Field | Value |
|---|---|
| Repository | Maurits-pixe/palaco-genesis |
| Change under review | PR #160 — Harbor v0.23 governed signed-floor bridge |
| PR state | Open / Draft / Not merged |
| Base branch | codex/harbor-signed-floor-verifier-v0-22 |
| Base SHA | 0e4224dd3f243034f9ed178f9668a098df9c0302 |
| Review head at dossier creation | a277a2111a546e49d5fd138d0ed3efff0c8f4c68 |
| Changed implementation | crates/palaco-harbor/src/governed_floor.rs |
| Exposed module | crates/palaco-harbor/src/lib.rs |
| Contract document | docs/harbor/HARBOR-V023-GOVERNED-FLOOR-BRIDGE.md |

The dossier branch itself requires a new exact-head CI run before review. The
reviewer must record the new run IDs rather than reusing an earlier run from a
different head.

## Scope claims to review

The implementation claims only to verify evidence supplied by an external
registry/time boundary. The reviewer must confirm that:

1. The policy binds the expected source identifier and expected registry key.
2. The candidate key identifier is checked against policy before registry lookup. The v0.22 signature bytes do not themselves include that external key-ID label, so the reviewer must assess the source-to-key mapping or require a key-bound signature variant.
3. The registry response is exact, non-missing, non-revoked and structurally
   valid.
4. The trusted-time snapshot rejects clock rollback and does not silently fall
   back to local time.
5. Key validity is checked for both current time and observation time.
6. Candidate trust epoch is above policy, time and registry floors.
7. The complete signed floor payload is domain-separated and verified.
8. A predecessor cannot be replaced by a lower epoch, lower floor, fork,
   freshness regression or registry epoch rollback.
9. Registry unavailability and uncertainty fail closed.
10. The returned value is typed and documented as evidence, not authority.

## Required reviewer exercises

The reviewer should inspect the implementation and execute or reproduce at
least these cases:

| Case | Expected result |
|---|---|
| Unknown key | Hold closed; no local fallback |
| Registry unavailable | Hold closed |
| Registry uncertain | Hold closed |
| Revoked key with rolled-back time | Revoked / closed |
| Current time below accepted high-water mark | Temporal uncertainty |
| Observation before key validity | Closed |
| Observation after key validity | Closed |
| Wrong key identifier | Key mismatch |
| Wrong source identifier | Floor verification failure |
| Altered signed payload | Invalid signature |
| Wrong public key | Invalid signature |
| Candidate below minimum trust epoch | Closed |
| Registry epoch below predecessor | Registry epoch regression |
| Lower floor or same-revision fork | Floor regression/conflict |
| Older observation after newer evidence | Freshness regression |
| Valid candidate | Evidence object only |

The reviewer must also check the negative space: no function in this slice
creates an admission decision, authorization grant, execution permission,
publication result, release, merge, or activation.

## Evidence package required from the review run

Record these values append-only:

- repository and PR number;
- exact base branch and base SHA;
- exact review head SHA;
- workflow run IDs and job names;
- workflow configuration commit or SHA;
- test result and architecture-validation result;
- changed-file list;
- reviewer identity and role;
- review timestamp in UTC;
- findings with file/path and severity;
- decision: comment, request-changes, or approve;
- unresolved assumptions and next gate.

Do not report a review as complete when any exact-head value is missing.

## Open authority gates

PR #160 does not close these gates:

- key enrollment and identity-to-key binding;
- cryptographic binding of key-ID labels to signed floor bytes;
- source-to-key governance mapping;
- independently authenticated trusted time;
- durable monotone trust epoch and anti-rollback floor;
- revocation propagation and recovery;
- quorum or independent checkpoint service;
- crash-safe external reconciliation;
- Windows storage and filesystem semantics;
- tenant or project isolation;
- human security review;
- feature-flag enablement and runtime activation.

A valid signature remains technical evidence of key possession. It is not proof
of authority.

## Review record template

Complete this section only by a human reviewer:

- Reviewer:
- Role:
- Date/time UTC:
- Exact head:
- Base SHA:
- CI run IDs:
- Findings:
- Decision:
- Follow-up gate:
- Signature or review-system reference:

Until this section is completed by an authorized human, the status remains:

REVIEW PREPARED / NO HUMAN DECISION / DRAFT / EVIDENCE-ONLY / NOT ACTIVATED
