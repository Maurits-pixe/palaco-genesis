# Genesis epistemic draft contracts

**Status:** DRAFT / non-canonical / unverified  
**Date:** 2026-10-07

This is a Rust-contract design note only. It does not add public types, change behavior or claim Core Alpha certification.

## Reuse existing boundaries

The candidate design should build on the existing separation between HistoricalClassification, EvidenceBundle, KnowledgeRecord, provenance, current validity, revalidation and authorization checks. It must not collapse these into one enum or treat a successful check as permission.

## Candidate future records

The following shapes are review sketches, not code:

~~~rust
struct EpistemicTransition {
    transition_id: TransitionId,
    subject: SubjectRef,
    previous_state: EpistemicState,
    new_state: EpistemicState,
    trigger: EpistemicTrigger,
    evidence: Vec<EvidenceRef>,
    rationale: TransitionRationale,
    effective_at: Timestamp,
    provenance: ProvenanceRef,
}

struct SourceLineageRecord {
    source_id: SourceId,
    parent_source_ids: Vec<SourceId>,
    independence: EvidenceIndependence,
    transformations: Vec<TransformationRef>,
}

struct EpistemicConflict {
    conflict_id: ConflictId,
    subject: SubjectRef,
    assertions: Vec<ClaimRef>,
    evidence: Vec<EvidenceRef>,
    conflict_type: ConflictType,
    resolution: Option<ResolutionRef>,
    provenance: ProvenanceRef,
}
~~~

These sketches require stable identifiers, serialization rules, validation, append-only persistence and replay fixtures before implementation.

## Gate separation

- KESG returns evidence sufficiency for a declared claim/context.
- KAG returns purpose/consequence adequacy for a declared use.
- ETCG records whether an epistemic state may transition.
- Governance decides whether any consequential action is allowed.
- Authorization checks whether the action is permitted.
- Runtime executes only a bounded, authorized action.

HRAEG and the seven-ambassador model remain unimplemented because no constitutional authority source was identified. Source-independence assessment is metadata about evidence lineage, not a confidence shortcut.

 The Linnaeus/HORTUS model remains a draft knowledge boundary and this note does not create constitutional authority.

## Candidate negative tests

Future Rust tests should cover missing provenance, partial evidence, stale context, copied-source chains, identity conflicts, preserved conflict history, adequacy without authorization, CI without runtime permission and exact VORM9EVIN9 status labels. These tests are not present or passing as a result of this documentation-only change.

See the PALACO epistemic draft specification at:
https://github.com/Maurits-pixe/PALACO/blob/codex/palaco-epistemic-draft-specs-20261007/docs/governance/PALACO-EPISTEMIC-DRAFT-SPEC-2026-10.md

**No new public API, authority, certification, merge or deployment is claimed.**
