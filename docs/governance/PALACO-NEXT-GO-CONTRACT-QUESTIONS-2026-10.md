# Genesis next GO contract questions

**Status:** DRAFT / non-canonical / unverified  
**Date:** 2026-10-07

This document is a contract-question list for future Genesis work. It intentionally does not add ETCG, KAG, KESG, HRAEG, Linnaeus/HORTUS or ambassador types to the Rust API.

## Existing implementation anchors

Genesis already has useful boundaries:

- `HistoricalClassification` separates Canon, Specification, Decision, Design, Experiment, Draft, Rejected and Superseded.
- `EvidenceBundle` makes current validity context-dependent and escalates partial evidence.
- `KnowledgeRecord` carries evidence and provenance and defaults to `Draft`.
- Constitutional helpers reject missing context, evidence, provenance and authorization and detect revocation.

The next GO must extend these only after contract questions are answered.

## Contract questions

1. **ETCG:** Is a transition a new event/envelope, and how are allowed edges, prior state, effective time and provenance replayed without overwriting history?
2. **KESG:** What makes an evidence bundle sufficient for a claim, and how are source lineage, copied sources, revoked evidence and contradictions represented?
3. **KAG:** Which purpose, scope, consequence and temporal dimensions are critical, and how does a critical failure veto adequacy without becoming authorization?
4. **Linnaeus/HORTUS:** How are identity, determination, classification, relation, snapshot, drift and `InDoubt` represented while keeping capability and authority separate?
5. **Conflict/revalidation:** Which conflict types are first-class, how does identity conflict block unsafe classification, and how is a new assessment linked to the prior record?
6. **HRAEG:** What existing constitutional source grants recognition or authorization, and what evidence proves identity, consent, time, veto and scope? Without that source, no grant type is justified.
7. **Seven ambassadors:** Where is the constitutional role, appointment, quorum, veto, revocation and audit model defined? A seven-member count cannot create authority.
8. **Surface semantics:** How does `VORM9EVIN9` preserve status fidelity, and how do RIO and ELIXER remain distinct?

## Evidence required before code

Future code work needs schema fixtures, negative tests, append-only replay, Quay reconstruction and explicit separation between CI/evidence outcomes and runtime authorization. The current conversation proposals remain design inputs only.

See the [PALACO next GO proposal register](https://github.com/Maurits-pixe/PALACO/blob/codex/palaco-next-go-epistemic-20261007/docs/governance/PALACO-NEXT-GO-PROPOSAL-REGISTER-2026-10.md).

**No new public API, authority, certification or deployment is claimed.**
