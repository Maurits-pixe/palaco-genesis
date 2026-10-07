# Genesis filtered governance contract

**Status:** implementation-facing review note; not a new authority contract  
**Date:** 2026-10-07

This document records how the existing Rust contracts should be read during PALACO integration. It does not change the public API and does not claim Core Alpha certification.

## Existing contract evidence

The inspected `main` code already separates several important dimensions:

- `HistoricalClassification` distinguishes Canon, Specification, Decision, Design, Experiment, Draft, Rejected and Superseded.
- Constitutional helpers reject missing context, provenance, evidence and authorization, and reject revoked grants.
- `EvidenceBundle` delegates current validity only when evidence is complete; partial evidence becomes insufficient and requires escalation during revalidation.
- `KnowledgeRecord` carries evidence and provenance and starts as `Draft`.
- The Quay/runtime layers provide implementation points for durable history and bounded execution.

These are implementation baselines. They are not proof that every proposed PALACO governance concept has been ratified.

## Required interpretation

```text
evidence -> determination -> historical classification
         -> current validity for a declared context
         -> provenance and adequacy review
         -> append-only transition record
         -> explicit governance authorization
         -> bounded runtime execution
```

A Rust enum variant, passing test, CI check or evidence object cannot silently become runtime authority. A transition must preserve the previous record and include its trigger, evidence, rationale, effective time and provenance. Revalidation can change the current assessment without deleting the historical assessment.

The review filter also preserves: no derived authority; no silent state/time/history rewrite; exact `VORM9EVING`; RIO as the river and distinct from ELIXER; uncertainty and provenance in the knowledge layer; and QUAY as history/provenance storage. These constraints are applied because the user explicitly required them; they are not represented here as a new ratified constitutional type.

## Draft boundary

Genesis PR #127 (`PVC-001`) is explicitly a draft candidate. Its own description separates system-graph validity, execution plans, CI, G8/G9 and automatic merge/deployment. That separation is consistent with this note but remains PR-scoped until merged.

Conversation proposals named ETCG, KAG, KESG, HRAEG and Linnaeus/HORTUS are not treated as implemented Genesis contracts without a mainline source and executable evidence.

## Cross-reference

See the [PALACO filtered governance synthesis](https://github.com/Maurits-pixe/PALACO/blob/codex/palaco-filtered-governance-20261007/docs/governance/PALACO-FILTERED-GOVERNANCE-2026-10.md) for the evidence matrix, open-PR status and conflicts.

**Not merged, published or deployed:** this note is on the review branch only.
