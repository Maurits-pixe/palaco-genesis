# PAD-RECORD-001 — Harness test contract

Status: SPECIFICATION COMPLETE — TESTS IMPLEMENTED AS PURE IN-MEMORY CONTRACT TESTS

Implementation under test: `crates/palaco-record`

The harness tests exercise record identity, append-only lineage, lifecycle separation, evidence state, and idempotent replay. They do not launch a process, access PostgreSQL, send a network request, mutate a fixture, create a runtime handoff, or authorize RUN 002.

## Required scenarios

| Scenario | Test | Required assertion |
| --- | --- | --- |
| Crash before first effect | `crash_before_first_effect_preserves_no_effect_boundary` | `CrashAmbiguous` preserves `CrashBeforeFirstEffect`; no first effect is claimed |
| Crash after first effect | `crash_after_first_effect_preserves_uncertain_outcome` | First effect remains observed; completion remains `Unknown` |
| Replay/idempotency | `replay_is_idempotent_and_does_not_append_a_second_record` | Duplicate identity does not append a second record |
| Scope drift | `scope_drift_is_rejected_without_mutating_bound_scope` | Changed scope is rejected and bound scope remains unchanged |
| Record handoff | `record_handoff_preserves_parent_and_previous_lineage_without_authority` | Parent/previous lineage is preserved; record grants no authority |
| Missing evidence | `missing_evidence_cannot_become_verified` | Missing evidence yields `Unverified`, never `Verified` |
| Conflicting evidence | `conflicting_evidence_cannot_become_verified` | Conflicting evidence yields `Conflicted`, never `Verified` |
| Uncertain completion | `uncertain_completion_blocks_verification_even_with_complete_evidence` | Complete evidence cannot verify an unknown completion |

## Separation invariants

The tests preserve these boundaries:

`execution release ≠ first effect ≠ completion ≠ verification`

`record ≠ authorization`

`replay ≠ new execution`

The test crate is a deterministic contract harness. Passing these tests is structural evidence for the tested in-memory model only; it is not runtime evidence, authorization, proof of external truth, or conformance.
