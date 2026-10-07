# Register metadata schema contract boundary

Status: `DRAFT_PROPOSAL`  
Classification: `NON-CANONICAL CONTRACT NOTE`  
Date: 2026-10-07  
Branch: `codex/palaco-register-schema-audit-20261007`

The pasted PCR/PMS material proposes mandatory metadata and a combined JSON Schema. Genesis records it as a candidate contract only. The draft schema is repository documentation and is not wired into Rust code, authorization, merge policy or deployment.

Compatibility requirements:

- Historical classification remains separate from validation output. A missing field produces a diagnostic; it does not perform a state transition.
- Provenance, evidence and purpose scope are required for epistemic records.
- Approval references identify a decision and evidence bundle; they do not derive authority.
- Verification is scoped, time-bound and replayable. A CI pass is not runtime authorization.
- Lifecycle and change records are append-only and preserve earlier observations.
- Repository references pin the source location and commit when available.
- RIO and ELIXER remain distinct, and Linnaeus/HORTUS extensions retain uncertainty and provenance.
- The exact spelling `VORM9EVIN9` is required in future additions.

No new Rust types, public APIs or runtime behavior are introduced.
