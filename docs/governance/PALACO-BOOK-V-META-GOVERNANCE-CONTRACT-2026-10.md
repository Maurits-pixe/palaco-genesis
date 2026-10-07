# Book V meta-governance contract boundary

Status: `DRAFT_PROPOSAL`  
Classification: `NON-CANONICAL CONTRACT INTAKE`  
Date: 2026-10-07  
Branch: `codex/palaco-book-v-meta-governance-intake-20261007`

The Book V proposal introduces a large polymorphic registry and relationship graph. Genesis records the candidate object families and relation vocabulary as documentation only.

Before implementation, Genesis requires:

- a stable identifier and namespace policy;
- explicit provenance and evidence for every record and edge;
- a lifecycle state machine with append-only transition records;
- separation of historical classification, epistemic state, verification result and runtime authorization;
- registry-aware referential-integrity and graph validation outside JSON Schema;
- authority references that resolve to explicit decisions rather than free-text roles;
- replay and conflict behavior for stale, disputed or superseded records.

No Rust type, public API, runtime behavior or automatic authorization is introduced. RIO and ELIXER remain distinct, and the exact spelling `VORM9EVIN9` is required.
