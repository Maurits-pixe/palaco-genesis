# PALACO Integration Registry v0.1 — design-time HOLD

This registry describes intended PALACO module boundaries and their *logical*
dependencies. It does **not** assert that a module, integration, site, account,
database table, synchronization path, or security control is live or verified.

## Artifacts

- `ecosystem/integration-registry.v0.1.json`: declarative module graph.
- `tools/validate_integration_registry.py`: Python standard-library validator.

Run from the repository root:

```sh
python3 tools/validate_integration_registry.py
```

The validator rejects duplicate/invalid identifiers, missing or cyclic dependencies,
invalid stage, runtime enablement and any change of the v0.1 release gate from
`HOLD`. It requires no network access, secrets or third-party packages.

## Boundaries and rollout

1. PALACO ONE owns identity/session decisions; no dependent surface may
   mint its own owner authority.
2. ERA records evidence and causal lineage; a proposed graph relationship is
   never evidence of a completed integration.
3. Citadel enforces authorization separately from the frontend. UI role labels
   are not an authorization decision.
4. RIO, MUNDO, PRECISIO, HARA and LEVENSADER remain consumers of explicit
   identity/authorization contracts; their presence in this registry creates
   neither trusted connectivity nor permissions.
5. Offline packaging must preserve provenance and fail closed on unverifiable
   authorization; no automatic issuance or merge follows from this document.
6. All entries intentionally remain `stage: proposed`,
   `runtime_enabled: false` and `release_gate: HOLD`.

## Release prerequisites (not satisfied by registry validation)

- Documented contracts and ownership for each concrete integration edge.
- Authenticated integration tests with negative authorization cases.
- Durable append-only evidence and replay protection tests.
- Offline conflict/reconciliation and corruption-recovery tests.
- Independent human review, passing CI, and explicit release decision.

Do not treat a successful registry validation as production approval. Do not
automatically change protected branches, merge, deploy, issue identities, or
expose private sites based on this registry.
