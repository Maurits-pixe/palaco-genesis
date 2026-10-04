# ERA / registry — reproducible evidence, 2026-09-26

## Exact scope and status

IMPLEMENTED (draft reference code) ≠ VERIFIED (scoped checks) ≠ MERGED ≠ ACTIVATED.

- IMPLEMENTED: narrow ERA temporal interval adapter and local SQLite release journal.
- VERIFIED: 39 methods pass on files fetched from Genesis commit `cfd53ce523d74a629966f6816ea6062e81d29841`; each file's Git blob was checked before execution. This is reproducible testing, not independent security review or production proof.
- MERGED: false for all five PRs at inspection.
- ACTIVATED: no production adapter, signer or execution gate connected by this work; no deployment performed. Visual freeze and EVA-LA-001 DRAFT remain.

This report refers to the exact tested SOURCE commits below. The later commit containing this report is an EVIDENCE commit and must be checked separately before any merge. Green CI for an ancestor is not green CI for a later head.

## Implemented constraints and test mapping

| Constraint | Concrete implementation / tests | Limit |
|---|---|---|
| NO SILENT TIME, fail-closed temporal evidence (ERA-008) | `era_boundary.time_condition`; `test_missing_conflicting_and_synthetic_time`, `test_verified_interval_only_satisfies_time`, `test_unknown_schema_fields_and_reversed_interval` | Returns UNKNOWN, EXPIRED, NOT_YET_VALID or SATISFIED; does **not** implement DENY/HOLD execution decisions or full EDTR verification. |
| Uncertainty cannot silently cross validity boundaries | `test_uncertainty_overlaps_start`, `test_uncertainty_overlaps_expiry` | Whole-second interval profile only; no physical clock accuracy claim. |
| Expiry remains distinct from revocation | `test_expiration_is_not_revocation`, `test_revocation_terminal` | No production authorization service. |
| Concurrent updates cannot overwrite history | `test_two_connections_one_winner`, `test_replay_and_concurrent_tabs` | Two threads with independent SQLite connections; serialized write transaction plus expected-head check, not distributed optimistic concurrency. The reducer's tab case is simulated. |
| Replay/idempotency | `test_restart_and_exact_retry`, `test_id_reuse_changed_payload_rejected`, `test_retry_requires_current_verification_and_window` | Historical retry receipt is returned alongside current state; it is not renewed authorization. |
| No resurrection after reopening (partial ERA-009) | `test_revocation_survives_restart_and_retry`, `test_untrusted_checkpoint_and_genesis` | Reopens the store in one process. Does **not** test abrupt process crash, power loss, stale snapshot recovery or full ERA-009 execution ordering. |
| Failed transactions preserve state | `test_failed_write_rolls_back`, `test_locked_database_and_retry` | SQL-trigger fault injection and lock timeout; no network or hardware fault tests. |
| Append-only candidate storage | `test_sql_updates_and_deletes_denied` | SQL triggers do not constrain a database administrator or file replacement. |

No new A1/ERA canonical signing contract is claimed. Trusted verifier callbacks are synthetic fixtures. The adapter is not wired to live sites or release authority.

## Test environment and count

Fresh reproduction: CPython 3.12.14, Windows 11 build 26200, AMD64, SQLite 3.53.1. Dependencies: Python standard library only; no pip packages. Exact compiler/runtime string, per-method names, raw output, UTC times and all source SHA-256/Git blob hashes are retained in [reproduction.json](reproduction.json).

39 means **39 unittest methods**, not 39 independent attack classes. Subtests are not added to this count.

| Class | Methods |
|---|---:|
| ContractTests | 1 |
| RegistryTests | 14 |
| FreshnessTests | 9 |
| DurableJournalTests | 9 |
| EraBoundaryTests | 6 |

Classification by method purpose: **4 positive, 28 negative, 7 mixed**. Positive tests exercise a valid path/invariant; negative tests exercise rejection/error/stale boundaries; mixed methods include both success and refusal/recovery. The JSON lists every classification for review.

CI workflow requests Ubuntu latest and Python 3.12. Exact hosted Python/SQLite patch versions are not asserted here; they were not retained in the previous workflow. Local reproduction records its actual toolchain.

## Source commits and observed CI

| Repository | Tested candidate SHA | Observed PR runs |
|---|---|---|
| PALACO | `183ddd9e69e9adbfda17ea1d853f37a4e82a5f91` | [Draft registry contract checks: success](https://github.com/Maurits-pixe/PALACO/actions/runs/36248444528) |
| palaco-genesis | `cfd53ce523d74a629966f6816ea6062e81d29841` | [Draft registry contract checks: success](https://github.com/Maurits-pixe/palaco-genesis/actions/runs/36248537459); [PALACO CI/CD: success](https://github.com/Maurits-pixe/palaco-genesis/actions/runs/36248537483); [PALACO CI: success](https://github.com/Maurits-pixe/palaco-genesis/actions/runs/36248537496) |
| PALACO-BOOK-1 | `90d54191a0139b713b7d432a4727d851f2345759` | [CI: success](https://github.com/Maurits-pixe/PALACO-BOOK-1/actions/runs/36248455437); [Draft registry contract checks: success](https://github.com/Maurits-pixe/PALACO-BOOK-1/actions/runs/36248455430) |
| PALACO-INDUSTRIE | `a3495652f466380a021d3d222a48ad2a4099959a` | [Authentication regression checks: success](https://github.com/Maurits-pixe/PALACO-INDUSTRIE/actions/runs/36248461153); [Draft registry contract checks: success](https://github.com/Maurits-pixe/PALACO-INDUSTRIE/actions/runs/36248461129) |
| PALACO-Citadel | `5b5f8a78afc9fdc1883ce6dd9cdf32756e5025d4` | [Draft registry contract checks: success](https://github.com/Maurits-pixe/PALACO-Citadel/actions/runs/36248466091) |

All listed runs were completed/success at this inspection. This is a snapshot of returned PR-triggered runs, not proof that branch protection, external checks or independent review requirements are satisfied.

## External reproduction without private Genesis access

The nine Python/contract input files in the following public PALACO commit have Git blob SHAs identical to the tested Genesis files. A reviewer can therefore reproduce the same 39 methods without access to the private Genesis repository:

```sh
git clone https://github.com/Maurits-pixe/PALACO.git
cd PALACO
git checkout --detach 183ddd9e69e9adbfda17ea1d853f37a4e82a5f91
python --version
python -m unittest discover -s release-registry -p 'test_*.py' -v
```

Use Python 3.12 (local reproduction used 3.12.14). From a checkout, compare file SHA-256 values with reproduction.json; configure Git not to convert line endings when comparing raw-file hashes. Git blob SHAs identify committed bytes independently of checkout line-ending settings.

The private source can instead be checked out at `cfd53ce523d74a629966f6816ea6062e81d29841` with the same test command. No user token is required for the public route. A 404 for private Genesis does not demonstrate absent code; access must be established separately. Repository visibility and permissions have not been changed.

## Objective next merge gate — NOT SATISFIED

Every item below is required; no test count or timestamp grants authority:

1. Exact proposed head SHA pinned for each PR, all required CI successful on that SHA, clean reproduction of the 39 named methods and file hashes; any code change invalidates earlier acceptance.
2. Negative evidence for concurrency, restart, replay/idempotency, revocation and conflicting time retained. Distinguish existing local evidence from missing real crash/network/distributed execution tests.
3. Reviewer independently reproduces the result and records identity, scope, reviewed commit, findings and disposition. This work is not that independent review.
4. Threat model closed through explicit acceptance of every OPEN item, including actual time at commit, signed EDTR linkage, durable freshness history, trusted checkpoints and atomic revocation/execution integration.
5. Real reviewer public-key binding and release authority explicitly recorded and independently verifiable; interim single-reviewer governance and eventual Ambassador handover remain explicit policies.
6. Cross-repository contracts and integration acceptance agree. A separate explicit activation decision follows any eventual merge.

Until then: CONCEPT IMPLEMENTED / SCOPED TESTS PASS / LISTED SOURCE-COMMIT CI PASS / NOT MERGED / NOT ACTIVATED.

## Source specifications

[ERA source dossier](https://app.notion.com/p/3e029e9a126a809c978adc20f2d486ff) and [ERA-002](https://app.notion.com/p/04ab83fe094446679864e8bbe63c61aa) informed the mapping. Their document status does not establish implemented conformance. The separate ERA-INTEGRATION.md retains open integration boundaries. No private source text is reproduced here.
