# PALACO release registry — draft 0.1

**Visual freeze. No merge, deployment, activation, key creation or shared login.**

The three existing Sites publications may be described as PUBLISHED. This is a hosting observation, not constitutional authorization. EVA-LA-001 remains DRAFT. This package is a separate draft registry proposal and does not overwrite the A1/A2 contracts in PRs #99/#100.

## Separate dimensions

| Dimension | Values | Meaning |
|---|---|---|
| Presentation | foundation / black | Visual preference; cannot grant authority |
| Publication | PUBLISHED / unpublished / unknown | Hosting observation for an exact deployment |
| Release | DRAFT → REVIEWABLE → AUTHORIZED → ENABLED | Authenticated, audited release lifecycle |
| Revocation | REVOKED | Terminal for this release ID; replacement requires a new release |
| Freshness | CURRENT / STALE / UNKNOWN / REVOKED | Scoped observation, never a substitute for release authorization |

The working Foundation/Black Edition controls are not release switches. Mapping either visual choice to AUTHORIZED or ENABLED is invalid.

## Evidence vocabulary

- **REPORTED / gerapporteerd**: prior narrative or an unretained check. No retrospective upgrade.
- **CHECKED / gecontroleerd**: an observed operation with retained output, scope, source revision and timestamp. Screenshots prove only what was rendered in the captured viewport.
- **PROVEN / bewezen**: a narrowly stated claim supported by reproducible artifacts and an independently trusted verification anchor. A checksum alone is not identity, source truth, authorization, or a signed release. No production claim in this package is PROVEN.

The original QA report remains as a historical report. Its statements do not establish complete device/browser coverage. New screenshots are local reproductions of the frozen source, not retroactive screenshots of the earlier hosted visit.

## Contracts and reference implementation

`contract.json` is copied byte-for-byte across the five participating repositories. `contract.sha256` pins this proposal. No old A1 vectors are rewritten. `registry.py` is a dependency-free offline reference model, not a network service or authority verifier. Run:

```sh
python -m unittest discover -s release-registry -p 'test_*.py' -v
```

All requests bind schema, release ID, combined source-version digest, policy digest, Citadel ID, world ID, expected sequence, previous digest, request ID, issue time and expiry. Unknown fields/versions fail closed. Signed request bytes use a separate `PALACO-RELEASE-REQUEST` prefix. Hashes use profile and event-kind domain separation. This narrow canonical profile rejects floating-point numbers and does not claim cross-language equivalence with A1.

An injected `verify(bytes)` callback must come from a trusted server integration and verify reviewer identity, signature, policy, gates and current revocation state. Missing, false, exceptional, non-boolean or offline results deny the transition. The tests' always-true callbacks are synthetic fixtures only. No such callback is connected to a website. Every returned event has `production_release_enabled=false`, including simulated ENABLED events.

## State and failure behavior

- Only adjacent forward transitions are accepted. Authenticated revocation is terminal.
- Schema, context, expected sequence and previous digest must match exactly. Expired, future or overlong (five-minute) requests fail. A late response cannot replace a later state.
- A second tab must reload after an expected-head conflict. There is no last-write-wins fallback.
- Refresh must replay retained events with signature verification and an independently pinned head. A browser-supplied checkpoint is insufficient.
- Offline/timeout/unknown authority means UNKNOWN and disables actions; it does not invent a new authorized state. Failed requests do not alter the authoritative state.
- The pure reducer is supplemented by `sqlite_journal.py`, a local candidate transaction harness. Independent connections serialize writes; expected checkpoints and unique per-release request IDs prevent lost updates. Exact retries return a historical receipt alongside the current state. Reopening replays history against caller-supplied trusted genesis and head. SQL triggers reject updates/deletes. This is not distributed locking, production authorization or a revocation service. There are no active release controls.

## RIO freshness

RIO source versions identify a canonical manifest of all source references, not just a single repository SHA. Current RIO has multiple sources, including a mutable preview URL: that part cannot be treated as an immutable proof.

Required fields: `source_version`, `generated_at`, `verified_at`, `valid_for_seconds`, `revoked_at`; each observation adds sequence, previous digest, observation time and `CURRENT | STALE | UNKNOWN | REVOKED`.

`CURRENT` needs exact source identity, trustworthy time, a verified receipt, current revocation knowledge, network availability and an unexpired verification. TTL is bounded to 24 hours in this **proposed** profile; the owner has not approved a production TTL. Null or invalid dates, mismatched sources and missing trust return UNKNOWN. Authenticated revocation remains REVOKED offline. An already verified but expired observation is STALE even offline. Historical observations are appended, never replaced. A refresh without a trusted checkpoint returns UNKNOWN.

`freshness-panel.mjs` is a proposed, unstyled metadata component. It uses text nodes, exposes all fields and retains a history view. It does not validate signatures or pretend a browser timestamp is a verification. It is not imported into any live application in this draft.

## Merge / activation gates

All stay closed until independently satisfied: repository contract agreement, negative tests, reviewer-key binding, explicit release authority, closed threat model. Passing candidate tests is necessary but insufficient.

Interim reviewer: Maurits (`github:Maurits-pixe`), one identity. No verified public key is installed. Ambassadors require a new explicit policy with keys, effective boundary and preservation of prior history. Do not infer trust from an email, GitHub username, green CI or the appearance of a seal.

See `THREAT-MODEL.md` for unresolved integration risks and acceptance criteria. See the private central evidence package in the palaco-genesis draft for publication records and screenshots. This documentation does not make private source or Sites resources publicly accessible.

## ERA and storage acceptance scope

`era_boundary.py` implements a separate draft temporal interval check: uncertainty must fit wholly inside a validity window. Missing verification, unknown/conflicting/degraded time and unsupported representations yield UNKNOWN. SATISFIED is a time condition only. No signing or execution permission follows from it. The private central `ERA-INTEGRATION.md` maps the source requirements and open work; private source text is not copied into public repositories.

Tests use temporary SQLite files and independent writer connections: restart, competing writes, exact/changed retries, injected transaction failure, lock timeout and terminal revocation. They do not test power loss, distributed finality or a live browser/service flow. Database administrators can bypass triggers; separately trusted checkpoints remain required. Request time is caller-supplied in this harness; a production adapter must sample verified time after waits and recheck it at the actual commit boundary. Freshness history persistence remains open. No SQLite file is shipped or connected to the sites.
