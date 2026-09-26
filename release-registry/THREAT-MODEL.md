# Threat model — OPEN / production blocked

Assets: release authority, source/deployment identity, historical evidence, revocation state, user-entered RIO content. Trust boundaries: browser vs service; Sites source repository vs GitHub; unsigned report vs signed receipt; GitHub account vs designated key; presentation preference vs authority.

| Threat | Candidate control / negative test | Remaining release gate |
|---|---|---|
| Theme button interpreted as authorization | Separate enum; invalid transition tests | Real controls must consume only server receipts |
| Replay, concurrent tabs, delayed response | Context + expected sequence/head + expiry | Durable atomic compare-and-swap and unique request IDs; real concurrent integration tests |
| Tampered/truncated history after refresh | Replay and independently pinned head | Trusted checkpoint distribution and append-only storage |
| Forged browser trust flags | No connected production adapter; missing verifier denies | Bind A2 verifier and approved key policy on server, not browser |
| Stale or rolled-back RIO data | Source digest, bounded TTL, monotonic trusted time, retained observations | Trusted clock, signed source receipts, revocation service and storage retention |
| Offline or failed requests grant authority | Default UNKNOWN/deny, verifier exception test | Real transport failure tests and UI/server consistency |
| Revoked key/release returns through old cached data | Terminal REVOKED; no offline promotion | Authenticated revocation feed, bounded cache age, operational disable action |
| Public report exposes private repositories/content | Central evidence only in private genesis; public adapters contain generic contracts | Confirm audience before wider publication |
| Digest proves more than bytes | Explicit evidence level and scope | Independent signed attestation of source-to-build-to-deployment provenance |
| GitHub identity mistaken for signing identity | Reviewer key remains null; no enabling integration | Verify identity-to-key binding and authorized policy |
| Cross-repo contract drift | Byte-identical contract + checksum, same reference tests | CI verifying pinned counterpart commits and reviewer acceptance |

No production threat is marked closed solely by a mock test. This draft introduces a local SQLite test harness but no production database, API endpoint, login federation, active signer or deployment action. Server-side integration must reject a fabricated/replayed receipt even if a browser displays AUTHORIZED.

Storage follow-up: local transactional serialization, unique request IDs, trigger-enforced append-only records and restart replay are now tested. This partially addresses the storage row above; production database roles, authenticated checkpoint distribution, power-loss recovery, multi-process/network integration and atomic external effects remain OPEN. Trigger enforcement does not defend against a database administrator or file replacement.

ERA follow-up: conservative interval tests reject missing/conflicting time and uncertainty spanning a validity boundary. The exact EDTR signature linkage, source uncertainty measurement, post-wait clock freshness and revocation/commit serialization are not implemented. The time-condition result cannot create authority. These are additional OPEN gates, not temporal certification.

Independent review is required before promoting the reference model. No independent security review of this new package has been performed in this work session.
