# RIO native transaction verification

This isolated verification slice checks the existing RIO revocation writer, transaction-outcome coordinator, receipt guard and HTTP inspection route. It uses synthetic identities, disposable PostgreSQL databases and ephemeral fixture credentials. It does not connect to PALACO services or implement a PALACO One login.

The native parallel suite checks two physical writer backends contending on the same idempotency key, exact payload conflicts, atomic rollback, unknown COMMIT outcomes, read-only reconciliation, least-privilege SCRAM logins, receipt/key revocation, stale snapshots and clean restart persistence. The lost-application-reply scenario injects an exception after an actual COMMIT; it does not simulate a real network acknowledgement loss. The private Unix socket does not verify remote TLS. Clean restart does not prove power-loss durability.

## Run

Use Linux x64 as a non-root user with Node.js 24 and permission to create a private Unix socket. The standalone PostgreSQL check needs no socket. Dependencies are locked; installation scripts are disabled. The inspected binary helper restores only package-contained symlinks before native execution.

```sh
npm ci --prefix staging --ignore-scripts --no-audit --no-fund
npm ci --prefix native-staging --ignore-scripts --no-audit --no-fund
npm run test:ci
```

`test:ci` executes regression/PGlite tests, native standalone assertions and the native multi-connection suite. Any failed phase, incomplete scenario count or missing evidence fails the process. `evidence/CI-RESULT-v281.json` binds results to the PR source head, source-file hashes and transcript hashes. CI uploads only synthetic result files and test transcripts; no database directory, passwords or private keys are uploaded. The fixture's permissive single-tenant RLS policies are unsuitable for production.

## Source continuity and status

`BASELINE-v281.json` lists byte-identical files imported from the v279 transaction/native staging candidate. The v281 parallel harness adds a bounded parent-test timeout and rejects early completion of the first writer instead of waiting forever for a lock barrier. The original v279 harness remains preserved. This focused repository slice does not replace the separate RIO frontend or archive/governance candidates.

The workflow checks out the exact PR head with read-only repository permissions and no retained credentials. It does not merge, deploy, migrate a remote database or issue authority. PASS is limited to the named synthetic checks in the recorded environment. Real PALACO One authentication, remote TLS, production policy and release acceptance remain unverified; acceptance is HOLD and authorization is NONE.

AI review through three lenses: TRIAS limits this change to disposable verification; ORACLE requires the exact-head run, scenario evidence and transcripts before a PASS claim; MENTOR keeps one documented command and a failing exit status for incomplete evidence. These are three review lenses applied by one assistant, not independent approvals.
