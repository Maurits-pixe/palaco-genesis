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

## One session source preparation (v295)

`rio-palaco-one-session-reader-v295.mjs` prepares the trusted-host session boundary for RIO. The current PALACO One v16.0 gateway returns no authenticated session; its base session route refuses access. The separate One v9.9 SQL module records **pending intents**. Neither source can authenticate RIO today. `ONE-SOURCE-CONTRACT-v295.json` records the reviewed source-byte hashes and this compatibility gap. No existing One file is replaced.

The new host port deliberately requires a future, authenticated One service to implement `palaco-one-authenticated-host-session-v295-DRAFT`. Its callback is injected by trusted server configuration. Format labels and `SERVER_AUTHENTICATED` are a host contract, not cryptographic proof. Never implement that callback by reading browser claims, a public cookie selector, a pending-intent row, local storage or a self-reported review bundle. No network endpoint or credential handler is added here.

For each check, the reader:

- Gets the existing session from that trusted One service, requires active state, bounded fresh observation, exact tenant and compatible identifiers, and refuses excess privilege fields.
- Acquires an exclusively owned database reader connection and begins READ COMMITTED READ ONLY. The connection must use a direct least-privilege login: no superuser, BYPASSRLS, ownership, or DML rights on the three source tables; all three tables must have ENABLE/FORCE RLS.
- Reads the original One column contract with parameterized SQL: verified PP/credential ownership and registry revision, active subject epoch, active credential/session epoch, revocation revision and device binding. Safe-integer bounds prevent lossy bigint coercion.
- Rolls back the read-only transaction, releases the connection, and checks expiry again. Any provider, SQL, clock or cleanup failure refuses the session without returning private details.
- Pins the complete security tuple to the exact Fetch Request object. Every later host recheck repeats the source read; a changed PP revision cannot hide behind an unchanged session epoch. Observations may refresh; identity and security tuples cannot change mid-inspection.

Use the resulting callback as the existing v267 host adapter's `authenticateHostRequest` dependency:

```js
const sessionPort = createRioOneSessionReaderV295({
  tenantRef, authenticateOneRequest, acquireOneReadConnection, now,
});
const host = createRioReceiptHostAdapterV267({
  ...trustedReceiptServices, tenantRef,
  authenticateHostRequest: sessionPort.authenticateHostRequest,
});
```

The authenticated callback, database pool, receipt policies, original request ledger and key pins remain independently configured trusted services. There is no usable callback in the current One gateway. Unsupported One identifiers are refused rather than silently rewritten. Sequential rechecks do not provide atomic authorization for any later action.

The six new native scenarios use minimal synthetic tables with selected One column names and dedicated tenant RLS policies. They verify the reader's actual SQL, fresh physical connections, committed revocation, registry changes, another tenant's denial and unsafe source configuration. They **do not execute the original One login/session/revocation functions**, verify the full migration chain or prove a real IdP. Contract unit tests separately simulate the trusted session service and adverse database replies. Real One authentication and remote TLS remain NOT EXECUTED.

`test:ci` now also runs `one-session-reader-v295.test.mjs`, requires all six scenario records, and writes `evidence/CI-RESULT-v295.json`. The original v281 runner and evidence format remain in the source history. AI review: TRIAS keeps pending intents outside authentication; ORACLE limits native evidence to the selected SQL contract; MENTOR provides an explicit callback integration point while retaining HOLD until a genuine One session service exists.
