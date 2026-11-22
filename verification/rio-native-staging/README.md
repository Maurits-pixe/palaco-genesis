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

`test:ci` executes regression/PGlite tests, native standalone assertions, the native multi-connection suite and the One source/composition/statement-issuer/software-signer checks described below. Any failed phase, incomplete scenario count or missing evidence fails the process. `evidence/CI-RESULT-v299.json` binds results to the PR source head, source-file hashes and transcript hashes. CI uploads only synthetic result files and test transcripts; no database directory, passwords or private keys are uploaded. The fixture's permissive single-tenant RLS policies are unsuitable for production.

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

`run-ci-v295.mjs` adds `one-session-reader-v295.test.mjs`, requires all six scenario records, and writes `evidence/CI-RESULT-v295.json`. The earlier runners remain preserved; v297 is the current command entry point. AI review: TRIAS keeps pending intents outside authentication; ORACLE limits native evidence to the selected SQL contract; MENTOR provides an explicit callback integration point while retaining HOLD until a genuine One session service exists.

## Signed source preparation (v296)

`run-ci-v296.mjs` adds real Ed25519 source-message verification and seven native composition scenarios, producing `evidence/CI-RESULT-v296.json`. See [the v296 source contract](ONE-SIGNED-SESSION-CONTRACT-v296.md) for the independent issuer pin, per-call server challenge, exact request/audience/tenant binding, key-state rechecks and integration with the unchanged v295 reader and original RIO route. Earlier runners remain preserved. The last reviewed One gateway supplies no real authenticated issuer; no live sign-in is enabled.

## Central inspection entry point (v297)

Use `createRioSignedOneInspectionRouteV297` from `rio-signed-one-inspection-route-v297.mjs` to assemble all three existing layers in one trusted-server entry point. Its exact configuration refuses alternate authentication callbacks or a second tenant/clock hidden in receipt services. Source-message keys and receipt-signing keys must have different independent SPKI pins. This is key separation; it does not add a signed domain to the older v242 receipt format.

```js
const route = createRioSignedOneInspectionRouteV297({
  tenantRef, allowedOrigin, issuerKey, requestSignedSession, readIssuerKeyState,
  acquireOneReadConnection, now, requestTimeoutMs, maxConcurrentInspections,
  receiptServices: {
    keyPins, readInspectionPolicy, readOriginalRevocationRequest,
    confirmCurrentRevocation, queryVerificationKeys,
  },
});
// Trusted server handler: return route.handle(fetchRequest).
```

Every dependency remains an explicitly configured trusted server service. Construction performs only structural validation and public-key parsing; it does not call providers or prove their readiness. A missing or unsigned source refuses inspection before One SQL or receipt policy. There is no public fixture-cookie fallback, listener, configured real issuer or enabled sign-in.

`run-ci-v297.mjs` adds two native central-entry scenarios: successful synthetic signed-source/One SQL/original-route composition, and refusal after One revocation during that inspection. Its evidence is written to `evidence/CI-RESULT-v297.json`. Earlier verifier modules, native suites and runners remain preserved.

AI review: TRIAS keeps the original read-only route and HOLD/NONE boundary; ORACLE requires native evidence for the central entry point rather than inferring its behavior from separately tested components; MENTOR replaces manual wiring with one explicit constructor and rejects ambiguous overrides. A real authenticated One issuer, original One transaction chain and production transport still require separate integration and evidence.

## Existing-session statement producer (v298)

`createRioOneSessionStatementIssuerV298` in `rio-one-session-statement-issuer-v298.mjs` implements the producer side of the unchanged v296 signed-message protocol. It produces a short-lived statement about an **already authenticated existing One session**. It does not create a session, log in a person, register PP, issue an identity or grant authority. No listener, cookie handler or network endpoint is provided.

```js
const issuer = createRioOneSessionStatementIssuerV298({
  tenantRef, allowedOrigin, issuerKey, readAuthenticatedOneSession,
  readIssuerKeyState, signSessionStatement, now,
});
const route = createRioSignedOneInspectionRouteV297({
  ...trustedRouteConfiguration,
  requestSignedSession: issuer.requestSignedSession,
});
```

The trusted One backend must implement `readAuthenticatedOneSession(request)` by authenticating the existing user session and returning the exact active v295 host-session contract. This dependency is not implemented here and must never copy self-reported labels, a pending-intent row or browser identity fields. The One backend and RIO verifier require independently approved issuer-key configuration. The issuer accepts only a pinned public Ed25519 key; a private key is not a configuration option.

`signSessionStatement({purpose,issuerId,keyId,payload})` is a separately configured server/HSM signer restricted to the read-only RIO review purpose. It returns a canonical base64url Ed25519 signature. This is not a public arbitrary-message signing API. The module verifies the returned signature against the independent public pin before exposing any envelope.

The producer validates the request/challenge and current signing-key state before requesting authentication. It requires a source observation made during this lookup, preserves its timestamp, and bounds the statement's lifetime by five seconds, the existing session expiry and key expiry. It checks the existing session again after signing and re-reads the key state; changed identity, epochs, PP revision, device binding, session expiry or key state withholds the statement. Only the observation time may refresh. Cached facts are never relabeled as fresh, and failures return no statement or private diagnostic.

The v298 native fixture pairs this implemented producer with the unchanged verifier, One reader, central entry point and original receipt route. A private synthetic server binding simulates the unavailable user-authentication service; actual PostgreSQL queries check selected One column contracts. Four scenarios cover missing authentication, the complete paired chain, One revocation during signing and One revocation during receipt inspection. Real user authentication, registered WebAuthn, the original One SQL transaction chain, approved real signing keys and remote TLS remain unverified.

`run-ci-v298.mjs` requires all four producer scenarios and writes `evidence/CI-RESULT-v298.json`. Earlier modules and runners remain preserved. AI review: TRIAS distinguishes a session statement from session/identity issuance; ORACLE records synthetic authentication separately from real cryptographic/native SQL checks; MENTOR provides the producer callback needed by the existing central entry point. Acceptance HOLD; authorization NONE; no live login or deployment.

## Restricted local software signer (v299)

`createRioOneRestrictedSoftwareSignerV299` implements the issuer's signing port with a host-supplied, sign-only Ed25519 WebCrypto CryptoKey whose `extractable` flag is false. It generates no keys, reads no key files, persists no keys and exposes no key-export method. It verifies every produced signature against the independently configured public SPKI pin. A private-key PEM, exportable handle, different algorithm or handle/public-pin mismatch cannot produce a result through this API.

```js
const backend = createRioOneRestrictedSoftwareSignerV299({
  tenantRef, allowedOrigin, issuerKey, privateSigningKey,
  readIssuerKeyState, now, maxConcurrentSignatures: 1,
});
const issuer = createRioOneSessionStatementIssuerV298({
  tenantRef, allowedOrigin, issuerKey, readAuthenticatedOneSession,
  readIssuerKeyState, signSessionStatement: backend.signSessionStatement, now,
});
```

Instantiate the backend once per configured key/service instance. Its concurrency bound is per instance, with no background queue. Calls above capacity, stale jobs, malformed/noncanonical messages, wrong purpose/issuer/tenant/request scope, pending session facts, expired validity or key-state changes return no signature. The signing port is for the trusted issuer; it is not a public arbitrary-message signing endpoint or a user authenticator.

**Key protection is deliberately limited.** In the local Node v24.22.3 probe, `subtle.exportKey` refused an `extractable:false` private key, while `KeyObject.from(...).export(...)` could export it through a deprecated Node API. The module therefore records `hostKeyIsolation: NOT_PROVIDED` and `hardwareProtection: NOT_VERIFIED`. The WebCrypto flag must not be described as protection from a privileged Node host or as HSM custody.

| Surface | Evidence/limit |
| --- | --- |
| Module API | No private-key or export method is returned |
| WebCrypto export API | Rejected for the supplied private signing handle |
| Privileged Node host | Remains trusted; the runtime probe records whether Node conversion/export succeeds |
| Hardware custody / managed cloud signing | Not implemented or verified |
| Key enrollment and restart persistence | Not supplied by this backend |

The native fixture generates its ephemeral source key through WebCrypto without exporting that source private key. A separate disposable probe key tests Node-host export behavior; any returned probe buffer is wiped and never printed or retained. The probe does not test an enrolled/user key. Native evidence records the limitation rather than requiring a future Node runtime to remain exportable.

Six new native scenarios run the software backend through the unchanged issuer, verifier, One reader and central RIO route: key-protection scope, missing synthetic authentication, the complete paired chain, real issuer-key revocation between signer registry reads, One revocation during signing and One revocation during receipt inspection. The selected-column SQL fixtures and synthetic authentication remain distinct from an actual One IdP or the original One transaction chain.

`ONE-COMPATIBILITY-v299.json` records hashes of the reviewed One v16.7 package/readme. That source still declares no real authentication or sessions; its actual RIO signed-session protocol compatibility is not established. The current `test:ci` command uses the separate v299 runner and requires all six software-backend scenarios, with source-bound evidence in `evidence/CI-RESULT-v299.json`.

AI review: TRIAS retains HOLD/NONE and makes no hardware/identity-authority claim; ORACLE records the observed Node export bypass and confines cryptographic/native evidence to the tested software fixture; MENTOR supplies a usable bounded local signer while keeping the trusted-host requirement visible. Real One authentication, approved production key custody/enrollment and remote transport remain unconnected.
