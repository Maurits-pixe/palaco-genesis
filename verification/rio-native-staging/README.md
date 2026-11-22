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

`test:ci` executes regression/PGlite tests, native standalone assertions, the native multi-connection suite and the One source/composition/statement-issuer/software-signer/lifecycle/handover/key-correspondence checks described below. Any failed phase, incomplete scenario count or missing evidence fails the process. `evidence/CI-RESULT-v302.json` binds results to the PR source head, source-file hashes and transcript hashes. CI uploads only synthetic result files and test transcripts; no database directory, passwords or private keys are uploaded. The fixture's permissive single-tenant RLS policies are unsuitable for production.

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

`run-ci-v295.mjs` adds `one-session-reader-v295.test.mjs`, requires all six scenario records, and writes `evidence/CI-RESULT-v295.json`. The earlier runners remain preserved; the current command entry point is documented in Run above. AI review: TRIAS keeps pending intents outside authentication; ORACLE limits native evidence to the selected SQL contract; MENTOR provides an explicit callback integration point while retaining HOLD until a genuine One session service exists.

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

`ONE-COMPATIBILITY-v299.json` records hashes of the reviewed One v16.7 package/readme. That source still declares no real authentication or sessions; its actual RIO signed-session protocol compatibility is not established. This record does not assess later One gateway versions. The preserved v299 runner requires all six software-backend scenarios, with source-bound evidence in `evidence/CI-RESULT-v299.json`.

AI review: TRIAS retains HOLD/NONE and makes no hardware/identity-authority claim; ORACLE records the observed Node export bypass and confines cryptographic/native evidence to the tested software fixture; MENTOR supplies a usable bounded local signer while keeping the trusted-host requirement visible. Real One authentication, approved production key custody/enrollment and remote transport remain unconnected.

## One-way signer shutdown (v300)

`createRioOneDrainableSoftwareSignerV300` preserves the v299 signing restrictions and adds `stop()` and `getStatus()` for one backend instance. Instantiate it once per configured key/service instance and give its signing callback to the existing v298 issuer. The previous v299 module remains unchanged.

```js
const backend = createRioOneDrainableSoftwareSignerV300({
  tenantRef, allowedOrigin, issuerKey, privateSigningKey,
  readIssuerKeyState, now, maxConcurrentSignatures: 1,
});
// Configure the existing issuer with backend.signSessionStatement.
const drained = backend.stop(); // synchronously refuses new signing work
const status = backend.getStatus(); // DRAINING while admitted work remains
await drained; // STOPPED only after that backend's admitted work has settled
```

| State | Signing behavior |
| --- | --- |
| OPEN | Accepts valid work within the per-instance capacity |
| DRAINING | Refuses new work and withholds results from admitted work |
| STOPPED | No admitted work remains; later signing requests are refused |

`stop()` is idempotent and always returns the same completion promise. There is no resume operation. Status is a frozen snapshot with only state, in-flight count, capacity, availability and HOLD/NONE labels. A stop during input validation is checked again before admission. A stop during either registry lookup or asynchronous cryptography withholds the result; capacity stays occupied until the actual operation settles. Provider errors also release the occupied slot and can complete the drain.

Shutdown does not forcibly cancel a provider or cryptographic operation. A provider that never settles leaves the instance DRAINING; hosts must not claim STOPPED based on an unrelated timeout. A provider must not await this same instance's stop promise from within its own admitted signing call, because that would wait on itself. Completion covers only this backend's admitted signing operations, not all upstream issuer/route requests or another instance/process.

After draining, this backend drops its own signing-handle and registry-callback references. This is not a guarantee of memory zeroization, private-key destruction or removal of references held by the host. It does not revoke issuer keys, One sessions or authority. The trusted Node-host/software-only protection limit documented for v299 still applies. A new backend needs separate explicit trusted configuration; stopped instances cannot reopen.

The v300 contract suite covers concurrent drain barriers, stops during both registry lookups, provider failure, synchronous/reentrant stop, admission validation and producer/verifier use before and after stop. Three additional native scenarios run real Ed25519 cryptography and selected One PostgreSQL column checks through the existing issuer/verifier/reader/route: successful OPEN operation, stop after signing with no exposed result, and later refusal while the fixture's key/session state remains active. Authentication remains a synthetic server binding; the original One SQL function chain and real authentication are not executed.

The preserved `run-ci-v300.mjs` requires all three lifecycle scenarios alongside the earlier suites and writes `evidence/CI-RESULT-v300.json`. AI review: TRIAS distinguishes stopping one software instance from revocation or authority; ORACLE requires observed DRAINING/STOPPED transitions and a withheld cryptographic result in the native chain; MENTOR supplies an idempotent completion signal and documents nonreturning providers. These are three lenses applied by one assistant. Acceptance HOLD; authorization NONE.

## Explicit same-key backend handover (v301)

`createRioOneSignerHandoverV301` owns successive v300 software-backend instances behind one stable `signSessionStatement` callback. This lets an existing v298 issuer keep its callback while a trusted host explicitly replaces a completely retired software instance. Tenant, HTTPS origin, issuer/public-key pin, clock and capacity remain fixed for this controller. Replacement is not key rotation, key enrollment, a new session, or revocation.

```js
const host = createRioOneSignerHandoverV301({
  tenantRef, allowedOrigin, issuerKey, privateSigningKey,
  readIssuerKeyState, now, maxConcurrentSignatures: 1,
});
// Configure the existing issuer once with host.signSessionStatement.
const expectedGeneration = host.getStatus().generation;
const drained = host.retireGeneration({expectedGeneration});
if (drained !== null) {
  await drained;
  const installed = host.installReplacement({
    expectedGeneration, privateSigningKey: replacementHandle,
    readIssuerKeyState: replacementRegistryReader,
  });
  // null means refused; a receipt reports structural installation only.
}
// Final service shutdown: irreversible for this controller.
await host.close();
```

| Controller state | Meaning |
| --- | --- |
| SERVING | Current backend is OPEN; signing readiness has not been proved by this label |
| RETIRING | Admitted work is draining and its result will be withheld |
| RETIRED | Current backend is STOPPED; explicit replacement may be attempted |
| CLOSED | Terminal admission gate; inspect backendState/inFlight for drain completion |

Generation numbers start at one and advance only after installation. A stale expected generation, extra configuration fields, accessors, an OPEN/DRAINING backend or a closed controller refuse installation. Concurrent/reentrant install attempts cannot install two generations. An invalid constructor configuration leaves the retired generation in place. `close()` synchronously closes admission, returns the current backend's idempotent stop promise and prevents all later installations. A frozen status contains no signing handle or registry callback.

The controller invokes no authentication, registry or signing providers during construction/installation. Its installation receipt explicitly reports `readiness: NOT_CHECKED`. A well-shaped private handle for a different key can be structurally installed, but subsequent signing fails the unchanged independent public-pin verification and returns no signature; there is no fallback to a retired instance. Trusted hosts must supply the approved same-key handle and registry service. A new public signing key requires separate coordinated issuer/verifier configuration outside this controller.

Drain completion still covers only this controller's admitted backend signing work. A nonreturning provider remains pending; there is no forced cancellation or background queue. Other controllers/processes and external key references remain outside the boundary. CLOSED may have backendState DRAINING until the provider settles. This does not destroy/zeroize a key, revoke an already exposed statement, cancel all upstream inspections or provide hardware isolation. The v299 software-key protection limits and the requirement for genuine One authentication remain unchanged.

Fifteen contract cases exercise real Ed25519 signing across generations, drain barriers, stale/duplicate commands, invalid/mismatched handles, immutable scope, accessor/reentrant configuration, terminal close and the unchanged producer/verifier callback. Four new native scenarios reuse one actual RIO route instance: generation-one success; retirement during the post-sign registry lookup; explicit generation-two installation with stale-command refusal and successful inspection; terminal close with active fixture key/session state unchanged. SQL uses selected One columns and a synthetic authenticated-server binding, not the original One function chain or a real IdP.

The preserved `run-ci-v301.mjs` requires the four handover records alongside earlier suites and writes `evidence/CI-RESULT-v301.json`. AI review: TRIAS separates backend generation from identity/key authority; ORACLE requires the same route to succeed across explicit replacement and refuses to infer readiness from construction; MENTOR provides a stable callback and expected-generation checks. These are three lenses applied by one assistant, not independent approvals. Acceptance HOLD; authorization NONE.

## Key-correspondence check before installation (v302)

`createRioOneKeyCheckedSignerHandoverV302` rejects a mismatched private handle before returning the initial controller or installing a replacement generation. Both construction and `installReplacement` are asynchronous. It retains v301's fixed configuration scope, stable signing callback, explicit generation comparison, full retirement barrier and terminal close. Earlier v301/v300 implementations remain unchanged.

```js
const host = await createRioOneKeyCheckedSignerHandoverV302({
  tenantRef, allowedOrigin, issuerKey, privateSigningKey,
  readIssuerKeyState, now, maxConcurrentSignatures: 1,
});
// Configure the existing issuer with host.signSessionStatement once.
const expectedGeneration = host.getStatus().generation;
const drained = host.retireGeneration({expectedGeneration});
if (drained !== null) {
  await drained;
  const installed = await host.installReplacement({
    expectedGeneration, privateSigningKey: replacementHandle,
    readIssuerKeyState: replacementRegistryReader,
  });
  // null means refused; no failed candidate replaces the retired generation.
}
await host.close();
```

After the unchanged v300 constructor validates the handle type and independent public SPKI pin, the candidate signs an internally generated message beginning with `RIO_ONE_SOFTWARE_KEY_CHECK_V302` and a NUL byte. Its JSON suffix binds tenant, origin, issuer, key identifier and a fresh 32-byte random nonce. Node crypto verifies the real Ed25519 result against the fixed public key. No caller controls the proof bytes; the proof is not a v296 session statement and neither its signature nor a private key is returned. This adds no key export, generation, enrollment, file storage or network endpoint.

| Observation | Meaning |
| --- | --- |
| `keyCorrespondence: VERIFIED_AT_INSTALL` | The supplied handle signed a fresh local challenge verified by the fixed public key at installation |
| `registryReadiness: NOT_CHECKED` | Proof construction/installation invokes no registry, session or clock provider; key revocation/expiry checks remain on every actual signing request |
| `CHECKING_REPLACEMENT` | One candidate check is pending; no new signing or second installation is admitted |
| `CLOSED` with `keyChecksInFlight: 1` | Terminal admission gate is closed while the pending proof is still settling |

A failed, malformed or wrong-key candidate leaves the retired generation unchanged and returns null without private diagnostics. An invalid initial configuration or failed initial proof rejects construction with no usable controller. The fixed issuer/public pin cannot be changed by a replacement command. There is no automatic fallback, background retry or public-key rotation. SERVING still describes the local lifecycle and capacity; it does not promise registry, service, database or user-authentication readiness.

Terminal close now also waits for an admitted candidate check to settle. A close during proof permanently withholds installation, stops the candidate and resolves the one idempotent close promise only when current backend work and the candidate check have finished. This does not forcibly cancel cryptography; a nonreturning runtime operation leaves completion pending. The completion scope still excludes upstream route requests, other instances/processes, host-held references and previously exposed statements. Memory zeroization, key destruction, hardware isolation and production authority are not supplied.

Sixteen contract cases use real Ed25519 signing, including fresh internal challenge domains/nonces, wrong initial/replacement handles, bad pins, blocked admission during proof, close/proof races, crypto failure, revoked registry, immutable scope and unchanged issuer/verifier use. A test-only WebCrypto scheduling interception controls pending/failing operations and is restored after each case; successful proofs delegate to actual WebCrypto. Five new native scenarios reuse one original route with PostgreSQL selected One columns: checked generation-one success; retirement after real signing; mismatched-handle refusal; checked same-key replacement success; close during actual asynchronous proof with installation withheld and fixture key/session state unchanged. The native suite does not intercept crypto.

`test:ci` uses `run-ci-v302.mjs`, requires all five key-check scenarios alongside preserved suites and writes `evidence/CI-RESULT-v302.json`. Authentication remains a synthetic server binding; original One SQL functions, real user authentication, production key custody and remote TLS remain unverified. AI review: TRIAS distinguishes a local key-pair proof from authority or authenticated identity; ORACLE records successful real verification and close barriers without inflating readiness; MENTOR refuses a wrong handle before service installation and retains the stable callback. These are three lenses applied by one assistant. Acceptance HOLD; authorization NONE.
