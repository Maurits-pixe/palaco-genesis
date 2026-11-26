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

`test:ci` executes regression/PGlite tests, native standalone assertions, the native multi-connection suite and the One source/composition/statement-issuer/software-signer/lifecycle/handover/key-and-registry/cancellation/reporting/controller/history/service/draining checks described below. Any failed phase, incomplete scenario count or missing evidence fails the process. `evidence/CI-RESULT-v310.json` binds results to the PR source head, source-file hashes and transcript hashes. CI uploads only synthetic result files and test transcripts; no database directory, passwords or private keys are uploaded. The fixture's permissive single-tenant RLS policies are unsuitable for production.

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

The preserved `run-ci-v302.mjs` requires all five key-check scenarios alongside earlier suites and writes `evidence/CI-RESULT-v302.json`. Authentication remains a synthetic server binding; original One SQL functions, real user authentication, production key custody and remote TLS remain unverified. AI review: TRIAS distinguishes a local key-pair proof from authority or authenticated identity; ORACLE records successful real verification and close barriers without inflating readiness; MENTOR refuses a wrong handle before service installation and retains the stable callback. These are three lenses applied by one assistant. Acceptance HOLD; authorization NONE.

## Bounded key-and-registry installation checks (v303)

`createRioOneRegistryCheckedSignerHandoverV303` checks the trusted issuer registry before and after the real private/public-key proof, for initial construction and replacement. It preserves the stable signing callback, immutable scope, expected-generation checks and full retirement barrier. Previous v302 and earlier modules remain unchanged. Construction and replacement remain asynchronous:

```js
const host = await createRioOneRegistryCheckedSignerHandoverV303({
  tenantRef, allowedOrigin, issuerKey, privateSigningKey,
  readIssuerKeyState, now, maxConcurrentSignatures: 1,
});
// Configure the existing issuer once with host.signSessionStatement.
const expectedGeneration = host.getStatus().generation;
const retired = host.retireGeneration({expectedGeneration});
if (retired !== null) {
  await retired;
  const installed = await host.installReplacement({
    expectedGeneration, privateSigningKey: replacementHandle,
    readIssuerKeyState: replacementRegistryReader,
  });
  // null means refused; the old generation stays retired.
}
await host.close();
```

The trusted registry callback must return exactly `state`, `issuerId`, `keyId`, `revision`, `notBefore` and `notAfter` as own enumerable data properties. ACTIVE state, the configured issuer/key, a positive safe-integer revision and canonical ISO validity timestamps are required. Each record is copied immediately after its lookup; a callback cannot mutate the first observation in place to conceal a later change. Both records must match in every field and remain valid through the completed check. No source callback, registry or network endpoint is configured by this module.

All sampled host-clock values must be valid and nondecreasing, and the completed check must fit within 1,000 milliseconds from its initial clock observation. A stale first lookup is refused before cryptography. Expiry, revision/window changes, revocation, malformed data, clock rollback or provider/crypto failure return no installation. The cryptographic challenge uses the separate internal `RIO_ONE_SOFTWARE_KEY_CHECK_V303` plus NUL domain and a fresh nonce; it is not a session statement, and no proof signature or private key is exposed.

| Status or receipt field | Scope |
| --- | --- |
| `keyCorrespondence: VERIFIED_AT_INSTALL` | Actual key-pair verification completed for this installed generation |
| `registryReadiness: VERIFIED_AT_INSTALL` | Two matching active registry observations passed within the bounded check |
| `registryRevisionAtInstall` / `installationCheckedAt` | The observed installation revision/time; not a live registry view |
| `candidateChecksInFlight` | An admitted candidate assessment, including registry waits and cryptography, has not settled |

These installation observations do not grant continuous readiness. The unchanged v300 signer still rechecks current registry state/expiry around every actual signature, and the existing One/session/receipt checks still run. A key revoked after installation must fail subsequent signing even while the status retains its historical installation revision. Sequential reads do not provide atomic authorization or rule out a change between/after observations. A registry service is still a separately trusted dependency; this module does not prove its backing transport or database.

Close during either registry lookup or cryptography withholds the candidate and waits for the actual admitted assessment to settle. A close after the first registry lookup prevents unnecessary key proof and the second lookup. The one-second acceptance bound is not forced cancellation: a nonreturning provider keeps completion pending and occupies the candidate slot. CLOSED can therefore still have `candidateChecksInFlight: 1`. There is no automatic retry, fallback, new public key, authority grant, key destruction or memory-zeroization guarantee.

Seventeen contract cases cover invalid/revoked/expired/misbound records, copied mutable observations, actual key mismatch, changed revision/windows during real crypto, clock bounds/rollback, provider failure, both close/registry races, immutable scope, duplicate/stale commands, per-request revocation and the unchanged issuer/verifier callback. Test-only crypto scheduling interception is restored after each case; successful crypto uses real WebCrypto.

Six new native scenarios reuse one actual route and selected One PostgreSQL columns: verified initial generation; retirement after signing; committed issuer-key revocation before installation; committed revocation between the two candidate observations; successful same-key replacement at the new active registry revision; close during a real registry query with candidate withheld. The fixture intentionally revokes/restores its disposable key registry through revisions 1 to 5. The reviewer session remains ACTIVE with its original epoch/revocation revision. Native cryptography is not intercepted, and the original One SQL function chain and real user authentication remain unexecuted.

The preserved `run-ci-v303.mjs` requires all six registry-check records alongside earlier suites and writes `evidence/CI-RESULT-v303.json`. AI review: TRIAS separates installation observations from continuous authority; ORACLE requires committed native registry changes and bounds the evidence to sampled observations; MENTOR rejects an invalid candidate before service installation while retaining the stable callback. These are three lenses applied by one assistant, not independent approvals. Software/Node-host key-isolation limits, synthetic authentication and unverified remote TLS remain unchanged. Acceptance HOLD; authorization NONE.

## Cancellation bound to one replacement attempt (v304)

`createRioOneCancellableSignerHandoverV304` retains the v303 key/registry checks and adds `cancelReplacement({expectedGeneration,attemptId})` for an admitted replacement attempt. Construction remains asynchronous and must finish before this control API is available. The earlier v303 module remains unchanged. The existing issuer/route still receives one stable `signSessionStatement` callback.

```js
const host = await createRioOneCancellableSignerHandoverV304(trustedConfiguration);
const expectedGeneration = host.getStatus().generation;
const retired = host.retireGeneration({expectedGeneration});
if (retired !== null) {
  await retired;
  const work = host.installReplacement({
    expectedGeneration, privateSigningKey: replacementHandle,
    readIssuerKeyState: replacementRegistryReader,
  });
  const status = host.getStatus();
  if (status.candidateAttemptId !== null) {
    const acknowledgement = host.cancelReplacement({
      expectedGeneration: status.generation, attemptId: status.candidateAttemptId,
    });
    // null means refused; an acknowledgement means only cancellation requested.
  }
  const result = await work; // null after an accepted cancellation has settled
}
await host.close();
```

An attempt identifier increases for every admitted candidate, including a candidate that later fails or is cancelled. It is not reused by this controller. This keeps a delayed cancellation for an earlier attempt from affecting a later attempt in the same retired generation. Generation and attempt must both match. Identifiers are local to one controller, are not persisted across process restarts and are not authentication tokens or transferable authority. These methods are trusted host controls; no public endpoint is added.

| Observation | Meaning |
| --- | --- |
| `CANCELLATION_REQUESTED` acknowledgement | This matching attempt is marked to withhold installation; its operation may still be running |
| `CANCELLING_REPLACEMENT` / `candidateChecksInFlight: 1` | The marked candidate still occupies its slot while actual work/cleanup settles |
| `candidateAttemptId: null` with RETIRED | No pending attempt remains; a trusted host may explicitly submit a new attempt |
| Successful installation receipt `attemptId` | The attempt that installed the new generation; later cancellation cannot undo it |

Cancellation is idempotent for the pending attempt and returns the same frozen acknowledgement. Wrong/stale generations or attempt IDs, malformed/extra/accessor fields, idle/serving states, a completed installation or a closed controller return null. There is no background retry or automatic reopening. Attempt/generation counter exhaustion refuses further installation.

An accepted cancellation prevents installation even if it arrives after the final assessment has completed but before the installation continuation commits it. During a registry wait or actual asynchronous key proof, the slot remains occupied until the operation really settles. A cancelled first registry observation skips the key proof and later lookup; a cancellation during proof skips later lookup after proof returns. No query or crypto operation is forcibly aborted or signalled, and a nonreturning provider keeps the installation promise pending. The one-second observation acceptance bound remains separate from completion.

Cancellation leaves the old generation retired and grants no identity/key authority. It does not revoke an installed generation, destroy a key, cancel all upstream requests or affect other controllers/processes. Terminal `close()` still prevents all future installations and waits for admitted candidate work even when cancellation was already requested. Installation-time registry metadata remains historical; per-request registry/session/receipt checks are unchanged. The internal key-check challenge retains the separate v303 domain and is not a One session statement.

Thirteen contract cases cover cancellation at both registry lookups, during real cryptography, immediately before installation commit, from a trusted clock, across failed/duplicate/stale attempts, after completion, through provider failure and terminal close, plus unchanged issuer/verifier use. Test-only scheduling interception is restored after each case; successful cryptography uses real WebCrypto. Six new native scenarios reuse one actual route and selected One PostgreSQL columns: checked initial success, full retirement, cancellation after the first registry query, stale-command refusal with cancellation after actual key proof, explicit successful retry, and terminal close during a candidate query. Native crypto/SQL is not intercepted. The fixture's key and reviewer session remain active with their original registry/epoch/revocation values.

The preserved `run-ci-v304.mjs` requires all six cancellation records alongside earlier suites and writes `evidence/CI-RESULT-v304.json`. AI review: TRIAS distinguishes withholding a candidate from revocation or authority; ORACLE requires stale-attempt refusal and real completion barriers; MENTOR provides an idempotent acknowledgement without falsely freeing occupied work. These are three lenses applied by one assistant. Synthetic authentication, unexecuted original One SQL functions, software/Node-host key-isolation limits and unverified remote TLS remain unchanged. Acceptance HOLD; authorization NONE.

## Last completed replacement result (v305)

`createRioOneReportingSignerHandoverV305` keeps v304's cancellation and installation controls and adds `getLastAttemptResult()`. It returns null until an admitted replacement attempt has completed its assessment and candidate cleanup. A cancellation acknowledgement remains a request acknowledgement; it is never copied into the completion record while work is pending. Earlier v304 and older modules remain unchanged.

```js
const host = await createRioOneReportingSignerHandoverV305(trustedConfiguration);
const expectedGeneration = host.getStatus().generation;
const retired = host.retireGeneration({expectedGeneration});
if (retired !== null) {
  await retired;
  const work = host.installReplacement({
    expectedGeneration, privateSigningKey: replacementHandle,
    readIssuerKeyState: replacementRegistryReader,
  });
  const attemptId = host.getStatus().candidateAttemptId;
  await work;
  const completed = host.getLastAttemptResult();
  if (completed?.attemptId === attemptId) {
    // This is the completed result for this attempt, not a pending acknowledgement.
  }
}
```

Each frozen record contains only format, attempt ID, expected/resulting generation, `completion: COMPLETED`, outcome, cancellation-request flag and HOLD/NONE labels. Status exposes `lastCompletedAttemptId` separately from the pending `candidateAttemptId`. Reading either result/status invokes no provider, clock, storage or network operation. No keys, signatures, session/tenant/subject identifiers, SQL diagnostics or provider error messages are included.

| Outcome | Meaning at completion |
| --- | --- |
| INSTALLED | This attempt installed its new backend generation |
| WITHHELD_AFTER_CLOSE | Terminal close was set before completion and the candidate was not installed |
| WITHHELD_AFTER_CANCELLATION | Cancellation was requested before installation commit and the candidate was withheld |
| CHECK_FAILED | An admitted assessment did not pass, with no close/cancellation flag at completion |

Installed outcome takes precedence for an actual installation; otherwise terminal close takes precedence over cancellation, and `cancellationRequested` preserves whether that request also occurred. These outcomes describe the controlled result at completion. They do not identify an independent failure's root cause or prove that a query/crypto operation was forcibly cancelled. CHECK_FAILED deliberately does not expose a more specific provider diagnostic.

Commands rejected before admission, initial construction, idle retirement, late cancellation and idle close do not fabricate or rewrite a result. The controller retains only its latest completed record. While a later attempt is pending, `getLastAttemptResult()` still returns the previous completed record with its previous ID; callers must match IDs before treating it as the new attempt's result. When the new admitted attempt completes, it replaces that one reference. There is no growing history, persistence, durable audit ledger, cryptographic receipt or cross-process authority.

Publication occurs after the candidate assessment and any candidate stop/cleanup have settled, alongside clearing its occupied slot. Terminal close resolves after publishing a matching candidate result. A nonreturning provider still leaves the candidate pending; an earlier completed result remains historical and does not claim that current work is done. A successful result likewise remains historical if the service later closes or a key is revoked. It does not prove continuous readiness, global quiescence, upstream-request completion, key destruction or user authentication.

Twelve contract cases cover minimized immutable records, rejected/unadmitted commands, generic provider failure, pending registry/crypto barriers, cancellation versus terminal close, bounded previous-result retention, late cancellation, the final installation-continuation race and unchanged issuer/verifier use. Test-only scheduling interception is restored per case; successful cryptography uses real WebCrypto. Six new native scenarios reuse one original route and selected One PostgreSQL columns: checked initial success, full retirement, completed withholding after a real registry query, an actual missing-relation query error (42P01) producing a generic CHECK_FAILED record, successful explicit retry, and terminal close publishing the matching completed candidate record. Native SQL/crypto is not intercepted. The disposable key and reviewer session retain their original active states/revisions/epochs.

The preserved `run-ci-v305.mjs` requires all six reporting scenarios alongside earlier suites and writes `evidence/CI-RESULT-v305.json`. AI review: TRIAS separates local operational completion from authority or durable evidence; ORACLE requires actual completion barriers and a real SQL failure without diagnostic leakage; MENTOR distinguishes a request acknowledgement from one completed-attempt result using explicit IDs. These are three lenses applied by one assistant, not independent approvals. Synthetic authentication, original One SQL-function limits, software-key isolation limits and unverified remote TLS remain unchanged. Acceptance HOLD; authorization NONE.

## Control commands bound to one controller instance (v306)

`createRioOneScopedSignerHandoverV306` adds a freshly generated controller correlation identifier. Two independently created controllers can otherwise both be at generation one, attempt one, even with identical tenant, issuer and private-handle configuration. The new controller requires its own `controllerId` on data-driven retirement, replacement and cancellation commands. A command carrying another instance's identifier is refused even when its local numbers match. Previous v305 and earlier modules remain unchanged.

```js
const host = await createRioOneScopedSignerHandoverV306(trustedConfiguration);
const status = host.getStatus();
const control = {controllerId: status.controllerId, expectedGeneration: status.generation};
const retired = host.retireGeneration(control);
if (retired !== null) {
  await retired;
  const work = host.installReplacement({
    ...control, privateSigningKey: replacementHandle,
    readIssuerKeyState: replacementRegistryReader,
  });
  const pending = host.getStatus();
  // Optional trusted-host cancellation of this exact controller/attempt:
  // host.cancelReplacement({...control, attemptId: pending.candidateAttemptId});
  await work;
  const completed = host.getLastAttemptResult();
  if (completed?.controllerId === control.controllerId &&
      completed.attemptId === pending.candidateAttemptId) {
    // Matching completed result for this controller and attempt.
  }
}
await host.close();
```

The identifier is generated once from 32 cryptographically random bytes and encoded as canonical base64url. It remains constant across generations for that controller; another construction generates another value. It cannot be supplied through configuration. This is a public correlation label for one local lifetime, not an authentication secret, user/tenant identity, key identifier, capability or authority grant. A trusted host that knows an identifier still needs all existing service configuration and controls. No public management endpoint or authenticated One service is added.

| Surface | Binding |
| --- | --- |
| Status | Own `controllerId`, current generation, pending/last-completed attempt IDs |
| retireGeneration | Exact own `controllerId` plus expected generation |
| installReplacement | Exact own `controllerId`, expected generation and trusted replacement ports |
| cancelReplacement | Exact own `controllerId`, expected generation and pending attempt ID |
| Installation/cancellation/completion results | Own `controllerId` attached to the existing minimized result |

Missing, foreign, wrong-type, accessor or extra configuration fields are refused without implicit fallback to earlier command shapes. Foreign replacement commands reach neither registry lookup nor candidate admission. Same-controller stale attempt/generation checks still apply. Status and new v306 result formats are frozen. Callers correlating results must match controller and attempt IDs together; local numbers alone are insufficient across instances. `close()` remains bound to the host object reference and returns that host's scoped status; it is not a data-driven command.

The v306 status, installation, cancellation and completed-result format identifiers are distinct from earlier versions. One's signed-session formats and the internal v303 key-check domain remain unchanged. Key/registry observations, completion barriers, bounded result retention and the stable issuer/route signing callback are preserved. A cancelled/closed controller does not revoke the host-held key: a separately configured fresh controller can reuse that approved handle while receiving a fresh control scope. This does not establish durable restart state, real process-restart safety, cross-process coordination or authentication.

Twelve contract cases cover independent scopes for identical configuration, refusal of foreign/missing control data, simultaneous equal local numbers, scoped results, a closed/new instance sequence, invalid types/accessors, stale local commands, final-continuation cancellation, close completion and unchanged issuer/verifier use. Six new native scenarios use three controllers and reuse one original route with selected One PostgreSQL columns. They verify foreign retirement/installation refusal, matching-scope drain, simultaneous equal generation/attempt numbers with foreign cancellation refusal, explicit same-route retry and a fresh instance refusing the closed instance's command. Real SQL and Ed25519 are used; callback barriers control scheduling without intercepting SQL or crypto. This tests new instances within one process, not an operating-system restart.

The preserved `run-ci-v306.mjs` requires all six controller-scope scenarios alongside earlier suites and writes `evidence/CI-RESULT-v306.json`. AI review: TRIAS separates correlation scope from identity or authority; ORACLE requires equal-number cross-controller tests and matching result identifiers; MENTOR refuses stale routing context while retaining explicit trusted-host control. These are three lenses applied by one assistant. Synthetic authentication, original One SQL-function limits, software-key isolation limits and unverified remote TLS remain unchanged. Acceptance HOLD; authorization NONE.

## Observed completion required for replacement admission (v307)

`createRioOneHistoryBoundSignerHandoverV307` requires the last completed attempt observed by the caller when admitting a replacement. After a cancelled or failed assessment, the controller can return to RETIRED with the same generation. An earlier cached command would still match that generation and controller. The added `expectedLastCompletedAttemptId` must match the current completed result, so that cached command is refused before registry work or admission. Earlier v306 and older modules remain unchanged.

```js
const host = await createRioOneHistoryBoundSignerHandoverV307(trustedConfiguration);
const initial = host.getStatus();
const retired = host.retireGeneration({
  controllerId: initial.controllerId, expectedGeneration: initial.generation,
});
if (retired !== null) {
  await retired;
  const observed = host.getStatus();
  const result = await host.installReplacement({
    controllerId: observed.controllerId,
    expectedGeneration: observed.generation,
    expectedLastCompletedAttemptId: observed.lastCompletedAttemptId,
    privateSigningKey: replacementHandle,
    readIssuerKeyState: replacementRegistryReader,
  });
  // After a completed failed/cancelled attempt, read a fresh status before retrying.
}
```

| Marker | Admission behavior |
| --- | --- |
| Explicit null | Accepted only while this controller has no completed replacement attempt |
| Current positive safe-integer attempt ID | Accepted only when it equals this controller's last completed attempt |
| Older/future ID, missing field, undefined, zero or malformed type | Refused before provider work or candidate admission |

The controller scope, expected generation, completed-attempt marker and full retirement barrier are checked together. The completed marker does not replace the other checks. A duplicate command is refused while an attempt is pending and remains stale after that attempt completes unsuccessfully, even if generation and RETIRED state are unchanged. A trusted host must observe the new completion marker and explicitly construct a new command. There is no automatic retry or implicit server substitution of the current marker.

Only an admitted completed attempt advances the marker. Cancellation acknowledgement alone does not advance it while a provider/crypto operation remains pending. Rejected commands and invalid handles refused before admission do not create a result, consume an attempt or invalidate a current marker. All existing cancellation, terminal-close, registry/key validity and per-request checks remain in place.

Installation receipts and completed-attempt records include `previousCompletedAttemptId`, the observed marker accepted for that attempt. New v307 status/result formats retain controller/attempt IDs and HOLD/NONE. The controller still retains only its latest completed record; this extra number does not create a persistent chain, audit ledger, cryptographic proof, approval, user identity or authority. The One statement formats and internal v303 key-check domain are unchanged. No new provider call, clock sample, network endpoint or storage is introduced by the marker check.

Twelve contract cases cover explicit initial null, invalid/stale/future markers, unchanged-generation cancellation/failure, busy duplicates, multiple completed attempts, unadmitted commands, later generations, completion barriers, controller binding, final-continuation cancellation and unchanged issuer/verifier use. Six new native scenarios reuse one original route with selected One PostgreSQL columns: initial success, full retirement, cancellation plus cached-command refusal, actual PostgreSQL query error 42P01 plus stale-marker refusal, successful retry from a fresh observation, and close completion retaining its admitted predecessor. Stale native commands perform zero registry lookups and do not create results. SQL/Ed25519 are real and are not intercepted; the key and reviewer session retain their original active values.

The preserved `run-ci-v307.mjs` requires all six history-admission records alongside earlier suites and writes `evidence/CI-RESULT-v307.json`. AI review: TRIAS separates observed operation context from authority; ORACLE requires refusal after actual cancellation/SQL failure while generation remains unchanged; MENTOR requires a fresh explicit observation before retry. These are three lenses applied by one assistant, not independent approvals. Synthetic authentication, original One SQL-function limits, software-key isolation limits and unverified remote TLS remain unchanged. Acceptance HOLD; authorization NONE.

## One inspection service with separate host control (v308)

`createRioOneInspectionServiceV308` assembles the v307 signer controller, v298 statement issuer, v296 signed source, v295 One reader and original v269 inspection route in one asynchronous construction. A trusted host previously had to connect these components manually. The new factory returns a frozen inspection port and a separate frozen signer-control port without exposing raw signing or session-statement callbacks. Earlier modules and their public APIs remain unchanged.

```js
const service = await createRioOneInspectionServiceV308({
  tenantRef, allowedOrigin, issuerKey, privateSigningKey,
  readIssuerKeyState, readAuthenticatedOneSession, acquireOneReadConnection,
  receiptServices, now,
  limits: {requestTimeoutMs: 5000, maxConcurrentInspections: 2, maxConcurrentSignatures: 2},
});
// Pass only this port to the host's existing inspection HTTP adapter.
const response = await service.inspection.handle(request);

// Keep this separate port inside trusted host administration.
const control = service.signerControl;
const observed = control.getStatus();
const retired = control.retireGeneration({
  controllerId: observed.controllerId, expectedGeneration: observed.generation,
});
if (retired !== null) {
  await retired;
  const current = control.getStatus();
  await control.installReplacement({
    controllerId: current.controllerId,
    expectedGeneration: current.generation,
    expectedLastCompletedAttemptId: current.lastCompletedAttemptId,
    privateSigningKey: replacementHandle,
  });
}
await control.close(); // Stops this signer; not a whole-host or connection-pool shutdown.
```

| Configuration / port | Contract |
| --- | --- |
| issuerKey | Exact issuerId, keyId, publicKeyPem and spkiSha256; copied before asynchronous work |
| receiptServices | Exact keyPins, readInspectionPolicy, readOriginalRevocationRequest, confirmCurrentRevocation and queryVerificationKeys; independent receipt pins remain required |
| limits | Exact requestTimeoutMs, maxConcurrentInspections and maxConcurrentSignatures |
| readAuthenticatedOneSession | Mandatory trusted server authentication callback for an already authenticated session; no login fallback |
| readIssuerKeyState | One captured callback shared by issuer, verifier and signer, including replacement |
| inspection | handle, path, purpose and HOLD/NONE; no signer administration or raw signature method |
| signerControl | getStatus, getLastAttemptResult, retireGeneration, installReplacement, cancelReplacement and close, plus HOLD/NONE |

The root configuration and named nested records require exact own enumerable data fields. Getters, extra fields and sparse/accessor pin arrays are refused without evaluating those accessors. Receipt pins are a dense array of 1–32 exact keyId/algorithm/spkiSha256 records. Public scope, key descriptions, pin records, callbacks and limits are captured synchronously before the first await. Later caller mutation does not redirect the assembled service. The host-provided private key remains a software handle with the earlier isolation limitations; copying configuration provides no key isolation or protection against malicious host code.

Static issuer/route validation runs before any register or authentication callback. Only after structural validation does construction await the existing actual private/public correspondence proof and two bounded registry observations. A failed initial assessment rejects construction without returning a partial service. Construction does not authenticate a user, issue a session, start a listener or run receipt policy/One-reader SQL.

The service's replacement command is narrower than the standalone v307 controller: exactly controllerId, expectedGeneration, expectedLastCompletedAttemptId and privateSigningKey. It cannot select another readIssuerKeyState callback; the factory injects its original shared callback. Caller scope, completion observation and retirement barriers still apply. A different registry configuration requires a separately assembled service. Cancellation acknowledges a request and waits for actual provider/crypto settlement under the preserved controller rules; it does not forcibly cancel that work.

`signerControl.close()` closes the signer controller only. It does not close the inspection route, stop upstream authentication/registry callbacks, drain every HTTP operation or dispose host-owned database connections. A later authenticated inspection is refused when signing is unavailable, while earlier route deadlines and in-flight limits retain their original behavior. The host still owns HTTP admission, whole-service shutdown, authentication, provider cancellation policy and pool lifecycle. The two returned JavaScript ports help the host distribute references deliberately; they do not establish an operating-system security boundary or implement management authentication.

Twelve contract tests cover frozen ports, exact configuration, missing authentication dependency, separated source/receipt pins, accessor refusal, absent authenticated session refusal, origin/path guards, snapshots during pending initialization, fixed-registry replacement, revoked initial registry, observed-context cancellation/retry and signer-scoped close. Six native scenarios exercise the single constructor through real Ed25519 and selected One PostgreSQL columns: missing existing authentication, complete receipt inspection, cancellation, stale/alternate-registry refusal without registry work, fresh same-port replacement and signer-only close with unchanged session/key authority. Authentication in that fixture is a synthetic server binding, not a real One identity provider. The existing v242 unsigned-domain limitation is unchanged.

The preserved `run-ci-v308.mjs` requires six service records alongside earlier suites and writes `evidence/CI-RESULT-v308.json`. AI review through three lenses by one assistant: TRIAS keeps inspection and trusted control references distinct without claiming authority; ORACLE requires the complete SQL/crypto chain and rejects alternate registry injection; MENTOR requires an explicit host authentication dependency and documents signer-only shutdown. These are not independent approvals. Real One authentication, original One functions, remote TLS, production key custody and release acceptance remain unverified. Acceptance HOLD; authorization NONE; productionReady false.

## Terminal service admission and real-work completion (v309)

An HTTP timeout or client abort can return a response while an inspection provider is still running. Awaiting only the HTTP handler, or closing only the signer, therefore cannot establish that the assembled inspection service has finished its work. `createRioManagedInspectionServiceV309` combines the existing source/issuer/One reader/signer with a drainable route derived from v269. It returns an inspection port and a trusted control port. The original v269 route and v308 factory remain unchanged.

```js
const service = await createRioManagedInspectionServiceV309(trustedConfiguration);
// Same exact configuration contract as v308, including all three explicit limits.
const response = await service.inspection.handle(request);

const status = service.control.getStatus();
// Signer management uses the nested status.signer controller/generation/history fields.
// Keep service.control inside trusted host administration.
const completion = service.control.close();
// Admission is already blocked here. Repeated close() returns this same promise.
const completed = await completion;
// completed.state === 'CLOSED'; tracked inspection/signing work has settled.
```

| Service state | Admission and completion |
| --- | --- |
| OPEN | Original origin, input, capacity, authentication, SQL and crypto controls apply; explicit signer management is available |
| DRAINING | New inspection requests receive no-store 503 INSPECTION_SERVICE_CLOSING before body reads or providers; new retirement/replacement/cancellation commands return null |
| CLOSED | Terminal; route jobs, tracked body-reader cancellation callbacks and signer completion have settled; new work remains refused |

`control.close()` synchronously blocks route admission, requests signer close and waits for both real completion barriers. The route counts execution jobs until they actually settle, including adapter authentication, SQL callbacks and connection-release work. A previously returned 504/408 does not remove its running job from that barrier. Body-reader cancellation promises are counted separately until settlement, even when the pending read has already ended. The route status exposes both counts, and the service status reports inFlightInspections, readerCancellationsInFlight, inspectionCapacity and the nested signer status. Status objects and the completion result are frozen and retain HOLD/NONE.

Close starts signer shutdown immediately. An admitted inspection may therefore fail as signing becomes unavailable; this is not a guarantee that admitted requests complete successfully. Results returned from a still-running handler after closing begins are minimized 503 responses, including a late otherwise-successful inspection. A response already returned to its caller is not retracted. The service does not force SQL, registry, authentication, stream or crypto operations to terminate. Existing jobs may continue callbacks while draining. A nonreturning provider or cancellation callback keeps completion pending; there is no artificial deadline that marks it CLOSED.

Unresolved body-reader cancellation also occupies admission capacity while OPEN, preventing repeated timed-out streams from accumulating unlimited cancellation callbacks. Admission uses the sum of route jobs and pending cancellations; while both are active for one request this is deliberately conservative. Deadline timers and abort listeners are detached before a settled route job releases the drain barrier, so later client aborts cannot start cancellation work after terminal completion.

The managed control port exposes getStatus, getLastAttemptResult, retireGeneration, installReplacement, cancelReplacement and close. Its signer commands retain the v308 narrow replacement contract and shared registry, using controller/generation/completion values from getStatus().signer. Closing prevents further management admission and asks an already pending replacement to withhold installation under the existing v307 close semantics. Service completion waits for that admitted assessment even if no inspection request is running. The signer controller's own CLOSED flag is terminal admission state; the managed service remains DRAINING until the controller's actual completion promise and route barrier resolve.

This barrier covers the assembled service's tracked work. It does not stop a host's HTTP listener, dispose an externally owned connection pool, cancel work the host starts independently, revoke sessions/keys, destroy private keys or establish operating-system isolation. The host should stop its listener and dispose host-owned pools around the completed service barrier as appropriate. Real One authentication remains an explicit external dependency, not a service implemented here. The separate source/receipt pins, initial real key/registry assessment, no raw signing methods and static-before-provider configuration checks are preserved.

Twelve focused tests cover crypto success, frozen/structural state, idle terminal close, late result withholding, provider timeout/abort, asynchronous stream cancellation, multiple admitted jobs, provider failure, invalid service configuration, post-close provider/management refusal and pending replacement assessment. Six native scenarios exercise the managed constructor through real SQL/Ed25519, same-port replacement, a returned HTTP deadline while a One connection release callback is deliberately held, refusal of new provider work, release followed by completion, and a held SQL registry assessment with withheld replacement. The release/registry barriers control callback scheduling; SQL and crypto are not simulated or intercepted. Fixture authentication is synthetic and tables cover selected One column contracts, not original One functions.

The preserved `run-ci-v309.mjs` requires six managed-service records and earlier suites, and writes `evidence/CI-RESULT-v309.json`. AI review through three lenses applied by one assistant: TRIAS keeps terminal admission separate from authority or revocation; ORACLE requires actual connection/provider settlement after a returned timeout and retains the separate cancellation barrier; MENTOR provides one idempotent close promise with observable pending counts and explicit host ownership of listener/pool disposal. These are not independent approvals. Original receipt-domain limits, software-key isolation limits and unverified production authentication/TLS remain. Acceptance HOLD; authorization NONE; productionReady false.

## Host admission, actual service drain and registered resource release (v310)

`createRioInspectionHostLifecycleV310` connects an already constructed v309 service to explicit trusted host callbacks. It returns separate frozen inspection and lifecycle-control ports. It forwards the original Fetch Request and Response without cloning or consuming the body, preserving the signal and existing server-side request binding. It does not implement IncomingMessage conversion, URL/proxy trust, TLS or authentication.

```js
const host = createRioInspectionHostLifecycleV310({
  service: await createRioManagedInspectionServiceV309(trustedConfiguration),
  stopHttpAdmission: () => new Promise((resolve, reject) => {
    server.close(error => error ? reject(error) : resolve());
  }),
  releaseHostResources: async () => { await hostOwnedPool.end(); },
});
const response = await host.inspection.handle(request);
const completion = host.control.close();
const status = await completion; // Check CLOSED versus HELD.
```

Configuration is exactly service, stopHttpAdmission and releaseHostResources, with own enumerable data fields and no getters. The service and its two ports must have the existing v309 shapes and HOLD/NONE boundaries. Construction snapshots callbacks without invoking providers or host effects. Port validation is a contract check for trusted dependencies, not code-provenance verification or OS isolation. The host retains the original managed service reference for signer administration.

Close synchronously blocks new logical inspection requests, invokes transport shutdown first and requests service drain immediately without awaiting transport completion. This concurrent start avoids making service drain wait for HTTP connections that themselves need service completion. Resource release starts only when both stages complete and the service result confirms CLOSED with zero inspection, cancellation, signing and replacement work. Repeated or reentrant close returns one stable completion promise. The inspection port exposes no lifecycle or signing methods.

| State | Meaning |
| --- | --- |
| RUNNING | Same Fetch Request reaches the existing service |
| STOPPING | New host admission is blocked; transport and service completion are pending |
| RELEASING_RESOURCES | Both prior barriers completed; registered release callback is pending |
| CLOSED | All three stages completed successfully |
| HELD | A callback failed or service result was invalid; overall completion is not confirmed |

Status reports httpAdmissionStop, serviceDrain and hostResourceRelease as NOT_STARTED, PENDING, COMPLETED or NOT_CONFIRMED. Status and issue arrays are frozen. Transport stop failure still permits the independently started service drain to settle but skips resource release. Failed, malformed or still-busy service results also skip release. Disposal failure may follow actual partial effects; NOT_CONFIRMED does not mean no change. Responses disclose only fixed issue codes, not exception diagnostics. No automatic retry or reopening follows uncertainty. A nonreturning callback leaves the relevant stage pending; no deadline invents completion.

Callbacks must reflect completion of the host's actual registered work and must not await the same outer completion promise. Callback fulfillment is a trusted host observation, not independent network verification or cryptographic evidence. Unregistered resources, independently started work, proxy admission, upgraded connections and transport-to-Fetch security remain host responsibilities. The adapter does not create a listener, force query/crypto/socket cancellation, revoke sessions/keys or issue authority.

Twelve focused tests cover static/accessor refusal, frozen ports, unchanged request/signal/body/Response, concurrent ordered shutdown, callback reentry, both pending barriers, stop failure, malformed/busy service result, pending/failed disposal, captured configuration and actual v309 key-checked service drain. Six native scenarios use actual PostgreSQL and Ed25519 plus a temporary loopback-only HTTP listener: full inspection; HTTP 504 while a real One release callback holds its connection; listener stop and new connection refusal; resource release after actual drain; failed stop skipping disposal; and actual partial disposal followed by rejection without retry. Callback barriers control scheduling; SQL and crypto are not intercepted.

The fixture wire is plain loopback HTTP, with a fixed logical HTTPS Fetch Request and a synthetic trusted session binding. It is not a production IncomingMessage bridge, real One login or TLS test. Production authentication, original One functions, remote TLS, key custody and later gateway compatibility remain unverified. The Node 24 server.close contract is described by the [official HTTP API](https://nodejs.org/download/release/v24.22.3/docs/api/http.html#serverclosecallback). Forced socket cleanup is restricted to fixture failure cleanup.

`test:ci` uses `run-ci-v310.mjs`, requires six new host records alongside all preserved suites and writes `evidence/CI-RESULT-v310.json`. AI review through three lenses by one assistant: TRIAS separates lifecycle from authority and host trust; ORACLE requires real listener/database observations and preserves uncertainty after partial disposal; MENTOR provides one observable close operation with explicit failure stages and no automatic retry. These are not independent approvals. Acceptance HOLD; authorization NONE; productionReady false. A production transport/authentication adapter remains a separate engineering and acceptance step.
