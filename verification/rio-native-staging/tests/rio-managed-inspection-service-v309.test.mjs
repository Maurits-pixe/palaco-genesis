import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, createPublicKey, generateKeyPairSync, sign, webcrypto} from 'node:crypto';
import {createRioDrainableReceiptHttpRouteV309 as createRioReceiptHttpRouteV269,
  inspectRioDrainableReceiptRouteConfigV309 as inspectRioReceiptRouteConfigV269} from '../rio-drainable-receipt-http-route-v309.mjs';
import {RIO_RECEIPT_INSPECTION_PATH_V269 as PATH} from '../rio-receipt-http-route-v269.mjs';
import {createRioManagedInspectionServiceV309} from '../rio-managed-inspection-service-v309.mjs';

const ORIGIN = 'https://rio.example.test';
const NOW = Date.parse('2026-11-16T13:00:00.000Z');
const pair = generateKeyPairSync('ed25519');
const publicPem = pair.publicKey.export({format: 'pem', type: 'spki'});
const fingerprint = createHash('sha256').update(pair.publicKey.export({format: 'der', type: 'spki'})).digest('hex');
const expected = {kind: 'session', requestId: 'synthetic-request', actorAuditRef: 'synthetic-revoker',
  subjectId: 'synthetic-target', sessionRef: 'synthetic-target-session', reason: 'REVOKED', generation: 9};
const evidence = {format: 'rio-revocation-evidence-v242', requestId: expected.requestId,
  kind: expected.kind, actorAuditRef: expected.actorAuditRef, subjectId: expected.subjectId,
  sessionRef: expected.sessionRef, reason: expected.reason, generation: expected.generation,
  committedAt: '2026-11-16T12:00:00.000Z', authorityEvidenceRef: 'synthetic-authority',
  acceptance: 'HOLD', authorization: 'NONE', retriedRevocation: false, mayMigrate: false};
const payload = JSON.stringify(evidence);
const receipt = {ok: true, format: 'rio-revocation-receipt-v242', evidence,
  sha256: createHash('sha256').update(payload).digest('hex'),
  signature: sign(null, Buffer.from(payload), pair.privateKey).toString('base64url'),
  keyId: 'synthetic-key', algorithm: 'Ed25519', signatureValidation: 'NOT_VERIFIED_IN_THIS_MODULE',
  acceptance: 'HOLD', authorization: 'NONE', mayMigrate: false, mayRollback: false, mayDelete: false};
const input = () => ({requestId: expected.requestId, receiptJson: JSON.stringify(receipt)});
const keyRow = {key_id: 'synthetic-key', algorithm: 'Ed25519', public_key_pem: publicPem,
  spki_sha256: fingerprint, status: 'ACTIVE', revoked_at: null,
  not_before: '2026-11-01T00:00:00.000Z', not_after: '2026-12-01T00:00:00.000Z'};
const actor = () => ({state: 'ACTIVE', assurance: 'HOST_VERIFIED', tenantRef: 'synthetic-tenant',
  subjectId: 'synthetic-reviewer', sessionRef: 'synthetic-reviewer-session', sessionGeneration: 3});
function harness(hostOverrides = {}, routeOverrides = {}) {
  const calls = {auth: 0, policy: 0, original: 0, authority: 0, query: 0};
  const config = {allowedOrigin: ORIGIN, maxConcurrentInspections: 1, requestTimeoutMs: 1000,
    host: {tenantRef: 'synthetic-tenant', keyPins: [{keyId: 'synthetic-key', algorithm: 'Ed25519', spkiSha256: fingerprint}],
      now: () => new Date(NOW),
      authenticateHostRequest: async request => {
        calls.auth++;
        assert.equal(request instanceof Request, true);
        return request.headers.get('Cookie') === 'synthetic-session=active' ? actor() : null;
      },
      readInspectionPolicy: async context => {calls.policy++; return {...context, state: 'PERMITTED',
        purpose: 'RIO_REVOCATION_AUDIT_REVIEW_ONLY', policyRevision: 1};},
      readOriginalRevocationRequest: async () => {calls.original++; return {state: 'COMPLETE',
        tenantRef: 'synthetic-tenant', recordRevision: 1, request: {...expected}};},
      confirmCurrentRevocation: async request => {
        calls.authority++;
        const {authorityEvidenceRef, ...rest} = request;
        return {...rest, state: 'REVOKED_CONFIRMED', evidenceRef: authorityEvidenceRef};
      },
      queryVerificationKeys: async sql => {calls.query++; assert.match(sql.trim(), /^SELECT\s/); return {rows: [{...keyRow}]};},
      ...hostOverrides,
    }, ...routeOverrides};
  return {route: createRioReceiptHttpRouteV269(config), config, calls};
}
function request({method = 'POST', body = JSON.stringify(input()), url = ORIGIN + PATH,
  headers = {}, signal, duplex} = {}) {
  const options = {method, headers: {'Origin': ORIGIN, 'X-RIO-Inspection': '1',
    'Sec-Fetch-Site': 'same-origin', 'Content-Type': 'application/json',
    'Cookie': 'synthetic-session=active', ...headers}, signal};
  for (const [key, value] of Object.entries(options.headers)) if (value === null) delete options.headers[key];
  if (!['GET', 'HEAD'].includes(method)) options.body = body;
  if (duplex) options.duplex = duplex;
  return new Request(url, options);
}
const deferred = () => {let resolve; const promise = new Promise(r => {resolve = r;}); return {promise, resolve};};
const flush = () => new Promise(resolve => setImmediate(resolve));
function safeHeaders(response) {
  assert.match(response.headers.get('Cache-Control'), /no-store/);
  assert.equal(response.headers.get('X-Content-Type-Options'), 'nosniff');
  assert.equal(response.headers.get('Cross-Origin-Resource-Policy'), 'same-origin');
  assert.equal(response.headers.has('Access-Control-Allow-Origin'), false);
  assert.equal(response.headers.has('Set-Cookie'), false);
}
async function denied(response, status, code) {
  assert.equal(response.status, status);
  safeHeaders(response);
  const body = await response.json();
  assert.equal(body.ok, false);
  assert.equal(body.code, code);
  assert.equal(body.authorization, 'NONE');
  assert.equal(body.acceptance, 'HOLD');
  assert.equal(body.productionReady, false);
}


test('drainable route keeps original crypto, origin guards and frozen structural status',async()=>{
  const {route,config,calls}=harness();assert.equal(Object.isFrozen(route.getStatus()),true);
  assert.equal(inspectRioReceiptRouteConfigV269(config).providerCallsPerformed,false);
  assert.equal((await route.handle(request({headers:{Origin:'https://other.invalid'}}))).status,403);
  assert.equal(calls.auth,0);assert.equal((await route.handle(request())).status,200);
  assert.equal(route.getStatus().inFlight,0);assert.equal(route.getStatus().state,'OPEN');
  await route.close();assert.equal(route.getStatus().state,'CLOSED');
});
test('idle route close is terminal idempotent and rejects before request body or providers',async()=>{
  const {route,calls}=harness(),closed=route.close();assert.equal(closed,route.close());
  assert.equal((await closed).state,'CLOSED');const req=request();
  await denied(await route.handle(req),503,'INSPECTION_SERVICE_CLOSING');assert.equal(req.bodyUsed,false);
  assert.deepEqual(calls,{auth:0,policy:0,original:0,authority:0,query:0});
});
test('route close waits for a parked provider and withholds a late successful receipt',async()=>{
  const entered=deferred(),release=deferred();let count=0;
  const {route}=harness({authenticateHostRequest:async()=>{if(++count===1){entered.resolve();await release.promise;}return actor();}});
  const pending=route.handle(request());await entered.promise;
  let completed=false;const closed=route.close();closed.then(()=>{completed=true;});
  assert.equal(route.getStatus().state,'DRAINING');await flush();assert.equal(completed,false);
  await denied(await route.handle(request()),503,'INSPECTION_SERVICE_CLOSING');assert.equal(count,1);
  release.resolve();await denied(await pending,503,'INSPECTION_SERVICE_CLOSING');await closed;
  assert.equal(route.getStatus().inFlight,0);assert.equal(route.getStatus().state,'CLOSED');
});
test('HTTP deadline cannot complete route close before the actual authentication callback',async()=>{
  const entered=deferred(),release=deferred();
  const {route}=harness({authenticateHostRequest:async()=>{entered.resolve();await release.promise;return null;}},{requestTimeoutMs:25});
  const pending=route.handle(request());await entered.promise;await denied(await pending,504,'INSPECTION_DEADLINE_REACHED');
  assert.equal(route.getStatus().inFlight,1);let completed=false;
  const closed=route.close();closed.then(()=>{completed=true;});await flush();assert.equal(completed,false);
  release.resolve();await closed;assert.equal(route.getStatus().inFlight,0);
});
test('client abort cannot release the real-work close barrier',async()=>{
  const entered=deferred(),release=deferred(),abort=new AbortController();
  const {route}=harness({authenticateHostRequest:async()=>{entered.resolve();await release.promise;return null;}});
  const pending=route.handle(request({signal:abort.signal}));await entered.promise;abort.abort();
  await denied(await pending,408,'REQUEST_ABORTED');assert.equal(route.getStatus().inFlight,1);
  let completed=false;const closed=route.close();closed.then(()=>{completed=true;});await flush();assert.equal(completed,false);
  release.resolve();await closed;assert.equal(route.getStatus().state,'CLOSED');
});
test('pending ReadableStream cancellation remains in the close barrier after read ends',async()=>{
  const entered=deferred(),release=deferred();const body=new ReadableStream({pull(){},cancel(){entered.resolve();return release.promise;}});
  const {route,calls}=harness({}, {requestTimeoutMs:25});
  await denied(await route.handle(request({body,duplex:'half'})),504,'INSPECTION_DEADLINE_REACHED');await entered.promise;await flush();
  assert.equal(route.getStatus().inFlight,0);assert.equal(route.getStatus().readerCancellationsInFlight,1);
  await denied(await route.handle(request()),503,'INSPECTION_CAPACITY_REACHED');assert.equal(calls.auth,0);
  let completed=false;const closed=route.close();closed.then(()=>{completed=true;});await flush();assert.equal(completed,false);
  release.resolve();await closed;assert.equal(route.getStatus().readerCancellationsInFlight,0);assert.equal(calls.auth,0);
});
test('closing waits for every admitted route job rather than the first settled response',async()=>{
  const entered=deferred(),a=deferred(),b=deferred();let count=0;
  const {route}=harness({authenticateHostRequest:async()=>{const n=++count;if(n===2)entered.resolve();await(n===1?a.promise:b.promise);return null;}},{maxConcurrentInspections:2});
  const first=route.handle(request()),second=route.handle(request());await entered.promise;
  let completed=false;const closed=route.close();closed.then(()=>{completed=true;});assert.equal(route.getStatus().inFlight,2);
  a.resolve();await first;await flush();assert.equal(route.getStatus().inFlight,1);assert.equal(completed,false);
  b.resolve();await second;await closed;assert.equal(route.getStatus().state,'CLOSED');
});
test('provider failure still releases its route slot without disclosing diagnostics',async()=>{
  const {route}=harness({authenticateHostRequest:async()=>{throw Error('SYNTHETIC_PRIVATE_DIAGNOSTIC');}});
  const response=await route.handle(request());assert.equal(response.status,403);
  assert.equal((await response.text()).includes('SYNTHETIC_PRIVATE_DIAGNOSTIC'),false);
  assert.equal((await route.close()).state,'CLOSED');assert.equal(route.getStatus().inFlight,0);
});

async function serviceHarness(){
  const pair=await webcrypto.subtle.generateKey({name:'Ed25519'},false,['sign','verify']);
  const pub=createPublicKey({key:Buffer.from(await webcrypto.subtle.exportKey('spki',pair.publicKey)),format:'der',type:'spki'});
  const issuerKey={issuerId:'synthetic-one',keyId:'source-key',publicKeyPem:pub.export({format:'pem',type:'spki'}),
    spkiSha256:createHash('sha256').update(pub.export({format:'der',type:'spki'})).digest('hex')};
  const state={keyReads:0,authReads:0,oneReads:0,key:{state:'ACTIVE',issuerId:issuerKey.issuerId,keyId:issuerKey.keyId,
    revision:1,notBefore:new Date(NOW-60000).toISOString(),notAfter:new Date(NOW+60000).toISOString()}};
  const config={tenantRef:'synthetic-tenant',allowedOrigin:ORIGIN,issuerKey,privateSigningKey:pair.privateKey,
    readIssuerKeyState:async()=>{state.keyReads++;await state.onRegistry?.();return {...state.key};},
    readAuthenticatedOneSession:async()=>{state.authReads++;await state.onAuth?.();return null;},
    acquireOneReadConnection:async()=>{state.oneReads++;throw Error('SYNTHETIC_UNAVAILABLE_SQL');},
    receiptServices:{keyPins:[{keyId:'synthetic-key',algorithm:'Ed25519',spkiSha256:fingerprint}],
      readInspectionPolicy:async()=>null,readOriginalRevocationRequest:async()=>null,
      confirmCurrentRevocation:async()=>null,queryVerificationKeys:async()=>({rows:[]})},
    now:()=>new Date(NOW),limits:{requestTimeoutMs:1000,maxConcurrentInspections:1,maxConcurrentSignatures:1}};
  return {pair,state,config,build:()=>createRioManagedInspectionServiceV309(config)};
}
const command=(x,s)=>{const v=s.control.getStatus().signer;return {controllerId:v.controllerId,expectedGeneration:v.generation,
  expectedLastCompletedAttemptId:v.lastCompletedAttemptId,privateSigningKey:x.pair.privateKey};};
test('managed assembly validates before callbacks and returns frozen separated ports',async()=>{
  const x=await serviceHarness();
  await assert.rejects(createRioManagedInspectionServiceV309({...x.config,limits:{...x.config.limits,maxConcurrentInspections:0}}),TypeError);
  await assert.rejects(createRioManagedInspectionServiceV309({...x.config,readAuthenticatedOneSession:undefined}),TypeError);
  assert.equal(x.state.keyReads,0);
  const service=await x.build();assert.equal(Object.isFrozen(service),true);assert.equal(Object.isFrozen(service.control),true);
  assert.equal(Object.isFrozen(service.inspection),true);assert.equal(x.state.keyReads,2);
  assert.equal(service.control.getStatus().state,'OPEN');assert.equal(service.sessionIssuance,false);
  assert.equal(Object.hasOwn(service.inspection,'close'),false);assert.equal(Object.hasOwn(service.control,'signSessionStatement'),false);
  await service.control.close();
});
test('managed close rejects new inspection and management before callbacks or command getters',async()=>{
  const x=await serviceHarness(),service=await x.build(),closed=service.control.close();assert.equal(closed,service.control.close());
  await closed;const before={...x.state};const req=request();await denied(await service.inspection.handle(req),503,'INSPECTION_SERVICE_CLOSING');
  assert.equal(req.bodyUsed,false);let evaluated=0;const bad={get controllerId(){evaluated++;throw Error('NO');}};
  assert.equal(service.control.retireGeneration(bad),null);assert.equal(await service.control.installReplacement(bad),null);
  assert.equal(service.control.cancelReplacement(bad),null);assert.equal(evaluated,0);
  for(const k of ['keyReads','authReads','oneReads'])assert.equal(x.state[k],before[k]);
  assert.equal(service.control.getStatus().state,'CLOSED');assert.equal(service.control.getStatus().signer.backendState,'STOPPED');
});
test('managed close waits for actual upstream work after a returned HTTP timeout',async()=>{
  const x=await serviceHarness(),entered=deferred(),release=deferred();x.config.limits.requestTimeoutMs=25;
  x.state.onAuth=async()=>{entered.resolve();await release.promise;};const service=await x.build();
  const response=service.inspection.handle(request());await entered.promise;await denied(await response,504,'INSPECTION_DEADLINE_REACHED');
  let completed=false;const closed=service.control.close();closed.then(()=>{completed=true;});
  await flush();const status=service.control.getStatus();assert.equal(status.state,'DRAINING');
  assert.equal(status.inFlightInspections,1);assert.equal(status.signer.backendState,'STOPPED');assert.equal(completed,false);
  release.resolve();await closed;assert.equal(service.control.getStatus().state,'CLOSED');
  assert.equal(service.control.getStatus().inFlightInspections,0);assert.equal(x.state.oneReads,0);
});
test('managed close also waits for an admitted replacement assessment and withholds installation',async()=>{
  const x=await serviceHarness(),service=await x.build();const v=service.control.getStatus().signer;
  await service.control.retireGeneration({controllerId:v.controllerId,expectedGeneration:v.generation});
  const entered=deferred(),release=deferred();x.state.onRegistry=async()=>{entered.resolve();await release.promise;};
  const pending=service.control.installReplacement(command(x,service));await entered.promise;
  let completed=false;const closed=service.control.close();closed.then(()=>{completed=true;});await flush();
  assert.equal(completed,false);assert.equal(service.control.getStatus().signer.candidateChecksInFlight,1);
  assert.equal(service.control.getStatus().inFlightInspections,0);
  release.resolve();assert.equal(await pending,null);await closed;
  assert.equal(service.control.getLastAttemptResult().outcome,'WITHHELD_AFTER_CLOSE');
  assert.equal(service.control.getStatus().signer.generation,1);assert.equal(service.control.getStatus().state,'CLOSED');
});

