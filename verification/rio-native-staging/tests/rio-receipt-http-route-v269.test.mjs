import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, generateKeyPairSync, sign} from 'node:crypto';
import {createRioReceiptHttpRouteV269, inspectRioReceiptRouteConfigV269,
  RIO_RECEIPT_INSPECTION_PATH_V269 as PATH} from '../rio-receipt-http-route-v269.mjs';

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

test('real Request/Response route executes crypto and both host rechecks', async () => {
  const {route, calls} = harness();
  const result = await route.handle(request());
  assert.equal(result.status, 200);
  safeHeaders(result);
  const body = await result.json();
  assert.equal(body.ok, true);
  assert.equal(body.code, 'RECEIPT_INSPECTED');
  assert.equal(body.signatureStatus, 'CRYPTOGRAPHICALLY_VALID');
  assert.equal(body.domainBinding, 'NOT_SIGNED_IN_V242');
  for (const key of ['subjectId', 'sessionRef', 'tenantRef', 'requestId', 'keyId', 'evidence'])
    assert.equal(Object.hasOwn(body, key), false);
  assert.equal(body.authorization, 'NONE');
  assert.equal(body.acceptance, 'HOLD');
  assert.equal(body.productionReady, false);
  assert.deepEqual(calls, {auth: 2, policy: 2, original: 2, authority: 1, query: 4});
});
test('preflight is structural, makes no provider calls and never marks production ready', () => {
  const {route, config, calls} = harness();
  const result = inspectRioReceiptRouteConfigV269(config);
  assert.equal(result.ok, true);
  assert.equal(result.structuralStatus, 'STRUCTURALLY_VALIDATED');
  assert.equal(result.runtimeDependencyStatus, 'NOT_CHECKED');
  assert.equal(result.providerCallsPerformed, false);
  assert.equal(result.listenerStarted, false);
  assert.equal(result.productionReady, false);
  assert.equal(route.preflight.productionReady, false);
  assert.deepEqual(calls, {auth: 0, policy: 0, original: 0, authority: 0, query: 0});
});
test('invalid startup origin, concurrency, deadline or host dependencies block creation', () => {
  const {config} = harness();
  for (const patch of [{allowedOrigin: 'http://rio.example.test'}, {allowedOrigin: ORIGIN + '/'},
    {allowedOrigin: 'https://user:secret@rio.example.test'}, {maxConcurrentInspections: 0},
    {maxConcurrentInspections: 17}, {requestTimeoutMs: 9}, {requestTimeoutMs: 30001},
    {host: {...config.host, queryVerificationKeys: undefined}}, {extra: true}]) {
    const result = inspectRioReceiptRouteConfigV269({...config, ...patch});
    assert.equal(result.ok, false);
    assert.equal(result.productionReady, false);
    assert.throws(() => createRioReceiptHttpRouteV269({...config, ...patch}), /PREFLIGHT_REJECTED/);
    assert.equal(JSON.stringify(result).includes('secret@'), false);
  }
});
test('wrong path and query routes return no-store 404 without host calls', async () => {
  const {route, calls} = harness();
  for (const url of [ORIGIN + '/other', ORIGIN + PATH + '?requestId=leak', ORIGIN + PATH + '#fragment'])
    await denied(await route.handle(request({url})), 404, 'ROUTE_NOT_FOUND');
  assert.equal(calls.auth, 0);
});
test('GET, HEAD and OPTIONS never inspect a receipt or add CORS headers', async () => {
  const {route, calls} = harness();
  for (const method of ['GET', 'HEAD', 'OPTIONS']) {
    const result = await route.handle(request({method}));
    assert.equal(result.headers.get('Allow'), 'POST');
    await denied(result, 405, 'POST_REQUIRED');
  }
  assert.equal(calls.auth, 0);
});
test('origin, fetch-site, custom-header and destination-origin mismatches fail closed', async () => {
  const {route, calls} = harness();
  for (const headers of [{Origin: null}, {Origin: 'null'}, {Origin: 'https://other.example.test'},
    {'Sec-Fetch-Site': 'cross-site'}, {'X-RIO-Inspection': null}, {'X-RIO-Inspection': '0'}])
    await denied(await route.handle(request({headers})), 403, 'ORIGIN_CHECK_FAILED');
  await denied(await route.handle(request({url: 'https://other.example.test' + PATH})), 403, 'ORIGIN_CHECK_FAILED');
  assert.equal(calls.auth, 0);
});
test('unsupported media types and any content encoding are refused before body processing', async () => {
  const {route, calls} = harness();
  for (const headers of [{'Content-Type': 'text/plain'}, {'Content-Type': null},
    {'Content-Type': 'application/json; charset=iso-8859-1'}, {'Content-Encoding': 'gzip'}, {'Content-Encoding': 'identity'}])
    await denied(await route.handle(request({headers})), 415, 'JSON_UTF8_REQUIRED');
  assert.equal(calls.auth, 0);
});
test('declared length limits and actual byte limits both apply', async () => {
  const {route, calls} = harness();
  for (const value of ['32769', '999999999999999999', '-1', '1.5', '0001'])
    await denied(await route.handle(request({headers: {'Content-Length': value}})), 413, 'BODY_LIMIT_EXCEEDED');
  await denied(await route.handle(request({body: 'é'.repeat(17000)})), 413, 'BODY_LIMIT_EXCEEDED');
  await denied(await route.handle(request({headers: {'Content-Length': '1'}})), 400, 'BODY_LENGTH_MISMATCH');
  assert.equal(calls.auth, 0);
});
test('malformed JSON, invalid UTF-8 and invalid input shape do not reach authentication', async () => {
  const {route, calls} = harness();
  for (const body of ['{', new Uint8Array([0xff]), ''])
    await denied(await route.handle(request({body})), 400, 'INVALID_JSON_BODY');
  for (const value of [null, [], {}, {...input(), role: 'OWNER'}, {...input(), requestId: '../id'},
    {...input(), receiptJson: 'x'.repeat(16385)}])
    await denied(await route.handle(request({body: JSON.stringify(value)})), 400, 'INVALID_INSPECTION_INPUT');
  assert.equal(calls.auth, 0);
});
test('a previously consumed body and a non-Request object are refused', async () => {
  const {route} = harness();
  const req = request();
  await req.text();
  await denied(await route.handle(req), 400, 'UNREAD_BODY_REQUIRED');
  await denied(await route.handle({method: 'POST'}), 400, 'INVALID_REQUEST');
});
test('missing authentication and denied policy have the same minimized external error', async () => {
  const missing = harness();
  const resultA = await missing.route.handle(request({headers: {Cookie: null}}));
  const forbidden = harness({readInspectionPolicy: async () => null});
  const resultB = await forbidden.route.handle(request());
  assert.equal(resultA.status, 403);
  assert.equal(resultB.status, 403);
  assert.deepEqual(await resultA.json(), await resultB.json());
});
test('signature failure and provider exceptions do not leak internal diagnostics', async () => {
  const bad = structuredClone(receipt);
  const bytes = Buffer.from(bad.signature, 'base64url'); bytes[0] ^= 1;
  bad.signature = bytes.toString('base64url');
  const {route, calls} = harness();
  await denied(await route.handle(request({body: JSON.stringify({...input(), receiptJson: JSON.stringify(bad)})})), 403, 'INSPECTION_NOT_CONFIRMED');
  assert.equal(calls.authority, 0);
  const broken = harness({authenticateHostRequest: async () => {throw Error('private-server-detail');}});
  const result = await broken.route.handle(request());
  const text = await result.text();
  assert.equal(result.status, 403);
  assert.equal(text.includes('private-server-detail'), false);
});
test('configuration is snapshotted and later caller mutation cannot open the route', async () => {
  const {route, config} = harness();
  config.allowedOrigin = 'https://attacker.example.test';
  config.maxConcurrentInspections = 100000;
  config.host.keyPins[0].spkiSha256 = '0'.repeat(64);
  assert.equal((await route.handle(request())).status, 200);
});
test('concurrency limit is enforced while the first provider is running', async () => {
  const entered = deferred(), release = deferred();
  let calls = 0;
  const {route} = harness({authenticateHostRequest: async () => {
    if (++calls === 1) {entered.resolve(); await release.promise;} return actor();
  }});
  const first = route.handle(request());
  await entered.promise;
  await denied(await route.handle(request()), 503, 'INSPECTION_CAPACITY_REACHED');
  release.resolve();
  assert.equal((await first).status, 200);
  assert.equal((await route.handle(request())).status, 200);
});
test('provider deadline returns 504 but holds capacity until actual completion', async () => {
  const entered = deferred(), release = deferred();
  let calls = 0;
  const {route} = harness({authenticateHostRequest: async () => {
    if (++calls === 1) {entered.resolve(); await release.promise;} return actor();
  }}, {requestTimeoutMs: 25});
  const first = route.handle(request());
  await entered.promise;
  await denied(await first, 504, 'INSPECTION_DEADLINE_REACHED');
  await denied(await route.handle(request()), 503, 'INSPECTION_CAPACITY_REACHED');
  release.resolve(); await flush();
  assert.equal((await route.handle(request())).status, 200);
});
test('stalled request body times out and never starts host authentication', async () => {
  let cancelled = false;
  const body = new ReadableStream({pull() {}, cancel() {cancelled = true;}});
  const {route, calls} = harness({}, {requestTimeoutMs: 25});
  await denied(await route.handle(request({body, duplex: 'half'})), 504, 'INSPECTION_DEADLINE_REACHED');
  await flush();
  assert.equal(cancelled, true);
  assert.equal(calls.auth, 0);
  assert.equal((await route.handle(request())).status, 200);
});
test('client abort before processing does not call any host provider', async () => {
  const controller = new AbortController(); controller.abort();
  const {route, calls} = harness();
  await denied(await route.handle(request({signal: controller.signal})), 408, 'REQUEST_ABORTED');
  assert.equal(calls.auth, 0);
});
test('client abort while a provider runs retains its occupied slot', async () => {
  const entered = deferred(), release = deferred(), controller = new AbortController();
  let calls = 0;
  const {route} = harness({authenticateHostRequest: async () => {
    if (++calls === 1) {entered.resolve(); await release.promise;} return actor();
  }});
  const first = route.handle(request({signal: controller.signal}));
  await entered.promise; controller.abort();
  await denied(await first, 408, 'REQUEST_ABORTED');
  await denied(await route.handle(request()), 503, 'INSPECTION_CAPACITY_REACHED');
  release.resolve(); await flush();
  assert.equal((await route.handle(request())).status, 200);
});
test('multiple byte chunks form a valid bounded JSON body', async () => {
  const body = new TextEncoder().encode(JSON.stringify(input()));
  const first = body.slice(0, 10), second = body.slice(10);
  let index = 0;
  const stream = new ReadableStream({pull(controller) {
    if (index++ === 0) controller.enqueue(first);
    else {controller.enqueue(second); controller.close();}
  }});
  const {route} = harness();
  assert.equal((await route.handle(request({body: stream, duplex: 'half'}))).status, 200);
});
