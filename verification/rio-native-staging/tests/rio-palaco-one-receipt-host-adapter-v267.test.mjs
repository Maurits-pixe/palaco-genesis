import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, generateKeyPairSync, sign} from 'node:crypto';
import {createRioRevocationReconcilerV242} from '../rio-revocation-reconciler-v242.mjs';
import {createRioReceiptHostAdapterV267} from '../rio-palaco-one-receipt-host-adapter-v267.mjs';

// Synthetic database rows, identities and permissions; real ephemeral crypto.
const pairs = {
  Ed25519: generateKeyPairSync('ed25519'),
  ES256: generateKeyPairSync('ec', {namedCurve: 'prime256v1'}),
  RS256: generateKeyPairSync('rsa', {modulusLength: 2048}),
};
const rogue = generateKeyPairSync('ed25519');
const NOW = Date.parse('2026-11-16T12:00:00.000Z');
const TENANT = 'synthetic-tenant';
const PURPOSE = 'RIO_REVOCATION_AUDIT_REVIEW_ONLY';
const HANDLE = Object.freeze({opaqueServerTransport: true});
const sessionRequest = Object.freeze({requestId: 'synthetic-request', actorAuditRef: 'synthetic-revoker',
  subjectId: 'synthetic-target', sessionRef: 'synthetic-target-session', reason: 'REVOKED'});
const policyRequest = Object.freeze({requestId: 'synthetic-policy', actorAuditRef: 'synthetic-revoker',
  subjectId: 'synthetic-target', conversationId: 'synthetic-conversation',
  dossierId: 'synthetic-dossier', reason: 'POLICY_CHANGED'});
const original = (kind = 'session') => ({kind, ...(kind === 'session' ? sessionRequest : policyRequest), generation: 9});
const clone = value => JSON.parse(JSON.stringify(value));
const fingerprint = key => createHash('sha256').update(key.export({format: 'der', type: 'spki'})).digest('hex');
const pin = algorithm => ({keyId: 'synthetic-' + algorithm, algorithm, spkiSha256: fingerprint(pairs[algorithm].publicKey)});
const keyRow = algorithm => ({key_id: pin(algorithm).keyId, algorithm,
  public_key_pem: pairs[algorithm].publicKey.export({format: 'pem', type: 'spki'}),
  spki_sha256: pin(algorithm).spkiSha256, status: 'ACTIVE', revoked_at: null,
  not_before: '2026-11-01T00:00:00.000Z', not_after: '2026-12-01T00:00:00.000Z'});
const actor = () => ({state: 'ACTIVE', assurance: 'HOST_VERIFIED', tenantRef: TENANT,
  subjectId: 'synthetic-reviewer', sessionRef: 'synthetic-reviewer-session', sessionGeneration: 3});
const policy = context => ({state: 'PERMITTED', purpose: PURPOSE, ...context, policyRevision: 7});
const confirmation = input => {
  const {authorityEvidenceRef, ...request} = input;
  return {state: 'REVOKED_CONFIRMED', ...request, evidenceRef: authorityEvidenceRef};
};
async function produce(algorithm = 'Ed25519', kind = 'session') {
  const request = kind === 'session' ? sessionRequest : policyRequest;
  const producer = createRioRevocationReconcilerV242({
    query: async (sql, values) => {
      assert.match(sql.trim(), /^SELECT\s/);
      assert.deepEqual(values, [request.requestId]);
      return {rows: [{request_payload: {kind, ...request}, status: 'COMPLETE', result_generation: 9,
        recorded_at: '2026-11-16T11:00:00.000Z'}]};
    },
    verifyCurrentAuthority: async () => ({state: 'REVOKED_CONFIRMED', requestId: request.requestId,
      generation: 9, evidenceRef: 'synthetic-authority'}),
    signReceipt: async ({payload}) => ({state: 'SIGNED', keyId: pin(algorithm).keyId, algorithm,
      signatureBase64url: sign(algorithm === 'Ed25519' ? null : 'sha256', Buffer.from(payload),
        algorithm === 'ES256' ? {key: pairs[algorithm].privateKey, dsaEncoding: 'ieee-p1363'} : pairs[algorithm].privateKey)
        .toString('base64url')}),
  });
  const receipt = await producer.sign(await producer.reconcile(kind, request));
  assert.equal(receipt.ok, true);
  return receipt;
}
const receipts = Object.fromEntries(await Promise.all(Object.keys(pairs).map(async algorithm => [algorithm, await produce(algorithm)])));
const inputFor = (receipt = receipts.Ed25519) => ({requestId: receipt.evidence.requestId, receiptJson: JSON.stringify(receipt)});
function harness(overrides = {}, kind = 'session') {
  const calls = {auth: 0, policy: 0, original: 0, authority: 0, query: 0};
  const config = {
    tenantRef: TENANT, keyPins: Object.keys(pairs).map(pin), now: () => new Date(NOW),
    authenticateHostRequest: async hostRequest => {
      calls.auth++;
      assert.equal(hostRequest, HANDLE);
      return actor();
    },
    readInspectionPolicy: async context => {
      calls.policy++;
      assert.equal(Object.isFrozen(context), true);
      assert.equal(context.reviewerSubjectId, 'synthetic-reviewer');
      return policy(context);
    },
    readOriginalRevocationRequest: async lookup => {
      calls.original++;
      assert.deepEqual(lookup, {tenantRef: TENANT, requestId: original(kind).requestId});
      return {state: 'COMPLETE', tenantRef: TENANT, recordRevision: 2, request: original(kind)};
    },
    confirmCurrentRevocation: async request => {
      calls.authority++;
      assert.equal(Object.isFrozen(request), true);
      assert.equal(request.subjectId, 'synthetic-target');
      assert.equal(request.tenantRef, TENANT);
      return confirmation(request);
    },
    queryVerificationKeys: async (sql, values) => {
      calls.query++;
      assert.match(sql.trim(), /^SELECT\s/);
      assert.equal(values[0], pin(values[1]).keyId);
      return {rows: [keyRow(values[1])]};
    }, ...overrides,
  };
  return {adapter: createRioReceiptHostAdapterV267(config), calls, config};
}
const run = (adapter = harness().adapter, receipt = receipts.Ed25519) => adapter.inspect(HANDLE, inputFor(receipt));
function denied(result, reason) {
  assert.equal(result.ok, false);
  assert.equal(result.reason, reason);
  assert.equal(result.authorization, 'NONE');
  assert.equal(result.acceptance, 'HOLD');
  for (const flag of ['mayExecute', 'mayMigrate', 'mayRollback', 'mayDelete', 'retriedRevocation', 'productionReady'])
    assert.equal(result[flag], false);
}
for (const algorithm of Object.keys(pairs)) {
  test(algorithm + ': real signer → registry resolver → request guard → host rechecks', async () => {
    const {adapter, calls} = harness();
    const result = await run(adapter, receipts[algorithm]);
    assert.equal(result.ok, true);
    assert.equal(result.signatureStatus, 'CRYPTOGRAPHICALLY_VALID');
    assert.equal(result.sessionCheck, 'RECHECKED');
    assert.equal(result.accessCheck, 'RECHECKED');
    assert.equal(result.keyCheck, 'REGISTRY_AND_INDEPENDENT_PIN_RECHECKED');
    assert.equal(result.domainBinding, 'NOT_SIGNED_IN_V242');
    assert.equal(result.authorization, 'NONE');
    assert.equal(result.acceptance, 'HOLD');
    assert.equal(result.mayExecute, false);
    assert.equal(result.productionReady, false);
    for (const name of ['subjectId', 'sessionRef', 'requestId', 'evidence', 'tenantRef'])
      assert.equal(Object.hasOwn(result, name), false);
    assert.equal(Object.isFrozen(result), true);
    assert.deepEqual(calls, {auth: 2, policy: 2, original: 2, authority: 1, query: 4});
  });
}
test('dossier policy receipts bind reviewer and target as distinct identities', async () => {
  const receipt = await produce('ES256', 'policy');
  assert.equal((await run(harness({}, 'policy').adapter, receipt)).ok, true);
});
test('caller identity and policy claims in the input are rejected before host reads', async () => {
  const {adapter, calls} = harness();
  for (const patch of [{subjectId: 'owner'}, {tenantRef: TENANT}, {role: 'OWNER'}, {authorization: 'ALLOW'}])
    denied(await adapter.inspect(HANDLE, {...inputFor(), ...patch}), 'INVALID_INSPECTION_INPUT');
  assert.deepEqual(calls, {auth: 0, policy: 0, original: 0, authority: 0, query: 0});
});
test('inactive, unverified and cross-tenant host sessions are refused', async () => {
  for (const patch of [{state: 'REVOKED'}, {assurance: 'SELF_REPORTED'}, {tenantRef: 'other-tenant'},
    {sessionGeneration: '3'}, {subjectId: '../actor'}]) {
    const {adapter, calls} = harness({authenticateHostRequest: async () => ({...actor(), ...patch})});
    denied(await run(adapter), 'HOST_SESSION_NOT_VERIFIED');
    assert.equal(calls.original, 0);
    assert.equal(calls.query, 0);
  }
});
test('missing or incorrectly scoped inspection policy prevents original request reads', async () => {
  for (const patch of [{state: 'DENIED'}, {purpose: 'MIGRATE'}, {tenantRef: 'other'},
    {reviewerSubjectId: 'other'}, {reviewerSessionGeneration: 4}, {requestId: 'other'}]) {
    const {adapter, calls} = harness({readInspectionPolicy: async context => ({...policy(context), ...patch})});
    denied(await run(adapter), 'RECEIPT_INSPECTION_NOT_PERMITTED');
    assert.equal(calls.original, 0);
    assert.equal(calls.query, 0);
  }
});
test('server ledger row must be complete, tenant scoped and match the requested ID', async () => {
  const valid = {state: 'COMPLETE', tenantRef: TENANT, recordRevision: 2, request: original()};
  for (const patch of [{state: 'PENDING'}, {tenantRef: 'other'}, {recordRevision: -1},
    {request: {...original(), requestId: 'other'}}, {request: {...original(), generation: '9'}}]) {
    const {adapter, calls} = harness({readOriginalRevocationRequest: async () => ({...valid, ...patch})});
    denied(await run(adapter), 'ORIGINAL_SERVER_REQUEST_UNAVAILABLE');
    assert.equal(calls.query, 0);
  }
});
test('receipt expected values come from the independent ledger, never the receipt', async () => {
  const value = clone(receipts.Ed25519);
  value.evidence.subjectId = 'unrelated-target';
  const {adapter, calls} = harness();
  denied(await run(adapter, value), 'EXPECTED_REQUEST_MISMATCH');
  assert.equal(calls.query, 0);
});
test('changing key and its database fingerprint together cannot bypass independent pins', async () => {
  const {adapter} = harness({queryVerificationKeys: async () => ({rows: [{...keyRow('Ed25519'),
    public_key_pem: rogue.publicKey.export({format: 'pem', type: 'spki'}), spki_sha256: fingerprint(rogue.publicKey)}]})});
  denied(await run(adapter), 'KEY_UNTRUSTED_REVOKED_OR_EXPIRED');
});
test('registry public-key fingerprint mismatch is rejected', async () => {
  const {adapter} = harness({queryVerificationKeys: async () => ({rows: [{...keyRow('Ed25519'), spki_sha256: '0'.repeat(64)}]})});
  denied(await run(adapter), 'KEY_UNTRUSTED_REVOKED_OR_EXPIRED');
});
test('registry revocation during the second SELECT prevents verification', async () => {
  let reads = 0;
  const {adapter} = harness({queryVerificationKeys: async () => ({rows: [{...keyRow('Ed25519'),
    revoked_at: ++reads === 2 ? '2026-11-16T12:00:00.000Z' : null}]})});
  denied(await run(adapter), 'KEY_UNTRUSTED_REVOKED_OR_EXPIRED');
});
test('session loss or generation change while verifying blocks the final result', async () => {
  for (const patch of [{state: 'REVOKED'}, {sessionGeneration: 4}, {subjectId: 'other'}]) {
    let reads = 0;
    const {adapter} = harness({authenticateHostRequest: async () => ({...actor(), ...(++reads > 1 ? patch : {})})});
    denied(await run(adapter), 'HOST_SESSION_CHANGED_DURING_INSPECTION');
  }
});
test('policy permission loss or revision change during verification is refused', async () => {
  for (const patch of [{state: 'DENIED'}, {policyRevision: 8}]) {
    let reads = 0;
    const {adapter} = harness({readInspectionPolicy: async context => ({...policy(context), ...(++reads > 1 ? patch : {})})});
    denied(await run(adapter), 'INSPECTION_POLICY_CHANGED');
  }
});
test('original request revision and payload are rechecked after authority lookup', async () => {
  for (const change of ['revision', 'payload']) {
    let reads = 0;
    const {adapter} = harness({readOriginalRevocationRequest: async () => {
      const changed = ++reads > 1;
      return {state: 'COMPLETE', tenantRef: TENANT, recordRevision: changed && change === 'revision' ? 3 : 2,
        request: {...original(), ...(changed && change === 'payload' ? {generation: 10} : {})}};
    }});
    denied(await run(adapter), 'ORIGINAL_SERVER_REQUEST_CHANGED');
  }
});
test('key revoked after cryptographic verification is refused by final registry read', async () => {
  let reads = 0;
  const {adapter} = harness({queryVerificationKeys: async () => ({rows: [{...keyRow('Ed25519'),
    status: ++reads > 2 ? 'REVOKED' : 'ACTIVE'}]})});
  denied(await run(adapter), 'SIGNING_KEY_CHANGED_OR_REVOKED');
});
test('key expiry during the final registry read is caught before returning', async () => {
  let reads = 0, current = NOW;
  const {adapter} = harness({now: () => new Date(current), queryVerificationKeys: async () => {
    if (++reads === 4) current = NOW + 1000;
    return {rows: [{...keyRow('Ed25519'), not_after: '2026-11-16T12:00:01.000Z'}]};
  }});
  denied(await run(adapter), 'SIGNING_KEY_EXPIRED_BEFORE_RESULT');
});
test('cross-tenant or incomplete current authority confirmations fail', async () => {
  for (const patch of [{tenantRef: 'other'}, {sessionRef: 'other'}, {actorAuditRef: 'other'}, {generation: 10}]) {
    const {adapter} = harness({confirmCurrentRevocation: async request => ({...confirmation(request), ...patch})});
    denied(await run(adapter), 'AUTHORITY_STATUS_NOT_CONFIRMED');
  }
});
test('modified signature never reaches current-authority service', async () => {
  const receipt = clone(receipts.Ed25519);
  const bytes = Buffer.from(receipt.signature, 'base64url');
  bytes[0] ^= 1;
  receipt.signature = bytes.toString('base64url');
  const {adapter, calls} = harness();
  denied(await run(adapter, receipt), 'CRYPTOGRAPHIC_SIGNATURE_INVALID');
  assert.equal(calls.authority, 0);
});
test('provider failures and diagnostics are contained', async () => {
  for (const provider of ['authenticateHostRequest', 'readInspectionPolicy', 'readOriginalRevocationRequest',
    'confirmCurrentRevocation', 'queryVerificationKeys']) {
    const {adapter} = harness({[provider]: async () => {throw Error('secret-provider-diagnostic');}});
    const result = await run(adapter);
    assert.equal(result.ok, false);
    assert.equal(result.authorization, 'NONE');
    assert.equal(JSON.stringify(result).includes('secret-provider-diagnostic'), false);
  }
});
test('explicit clock is required and invalid clock cannot fall back', async () => {
  for (const now of [() => {throw Error('secret-clock');}, () => new Date(NaN), () => NOW]) {
    const {adapter, calls} = harness({now});
    denied(await run(adapter), 'HOST_INSPECTION_FAILED');
    assert.equal(calls.auth, 0);
  }
});
test('input is snapshotted before authentication awaits', async () => {
  const input = inputFor();
  const {adapter} = harness({authenticateHostRequest: async () => {
    input.requestId = 'mutated'; input.receiptJson = '{}'; return actor();
  }});
  assert.equal((await adapter.inspect(HANDLE, input)).ok, true);
});
test('independent key pins are snapshotted from the trusted configuration', async () => {
  const pins = [pin('Ed25519')];
  const {adapter} = harness({keyPins: pins});
  pins[0].spkiSha256 = '0'.repeat(64); pins.length = 0;
  assert.equal((await run(adapter)).ok, true);
});
test('oversized input is rejected without authenticating', async () => {
  const {adapter, calls} = harness();
  denied(await adapter.inspect(HANDLE, {requestId: 'id', receiptJson: 'é'.repeat(9000)}), 'INVALID_INSPECTION_INPUT');
  assert.equal(calls.auth, 0);
});
test('constructor fails with missing services, duplicate or invalid pins', () => {
  const {config} = harness();
  for (const patch of [{now: undefined}, {tenantRef: ''}, {keyPins: []},
    {keyPins: [pin('Ed25519'), pin('Ed25519')]},
    {keyPins: [pin('Ed25519'), {...pin('Ed25519'), keyId: 'alias'}]},
    {keyPins: [{...pin('Ed25519'), spkiSha256: 'not-a-hash'}]},
    {authenticateHostRequest: undefined}, {readOriginalRevocationRequest: undefined}])
    assert.throws(() => createRioReceiptHostAdapterV267({...config, ...patch}), TypeError);
});
test('concurrent independent inspections do not share actor or request state', async () => {
  const {adapter} = harness();
  const results = await Promise.all(Object.values(receipts).map(receipt => run(adapter, receipt)));
  assert.equal(results.every(result => result.ok && result.mayExecute === false), true);
});
