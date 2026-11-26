import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, generateKeyPairSync, sign} from 'node:crypto';
import {createRioRevocationReconcilerV242} from '../rio-revocation-reconciler-v242.mjs';
import {createRioReceiptVerifierV243} from '../rio-receipt-verifier-v243.mjs';
import {createRioRequestBoundReceiptGuardV244} from '../rio-request-bound-receipt-guard-v244.mjs';

// Ephemeral private keys and synthetic data exist only in process memory.
const pairs = {
  Ed25519: generateKeyPairSync('ed25519'),
  ES256: generateKeyPairSync('ec', {namedCurve: 'prime256v1'}),
  RS256: generateKeyPairSync('rsa', {modulusLength: 2048}),
};
const rogue = generateKeyPairSync('ed25519');
const NOW = Date.parse('2026-11-16T07:00:00.000Z');
const COMMIT = '2026-11-16T06:00:00.000Z';
const SESSION = Object.freeze({requestId: 'synthetic-request', actorAuditRef: 'synthetic-actor',
  subjectId: 'synthetic-subject', sessionRef: 'synthetic-session', reason: 'REVOKED'});
const POLICY = Object.freeze({requestId: 'synthetic-policy', actorAuditRef: 'synthetic-actor',
  subjectId: 'synthetic-subject', conversationId: 'synthetic-conversation',
  dossierId: 'synthetic-dossier', reason: 'POLICY_CHANGED'});
const expected = (kind = 'session') => ({kind, ...(kind === 'session' ? SESSION : POLICY), generation: 9});
const clone = value => JSON.parse(JSON.stringify(value));
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const publicPem = key => key.export({format: 'pem', type: 'spki'});
const keyRecord = algorithm => ({state: 'ACTIVE', keyId: 'synthetic-' + algorithm, algorithm,
  revoked: false, publicKeyPem: publicPem(pairs[algorithm].publicKey),
  notBefore: '2026-11-01T00:00:00.000Z', notAfter: '2026-12-01T00:00:00.000Z'});
const confirmed = observed => {
  const {authorityEvidenceRef, ...request} = observed;
  return {state: 'REVOKED_CONFIRMED', ...request, evidenceRef: authorityEvidenceRef};
};
function host(overrides = {}) {
  const calls = {key: 0, authority: 0};
  const instance = createRioRequestBoundReceiptGuardV244({
    allowedKeyIds: Object.keys(pairs).map(algorithm => keyRecord(algorithm).keyId),
    resolveVerificationKey: async lookup => {
      calls.key++;
      assert.equal(Object.isFrozen(lookup), true);
      return keyRecord(lookup.algorithm);
    },
    verifyCurrentAuthority: async observed => {
      calls.authority++;
      assert.equal(Object.isFrozen(observed), true);
      return confirmed(observed);
    },
    now: () => new Date(NOW), ...overrides,
  });
  return {instance, calls};
}
async function produce(algorithm = 'Ed25519', kind = 'session', committedAt = COMMIT) {
  const req = kind === 'session' ? SESSION : POLICY;
  let selects = 0;
  const producer = createRioRevocationReconcilerV242({
    query: async (sql, values) => {
      selects++;
      assert.match(sql.trim(), /^SELECT\s/);
      assert.deepEqual(values, [req.requestId]);
      return {rows: [{request_payload: {kind, ...req}, status: 'COMPLETE',
        result_generation: '9', recorded_at: committedAt}]};
    },
    verifyCurrentAuthority: async () => ({state: 'REVOKED_CONFIRMED',
      requestId: req.requestId, generation: 9, evidenceRef: 'synthetic-authority'}),
    signReceipt: async ({payload, digestSha256}) => {
      assert.equal(hash(JSON.parse(payload)), digestSha256);
      const signature = sign(algorithm === 'Ed25519' ? null : 'sha256', Buffer.from(payload),
        algorithm === 'ES256' ? {key: pairs[algorithm].privateKey, dsaEncoding: 'ieee-p1363'} : pairs[algorithm].privateKey);
      return {state: 'SIGNED', keyId: keyRecord(algorithm).keyId, algorithm,
        signatureBase64url: signature.toString('base64url')};
    },
  });
  const receipt = await producer.sign(await producer.reconcile(kind, req));
  assert.equal(receipt.ok, true);
  assert.equal(selects, 1);
  return receipt;
}
const receipts = Object.fromEntries(await Promise.all(Object.keys(pairs)
  .map(async algorithm => [algorithm, await produce(algorithm)])));
const run = (receipt = receipts.Ed25519, context = expected(), instance = host().instance) =>
  instance.verifyForRequest(JSON.stringify(receipt), context);
function denied(result, reason) {
  assert.equal(result.ok, false);
  assert.equal(result.reason, reason);
  assert.equal(result.acceptance, 'HOLD');
  assert.equal(result.authorization, 'NONE');
  for (const flag of ['mayExecute', 'mayMigrate', 'mayRollback', 'mayDelete', 'retriedRevocation'])
    assert.equal(result[flag], false);
}

for (const algorithm of Object.keys(pairs)) {
  test(algorithm + ': real v242 signer → unchanged v243 verifier → v244 request guard', async () => {
    const {instance, calls} = host();
    const result = await run(receipts[algorithm], expected(), instance);
    assert.equal(result.ok, true);
    assert.equal(result.signatureStatus, 'CRYPTOGRAPHICALLY_VALID');
    assert.equal(result.requestBinding, 'MATCHED_ORIGINAL_SERVER_REQUEST');
    assert.equal(result.authorityStatus, 'CURRENT_REVOCATION_CONFIRMED');
    assert.equal(result.domainBinding, 'NOT_SIGNED_IN_V242');
    assert.equal(result.acceptance, 'HOLD');
    assert.equal(result.authorization, 'NONE');
    for (const flag of ['mayExecute', 'mayMigrate', 'mayRollback', 'mayDelete', 'retriedRevocation'])
      assert.equal(result[flag], false);
    assert.equal(Object.isFrozen(result), true);
    assert.equal(Object.hasOwn(result, 'subjectId'), false);
    assert.equal(Object.hasOwn(result, 'requestId'), false);
    assert.deepEqual(calls, {key: 1, authority: 1});
  });
}
test('policy receipt binds dossier and conversation as well as actor and generation', async () => {
  const receipt = await produce('ES256', 'policy');
  assert.equal((await run(receipt, expected('policy'))).ok, true);
  for (const key of ['conversationId', 'dossierId', 'actorAuditRef', 'generation'])
    denied(await run(receipt, {...expected('policy'), [key]: key === 'generation' ? 10 : 'other'}), 'EXPECTED_REQUEST_MISMATCH');
});
test('each session expectation mismatch is refused before trusted services are called', async () => {
  for (const key of ['requestId', 'actorAuditRef', 'subjectId', 'sessionRef', 'generation']) {
    const {instance, calls} = host();
    denied(await run(receipts.Ed25519, {...expected(), [key]: key === 'generation' ? 10 : 'other'}, instance), 'EXPECTED_REQUEST_MISMATCH');
    assert.deepEqual(calls, {key: 0, authority: 0});
  }
});
test('missing or malformed original request is refused', async () => {
  for (const value of [null, {}, {...expected(), extra: true}, {...expected(), generation: '9'},
    {...expected(), generation: Number.MAX_SAFE_INTEGER + 1}, {...expected(), reason: 'OTHER'}])
    denied(await run(receipts.Ed25519, value), 'EXPECTED_SERVER_REQUEST_REQUIRED');
});
test('unlisted signing key never triggers registry lookup', async () => {
  const {instance, calls} = host();
  denied(await run({...receipts.Ed25519, keyId: 'external-key'}, expected(), instance), 'UNPINNED_SIGNING_KEY');
  assert.deepEqual(calls, {key: 0, authority: 0});
});
test('changed evidence with original hash fails', async () => {
  const value = clone(receipts.Ed25519);
  value.evidence.authorityEvidenceRef = 'altered';
  denied(await run(value), 'EVIDENCE_DIGEST_MISMATCH');
});
for (const algorithm of Object.keys(pairs)) {
  test(algorithm + ': recomputed hash cannot replace an authentic signature', async () => {
    const value = clone(receipts[algorithm]);
    value.evidence.authorityEvidenceRef = 'altered';
    value.sha256 = hash(value.evidence);
    denied(await run(value), 'CRYPTOGRAPHIC_SIGNATURE_INVALID');
  });
}
test('wrong signing key and modified signature fail before authority lookup', async () => {
  for (const mode of ['wrong-key', 'changed-byte']) {
    const value = clone(receipts.Ed25519);
    const bytes = mode === 'wrong-key' ? sign(null, Buffer.from(JSON.stringify(value.evidence)), rogue.privateKey) : Buffer.from(value.signature, 'base64url');
    if (mode === 'changed-byte') bytes[0] ^= 1;
    value.signature = bytes.toString('base64url');
    const {instance, calls} = host();
    denied(await run(value, expected(), instance), 'CRYPTOGRAPHIC_SIGNATURE_INVALID');
    assert.deepEqual(calls, {key: 1, authority: 0});
  }
});
test('cryptographically valid receipt cannot bypass full authority scope confirmation', async () => {
  for (const key of ['kind', 'requestId', 'actorAuditRef', 'subjectId', 'sessionRef', 'reason', 'generation']) {
    const {instance} = host({verifyCurrentAuthority: async observed =>
      ({...confirmed(observed), [key]: key === 'generation' ? 10 : 'other'})});
    denied(await run(receipts.Ed25519, expected(), instance), 'AUTHORITY_STATUS_NOT_CONFIRMED');
  }
});
test('old partial authority reply is insufficient for the new host contract', async () => {
  const {instance} = host({verifyCurrentAuthority: async observed =>
    ({state: 'REVOKED_CONFIRMED', requestId: observed.requestId,
      generation: observed.generation, evidenceRef: observed.authorityEvidenceRef})});
  denied(await run(receipts.Ed25519, expected(), instance), 'AUTHORITY_STATUS_NOT_CONFIRMED');
});
test('revoked, inactive, expired and unknown registry keys are refused', async () => {
  for (const patch of [{revoked: true}, {state: 'RETIRED'}, {notAfter: '2026-11-16T07:00:00.000Z'},
    {keyId: 'other'}, {algorithm: 'ES256'}, {notBefore: '2026-11-17T00:00:00.000Z'}]) {
    const {instance} = host({resolveVerificationKey: async () => ({...keyRecord('Ed25519'), ...patch})});
    denied(await run(receipts.Ed25519, expected(), instance), 'KEY_UNTRUSTED_REVOKED_OR_EXPIRED');
  }
});
test('private key material and key supplied by a receipt are refused', async () => {
  const {instance} = host({resolveVerificationKey: async () => ({...keyRecord('Ed25519'),
    publicKeyPem: pairs.Ed25519.privateKey.export({format: 'pem', type: 'pkcs8'})})});
  denied(await run(receipts.Ed25519, expected(), instance), 'KEY_UNTRUSTED_REVOKED_OR_EXPIRED');
  denied(await run({...receipts.Ed25519, publicKeyPem: keyRecord('Ed25519').publicKeyPem}), 'RECEIPT_SHAPE_INVALID');
});
test('key type mismatch is refused', async () => {
  const {instance} = host({resolveVerificationKey: async () => ({...keyRecord('Ed25519'),
    publicKeyPem: keyRecord('ES256').publicKeyPem})});
  denied(await run(receipts.Ed25519, expected(), instance), 'KEY_TYPE_OR_STRENGTH_MISMATCH');
});
test('DER ECDSA and undersized RSA keys are refused by the existing verifier', async () => {
  const value = clone(receipts.ES256);
  value.signature = sign('sha256', Buffer.from(JSON.stringify(value.evidence)), pairs.ES256.privateKey).toString('base64url');
  denied(await run(value), 'SIGNATURE_LENGTH_INVALID');
  const small = generateKeyPairSync('rsa', {modulusLength: 1024});
  const {instance} = host({resolveVerificationKey: async () => ({...keyRecord('RS256'), publicKeyPem: publicPem(small.publicKey)})});
  denied(await run(receipts.RS256, expected(), instance), 'KEY_TYPE_OR_STRENGTH_MISMATCH');
});
test('unsupported algorithms and noncanonical signature encoding are refused', async () => {
  for (const algorithm of ['none', 'HS256', 'ed25519'])
    denied(await run({...receipts.Ed25519, algorithm}), 'RECEIPT_SHAPE_INVALID');
  for (const signature of ['', receipts.Ed25519.signature + '=', '*'.repeat(86)])
    denied(await run({...receipts.Ed25519, signature}), 'SIGNATURE_ENCODING_INVALID');
});
test('permission promotion and unknown fields fail closed', async () => {
  for (const patch of [{authorization: 'ALLOW'}, {acceptance: 'PASS'}, {mayMigrate: true},
    {mayRollback: true}, {mayDelete: true}, {signatureValidation: 'VERIFIED'}, {extra: true}])
    denied(await run({...receipts.Ed25519, ...patch}), 'RECEIPT_SHAPE_INVALID');
  const value = clone(receipts.Ed25519);
  value.evidence.authorization = 'ALLOW';
  denied(await run(value), 'EVIDENCE_SHAPE_INVALID');
});
test('canonical v242 evidence ordering is preserved rather than silently broadened', async () => {
  const value = clone(receipts.Ed25519);
  value.evidence = Object.fromEntries(Object.entries(value.evidence).reverse());
  denied(await run(value), 'NON_CANONICAL_EVIDENCE');
});
test('bounded JSON parser refuses objects, oversize UTF-8, invalid JSON and scalars', async () => {
  const {instance} = host();
  for (const value of [receipts.Ed25519, ' '.repeat(16385), 'é'.repeat(9000)])
    denied(await instance.verifyForRequest(value, expected()), 'INVALID_OR_OVERSIZED_JSON');
  denied(await instance.verifyForRequest('{', expected()), 'INVALID_JSON');
  for (const value of [null, [], 4, 'text']) denied(await run(value), 'INVALID_RECEIPT');
});
test('a signed commit from the future is refused before host calls', async () => {
  const value = await produce('Ed25519', 'session', '2026-11-16T07:00:00.001Z');
  const {instance, calls} = host();
  denied(await run(value, expected(), instance), 'COMMIT_TIMESTAMP_IN_FUTURE');
  assert.deepEqual(calls, {key: 0, authority: 0});
});
test('missing, throwing or invalid explicit clock has no implicit fallback', async () => {
  for (const now of [() => {throw Error('private-clock-detail');}, () => NaN,
    () => new Date(NaN), () => NOW, () => Promise.resolve(new Date(NOW))]) {
    const {instance, calls} = host({now});
    const result = await run(receipts.Ed25519, expected(), instance);
    denied(result, 'TRUSTED_CLOCK_UNAVAILABLE');
    assert.equal(JSON.stringify(result).includes('private-clock-detail'), false);
    assert.deepEqual(calls, {key: 0, authority: 0});
  }
});
test('key expiry during asynchronous verification is caught at completion', async () => {
  let time = NOW;
  const {instance} = host({now: () => new Date(time),
    resolveVerificationKey: async () => ({...keyRecord('Ed25519'), notAfter: '2026-11-16T07:00:01.000Z'}),
    verifyCurrentAuthority: async observed => {time += 1000; return confirmed(observed);}});
  denied(await run(receipts.Ed25519, expected(), instance), 'KEY_EXPIRED_DURING_VERIFICATION');
});
test('backward clock movement and lost completion clock are refused', async () => {
  let calls = 0;
  const {instance} = host({now: () => new Date(calls++ === 0 ? NOW : NOW - 1)});
  denied(await run(receipts.Ed25519, expected(), instance), 'VERIFICATION_CLOCK_MOVED_BACKWARDS');
  let secondCalls = 0;
  const second = host({now: () => {if (secondCalls++ > 0) throw Error('clock-offline'); return new Date(NOW);}});
  denied(await run(receipts.Ed25519, expected(), second.instance), 'TRUSTED_CLOCK_UNAVAILABLE');
});
test('callback failure is contained without exposing diagnostics', async () => {
  for (const service of ['resolveVerificationKey', 'verifyCurrentAuthority']) {
    const {instance} = host({[service]: async () => {throw Error('private-server-detail');}});
    const result = await run(receipts.Ed25519, expected(), instance);
    denied(result, 'VERIFICATION_FAILED');
    assert.equal(JSON.stringify(result).includes('private-server-detail'), false);
  }
});
test('expected request and allowlist are snapshotted across asynchronous host calls', async () => {
  const context = expected();
  const ids = ['synthetic-Ed25519'];
  const {instance} = host({allowedKeyIds: ids, resolveVerificationKey: async () => {
    context.subjectId = 'changed-after-start';
    ids.length = 0;
    return keyRecord('Ed25519');
  }});
  assert.equal((await run(receipts.Ed25519, context, instance)).ok, true);
});
test('concurrent verification requests do not share request context', async () => {
  const policy = await produce('RS256', 'policy');
  const {instance} = host();
  const results = await Promise.all([run(receipts.Ed25519, expected(), instance), run(policy, expected('policy'), instance)]);
  assert.equal(results.every(result => result.ok && result.mayExecute === false), true);
});
test('constructor requires pinned IDs, explicit clock and both trusted services', () => {
  const complete = {allowedKeyIds: ['key'], now: () => new Date(NOW),
    resolveVerificationKey: async () => null, verifyCurrentAuthority: async () => null};
  for (const config of [undefined, {}, {...complete, now: undefined}, {...complete, allowedKeyIds: []},
    {...complete, allowedKeyIds: ['key', 'key']}, {...complete, allowedKeyIds: ['../key']},
    {...complete, resolveVerificationKey: undefined}, {...complete, verifyCurrentAuthority: undefined}])
    assert.throws(() => createRioRequestBoundReceiptGuardV244(config), TypeError);
});
test('legacy v243 public API remains independently callable and unchanged', async () => {
  const instance = createRioReceiptVerifierV243({now: () => new Date(NOW),
    resolveVerificationKey: async () => keyRecord('Ed25519'),
    verifyCurrentAuthority: async observed => ({state: 'REVOKED_CONFIRMED',
      requestId: observed.requestId, generation: observed.generation, evidenceRef: observed.authorityEvidenceRef})});
  const result = await instance.verifyReceipt(receipts.Ed25519);
  assert.equal(result.ok, true);
  assert.equal(result.format, 'rio-audit-signature-verification-v243');
});
