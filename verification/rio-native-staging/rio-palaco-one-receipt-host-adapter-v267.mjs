/**
 * PALACO RIO v267: read-only receipt inspection host adapter.
 * Real session, ACL, request-ledger, authority and PostgreSQL services are
 * mandatory trusted host dependencies. This module does not supply an IdP.
 */
import {createHash, createPublicKey} from 'node:crypto';
import {createRioTrustedKeyResolverV244} from './rio-trusted-key-registry-v244.mjs';
import {createRioRequestBoundReceiptGuardV244} from './rio-request-bound-receipt-guard-v244.mjs';

const ID = /^[A-Za-z0-9_-]{1,128}$/;
const HEX = /^[a-f0-9]{64}$/;
const ALG = new Set(['Ed25519', 'ES256', 'RS256']);
const PURPOSE = 'RIO_REVOCATION_AUDIT_REVIEW_ONLY';
const MAX_RECEIPT_BYTES = 16 * 1024;
const id = x => typeof x === 'string' && ID.test(x);
const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const exact = (x, keys) => object(x) && Object.keys(x).length === keys.length &&
  keys.every(key => Object.hasOwn(x, key));
const serial = n => Number.isSafeInteger(n) && n >= 0;
const BOUNDARIES = Object.freeze({acceptance: 'HOLD', authorization: 'NONE',
  mayExecute: false, mayMigrate: false, mayRollback: false, mayDelete: false,
  retriedRevocation: false, productionReady: false});
const deny = reason => Object.freeze({ok: false, state: 'HOLD_UNVERIFIED', reason, ...BOUNDARIES});
const same = (a, b) => a && b && Object.keys(a).length === Object.keys(b).length &&
  Object.keys(a).every(key => a[key] === b[key]);
function time(now) {
  const date = now();
  if (!(date instanceof Date) || !Number.isFinite(date.getTime())) throw Error('CLOCK_UNAVAILABLE');
  return date.getTime();
}
function actorSnapshot(value, tenantRef) {
  const keys = ['state', 'assurance', 'tenantRef', 'subjectId', 'sessionRef', 'sessionGeneration'];
  if (!exact(value, keys)) return null;
  const a = Object.fromEntries(keys.map(key => [key, value[key]]));
  if (a.state !== 'ACTIVE' || a.assurance !== 'HOST_VERIFIED' || a.tenantRef !== tenantRef ||
      !id(a.subjectId) || !id(a.sessionRef) || !serial(a.sessionGeneration)) return null;
  return Object.freeze(a);
}
function policySnapshot(value, context) {
  const keys = ['state', 'purpose', 'tenantRef', 'reviewerSubjectId', 'reviewerSessionRef',
    'reviewerSessionGeneration', 'requestId', 'policyRevision'];
  if (!exact(value, keys)) return null;
  const p = Object.fromEntries(keys.map(key => [key, value[key]]));
  if (p.state !== 'PERMITTED' || p.purpose !== PURPOSE || !serial(p.policyRevision) ||
      Object.keys(context).some(key => p[key] !== context[key])) return null;
  return Object.freeze(p);
}
function requestSnapshot(value, tenantRef, requestId) {
  if (!exact(value, ['state', 'tenantRef', 'recordRevision', 'request']) ||
      value.state !== 'COMPLETE' || value.tenantRef !== tenantRef || !serial(value.recordRevision) ||
      !object(value.request)) return null;
  const r = value.request;
  if (r.kind !== 'session' && r.kind !== 'policy') return null;
  const keys = ['kind', 'requestId', 'actorAuditRef', 'subjectId',
    ...(r.kind === 'session' ? ['sessionRef'] : ['conversationId', 'dossierId']),
    'reason', 'generation'];
  if (!exact(r, keys)) return null;
  const req = Object.freeze(Object.fromEntries(keys.map(key => [key, r[key]])));
  if (req.requestId !== requestId || !Number.isSafeInteger(req.generation) || req.generation < 1 ||
      req.reason !== (req.kind === 'session' ? 'REVOKED' : 'POLICY_CHANGED') ||
      !keys.filter(key => !['kind', 'reason', 'generation'].includes(key)).every(key => id(req[key]))) return null;
  return Object.freeze({recordRevision: value.recordRevision, request: req});
}

export function createRioReceiptHostAdapterV267({tenantRef, keyPins,
  authenticateHostRequest, readInspectionPolicy, readOriginalRevocationRequest,
  confirmCurrentRevocation, queryVerificationKeys, now,
} = {}) {
  if (!id(tenantRef) || !Array.isArray(keyPins) || keyPins.length < 1 || keyPins.length > 32 ||
      [authenticateHostRequest, readInspectionPolicy, readOriginalRevocationRequest,
        confirmCurrentRevocation, queryVerificationKeys, now].some(fn => typeof fn !== 'function')) {
    throw TypeError('TRUSTED_HOST_DEPENDENCIES_REQUIRED');
  }
  const pins = new Map();
  const fingerprints = new Set();
  for (const pin of keyPins) {
    if (!exact(pin, ['keyId', 'algorithm', 'spkiSha256']) || !id(pin.keyId) ||
        !ALG.has(pin.algorithm) || typeof pin.spkiSha256 !== 'string' || !HEX.test(pin.spkiSha256) ||
        pins.has(pin.keyId) || fingerprints.has(pin.spkiSha256)) throw TypeError('INVALID_INDEPENDENT_KEY_PINS');
    pins.set(pin.keyId, Object.freeze({...pin}));
    fingerprints.add(pin.spkiSha256);
  }
  const keyRegistry = createRioTrustedKeyResolverV244({query: queryVerificationKeys, now});
  async function pinnedKey(lookup) {
    const pin = pins.get(lookup.keyId);
    if (!pin || pin.algorithm !== lookup.algorithm) return null;
    const key = await keyRegistry.resolveVerificationKey(lookup);
    if (!key) return null;
    const fingerprint = createHash('sha256').update(createPublicKey(key.publicKeyPem)
      .export({type: 'spki', format: 'der'})).digest('hex');
    return fingerprint === pin.spkiSha256 ? key : null;
  }
  async function inspect(hostRequest, input) {
    if (!exact(input, ['requestId', 'receiptJson'])) return deny('INVALID_INSPECTION_INPUT');
    // Copy before awaiting any service. Caller data is never an identity source.
    const requestId = input.requestId, receiptJson = input.receiptJson;
    if (!id(requestId) || typeof receiptJson !== 'string' || receiptJson.length > MAX_RECEIPT_BYTES ||
        Buffer.byteLength(receiptJson, 'utf8') > MAX_RECEIPT_BYTES) return deny('INVALID_INSPECTION_INPUT');
    try {
      const startedAt = time(now);
      const actor = actorSnapshot(await authenticateHostRequest(hostRequest), tenantRef);
      if (!actor) return deny('HOST_SESSION_NOT_VERIFIED');
      const context = Object.freeze({tenantRef, reviewerSubjectId: actor.subjectId,
        reviewerSessionRef: actor.sessionRef, reviewerSessionGeneration: actor.sessionGeneration, requestId});
      const policy = policySnapshot(await readInspectionPolicy(context), context);
      if (!policy) return deny('RECEIPT_INSPECTION_NOT_PERMITTED');
      const recordKey = Object.freeze({tenantRef, requestId});
      const original = requestSnapshot(await readOriginalRevocationRequest(recordKey), tenantRef, requestId);
      if (!original) return deny('ORIGINAL_SERVER_REQUEST_UNAVAILABLE');
      const guard = createRioRequestBoundReceiptGuardV244({
        allowedKeyIds: [...pins.keys()], now,
        resolveVerificationKey: pinnedKey,
        verifyCurrentAuthority: async expected => {
          const reply = await confirmCurrentRevocation(Object.freeze({tenantRef, ...expected}));
          if (!object(reply) || reply.tenantRef !== tenantRef) return null;
          return reply;
        },
      });
      const verification = await guard.verifyForRequest(receiptJson, original.request);
      if (!verification.ok) return deny(verification.reason);
      // Re-read access and original record after signature/authority callbacks.
      // These reads are NOT atomic with each other or with a future action.
      const freshActor = actorSnapshot(await authenticateHostRequest(hostRequest), tenantRef);
      if (!same(actor, freshActor)) return deny('HOST_SESSION_CHANGED_DURING_INSPECTION');
      const freshPolicy = policySnapshot(await readInspectionPolicy(context), context);
      if (!same(policy, freshPolicy)) return deny('INSPECTION_POLICY_CHANGED');
      const freshOriginal = requestSnapshot(await readOriginalRevocationRequest(recordKey), tenantRef, requestId);
      if (!freshOriginal || freshOriginal.recordRevision !== original.recordRevision ||
          !same(original.request, freshOriginal.request)) return deny('ORIGINAL_SERVER_REQUEST_CHANGED');
      const finalKey = await pinnedKey({keyId: verification.keyId, algorithm: verification.algorithm});
      if (!finalKey) return deny('SIGNING_KEY_CHANGED_OR_REVOKED');
      const completedAt = time(now);
      if (completedAt < startedAt) return deny('HOST_CLOCK_MOVED_BACKWARDS');
      if (completedAt < Date.parse(finalKey.notBefore) || completedAt >= Date.parse(finalKey.notAfter)) {
        return deny('SIGNING_KEY_EXPIRED_BEFORE_RESULT');
      }
      return Object.freeze({ok: true, format: 'rio-receipt-host-inspection-v267',
        state: 'HOST_BOUND_RECEIPT_INSPECTED', sessionCheck: 'RECHECKED', accessCheck: 'RECHECKED',
        originalRequestCheck: 'RECHECKED', keyCheck: 'REGISTRY_AND_INDEPENDENT_PIN_RECHECKED',
        signatureStatus: verification.signatureStatus, authorityStatus: verification.authorityStatus,
        domainBinding: 'NOT_SIGNED_IN_V242', sha256: verification.sha256,
        algorithm: verification.algorithm, inspectedAt: new Date(completedAt).toISOString(),
        proofScope: 'READ_ONLY_HOST_INSPECTION_NOT_FUTURE_AUTHORIZATION', ...BOUNDARIES});
    } catch { return deny('HOST_INSPECTION_FAILED'); }
  }
  return Object.freeze({inspect, purpose: PURPOSE, mode: 'SERVER_ONLY_READ_ONLY', ...BOUNDARIES});
}
