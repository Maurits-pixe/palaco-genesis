/**
 * RIO v244: bounded host-request guard around the unchanged v243 verifier.
 * Server-only, read-only. Injected services and expectedRequest MUST be trusted.
 * No tenant/issuer/audience is signed in v242; this does not add that proof.
 */
import {createRioReceiptVerifierV243} from './rio-receipt-verifier-v243.mjs';

const ID = /^[A-Za-z0-9_-]{1,128}$/;
const MAX_BYTES = 16 * 1024;
const id = value => typeof value === 'string' && ID.test(value);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exact = (value, keys) => object(value) && Object.keys(value).length === keys.length &&
  keys.every(key => Object.hasOwn(value, key));
const boundaries = Object.freeze({acceptance: 'HOLD', authorization: 'NONE',
  mayExecute: false, mayMigrate: false, mayRollback: false, mayDelete: false,
  retriedRevocation: false});
const deny = reason => Object.freeze({ok: false, state: 'HOLD_UNVERIFIED', reason, ...boundaries});
function requestKeys(kind) {
  if (kind !== 'session' && kind !== 'policy') return null;
  return ['kind', 'requestId', 'actorAuditRef', 'subjectId',
    ...(kind === 'session' ? ['sessionRef'] : ['conversationId', 'dossierId']),
    'reason', 'generation'];
}
function snapshotRequest(value) {
  const keys = requestKeys(value?.kind);
  if (keys === null || !exact(value, keys)) return null;
  const copy = Object.fromEntries(keys.map(key => [key, value[key]]));
  if (!Number.isSafeInteger(copy.generation) || copy.generation < 1 ||
      copy.reason !== (copy.kind === 'session' ? 'REVOKED' : 'POLICY_CHANGED') ||
      !keys.filter(key => !['kind', 'reason', 'generation'].includes(key))
        .every(key => id(copy[key]))) return null;
  return Object.freeze(copy);
}
function clockTime(now) {
  const date = now();
  if (!(date instanceof Date) || !Number.isFinite(date.getTime())) throw Error('INVALID_CLOCK');
  return date.getTime();
}

export function createRioRequestBoundReceiptGuardV244({
  allowedKeyIds, resolveVerificationKey, verifyCurrentAuthority, now,
} = {}) {
  if (!Array.isArray(allowedKeyIds) || allowedKeyIds.length < 1 || allowedKeyIds.length > 32 ||
      !allowedKeyIds.every(id) || new Set(allowedKeyIds).size !== allowedKeyIds.length ||
      [resolveVerificationKey, verifyCurrentAuthority, now].some(fn => typeof fn !== 'function')) {
    throw TypeError('PINNED_KEY_IDS_AND_TRUSTED_SERVICES_REQUIRED');
  }
  const pinnedIds = new Set(allowedKeyIds);
  async function verifyForRequest(receiptJson, expectedRequest) {
    if (typeof receiptJson !== 'string' || receiptJson.length > MAX_BYTES ||
        Buffer.byteLength(receiptJson, 'utf8') > MAX_BYTES) return deny('INVALID_OR_OVERSIZED_JSON');
    let receipt;
    try { receipt = JSON.parse(receiptJson); }
    catch { return deny('INVALID_JSON'); }
    const expected = snapshotRequest(expectedRequest);
    if (!expected) return deny('EXPECTED_SERVER_REQUEST_REQUIRED');
    if (!object(receipt) || !object(receipt.evidence)) return deny('INVALID_RECEIPT');
    if (requestKeys(expected.kind).some(key => receipt.evidence[key] !== expected[key])) {
      return deny('EXPECTED_REQUEST_MISMATCH');
    }
    if (!pinnedIds.has(receipt.keyId)) return deny('UNPINNED_SIGNING_KEY');
    // Private JSON-owned snapshot: callbacks cannot mutate caller-owned evidence.
    Object.freeze(receipt.evidence);
    Object.freeze(receipt);
    let startedAt;
    try { startedAt = clockTime(now); } catch { return deny('TRUSTED_CLOCK_UNAVAILABLE'); }
    const committedAt = Date.parse(receipt.evidence.committedAt);
    if (Number.isFinite(committedAt) && committedAt > startedAt) return deny('COMMIT_TIMESTAMP_IN_FUTURE');
    let resolvedKey;
    try {
      const verifier = createRioReceiptVerifierV243({
        now: () => new Date(startedAt),
        resolveVerificationKey: async lookup => {
          const source = await resolveVerificationKey(Object.freeze({...lookup}));
          if (!object(source) || typeof source.publicKeyPem !== 'string' ||
              source.publicKeyPem.length > 8192 ||
              !source.publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----')) return null;
          // Do not pass a mutable registry record across asynchronous boundaries.
          resolvedKey = Object.freeze(Object.fromEntries([
            'state', 'keyId', 'algorithm', 'revoked', 'publicKeyPem', 'notBefore', 'notAfter',
          ].map(key => [key, source[key]])));
          return resolvedKey;
        },
        verifyCurrentAuthority: async observed => {
          if (observed.requestId !== expected.requestId || observed.kind !== expected.kind ||
              observed.subjectId !== expected.subjectId || observed.generation !== expected.generation ||
              (expected.kind === 'session' ? observed.sessionRef !== expected.sessionRef :
                observed.conversationId !== expected.conversationId || observed.dossierId !== expected.dossierId)) {
            return null;
          }
          const confirmation = await verifyCurrentAuthority(Object.freeze({
            ...expected, authorityEvidenceRef: observed.authorityEvidenceRef,
          }));
          // The host must echo the FULL scope it independently checked, not just
          // the requestId/generation. Echoing without checking is not trusted.
          if (!object(confirmation) || confirmation.state !== 'REVOKED_CONFIRMED' ||
              confirmation.evidenceRef !== observed.authorityEvidenceRef ||
              requestKeys(expected.kind).some(key => confirmation[key] !== expected[key])) return null;
          return Object.freeze({state: 'REVOKED_CONFIRMED', requestId: expected.requestId,
            generation: expected.generation, evidenceRef: observed.authorityEvidenceRef});
        },
      });
      const result = await verifier.verifyReceipt(receipt);
      if (!result.ok) return deny(result.reason);
      let completedAt;
      try { completedAt = clockTime(now); } catch { return deny('TRUSTED_CLOCK_UNAVAILABLE'); }
      if (completedAt < startedAt) return deny('VERIFICATION_CLOCK_MOVED_BACKWARDS');
      if (!resolvedKey || completedAt < Date.parse(resolvedKey.notBefore) ||
          completedAt >= Date.parse(resolvedKey.notAfter)) return deny('KEY_EXPIRED_DURING_VERIFICATION');
      return Object.freeze({ok: true, format: 'rio-request-bound-receipt-verification-v244',
        state: 'SIGNATURE_AND_REQUEST_SCOPE_CONFIRMED',
        signatureStatus: result.signatureStatus, keyStatus: result.keyStatus,
        authorityStatus: result.authorityStatus,
        requestBinding: 'MATCHED_ORIGINAL_SERVER_REQUEST',
        domainBinding: 'NOT_SIGNED_IN_V242',
        keyId: result.keyId, algorithm: result.algorithm, sha256: result.sha256,
        verifiedAt: new Date(completedAt).toISOString(),
        proofScope: 'HOST_BOUND_CURRENT_CHECK_NOT_AUTHORIZATION', ...boundaries});
    } catch { return deny('VERIFICATION_FAILED'); }
  }
  return Object.freeze({verifyForRequest, mode: 'READ_ONLY_REQUEST_BOUND_VERIFICATION', ...boundaries});
}
