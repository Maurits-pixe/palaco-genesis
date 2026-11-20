/**
 * PALACO RIO v243 — independent signature verifier, read-only.
 * Trust anchor: supplied server-side key resolver (NOT keys embedded in receipts).
 * Verifies the EXACT JSON serialization signed in v242.
 * ES256 requires IEEE-P1363 (64 byte r||s) signatures.
 */
import {createHash,createPublicKey,verify as cryptoVerify} from 'node:crypto';

const ID=/^[A-Za-z0-9_-]{1,128}$/;
const HEX=/^[a-f0-9]{64}$/;
const B64URL=/^[A-Za-z0-9_-]+$/;
const ALGORITHMS=new Set(['Ed25519','ES256','RS256']);
const fail=reason=>Object.freeze({
  ok:false,reason,state:'HOLD_UNVERIFIED',acceptance:'HOLD',
  authorization:'NONE',mayMigrate:false,mayRollback:false,mayDelete:false
});
const iso=value=>typeof value==='string'&&Number.isFinite(Date.parse(value))&&
  new Date(value).toISOString()===value;
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const exact=(value,keys)=>object(value)&&Object.keys(value).length===keys.length&&
  keys.every(k=>Object.hasOwn(value,k));
const strictId=value=>typeof value==='string'&&ID.test(value);
const sha256=text=>createHash('sha256').update(text,'utf8').digest('hex');
const canonicalBase=['format','requestId','kind','actorAuditRef','subjectId'];
const canonicalTail=['reason','generation','committedAt','authorityEvidenceRef',
  'acceptance','authorization','retriedRevocation','mayMigrate'];
function canonicalEvidence(e){
  if(!object(e)||e.format!=='rio-revocation-evidence-v242')return null;
  if(!['session','policy'].includes(e.kind))return null;
  const mid=e.kind==='session'?['sessionRef']:['conversationId','dossierId'];
  const keys=[...canonicalBase,...mid,...canonicalTail];
  if(!exact(e,keys)||!keys.filter(k=>k!=='format'&&k!=='kind'&&k!=='reason'&&
    k!=='generation'&&k!=='committedAt'&&k!=='acceptance'&&k!=='authorization'&&
    k!=='retriedRevocation'&&k!=='mayMigrate').every(k=>strictId(e[k])))return null;
  if(e.reason!==(e.kind==='session'?'REVOKED':'POLICY_CHANGED')||
    !Number.isSafeInteger(e.generation)||e.generation<1||
    !iso(e.committedAt)||e.acceptance!=='HOLD'||e.authorization!=='NONE'||
    e.retriedRevocation!==false||e.mayMigrate!==false)return null;
  // Reconstruct in v242's exact property ordering so reordering input fields
  // cannot accidentally verify while displaying different bytes.
  return Object.fromEntries(keys.map(k=>[k,e[k]]));
}
function decodeBase64url(value){
  if(typeof value!=='string'||value.length>4096||value.length<32||
    !B64URL.test(value)||value.length%4===1)return null;
  const buffer=Buffer.from(value,'base64url');
  if(buffer.toString('base64url')!==value)return null;
  return buffer;
}
function verifyKey(key,algorithm){
  if(key.type!=='public')return false;
  if(algorithm==='Ed25519')return key.asymmetricKeyType==='ed25519';
  if(algorithm==='ES256')return key.asymmetricKeyType==='ec'&&
    key.asymmetricKeyDetails?.namedCurve==='prime256v1';
  if(algorithm==='RS256')return key.asymmetricKeyType==='rsa'&&
    Number.isInteger(key.asymmetricKeyDetails?.modulusLength)&&
    key.asymmetricKeyDetails.modulusLength>=2048;
  return false;
}
export function createRioReceiptVerifierV243({
  resolveVerificationKey,
  now=()=>new Date(),
  // Independent authority recheck is mandatory: signed evidence alone does
  // NOT prove current session or policy revocation state.
  verifyCurrentAuthority
}={}){
  if(typeof resolveVerificationKey!=='function'||
     typeof verifyCurrentAuthority!=='function')
    throw new TypeError('TRUSTED_VERIFICATION_SERVICES_REQUIRED');
  async function verifyReceipt(receipt){
    try{
      if(!exact(receipt,['ok','format','evidence','sha256','signature',
        'keyId','algorithm','signatureValidation','acceptance','authorization',
        'mayMigrate','mayRollback','mayDelete'])||
        receipt.ok!==true||receipt.format!=='rio-revocation-receipt-v242'||
        receipt.acceptance!=='HOLD'||receipt.authorization!=='NONE'||
        receipt.mayMigrate!==false||receipt.mayRollback!==false||
        receipt.mayDelete!==false||
        receipt.signatureValidation!=='NOT_VERIFIED_IN_THIS_MODULE'||
        !strictId(receipt.keyId)||!ALGORITHMS.has(receipt.algorithm)||
        !HEX.test(receipt.sha256))return fail('RECEIPT_SHAPE_INVALID');
      const evidence=canonicalEvidence(receipt.evidence);
      if(evidence===null)return fail('EVIDENCE_SHAPE_INVALID');
      // Signer in v242 signs JSON.stringify(evidence), no added envelope.
      // Requiring identical property ordering prevents misleading exports.
      if(JSON.stringify(receipt.evidence)!==JSON.stringify(evidence))
        return fail('NON_CANONICAL_EVIDENCE');
      const payload=JSON.stringify(evidence);
      if(sha256(payload)!==receipt.sha256)
        return fail('EVIDENCE_DIGEST_MISMATCH');
      const signature=decodeBase64url(receipt.signature);
      if(!signature)return fail('SIGNATURE_ENCODING_INVALID');
      if((receipt.algorithm==='Ed25519'&&signature.length!==64)||
         (receipt.algorithm==='ES256'&&signature.length!==64)||
         (receipt.algorithm==='RS256'&&signature.length<256))
        return fail('SIGNATURE_LENGTH_INVALID');
      const date=now();
      if(!(date instanceof Date)||!Number.isFinite(date.getTime()))
        return fail('VERIFICATION_CLOCK_UNAVAILABLE');
      // The server-side resolver MUST consult a pinned, trusted registry.
      // User-provided JWK, URLs, or keys in the receipt are NOT accepted.
      const keyRecord=await resolveVerificationKey({
        keyId:receipt.keyId,algorithm:receipt.algorithm
      });
      if(!keyRecord||keyRecord.state!=='ACTIVE'||
        keyRecord.keyId!==receipt.keyId||
        keyRecord.algorithm!==receipt.algorithm||
        keyRecord.revoked!==false||
        typeof keyRecord.publicKeyPem!=='string'||
        !iso(keyRecord.notBefore)||!iso(keyRecord.notAfter)||
        date.getTime()<Date.parse(keyRecord.notBefore)||
        date.getTime()>=Date.parse(keyRecord.notAfter))
        return fail('KEY_UNTRUSTED_REVOKED_OR_EXPIRED');
      const key=createPublicKey(keyRecord.publicKeyPem);
      if(!verifyKey(key,receipt.algorithm))return fail('KEY_TYPE_OR_STRENGTH_MISMATCH');
      const options=receipt.algorithm==='ES256'
        ?{key,dsaEncoding:'ieee-p1363'}:key;
      const valid=cryptoVerify(receipt.algorithm==='Ed25519'?null:'sha256',
        Buffer.from(payload,'utf8'),options,signature);
      if(!valid)return fail('CRYPTOGRAPHIC_SIGNATURE_INVALID');
      // Recheck current authoritative state after signature validation.
      // No claim of historical non-revocation is made.
      const authority=await verifyCurrentAuthority(Object.freeze({
        requestId:evidence.requestId,kind:evidence.kind,
        subjectId:evidence.subjectId,
        ...(evidence.kind==='session'
          ?{sessionRef:evidence.sessionRef}
          :{conversationId:evidence.conversationId,dossierId:evidence.dossierId}),
        generation:evidence.generation,
        authorityEvidenceRef:evidence.authorityEvidenceRef
      }));
      if(authority?.state!=='REVOKED_CONFIRMED'||
        authority.requestId!==evidence.requestId||
        authority.generation!==evidence.generation||
        authority.evidenceRef!==evidence.authorityEvidenceRef)
        return fail('AUTHORITY_STATUS_NOT_CONFIRMED');
      return Object.freeze({
        ok:true,format:'rio-audit-signature-verification-v243',
        requestId:evidence.requestId,keyId:receipt.keyId,
        algorithm:receipt.algorithm,sha256:receipt.sha256,
        verifiedAt:date.toISOString(),
        signatureStatus:'CRYPTOGRAPHICALLY_VALID',
        keyStatus:'ACTIVE_AT_VERIFICATION',
        authorityStatus:'CURRENT_REVOCATION_CONFIRMED',
        proofScope:'CURRENT_EVIDENCE_ONLY_NOT_HISTORICAL_ATTESTATION',
        acceptance:'HOLD',authorization:'NONE',
        mayMigrate:false,mayRollback:false,mayDelete:false
      });
    }catch{
      return fail('VERIFICATION_FAILED');
    }
  }
  return Object.freeze({verifyReceipt,mode:'READ_ONLY_INDEPENDENT_VERIFICATION',
    authorization:'NONE',mayMigrate:false});
}
