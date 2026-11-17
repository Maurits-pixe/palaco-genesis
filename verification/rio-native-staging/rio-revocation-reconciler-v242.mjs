/**
 * PALACO RIO v242 — read-only reconciliation and signed receipt preparation.
 *
 * This file has NO mutation SQL, no retry of revocation, and no authority
 * changes. A signed receipt REQUIRES an external trusted signing service.
 */
import {createHash} from 'node:crypto';

const ID=/^[A-Za-z0-9_-]{1,128}$/;
const HEX=/^[a-f0-9]{64}$/;
const DENY=reason=>Object.freeze({ok:false,reason,
  state:'HOLD_UNVERIFIED',acceptance:'HOLD',authorization:'NONE',
  mayMigrate:false,mayRollback:false,mayDelete:false,
  retriedRevocation:false});
const canonical=(kind,req)=>{
  if(kind!=='session'&&kind!=='policy')throw Error('INVALID_KIND');
  const keys=kind==='session'
    ?['requestId','actorAuditRef','subjectId','sessionRef','reason']
    :['requestId','actorAuditRef','subjectId','conversationId','dossierId','reason'];
  if(!req||typeof req!=='object'||Array.isArray(req)||
    Object.keys(req).length!==keys.length||keys.some(k=>!Object.hasOwn(req,k)))
    throw Error('INVALID_REQUEST_SHAPE');
  for(const k of keys){
    if(k==='reason')continue;
    if(typeof req[k]!=='string'||!ID.test(req[k]))throw Error('INVALID_'+k);
  }
  if(req.reason!==(kind==='session'?'REVOKED':'POLICY_CHANGED'))
    throw Error('INVALID_REASON');
  return Object.freeze({kind,...Object.fromEntries(keys.map(k=>[k,req[k]]))});
};
const same=(a,b)=>a&&b&&typeof a==='object'&&!Array.isArray(a)&&
  Object.keys(a).length===Object.keys(b).length&&
  Object.keys(b).every(k=>typeof a[k]===typeof b[k]&&a[k]===b[k]);
const generation=value=>{
  if(typeof value==='number'&&!Number.isSafeInteger(value))return null;
  if(typeof value==='string'&&!/^[1-9][0-9]*$/.test(value))return null;
  if(typeof value!=='number'&&typeof value!=='string')return null;
  const n=Number(value);
  return Number.isSafeInteger(n)&&n>0?n:null;
};
const digest=message=>createHash('sha256').update(message,'utf8').digest('hex');
const timeOk=v=>typeof v==='string'&&Number.isFinite(Date.parse(v)) &&
  new Date(v).toISOString()===v;
function createRioRevocationReconcilerV242({query,verifyCurrentAuthority,signReceipt}={}){
  if(typeof query!=='function'||typeof verifyCurrentAuthority!=='function')
    throw TypeError('TRUSTED_READ_SERVICES_REQUIRED');
  let inProgress=false;
  async function reconcile(kind,request){
    if(inProgress)return DENY('RECONCILIATION_BUSY');
    let expected;
    try{expected=canonical(kind,request);}catch{return DENY('INVALID_REQUEST');}
    inProgress=true;
    try{
      // Parameterized, read-only SELECT. Does not begin or mutate transactions.
      const result=await query(
        `SELECT request_payload,status,result_generation,recorded_at
           FROM rio_identity_gate.revocation_requests WHERE request_id=$1`,
        [expected.requestId]);
      if(result?.rows?.length!==1)return DENY('REQUEST_NOT_FOUND_OR_AMBIGUOUS');
      const row=result.rows[0];
      let stored=typeof row.request_payload==='string'
        ?JSON.parse(row.request_payload):row.request_payload;
      if(!same(stored,expected))return DENY('IDEMPOTENCY_REQUEST_MISMATCH');
      if(row.status!=='COMPLETE')return DENY('NOT_COMMITTED_OR_IN_PROGRESS');
      const gen=generation(row.result_generation);
      if(gen===null)return DENY('INVALID_COMMITTED_GENERATION');
      const committedAt=row.recorded_at instanceof Date
        ?row.recorded_at.toISOString():row.recorded_at;
      if(!timeOk(committedAt))return DENY('INVALID_COMMIT_TIMESTAMP');
      // Required current-authority check; registry outcome ALONE is not proof
      // that the authoritative session or policy change took effect.
      const authority=await verifyCurrentAuthority(Object.freeze({
        kind,request:Object.freeze({...expected}),generation:gen
      }));
      if(authority?.state!=='REVOKED_CONFIRMED'||
        authority.requestId!==expected.requestId||
        authority.generation!==gen||
        typeof authority.evidenceRef!=='string'||
        !ID.test(authority.evidenceRef))
        return DENY('AUTHORITY_NOT_INDEPENDENTLY_CONFIRMED');
      const evidence=Object.freeze({
        format:'rio-revocation-evidence-v242',
        requestId:expected.requestId,
        kind,actorAuditRef:expected.actorAuditRef,
        subjectId:expected.subjectId,
        ...(kind==='session'
          ?{sessionRef:expected.sessionRef}
          :{conversationId:expected.conversationId,dossierId:expected.dossierId}),
        reason:expected.reason,generation:gen,
        committedAt,authorityEvidenceRef:authority.evidenceRef,
        acceptance:'HOLD',authorization:'NONE',
        retriedRevocation:false,mayMigrate:false
      });
      const payload=JSON.stringify(evidence);
      const sha256=digest(payload);
      return Object.freeze({
        ok:true,state:'COMMIT_FOUND_AND_AUTHORITY_CONFIRMED',
        format:'rio-revocation-reconciliation-v242',
        evidence,sha256,
        acceptance:'HOLD',authorization:'NONE',
        mayMigrate:false,mayRollback:false,mayDelete:false,
        retriedRevocation:false,
        integrity:'SHA256_ONLY_NOT_AN_AUTHENTICATED_SIGNATURE'
      });
    }catch{return DENY('READ_OR_AUTHORITY_VERIFICATION_FAILED');}
    finally{inProgress=false;}
  }
  async function sign(reconciled){
    if(typeof signReceipt!=='function')return DENY('TRUSTED_SIGNER_MISSING');
    if(reconciled?.ok!==true||
      reconciled.state!=='COMMIT_FOUND_AND_AUTHORITY_CONFIRMED'||
      reconciled.format!=='rio-revocation-reconciliation-v242'||
      !HEX.test(reconciled.sha256)||
      digest(JSON.stringify(reconciled.evidence))!==reconciled.sha256)
      return DENY('UNVERIFIED_EVIDENCE');
    try{
      // Signer is a trusted external HSM / backend signature service.
      // Signature validation and key rotation are NOT provided here.
      const proof=await signReceipt(Object.freeze({
        payload:JSON.stringify(reconciled.evidence),
        digestSha256:reconciled.sha256
      }));
      if(proof?.state!=='SIGNED'||typeof proof.keyId!=='string'||
        !ID.test(proof.keyId)||typeof proof.signatureBase64url!=='string'||
        !/^[A-Za-z0-9_-]{32,4096}$/.test(proof.signatureBase64url)||
        typeof proof.algorithm!=='string'||
        !['Ed25519','ES256','RS256'].includes(proof.algorithm))
        return DENY('SIGNATURE_SERVICE_REJECTED');
      return Object.freeze({
        ok:true,format:'rio-revocation-receipt-v242',
        evidence:reconciled.evidence,
        sha256:reconciled.sha256,
        signature:proof.signatureBase64url,
        keyId:proof.keyId,algorithm:proof.algorithm,
        signatureValidation:'NOT_VERIFIED_IN_THIS_MODULE',
        acceptance:'HOLD',authorization:'NONE',mayMigrate:false,
        mayRollback:false,mayDelete:false
      });
    }catch{return DENY('SIGNATURE_SERVICE_FAILED');}
  }
  return Object.freeze({reconcile,sign,
    purpose:'READ_ONLY_RECONCILIATION',
    authorization:'NONE',mayMigrate:false});
}
export {createRioRevocationReconcilerV242};
