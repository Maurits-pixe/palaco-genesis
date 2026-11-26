/**
 * PALACO RIO v241 — reference-only atomic revocation / idempotency / audit.
 *
 * Trusted backend only. withTransaction MUST commit before fulfilling its promise
 * and rollback after ANY callback error. Never take actor IDs from the browser.
 */
const ID=/^[A-Za-z0-9_-]{1,128}$/;
const fail=reason=>Object.freeze({ok:false,reason,acceptance:'HOLD',
  authorization:'NONE',mayMigrate:false,mayRollback:false,mayDelete:false});
const assertId=(v,n)=>{if(typeof v!=='string'||!ID.test(v))throw Error('INVALID_'+n);};
const safeGen=v=>{
  if(!(typeof v==='string'&&/^(0|[1-9][0-9]*)$/.test(v)||
       typeof v==='number'&&Number.isSafeInteger(v)))throw Error('BAD_GENERATION');
  const n=Number(v);
  if(!Number.isSafeInteger(n)||n<=0)throw Error('BAD_GENERATION');
  return n;
};
function canonical(kind,request){
  assertId(request?.requestId,'REQUEST_ID');
  assertId(request?.actorAuditRef,'ACTOR_AUDIT_REF');
  assertId(request?.subjectId,'SUBJECT_ID');
  if(kind==='session'){
    assertId(request.sessionRef,'SESSION_REF');
    if(request.reason!=='REVOKED')throw Error('BAD_REASON');
    return Object.freeze({kind,requestId:request.requestId,
      actorAuditRef:request.actorAuditRef,subjectId:request.subjectId,
      sessionRef:request.sessionRef,reason:request.reason});
  }
  assertId(request.conversationId,'CONVERSATION_ID');
  assertId(request.dossierId,'DOSSIER_ID');
  if(request.reason!=='POLICY_CHANGED')throw Error('BAD_REASON');
  return Object.freeze({kind,requestId:request.requestId,
    actorAuditRef:request.actorAuditRef,subjectId:request.subjectId,
    conversationId:request.conversationId,dossierId:request.dossierId,
    reason:request.reason});
}
function equivalentPayload(a,b){
  if(!a||typeof a!=='object'||Array.isArray(a))return false;
  const ka=Object.keys(a).sort(),kb=Object.keys(b).sort();
  return ka.length===kb.length&&ka.every((k,i)=>
    k===kb[i]&&typeof a[k]===typeof b[k]&&a[k]===b[k]);
}
function single(result){
  if(result?.rowCount!==1||result?.rows?.length!==1)
    throw Error('EXPECTED_ONE_ROW');
  return result.rows[0];
}
export function createRioAuditedRevocationWriterV241({
  withTransaction,applySessionAuthorityMutation,applyPolicyAuthorityMutation
}={}){
  if([withTransaction,applySessionAuthorityMutation,applyPolicyAuthorityMutation]
    .some(f=>typeof f!=='function'))throw TypeError('TRUSTED_BACKEND_REQUIRED');
  let busy=false;
  async function execute(kind,input){
    if(busy)return fail('WRITER_BUSY');
    let req;
    try{req=canonical(kind,input);}catch{return fail('INVALID_REQUEST');}
    busy=true;
    try{
      return await withTransaction(async tx=>{
        if(typeof tx?.query!=='function')throw Error('TX_REQUIRED');
        // Insert before mutation. PostgreSQL unique key serializes concurrent
        // requests with the same idempotency key across processes.
        await tx.query(
          `INSERT INTO rio_identity_gate.revocation_requests
           (request_id,request_payload,status)
           VALUES ($1,$2::jsonb,'PENDING')
           ON CONFLICT (request_id) DO NOTHING`,
          [req.requestId,JSON.stringify(req)]);
        const row=single(await tx.query(
          `SELECT request_payload,status,result_generation,recorded_at
           FROM rio_identity_gate.revocation_requests
           WHERE request_id=$1 FOR UPDATE`,[req.requestId]));
        // Compare exact JSON payload, not a caller-provided digest.
        // PostgreSQL jsonb normalizes object key order.
        const fromDb=typeof row.request_payload==='string'
          ?JSON.parse(row.request_payload):row.request_payload;
        if(!equivalentPayload(fromDb,req))
          throw Error('IDEMPOTENCY_KEY_PAYLOAD_CONFLICT');
        if(row.status==='COMPLETE'){
          const gen=safeGen(row.result_generation);
          return Object.freeze({ok:true,format:'rio-revocation-audit-v241',
            state:'ALREADY_COMMITTED_NO_SECOND_MUTATION',
            requestId:req.requestId,kind,generation:gen,
            actorAuditRef:req.actorAuditRef,acceptance:'HOLD',
            authorization:'NONE',mayMigrate:false,mayRollback:false,mayDelete:false});
        }
        if(row.status!=='PENDING')throw Error('UNKNOWN_REQUEST_STATE');
        const apply=kind==='session'
          ?applySessionAuthorityMutation:applyPolicyAuthorityMutation;
        const mutation=await apply(tx,req);
        if(mutation?.state!=='AUTHORITY_MUTATED'||mutation.changed!==true)
          throw Error('AUTHORITY_MUTATION_UNCONFIRMED');
        let updated;
        if(kind==='session'){
          updated=await tx.query(
            `UPDATE rio_identity_gate.session_generation
             SET generation=generation+1,active=false,updated_at=clock_timestamp()
             WHERE session_ref=$1 AND subject_id=$2 AND active=true
               AND generation < 9007199254740991
             RETURNING generation`,
            [req.sessionRef,req.subjectId]);
        }else{
          updated=await tx.query(
            `UPDATE rio_identity_gate.review_policy_generation
             SET generation=generation+1,review_permitted=false,
                 updated_at=clock_timestamp()
             WHERE subject_id=$1 AND conversation_id=$2 AND dossier_id=$3
               AND review_permitted=true AND generation < 9007199254740991
             RETURNING generation`,
            [req.subjectId,req.conversationId,req.dossierId]);
        }
        const gen=safeGen(single(updated).generation);
        const saved=single(await tx.query(
          `UPDATE rio_identity_gate.revocation_requests
           SET status='COMPLETE',result_generation=$2,recorded_at=clock_timestamp()
           WHERE request_id=$1 AND status='PENDING'
           RETURNING request_id`,[req.requestId,gen]));
        if(saved.request_id!==req.requestId)throw Error('AUDIT_MISMATCH');
        return Object.freeze({ok:true,format:'rio-revocation-audit-v241',
          state:'COMMITTED_ON_TRANSACTION_SUCCESS',
          requestId:req.requestId,kind,generation:gen,
          actorAuditRef:req.actorAuditRef,
          acceptance:'HOLD',authorization:'NONE',
          mayMigrate:false,mayRollback:false,mayDelete:false});
      });
    }catch{
      return fail('TRANSACTION_ABORTED_OR_IDEMPOTENCY_CONFLICT');
    }finally{busy=false;}
  }
  return Object.freeze({
    revokeSession:request=>execute('session',request),
    revokeDossierReview:request=>execute('policy',request),
    purpose:'PRIVILEGED_SERVER_ONLY',
    authorization:'NONE',mayMigrate:false
  });
}
