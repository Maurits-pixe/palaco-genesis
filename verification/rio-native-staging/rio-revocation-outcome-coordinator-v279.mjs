/** Outcome-aware transaction facade; no connection, credential or authority supplied. */
import {createRioAuditedRevocationWriterV241} from './rio-audited-revocation-writer-v241.mjs';

export function createRioRevocationOutcomeCoordinatorV279({
  acquireConnection,applySessionAuthorityMutation,applyPolicyAuthorityMutation,
}={}) {
  if([acquireConnection,applySessionAuthorityMutation,applyPolicyAuthorityMutation]
    .some(fn=>typeof fn!=='function'))throw TypeError('TRUSTED_TRANSACTION_DEPENDENCIES_REQUIRED');
  async function execute(kind,request) {
    let outcome='NOT_STARTED',cleanup='NOT_REQUIRED';
    const writer=createRioAuditedRevocationWriterV241({
      applySessionAuthorityMutation,applyPolicyAuthorityMutation,
      withTransaction:async work=>{
        let connection,discard=false;
        try{
          connection=await acquireConnection();
          if(typeof connection?.query!=='function'||typeof connection?.release!=='function'){
            discard=true;throw Error('INVALID_CONNECTION_PORT');
          }
          await connection.query('BEGIN');
          outcome='OPEN';
          const result=await work(Object.freeze({query:(sql,values)=>connection.query(sql,values)}));
          // An exception from COMMIT cannot tell whether the server committed.
          outcome='COMMIT_SENT';
          await connection.query('COMMIT');
          outcome='COMMIT_CONFIRMED';
          return result;
        }catch{
          if(outcome==='COMMIT_SENT'){
            outcome='UNKNOWN_COMMIT_OUTCOME';discard=true;
          }else if(outcome==='OPEN'){
            try{await connection.query('ROLLBACK');outcome='ROLLBACK_CONFIRMED';}
            catch{outcome='ROLLBACK_OUTCOME_UNKNOWN';discard=true;}
          }else{discard=true;}
          throw Error('TRANSACTION_PORT_FAILED');
        }finally{
          if(connection){
            try{
              if(typeof connection.release==='function'){
                await connection.release(discard?new Error('DISCARD_TRANSACTION_CONNECTION'):undefined);
                cleanup='RELEASED';
              }else cleanup='FAILED_INVALID_PORT';
            }catch{cleanup='FAILED';}
          }
        }
      },
    });
    const result=await (kind==='session'?writer.revokeSession(request):writer.revokeDossierReview(request));
    const unknown=outcome==='UNKNOWN_COMMIT_OUTCOME'||outcome==='ROLLBACK_OUTCOME_UNKNOWN';
    return Object.freeze({...result,
      ...(unknown?{ok:false,state:'UNKNOWN_REQUIRES_READ_ONLY_RECONCILIATION',
        reason:outcome==='UNKNOWN_COMMIT_OUTCOME'?'COMMIT_OUTCOME_UNKNOWN':'ROLLBACK_OUTCOME_UNKNOWN'}:{}),
      format:'rio-revocation-outcome-v279',transactionOutcome:outcome,connectionCleanup:cleanup,
      automaticRetryAllowed:false,requiresReadOnlyReconciliation:unknown,
      acceptance:'HOLD',authorization:'NONE',mayExecute:false,mayMigrate:false,mayRollback:false,mayDelete:false,
    });
  }
  return Object.freeze({revokeSession:request=>execute('session',request),
    revokeDossierReview:request=>execute('policy',request),
    purpose:'TRUSTED_TRANSACTION_OUTCOME_CLASSIFICATION',automaticRetryAllowed:false,authorization:'NONE'});
}
