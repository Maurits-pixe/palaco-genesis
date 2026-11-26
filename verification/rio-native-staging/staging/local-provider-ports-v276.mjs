/** Disposable synthetic fixture providers, not a real PALACO One IdP. */
const TENANT='SYNTHETIC_RIO_V276';
export function createLocalFixtureHostV276({query,publicKeyPin,now}={}) {
  if(typeof query!=='function'||typeof now!=='function'||!publicKeyPin)throw TypeError('LOCAL_FIXTURE_PORTS_REQUIRED');
  const one=async(sql,values)=>{
    const result=await query(sql,values);
    return result?.rows?.length===1?result.rows[0]:null;
  };
  return Object.freeze({
    tenantRef:TENANT,keyPins:[Object.freeze({...publicKeyPin})],now,
    // A public synthetic cookie only selects a fixture row. No login is proved.
    authenticateHostRequest:async request=>{
      const cookie=request.headers.get('Cookie')??'';
      const match=/^rio-staging=([A-Za-z0-9_-]{1,128})$/.exec(cookie);
      if(!match)return null;
      const row=await one(`SELECT tenant_ref,subject_id,session_ref,generation
        FROM rio_staging_host.review_sessions
        WHERE tenant_ref=$1 AND session_handle=$2 AND active=true`,[TENANT,match[1]]);
      return row?{state:'ACTIVE',assurance:'HOST_VERIFIED',tenantRef:row.tenant_ref,
        subjectId:row.subject_id,sessionRef:row.session_ref,sessionGeneration:Number(row.generation)}:null;
    },
    readInspectionPolicy:async context=>{
      const row=await one(`SELECT tenant_ref,reviewer_subject_id,reviewer_session_ref,
        reviewer_session_generation,request_id,revision
        FROM rio_staging_host.inspection_policies
        WHERE tenant_ref=$1 AND reviewer_subject_id=$2 AND reviewer_session_ref=$3
          AND reviewer_session_generation=$4 AND request_id=$5 AND permitted=true`,
        [context.tenantRef,context.reviewerSubjectId,context.reviewerSessionRef,
          context.reviewerSessionGeneration,context.requestId]);
      return row?{state:'PERMITTED',purpose:'RIO_REVOCATION_AUDIT_REVIEW_ONLY',
        tenantRef:row.tenant_ref,reviewerSubjectId:row.reviewer_subject_id,
        reviewerSessionRef:row.reviewer_session_ref,
        reviewerSessionGeneration:Number(row.reviewer_session_generation),requestId:row.request_id,
        policyRevision:Number(row.revision)}:null;
    },
    readOriginalRevocationRequest:async lookup=>{
      const row=await one(`SELECT b.tenant_ref,b.record_revision,r.request_payload,r.result_generation
        FROM rio_identity_gate.revocation_requests r
        JOIN rio_staging_host.request_bindings b ON b.request_id=r.request_id
        WHERE b.tenant_ref=$1 AND r.request_id=$2 AND r.status='COMPLETE'`,
        [lookup.tenantRef,lookup.requestId]);
      return row?{state:'COMPLETE',tenantRef:row.tenant_ref,recordRevision:Number(row.record_revision),
        request:{...row.request_payload,generation:Number(row.result_generation)}}:null;
    },
    confirmCurrentRevocation:async expected=>{
      const select=`SELECT b.tenant_ref,b.authority_evidence_ref,r.request_payload,r.result_generation
        FROM rio_identity_gate.revocation_requests r
        JOIN rio_staging_host.request_bindings b ON b.request_id=r.request_id`;
      let row;
      if(expected.kind==='session'){
        row=await one(select+`
          JOIN rio_identity_gate.session_generation s
            ON s.session_ref=r.request_payload->>'sessionRef'
           AND s.subject_id=r.request_payload->>'subjectId'
           AND s.generation=r.result_generation AND s.active=false
          WHERE b.tenant_ref=$1 AND r.request_id=$2 AND r.status='COMPLETE'
            AND r.request_payload->>'kind'='session'`,[expected.tenantRef,expected.requestId]);
      }else if(expected.kind==='policy'){
        row=await one(select+`
          JOIN rio_identity_gate.review_policy_generation p
            ON p.subject_id=r.request_payload->>'subjectId'
           AND p.conversation_id=r.request_payload->>'conversationId'
           AND p.dossier_id=r.request_payload->>'dossierId'
           AND p.generation=r.result_generation AND p.review_permitted=false
          WHERE b.tenant_ref=$1 AND r.request_id=$2 AND r.status='COMPLETE'
            AND r.request_payload->>'kind'='policy'`,[expected.tenantRef,expected.requestId]);
      }else return null;
      return row?{state:'REVOKED_CONFIRMED',tenantRef:row.tenant_ref,...row.request_payload,
        generation:Number(row.result_generation),evidenceRef:row.authority_evidence_ref}:null;
    },
    queryVerificationKeys:(sql,values)=>query(sql,values),
  });
}
