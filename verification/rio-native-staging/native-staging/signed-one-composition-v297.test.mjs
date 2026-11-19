import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {generateKeyPairSync,createHash,sign} from 'node:crypto';
import {startLocalClusterV279} from './local-cluster-v279.mjs';
import {RIO_ONE_SESSION_FORMAT_V295} from '../rio-palaco-one-session-reader-v295.mjs';
import {RIO_ONE_SIGNED_SESSION_FORMAT_V296 as FORMAT,RIO_ONE_SESSION_AUDIENCE_V296 as AUDIENCE} from '../rio-one-signed-session-provider-v296.mjs';
import {createRioSignedOneInspectionRouteV297} from '../rio-signed-one-inspection-route-v297.mjs';
import {RIO_RECEIPT_INSPECTION_PATH_V269 as PATH} from '../rio-receipt-http-route-v269.mjs';
import {createRioRevocationReconcilerV242} from '../rio-revocation-reconciler-v242.mjs';

test('v297 central signed One inspection entry point',{timeout:60000},async t=>{
  const cluster=await startLocalClusterV279();
  const evidence={format:'rio-signed-one-composition-native-result-v297',syntheticDataOnly:true,
    sourceAuthority:'SYNTHETIC_EPHEMERAL_SERVICE_KEY_NOT_A_REAL_IDP',
    originalOneFunctionsExecuted:false,realIdpVerified:false,remoteTlsVerified:false,
    schemaScope:'MINIMAL_SELECTED_ONE_COLUMN_CONTRACT_FIXTURE_NOT_FULL_MIGRATION',
    acceptance:'HOLD',authorization:'NONE',productionReady:false,scenarios:[]};
  const scenario=async(name,fn)=>t.test(name,async()=>{await fn();evidence.scenarios.push({name,result:'PASS'});});
  try{
    const admin=await cluster.connect();
    evidence.postgresVersion=(await admin.query('SELECT version() AS v')).rows[0].v;
    await admin.query("SELECT set_config('palaco.rio_staging_scope','RIO_V279_LOCAL_SOCKET_DISPOSABLE_ONLY',false)");
    await admin.query(readFileSync(new URL('./native-schema-fixture-v279.sql',import.meta.url),'utf8'));
    // Selected column contracts from One v9.9/v10.3. This is not a replacement migration.
    await admin.query(`CREATE SCHEMA palaco_login_v94;CREATE SCHEMA palaco_session_v99;
      CREATE TABLE palaco_login_v94.pp_passkey_bindings_v96(
        tenant_reference text,subject_reference text,pp_reference text,credential_id_base64url text,
        ownership_state text,registry_revision bigint,PRIMARY KEY(tenant_reference,subject_reference,pp_reference,credential_id_base64url));
      CREATE TABLE palaco_login_v94.subject_session_security(
        tenant_reference text,subject_reference text,revocation_state text,session_epoch bigint,
        PRIMARY KEY(tenant_reference,subject_reference));
      CREATE TABLE palaco_session_v99.session_security_epochs(
        tenant_reference text,subject_reference text,pp_reference text,credential_id_base64url text,
        revocation_state text,session_epoch bigint,revocation_revision bigint,device_binding_sha256 text,
        PRIMARY KEY(tenant_reference,subject_reference,pp_reference,credential_id_base64url));
      REVOKE ALL ON SCHEMA palaco_login_v94,palaco_session_v99 FROM PUBLIC,anon,authenticated;
      GRANT USAGE ON SCHEMA palaco_login_v94,palaco_session_v99 TO rio_v276_reader,rio_v276_writer;`);
    const tables=['palaco_login_v94.pp_passkey_bindings_v96','palaco_login_v94.subject_session_security','palaco_session_v99.session_security_epochs'];
    for(const table of tables)await admin.query(`ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;
      ALTER TABLE ${table} FORCE ROW LEVEL SECURITY;
      GRANT SELECT ON ${table} TO rio_v276_reader,rio_v276_writer;
      GRANT UPDATE ON ${table} TO rio_v276_writer;
      CREATE POLICY fixture_tenant_read ON ${table} FOR SELECT TO rio_v276_reader,rio_v276_writer
        USING(tenant_reference='STAGING_TENANT_001');
      CREATE POLICY fixture_tenant_update ON ${table} FOR UPDATE TO rio_v276_writer
        USING(tenant_reference='STAGING_TENANT_001') WITH CHECK(tenant_reference='STAGING_TENANT_001');`);
    for(const tenant of ['STAGING_TENANT_001','OTHER_SYNTHETIC_TENANT']){
      await admin.query("INSERT INTO palaco_login_v94.pp_passkey_bindings_v96 VALUES($1,'reviewer-001','synthetic-pp-001','synthetic_credential_001','VERIFIED',5)",[tenant]);
      await admin.query("INSERT INTO palaco_login_v94.subject_session_security VALUES($1,'reviewer-001','ACTIVE',2)",[tenant]);
      await admin.query("INSERT INTO palaco_session_v99.session_security_epochs VALUES($1,'reviewer-001','synthetic-pp-001','synthetic_credential_001','ACTIVE',3,4,$2)",[tenant,'a'.repeat(64)]);
    }
    await cluster.provisionLogin(admin,'rio_v276_reader');await cluster.provisionLogin(admin,'rio_v276_writer');
    const writer=await cluster.connect('rio_v276_writer');
    const tenantRef='STAGING_TENANT_001',origin='https://rio.example.invalid';
    const pair=generateKeyPairSync('ed25519');
    const issuerKey={issuerId:'synthetic-one-issuer',keyId:'one-source-key',
      publicKeyPem:pair.publicKey.export({format:'pem',type:'spki'}),
      spkiSha256:createHash('sha256').update(pair.publicKey.export({format:'der',type:'spki'})).digest('hex')};
    await admin.query(`CREATE TABLE rio_staging_host.issuer_state(
      issuer_id text,key_id text,status text,revision integer,not_before timestamptz,not_after timestamptz);
      ALTER TABLE rio_staging_host.issuer_state ENABLE ROW LEVEL SECURITY;
      ALTER TABLE rio_staging_host.issuer_state FORCE ROW LEVEL SECURITY;
      GRANT SELECT ON rio_staging_host.issuer_state TO rio_v276_reader,rio_v276_writer;
      GRANT UPDATE ON rio_staging_host.issuer_state TO rio_v276_writer;
      CREATE POLICY fixture_read ON rio_staging_host.issuer_state FOR SELECT TO rio_v276_reader,rio_v276_writer USING(true);
      CREATE POLICY fixture_update ON rio_staging_host.issuer_state FOR UPDATE TO rio_v276_writer USING(true) WITH CHECK(true);`);
    await admin.query(`INSERT INTO rio_staging_host.issuer_state VALUES($1,$2,'ACTIVE',1,
      clock_timestamp()-interval '1 minute',clock_timestamp()+interval '10 minutes')`,[issuerKey.issuerId,issuerKey.keyId]);
    const state={replay:false,pending:false,revokeIssuerAfterSigning:false};
    const born=Date.now(),session={format:RIO_ONE_SESSION_FORMAT_V295,state:'ACTIVE',assurance:'SERVER_AUTHENTICATED',
      tenantRef,subjectId:'reviewer-001',sessionRef:'one-session-001',credentialId:'synthetic_credential_001',
      ppReference:'synthetic-pp-001',deviceBindingSha256:'a'.repeat(64),subjectEpoch:2,sessionEpoch:3,
      revocationRevision:4,ppRegistryRevision:5,issuedAt:new Date(born-1000).toISOString(),
      expiresAt:new Date(born+60000).toISOString(),observedAt:new Date(born).toISOString()};
    let acquired=0;const pids=[];
    const readIssuerKeyState=async()=>{
      const c=await cluster.connect('rio_v276_reader');
      try{
        const row=(await c.query('SELECT * FROM rio_staging_host.issuer_state WHERE issuer_id=$1 AND key_id=$2',
          [issuerKey.issuerId,issuerKey.keyId])).rows[0];
        return {state:row.status,issuerId:row.issuer_id,keyId:row.key_id,revision:row.revision,
          notBefore:row.not_before.toISOString(),notAfter:row.not_after.toISOString()};
      }finally{await c.end();}
    };
    const source=()=>{
      let prior;
      return {tenantRef,allowedOrigin:origin,issuerKey,now:()=>new Date(),readIssuerKeyState,
        requestSignedSession:async(_request,challenge)=>{
          if(state.replay)return prior;
          const issuedAt=new Date().toISOString();
          const payload=Buffer.from(JSON.stringify({format:FORMAT,issuerId:issuerKey.issuerId,audience:AUDIENCE,
            tenantRef,nonce:challenge.nonce,request:challenge.request,issuedAt,
            expiresAt:new Date(Date.parse(issuedAt)+5000).toISOString(),
            session:{...session,state:state.pending?'PENDING':'ACTIVE',observedAt:issuedAt}}));
          prior=JSON.stringify({format:'rio-one-session-envelope-v296-DRAFT',keyId:issuerKey.keyId,
            payload:payload.toString('base64url'),signature:sign(null,payload,pair.privateKey).toString('base64url')});
          if(state.revokeIssuerAfterSigning)await writer.query("UPDATE rio_staging_host.issuer_state SET status='REVOKED',revision=revision+1");
          return prior;
        }};
    };
    const acquireOneReadConnection=async()=>{
      acquired++;const c=await cluster.connect('rio_v276_reader');
      pids.push((await c.query('SELECT pg_backend_pid() AS pid')).rows[0].pid);
      return {query:(sql,values)=>c.query(sql,values),release:()=>c.end()};
    };
    const request=body=>new Request(origin+PATH,{method:'POST',headers:{Origin:origin,'X-RIO-Inspection':'1',
      'Content-Type':'application/json'},body:body??'{}'});
    const target={requestId:'request-route-001',actorAuditRef:'synthetic-revoker',subjectId:'target-subject-001',sessionRef:'target-session-001',reason:'REVOKED'};
    await admin.query("INSERT INTO rio_identity_gate.session_generation(session_ref,subject_id,generation,active) VALUES($1,$2,2,false)",[target.sessionRef,target.subjectId]);
    await admin.query("INSERT INTO rio_identity_gate.revocation_requests(request_id,request_payload,status,result_generation) VALUES($1,$2::jsonb,'COMPLETE',2)",[target.requestId,JSON.stringify({kind:'session',...target})]);
    await admin.query("INSERT INTO rio_staging_host.request_bindings VALUES($1,$2,1,'evidence-route-001')",[tenantRef,target.requestId]);
    await admin.query("INSERT INTO rio_staging_host.inspection_policies VALUES($1,'reviewer-001','one-session-001',3,$2,1,true)",[tenantRef,target.requestId]);
    const receiptPair=generateKeyPairSync('ed25519'),receiptPin={keyId:'receipt-key-001',algorithm:'Ed25519',
      spkiSha256:createHash('sha256').update(receiptPair.publicKey.export({format:'der',type:'spki'})).digest('hex')};
    await admin.query(`INSERT INTO rio_audit_keys.verification_keys(key_id,algorithm,public_key_pem,spki_sha256,status,not_before,not_after)
      VALUES($1,'Ed25519',$2,$3,'ACTIVE',clock_timestamp()-interval '1 minute',clock_timestamp()+interval '10 minutes')`,
      [receiptPin.keyId,receiptPair.publicKey.export({format:'pem',type:'spki'}),receiptPin.spkiSha256]);
    const rioReader=await cluster.connect('rio_v276_reader');
    const verifyTarget=async()=>{
      const r=await rioReader.query('SELECT generation FROM rio_identity_gate.session_generation WHERE session_ref=$1 AND subject_id=$2 AND active=false AND generation=2',[target.sessionRef,target.subjectId]);
      return r.rowCount===1?{state:'REVOKED_CONFIRMED',requestId:target.requestId,generation:2,evidenceRef:'evidence-route-001'}:null;
    };
    const reconciled=await createRioRevocationReconcilerV242({query:(s,v)=>rioReader.query(s,v),verifyCurrentAuthority:verifyTarget}).reconcile('session',target);
    assert.equal(reconciled.ok,true);
    const ev=reconciled.evidence,payload=JSON.stringify(ev);
    const receipt={ok:true,format:'rio-revocation-receipt-v242',evidence:ev,sha256:reconciled.sha256,
      signature:sign(null,Buffer.from(payload),receiptPair.privateKey).toString('base64url'),keyId:receiptPin.keyId,algorithm:'Ed25519',
      signatureValidation:'NOT_VERIFIED_IN_THIS_MODULE',acceptance:'HOLD',authorization:'NONE',mayMigrate:false,mayRollback:false,mayDelete:false};
    const body=JSON.stringify({requestId:target.requestId,receiptJson:JSON.stringify(receipt)});
    let revokeDuringInspection=false;
    const makeRoute=()=>createRioSignedOneInspectionRouteV297({...source(),requestTimeoutMs:5000,maxConcurrentInspections:1,acquireOneReadConnection,receiptServices:{
      keyPins:[receiptPin],
      readInspectionPolicy:async context=>{
        const r=await rioReader.query(`SELECT revision FROM rio_staging_host.inspection_policies
          WHERE tenant_ref=$1 AND reviewer_subject_id=$2 AND reviewer_session_ref=$3 AND reviewer_session_generation=$4 AND request_id=$5 AND permitted=true`,
          [context.tenantRef,context.reviewerSubjectId,context.reviewerSessionRef,context.reviewerSessionGeneration,context.requestId]);
        return r.rowCount===1?{state:'PERMITTED',purpose:AUDIENCE,...context,policyRevision:Number(r.rows[0].revision)}:null;
      },
      readOriginalRevocationRequest:async lookup=>{
        const r=await rioReader.query(`SELECT r.request_payload,r.result_generation,b.record_revision
          FROM rio_identity_gate.revocation_requests r JOIN rio_staging_host.request_bindings b ON b.request_id=r.request_id
          WHERE b.tenant_ref=$1 AND r.request_id=$2 AND r.status='COMPLETE'`,[lookup.tenantRef,lookup.requestId]);
        const row=r.rows[0];return r.rowCount===1?{state:'COMPLETE',tenantRef,recordRevision:Number(row.record_revision),request:{...row.request_payload,generation:Number(row.result_generation)}}:null;
      },
      confirmCurrentRevocation:async expected=>{
        const targetState=await verifyTarget();if(!targetState)return null;
        if(revokeDuringInspection)await writer.query("UPDATE palaco_session_v99.session_security_epochs SET revocation_state='REVOKED',session_epoch=4,revocation_revision=5");
        return {...expected,state:'REVOKED_CONFIRMED',evidenceRef:targetState.evidenceRef};
      },queryVerificationKeys:(s,v)=>rioReader.query(s,v),
    }});
    await scenario('central entry point executes signed source, fresh One SQL and original RIO route as HOLD inspection',async()=>{
      const result=await makeRoute().handle(request(body));assert.equal(result.status,200);
      const output=await result.json();assert.equal(output.authorization,'NONE');assert.equal(output.acceptance,'HOLD');
      assert.equal(JSON.stringify(output).includes('synthetic-pp'),false);
      assert.equal(output.domainBinding,'NOT_SIGNED_IN_V242');
      assert.notEqual(pids[0],pids[1]);evidence.distinctOneReaderBackendPids=pids.slice(0,2);
      evidence.originalRioRouteExecuted=true;evidence.centralFactoryRouteExecuted=true;
    });
    await scenario('central entry point catches One revocation during the original receipt inspection',async()=>{
      revokeDuringInspection=true;const result=await makeRoute().handle(request(body));assert.equal(result.status,403);
      assert.equal((await result.json()).authorization,'NONE');
    });
    evidence.scenarioCount=evidence.scenarios.length;
    writeFileSync(new URL('../SIGNED-ONE-COMPOSITION-NATIVE-RESULT-v297.json',import.meta.url),JSON.stringify(evidence,null,2)+'\n');
  }finally{await cluster.close();}
});
