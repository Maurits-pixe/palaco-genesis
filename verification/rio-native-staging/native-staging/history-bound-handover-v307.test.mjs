import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {generateKeyPairSync,createHash,sign,createPublicKey,webcrypto} from 'node:crypto';
import {startLocalClusterV279} from './local-cluster-v279.mjs';
import {RIO_ONE_SESSION_FORMAT_V295} from '../rio-palaco-one-session-reader-v295.mjs';
import {RIO_ONE_SESSION_AUDIENCE_V296 as AUDIENCE} from '../rio-one-signed-session-provider-v296.mjs';
import {createRioSignedOneInspectionRouteV297} from '../rio-signed-one-inspection-route-v297.mjs';
import {createRioOneSessionStatementIssuerV298} from '../rio-one-session-statement-issuer-v298.mjs';
import {createRioOneHistoryBoundSignerHandoverV307} from '../rio-one-history-bound-signer-handover-v307.mjs';
import {RIO_RECEIPT_INSPECTION_PATH_V269 as PATH} from '../rio-receipt-http-route-v269.mjs';
import {createRioRevocationReconcilerV242} from '../rio-revocation-reconciler-v242.mjs';

test('v307 observed-history admission through unchanged issuer, native One and RIO',{timeout:60000},async t=>{
  const cluster=await startLocalClusterV279();
  const evidence={format:'rio-one-history-bound-handover-native-result-v307',syntheticDataOnly:true,
    sourceAuthority:'SYNTHETIC_EPHEMERAL_SERVICE_KEY_NOT_A_REAL_IDP',
    keyBackend:'WEBCRYPTO_SOFTWARE_ONLY',hostKeyIsolation:'NOT_PROVIDED',hardwareProtection:'NOT_VERIFIED',
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
    const tenantRef='STAGING_TENANT_001',origin='https://rio.example.invalid';
    const cryptoPair=await webcrypto.subtle.generateKey({name:'Ed25519'},false,['sign','verify']);
    const pair={publicKey:createPublicKey({key:Buffer.from(await webcrypto.subtle.exportKey('spki',cryptoPair.publicKey)),format:'der',type:'spki'})};
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
    const bound=new WeakSet();let authCount=0,signCount=0;
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
    const readAuthenticatedOneSession=async request=>{
      authCount++;
      // Synthetic trusted server binding, not a browser cookie or a real IdP.
      if(!bound.has(request))return null;
      const c=await cluster.connect('rio_v276_reader');
      try{
        const row=(await c.query(`SELECT b.registry_revision,s.session_epoch AS subject_epoch,
          e.session_epoch,e.revocation_revision,e.device_binding_sha256
          FROM palaco_login_v94.pp_passkey_bindings_v96 b
          JOIN palaco_login_v94.subject_session_security s
            ON s.tenant_reference=b.tenant_reference AND s.subject_reference=b.subject_reference
          JOIN palaco_session_v99.session_security_epochs e
            ON e.tenant_reference=b.tenant_reference AND e.subject_reference=b.subject_reference
            AND e.pp_reference=b.pp_reference AND e.credential_id_base64url=b.credential_id_base64url
          WHERE b.tenant_reference=$1 AND b.subject_reference=$2 AND b.pp_reference=$3
            AND b.credential_id_base64url=$4 AND b.ownership_state='VERIFIED'
            AND s.revocation_state='ACTIVE' AND e.revocation_state='ACTIVE'`,
          [tenantRef,session.subjectId,session.ppReference,session.credentialId])).rows[0];
        if(!row||Number(row.registry_revision)!==session.ppRegistryRevision||Number(row.subject_epoch)!==session.subjectEpoch||
          Number(row.session_epoch)!==session.sessionEpoch||Number(row.revocation_revision)!==session.revocationRevision||
          row.device_binding_sha256!==session.deviceBindingSha256)return null;
        return {...session,observedAt:new Date().toISOString()};
      }finally{await c.end();}
    };
    let backendKeyReads=0,stopAtKeyRead=null,drained;
    const backend=await createRioOneHistoryBoundSignerHandoverV307({tenantRef,allowedOrigin:origin,issuerKey,
      privateSigningKey:cryptoPair.privateKey,now:()=>new Date(),maxConcurrentSignatures:1,
      readIssuerKeyState:async lookup=>{
        backendKeyReads++;const record=await readIssuerKeyState(lookup);
        if(backendKeyReads===stopAtKeyRead){
          drained=backend.retireGeneration({controllerId:backend.getStatus().controllerId,expectedGeneration:1});evidence.retiringSnapshot=backend.getStatus();
        }
        return record;
      }});
    const source=()=>{
      const issuer=createRioOneSessionStatementIssuerV298({tenantRef,allowedOrigin:origin,issuerKey,
        now:()=>new Date(),readAuthenticatedOneSession,readIssuerKeyState,
        signSessionStatement:async statement=>{
          signCount++;assert.equal(statement.purpose,AUDIENCE);
          return backend.signSessionStatement(statement);
        }});
      return {tenantRef,allowedOrigin:origin,issuerKey,now:()=>new Date(),readIssuerKeyState,
        requestSignedSession:issuer.requestSignedSession};
    };
    const acquireOneReadConnection=async()=>{
      acquired++;const c=await cluster.connect('rio_v276_reader');
      pids.push((await c.query('SELECT pg_backend_pid() AS pid')).rows[0].pid);
      return {query:(sql,values)=>c.query(sql,values),release:()=>c.end()};
    };
    const request=body=>{
      const r=new Request(origin+PATH,{method:'POST',headers:{Origin:origin,'X-RIO-Inspection':'1',
        'Content-Type':'application/json'},body:body??'{}'});bound.add(r);return r;
    };
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
        return {...expected,state:'REVOKED_CONFIRMED',evidenceRef:targetState.evidenceRef};
      },queryVerificationKeys:(s,v)=>rioReader.query(s,v),
    }});
    const route=makeRoute(),stablePort=backend.signSessionStatement;
    const scope=()=>({controllerId:backend.getStatus().controllerId,expectedGeneration:backend.getStatus().generation});
    const replacement=()=>({...scope(),expectedLastCompletedAttemptId:backend.getStatus().lastCompletedAttemptId,
      privateSigningKey:cryptoPair.privateKey,readIssuerKeyState});
    const cancelCommand=()=>({...scope(),attemptId:backend.getStatus().candidateAttemptId});
    const id=backend.getStatus().controllerId;let firstContext;
    assert.equal(backendKeyReads,2);assert.equal(backend.getStatus().lastCompletedAttemptId,null);
    await scenario('initial controller runs the original native One route with no completed replacement',async()=>{
      const result=await route.handle(request(body));assert.equal(result.status,200);
      const output=await result.json();assert.equal(output.authorization,'NONE');assert.equal(output.acceptance,'HOLD');
      assert.equal(JSON.stringify(output).includes('synthetic-pp'),false);
      assert.notEqual(pids[0],pids[1]);evidence.distinctOneReaderBackendPids=pids.slice(0,2);
      assert.equal(authCount,4);assert.equal(signCount,2);assert.equal(backend.getLastAttemptResult(),null);
      evidence.originalRioRouteExecuted=true;evidence.centralFactoryRouteExecuted=true;
      evidence.statementIssuerExecuted=true;evidence.historyBoundHandoverExecuted=true;
    });
    await scenario('full retirement permits capturing an explicit empty completion context',async()=>{
      stopAtKeyRead=backendKeyReads+2;
      assert.equal((await route.handle(request(body))).status,403);assert.equal((await drained).state,'STOPPED');
      assert.equal(evidence.retiringSnapshot.state,'RETIRING');assert.equal(evidence.retiringSnapshot.inFlight,1);
      firstContext=replacement();assert.equal(firstContext.expectedLastCompletedAttemptId,null);
      assert.equal(backend.getStatus().state,'RETIRED');evidence.initialObservedCompletion=null;
    });
    await scenario('cancellation invalidates the cached context without changing generation or retired state',async()=>{
      const cancellingRegistry=async lookup=>{const record=await readIssuerKeyState(lookup);backend.cancelReplacement(cancelCommand());
        assert.equal(backend.getStatus().lastCompletedAttemptId,null);return record;};
      assert.equal(await backend.installReplacement({...firstContext,readIssuerKeyState:cancellingRegistry}),null);
      const completed=backend.getLastAttemptResult();assert.equal(completed.outcome,'WITHHELD_AFTER_CANCELLATION');
      assert.equal(completed.previousCompletedAttemptId,null);assert.equal(backend.getStatus().generation,1);
      assert.equal(backend.getStatus().state,'RETIRED');let reads=0;
      assert.equal(await backend.installReplacement({...firstContext,readIssuerKeyState:async lookup=>{reads++;return readIssuerKeyState(lookup);}}),null);
      assert.equal(reads,0);assert.equal(backend.getLastAttemptResult(),completed);assert.equal(backend.getStatus().candidateAttemptId,null);
      evidence.cancelledResult=completed;evidence.cancelledStaleCommandRefused=true;evidence.sameGenerationStateObserved=true;
    });
    await scenario('actual PostgreSQL failure also invalidates the previously observed completion context',async()=>{
      const beforeFailure=replacement();assert.equal(beforeFailure.expectedLastCompletedAttemptId,evidence.cancelledResult.attemptId);
      const failingRegistry=async()=>{const c=await cluster.connect('rio_v276_reader');
        try{await c.query('SELECT * FROM rio_staging_host.missing_history_registry_fixture_v307');}
        catch(error){evidence.databaseErrorCodeObserved=error.code;throw error;}
        finally{await c.end();}};
      assert.equal(await backend.installReplacement({...beforeFailure,readIssuerKeyState:failingRegistry}),null);
      const completed=backend.getLastAttemptResult();assert.equal(completed.outcome,'CHECK_FAILED');assert.equal(evidence.databaseErrorCodeObserved,'42P01');
      assert.equal(completed.previousCompletedAttemptId,evidence.cancelledResult.attemptId);
      let reads=0;assert.equal(await backend.installReplacement({...beforeFailure,readIssuerKeyState:async lookup=>{reads++;return readIssuerKeyState(lookup);}}),null);
      assert.equal(reads,0);assert.equal(backend.getLastAttemptResult(),completed);assert.equal(backend.getStatus().generation,1);
      evidence.failedResult=completed;evidence.failedStaleCommandRefused=true;evidence.noStaleRegistryWorkObserved=true;
    });
    await scenario('freshly observed completion context admits retry through the same original route',async()=>{
      const current=replacement();assert.equal(current.expectedLastCompletedAttemptId,evidence.failedResult.attemptId);
      const installed=await backend.installReplacement(current);assert.equal(installed.generation,2);
      assert.equal(installed.previousCompletedAttemptId,evidence.failedResult.attemptId);assert.equal(installed.controllerId,id);
      assert.equal(backend.signSessionStatement,stablePort);
      const result=await route.handle(request(body));assert.equal(result.status,200);
      const output=await result.json();assert.equal(output.authorization,'NONE');assert.equal(output.acceptance,'HOLD');
      evidence.stableRouteReused=true;evidence.installedResult=backend.getLastAttemptResult();
    });
    await scenario('close completion retains the admitted predecessor without installing another generation',async()=>{
      await backend.retireGeneration(scope());const current=replacement();assert.equal(current.expectedLastCompletedAttemptId,evidence.installedResult.attemptId);
      let closed;const closingRegistry=async lookup=>{const record=await readIssuerKeyState(lookup);closed=backend.close();
        assert.equal(backend.getLastAttemptResult(),evidence.installedResult);return record;};
      assert.equal(await backend.installReplacement({...current,readIssuerKeyState:closingRegistry}),null);
      const final=await closed,record=backend.getLastAttemptResult();assert.equal(record.outcome,'WITHHELD_AFTER_CLOSE');
      assert.equal(record.previousCompletedAttemptId,evidence.installedResult.attemptId);assert.equal(record.controllerId,id);
      assert.equal(record.resultingGeneration,2);assert.equal(final.lastCompletedAttemptId,record.attemptId);
      assert.equal(final.state,'CLOSED');assert.equal(final.candidateChecksInFlight,0);
      assert.equal((await route.handle(request(body))).status,403);
      const credential=(await rioReader.query('SELECT revocation_state,session_epoch,revocation_revision FROM palaco_session_v99.session_security_epochs')).rows[0];
      const key=(await rioReader.query('SELECT status,revision FROM rio_staging_host.issuer_state')).rows[0];
      assert.equal(credential.revocation_state,'ACTIVE');assert.equal(Number(credential.session_epoch),3);
      assert.equal(Number(credential.revocation_revision),4);assert.equal(key.status,'ACTIVE');assert.equal(key.revision,1);
      evidence.authorityUnaffectedObserved=true;evidence.closedResult=record;evidence.closedStatus=final;
    });
    evidence.scenarioCount=evidence.scenarios.length;
    writeFileSync(new URL('../HISTORY-BOUND-HANDOVER-NATIVE-RESULT-v307.json',import.meta.url),JSON.stringify(evidence,null,2)+'\n');
  }finally{await cluster.close();}
});
