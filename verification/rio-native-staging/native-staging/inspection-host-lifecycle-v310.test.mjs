import {createRioManagedInspectionServiceV309} from '../rio-managed-inspection-service-v309.mjs';
import {createRioInspectionHostLifecycleV310} from '../rio-inspection-host-lifecycle-v310.mjs';
import {createServer,request as httpRequest} from 'node:http';
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {generateKeyPairSync,createHash,sign,createPublicKey,webcrypto} from 'node:crypto';
import {startLocalClusterV279} from './local-cluster-v279.mjs';
import {RIO_ONE_SESSION_FORMAT_V295} from '../rio-palaco-one-session-reader-v295.mjs';
import {RIO_ONE_SESSION_AUDIENCE_V296 as AUDIENCE} from '../rio-one-signed-session-provider-v296.mjs';
import {RIO_RECEIPT_INSPECTION_PATH_V269 as PATH} from '../rio-receipt-http-route-v269.mjs';
import {createRioRevocationReconcilerV242} from '../rio-revocation-reconciler-v242.mjs';

const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};
const flush=()=>new Promise(resolve=>setImmediate(resolve));

test('v310 host lifecycle through loopback HTTP and native One SQL',{timeout:60000},async t=>{
  const cluster=await startLocalClusterV279();let server;
  const evidence={format:'rio-inspection-host-lifecycle-native-result-v310',syntheticDataOnly:true,
    sourceAuthority:'SYNTHETIC_EPHEMERAL_SERVICE_KEY_NOT_A_REAL_IDP',
    loopbackHttpTransport:true,productionHostBridgeImplemented:false,transportTlsVerified:false,
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
    const bound=new WeakSet();let authCount=0;
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
    let releaseGate=null,parkedReleasePid;const releasedPids=new Set();
    const acquireOneReadConnection=async()=>{
      acquired++;const c=await cluster.connect('rio_v276_reader');
      const pid=(await c.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;pids.push(pid);
      return {query:(sql,values)=>c.query(sql,values),release:async()=>{
        if(releaseGate){const gate=releaseGate;releaseGate=null;parkedReleasePid=pid;gate.entered.resolve();await gate.release.promise;}
        await c.end();releasedPids.add(pid);
      }};
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
    const receiptServices={
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
    };


    let sharedReads=0;
    const sharedRegistry=async lookup=>{sharedReads++;return readIssuerKeyState(lookup);};
    const build=()=>createRioManagedInspectionServiceV309({tenantRef,allowedOrigin:origin,issuerKey,
      privateSigningKey:cryptoPair.privateKey,readIssuerKeyState:sharedRegistry,readAuthenticatedOneSession,
      acquireOneReadConnection,receiptServices,now:()=>new Date(),
      limits:{requestTimeoutMs:500,maxConcurrentInspections:1,maxConcurrentSignatures:1}});
    const service=await build();let host;const events=[];let stops=0,releases=0;
    const resourcePid=(await rioReader.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
    // Synthetic loopback-only transport. Fixed logical origin and fixture server session binding.
    // This is not production IncomingMessage conversion, TLS termination or real One login.
    server=createServer(async(incoming,outgoing)=>{
      try{
        if(incoming.method!=='POST'||incoming.url!==PATH){outgoing.writeHead(404);outgoing.end();return;}
        const chunks=[];let size=0;for await(const chunk of incoming){size+=chunk.length;
          if(size>32768){outgoing.writeHead(413);outgoing.end();return;}chunks.push(chunk);}
        const response=await host.inspection.handle(request(Buffer.concat(chunks).toString('utf8')));
        outgoing.writeHead(response.status,Object.fromEntries(response.headers));outgoing.end(await response.text());
      }catch{if(!outgoing.headersSent)outgoing.writeHead(500);outgoing.end();}
    });
    server.requestTimeout=3000;server.headersTimeout=3000;server.timeout=3000;
    host=createRioInspectionHostLifecycleV310({service,
      stopHttpAdmission:()=>{stops++;events.push('STOP_BEGIN');return new Promise((resolve,reject)=>server.close(error=>{
        if(error){reject(error);return;}events.push('STOP_COMPLETED');resolve();
      }));},
      releaseHostResources:async()=>{
        releases++;events.push('RELEASE_BEGIN');const status=service.control.getStatus();
        assert.equal(server.listening,false);assert.equal(status.state,'CLOSED');assert.equal(status.inFlightInspections,0);
        assert.equal(status.signer.inFlight,0);assert.equal(status.signer.candidateChecksInFlight,0);
        evidence.serviceClosedBeforeResourceRelease=true;await rioReader.end();events.push('RELEASE_COMPLETED');
      }});
    await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
    const address=server.address();
    const send=()=>new Promise((resolve,reject)=>{
      const req=httpRequest({hostname:'127.0.0.1',port:address.port,path:PATH,method:'POST',agent:false,
        headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body),Connection:'close'}},res=>{
          const chunks=[];res.on('data',x=>chunks.push(x));res.on('end',()=>resolve({status:res.statusCode,
            headers:res.headers,body:Buffer.concat(chunks).toString('utf8')}));
        });
      req.on('error',reject);req.setTimeout(3000,()=>req.destroy(Error('SYNTHETIC_TRANSPORT_TIMEOUT')));req.end(body);
    });
    await scenario('loopback HTTP traverses host adapter and actual One SQL and receipt crypto',async()=>{
      const response=await send();assert.equal(response.status,200);const output=JSON.parse(response.body);
      assert.equal(output.authorization,'NONE');assert.equal(output.acceptance,'HOLD');assert.equal(output.domainBinding,'NOT_SIGNED_IN_V242');
      assert.equal(host.control.getStatus().state,'RUNNING');assert.notEqual(pids[0],pids[1]);
      evidence.distinctOneReaderBackendPids=pids.slice(0,2);evidence.hostFactoryExecuted=true;evidence.httpToSqlChainExecuted=true;
    });
    let release,done;
    await scenario('HTTP deadline retains a real One connection pending its release callback',async()=>{
      const entered=deferred();release=deferred();releaseGate={entered,release};const pending=send();await entered.promise;
      assert.equal((await pending).status,504);assert.equal(service.control.getStatus().inFlightInspections,1);
      assert.equal((await admin.query('SELECT pid FROM pg_stat_activity WHERE pid=$1',[parkedReleasePid])).rowCount,1);
      assert.equal(server.listening,true);evidence.heldConnectionPid=parkedReleasePid;evidence.httpDeadlineBeforeActualRelease=true;
    });
    await scenario('host close stops actual HTTP listener and refuses new work before providers',async()=>{
      done=host.control.close();assert.equal(done,host.control.close());await flush();
      assert.equal(server.listening,false);assert.equal(releases,0);assert.equal(host.control.getStatus().state,'STOPPING');
      assert.equal(service.control.getStatus().state,'DRAINING');const before={sharedReads,authCount,acquired};
      const r=request(body);assert.equal((await host.inspection.handle(r)).status,503);assert.equal(r.bodyUsed,false);
      await assert.rejects(send(),e=>['ECONNREFUSED','ECONNRESET','EPIPE'].includes(e.code));
      assert.deepEqual({sharedReads,authCount,acquired},before);evidence.newWorkRefusedBeforeProviders=true;
      evidence.actualHttpListenerStopped=true;evidence.resourceReleaseWithheldWhileDrainPending=true;
    });
    await scenario('registered host resource releases once after actual listener and service drain',async()=>{
      release.resolve();const result=await done;assert.equal(result.state,'CLOSED');assert.equal(stops,1);assert.equal(releases,1);
      assert.equal(releasedPids.has(parkedReleasePid),true);assert.equal(result.httpAdmissionStop,'COMPLETED');
      assert.equal(result.serviceDrain,'COMPLETED');assert.equal(result.hostResourceRelease,'COMPLETED');
      assert.deepEqual(events,['STOP_BEGIN','STOP_COMPLETED','RELEASE_BEGIN','RELEASE_COMPLETED']);
      const until=performance.now()+2000;let remaining;
      do{remaining=(await admin.query('SELECT pid FROM pg_stat_activity WHERE pid=$1',[resourcePid])).rowCount;
        if(remaining)await new Promise(resolve=>setTimeout(resolve,10));
      }while(remaining&&performance.now()<until);
      assert.equal(remaining,0);evidence.closedStatus=result;evidence.actualResourceConnectionReleased=true;
      evidence.singleReleaseObserved=true;evidence.shutdownOrder=events;evidence.registeredResourcePid=resourcePid;
    });
    await scenario('admission-stop rejection still drains real service but skips disposal',async()=>{
      const other=await build();let disposed=0,attempts=0;
      const held=createRioInspectionHostLifecycleV310({service:other,stopHttpAdmission:async()=>{attempts++;throw Error('SYNTHETIC_PRIVATE_STOP');},
        releaseHostResources:async()=>{disposed++;}});
      const completion=held.control.close(),result=await completion;assert.equal(result.state,'HELD');
      assert.equal(other.control.getStatus().state,'CLOSED');assert.equal(result.hostResourceRelease,'NOT_STARTED');
      assert.deepEqual(result.issues,['HTTP_ADMISSION_STOP_NOT_CONFIRMED']);assert.equal(disposed,0);
      assert.equal(held.control.close(),completion);assert.equal(attempts,1);
      evidence.stopFailureHeld=true;evidence.disposalSkippedAfterStopFailure=true;evidence.stopFailureStatus=result;
    });
    await scenario('actual partial disposal followed by rejection stays HELD without automatic retry',async()=>{
      const other=await build(),registered=await cluster.connect('rio_v276_reader');let attempts=0;
      const held=createRioInspectionHostLifecycleV310({service:other,stopHttpAdmission:async()=>{},
        releaseHostResources:async()=>{attempts++;await registered.end();throw Error('SYNTHETIC_PRIVATE_RELEASE');}});
      const completion=held.control.close(),result=await completion;assert.equal(result.state,'HELD');
      assert.equal(result.hostResourceRelease,'NOT_CONFIRMED');assert.equal(other.control.getStatus().state,'CLOSED');
      assert.deepEqual(result.issues,['HOST_RESOURCE_RELEASE_NOT_CONFIRMED']);assert.equal(held.control.close(),completion);assert.equal(attempts,1);
      assert.equal(JSON.stringify(result).includes('SYNTHETIC_PRIVATE'),false);evidence.releaseFailureHeld=true;
      evidence.partialResourceEffectObserved=true;evidence.noAutomaticRetryObserved=true;evidence.releaseFailureStatus=result;
      const credential=(await admin.query('SELECT revocation_state,session_epoch,revocation_revision FROM palaco_session_v99.session_security_epochs')).rows[0];
      const key=(await admin.query('SELECT status,revision FROM rio_staging_host.issuer_state')).rows[0];
      assert.equal(credential.revocation_state,'ACTIVE');assert.equal(Number(credential.session_epoch),3);
      assert.equal(Number(credential.revocation_revision),4);assert.equal(key.status,'ACTIVE');assert.equal(key.revision,1);
      evidence.authorityUnaffectedObserved=true;
    });
    evidence.serviceClosedStatus=service.control.getStatus();evidence.scenarioCount=evidence.scenarios.length;
    evidence.hostSurface={inspection:Object.keys(host.inspection),control:Object.keys(host.control)};
    writeFileSync(new URL('../HOST-LIFECYCLE-NATIVE-RESULT-v310.json',import.meta.url),JSON.stringify(evidence,null,2)+'\n');
  }finally{
    if(server?.listening){server.closeAllConnections();await new Promise(resolve=>server.close(()=>resolve()));}
    await cluster.close();
  }
});
