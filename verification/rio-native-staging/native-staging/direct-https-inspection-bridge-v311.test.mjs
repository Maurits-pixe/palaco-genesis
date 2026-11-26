import {createRioManagedInspectionServiceV309} from '../rio-managed-inspection-service-v309.mjs';
import {createRioInspectionHostLifecycleV310} from '../rio-inspection-host-lifecycle-v310.mjs';
import {createServer,request as httpsRequest} from 'node:https';
import {execFileSync} from 'node:child_process';
import {checkServerIdentity} from 'node:tls';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createRioDirectHttpsInspectionBridgeV311} from '../rio-direct-https-inspection-bridge-v311.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync,mkdtempSync,rmSync,chmodSync} from 'node:fs';
import {generateKeyPairSync,createHash,sign,createPublicKey,webcrypto,randomBytes} from 'node:crypto';
import {startLocalClusterV279} from './local-cluster-v279.mjs';
import {RIO_ONE_SESSION_FORMAT_V295} from '../rio-palaco-one-session-reader-v295.mjs';
import {RIO_ONE_SESSION_AUDIENCE_V296 as AUDIENCE} from '../rio-one-signed-session-provider-v296.mjs';
import {RIO_RECEIPT_INSPECTION_PATH_V269 as PATH} from '../rio-receipt-http-route-v269.mjs';
import {createRioRevocationReconcilerV242} from '../rio-revocation-reconciler-v242.mjs';

const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};
const flush=()=>new Promise(resolve=>setImmediate(resolve));

test('v311 direct HTTPS bridge through actual TLS One SQL and receipt crypto',{timeout:60000},async t=>{
  const cluster=await startLocalClusterV279();let server,bridge,certDir,cert,onAuth,lastAuthenticatedRequest;
  const fixtureToken=randomBytes(24).toString('base64url');let fixtureSessionActive=true;
  const evidence={format:'rio-direct-https-inspection-bridge-native-result-v311',syntheticDataOnly:true,
    sourceAuthority:'SYNTHETIC_EPHEMERAL_SERVICE_KEY_NOT_A_REAL_IDP',
    loopbackHttpsTransport:true,localTlsVerified:false,syntheticSessionSource:true,
    keyBackend:'WEBCRYPTO_SOFTWARE_ONLY',hostKeyIsolation:'NOT_PROVIDED',hardwareProtection:'NOT_VERIFIED',
    originalOneFunctionsExecuted:false,realIdpVerified:false,remoteTlsVerified:false,
    schemaScope:'MINIMAL_SELECTED_ONE_COLUMN_CONTRACT_FIXTURE_NOT_FULL_MIGRATION',
    acceptance:'HOLD',authorization:'NONE',productionReady:false,scenarios:[]};
  const scenario=async(name,fn)=>t.test(name,async()=>{await fn();evidence.scenarios.push({name,result:'PASS'});});
  try{
    certDir=mkdtempSync(join(tmpdir(),'rio-v311-tls-'));
    const keyPath=join(certDir,'private.pem'),certPath=join(certDir,'certificate.pem');
    execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','1',
      '-subj','/CN=rio-fixture.invalid','-addext','subjectAltName=IP:127.0.0.1',
      '-keyout',keyPath,'-out',certPath],{stdio:'ignore',timeout:15000});
    chmodSync(keyPath,0o600);cert=readFileSync(certPath);
    server=createServer({key:readFileSync(keyPath),cert,minVersion:'TLSv1.3'},(incoming,outgoing)=>{
      if(bridge)void bridge.transport.handleIncoming(incoming,outgoing);
      else{outgoing.writeHead(503);outgoing.end();}
    });
    server.requestTimeout=5000;server.headersTimeout=5000;server.timeout=5000;
    server.on('tlsClientError',()=>{});
    await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
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
    const tenantRef='STAGING_TENANT_001',origin='https://127.0.0.1:'+server.address().port;
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
      lastAuthenticatedRequest=request;
      await onAuth?.(request);
      const context=bridge?.context.readRequestContext(request);
      // A runtime-generated token matched against synthetic server state, never a real One IdP.
      if(!context||!fixtureSessionActive||context.headers.cookie!=='rio-fixture='+fixtureToken)return null;
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
    const service=await createRioManagedInspectionServiceV309({tenantRef,allowedOrigin:origin,issuerKey,
      privateSigningKey:cryptoPair.privateKey,readIssuerKeyState:sharedRegistry,readAuthenticatedOneSession,
      acquireOneReadConnection,receiptServices,now:()=>new Date(),
      limits:{requestTimeoutMs:500,maxConcurrentInspections:1,maxConcurrentSignatures:1}});
    const events=[];let releases=0;
    const resourcePid=(await rioReader.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
    const host=createRioInspectionHostLifecycleV310({service,
      stopHttpAdmission:()=>{events.push('STOP_BEGIN');return Promise.all([
        new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve())),
        bridge.control.close(),
      ]).then(()=>{events.push('STOP_COMPLETED');});},
      releaseHostResources:async()=>{
        releases++;events.push('RELEASE_BEGIN');assert.equal(service.control.getStatus().state,'CLOSED');
        assert.equal(bridge.control.getStatus().state,'CLOSED');await rioReader.end();events.push('RELEASE_COMPLETED');
      }});
    bridge=createRioDirectHttpsInspectionBridgeV311({allowedOrigin:origin,inspection:host.inspection,maxConcurrentRequests:2});
    const address=server.address();
    const send=(options={})=>new Promise((resolve,reject)=>{
      const headers={Host:new URL(origin).host,Origin:origin,'X-RIO-Inspection':'1','Content-Type':'application/json',
        'Content-Length':Buffer.byteLength(body),Cookie:'rio-fixture='+fixtureToken,Connection:'close',...options.headers};
      for(const key of Object.keys(headers))if(headers[key]===null)delete headers[key];
      const req=httpsRequest({hostname:'127.0.0.1',port:address.port,path:options.path??PATH,method:'POST',agent:false,
        ca:cert,rejectUnauthorized:true,
        // Keep TLS endpoint identity fixed while deliberately varying the HTTP Host header.
        checkServerIdentity:(_name,peer)=>checkServerIdentity('127.0.0.1',peer),
        minVersion:options.minVersion??'TLSv1.3',maxVersion:options.maxVersion??'TLSv1.3',
        headers:options.rawHeaders??headers},res=>{
          const authorized=res.socket.authorized,protocol=res.socket.getProtocol(),chunks=[];
          res.on('data',x=>chunks.push(x));res.on('error',reject);res.on('end',()=>resolve({status:res.statusCode,
            authorized,protocol,body:Buffer.concat(chunks).toString('utf8')}));
        });
      req.on('error',reject);req.setTimeout(3000,()=>req.destroy(Error('SYNTHETIC_TRANSPORT_TIMEOUT')));
      options.observe?.(req);req.end(body);
    });
    const waitUntil=async check=>{const until=performance.now()+3000;while(!check()&&performance.now()<until)
      await new Promise(r=>setTimeout(r,5));assert.equal(check(),true);};
    await scenario('verified local TLS 1.3 request crosses direct bridge and actual One SQL receipt chain',async()=>{
      const response=await send();assert.equal(response.status,200);assert.equal(response.authorized,true);assert.equal(response.protocol,'TLSv1.3');
      const output=JSON.parse(response.body);assert.equal(output.authorization,'NONE');assert.equal(output.acceptance,'HOLD');
      assert.equal(output.domainBinding,'NOT_SIGNED_IN_V242');assert.notEqual(pids[0],pids[1]);
      const context=bridge.context.readRequestContext(lastAuthenticatedRequest);assert.ok(context);
      assert.equal(context.sessionAuthentication,'NOT_PROVIDED');assert.ok(Object.isFrozen(context.headers));
      evidence.localTlsVerified=true;evidence.directHttpsBridgeExecuted=true;evidence.completedSqlCryptoChain=true;
      evidence.distinctOneReaderBackendPids=pids.slice(0,2);evidence.contextHasNoAuthenticationClaim=true;
    });
    await scenario('missing session context proxy or duplicate headers wrong host and older TLS are refused',async()=>{
      const before=acquired;assert.equal((await send({headers:{Cookie:null}})).status,403);
      assert.equal((await service.inspection.handle(request(body))).status,403);assert.equal(acquired,before);
      const authBefore=authCount;
      assert.equal((await send({headers:{Host:'other.invalid'}})).status,400);
      assert.equal((await send({headers:{'X-Forwarded-Host':new URL(origin).host}})).status,400);
      assert.equal((await send({rawHeaders:['Host',new URL(origin).host,'Origin',origin,'X-RIO-Inspection','1',
        'Content-Type','application/json','Content-Length',String(Buffer.byteLength(body)),
        'Cookie','synthetic-a','Cookie','synthetic-b','Connection','close']})).status,400);
      assert.equal(authCount,authBefore);
      await assert.rejects(send({minVersion:'TLSv1.2',maxVersion:'TLSv1.2'}),e=>e.code==='EPROTO'||/PROTOCOL_VERSION/.test(e.code??''));
      evidence.noContextAndMissingSessionRefused=true;evidence.ambiguousTransportRefusedBeforeAuthentication=true;evidence.legacyTlsRejected=true;
    });
    await scenario('actual client disconnect aborts Fetch signal while pending provider context remains bound',async()=>{
      const entered=deferred(),release=deferred();let nodeRequest;
      onAuth=async()=>{entered.resolve();await release.promise;};
      const pending=send({observe:r=>{nodeRequest=r;}}).then(()=>false,()=>true);await entered.promise;
      const original=lastAuthenticatedRequest;nodeRequest.destroy();await pending;
      await waitUntil(()=>original.signal.aborted&&bridge.control.getStatus().inFlightTransport===0);
      assert.ok(bridge.context.readRequestContext(original));assert.equal(service.control.getStatus().inFlightInspections,1);
      onAuth=undefined;release.resolve();await waitUntil(()=>service.control.getStatus().inFlightInspections===0);
      evidence.peerAbortPropagated=true;evidence.pendingContextRetainedAfterPeerClose=true;evidence.realProviderSettlementObserved=true;
    });
    let release;
    await scenario('returned HTTPS deadline retains actual One connection and private request context',async()=>{
      const entered=deferred();release=deferred();releaseGate={entered,release};const pending=send();await entered.promise;
      const response=await pending;assert.equal(response.status,504);await waitUntil(()=>bridge.control.getStatus().inFlightTransport===0);
      assert.equal(service.control.getStatus().inFlightInspections,1);assert.ok(bridge.context.readRequestContext(lastAuthenticatedRequest));
      assert.equal((await admin.query('SELECT pid FROM pg_stat_activity WHERE pid=$1',[parkedReleasePid])).rowCount,1);
      evidence.httpDeadlineBeforeActualRelease=true;evidence.contextRetainedAfterHttpTimeout=true;evidence.heldConnectionPid=parkedReleasePid;
    });
    await scenario('host shutdown waits for bridge listener service and registered database release',async()=>{
      const done=host.control.close();assert.equal(done,host.control.close());await flush();
      assert.equal(server.listening,false);assert.equal(releases,0);assert.equal(service.control.getStatus().state,'DRAINING');
      assert.equal(bridge.control.getStatus().state,'CLOSED');release.resolve();assert.equal((await done).state,'CLOSED');
      assert.equal(releasedPids.has(parkedReleasePid),true);assert.equal(releases,1);
      assert.deepEqual(events,['STOP_BEGIN','STOP_COMPLETED','RELEASE_BEGIN','RELEASE_COMPLETED']);
      evidence.composedShutdownExecuted=true;evidence.releaseAfterServiceDrain=true;evidence.shutdownOrder=events;
    });
    await scenario('terminal counts and original authority remain unchanged and no credential is emitted',async()=>{
      const serviceStatus=service.control.getStatus(),bridgeStatus=bridge.control.getStatus();
      assert.equal(serviceStatus.inFlightInspections,0);assert.equal(serviceStatus.readerCancellationsInFlight,0);
      assert.equal(serviceStatus.signer.backendState,'STOPPED');assert.equal(bridgeStatus.state,'CLOSED');assert.equal(bridgeStatus.inFlightTransport,0);
      const row=(await admin.query('SELECT revocation_state,session_epoch,revocation_revision FROM palaco_session_v99.session_security_epochs')).rows[0];
      const key=(await admin.query('SELECT status,revision FROM rio_staging_host.issuer_state')).rows[0];
      assert.equal(row.revocation_state,'ACTIVE');assert.equal(Number(row.session_epoch),3);assert.equal(Number(row.revocation_revision),4);
      assert.equal(key.status,'ACTIVE');assert.equal(key.revision,1);evidence.authorityUnaffectedObserved=true;
      assert.equal(JSON.stringify(bridgeStatus).includes(fixtureToken),false);evidence.noCredentialInStatus=true;
      evidence.closedServiceStatus=serviceStatus;evidence.closedBridgeStatus=bridgeStatus;
    });
    evidence.scenarioCount=evidence.scenarios.length;
    assert.equal(JSON.stringify(evidence).includes(fixtureToken),false);
    writeFileSync(new URL('../DIRECT-HTTPS-NATIVE-RESULT-v311.json',import.meta.url),JSON.stringify(evidence,null,2)+'\n');
  }finally{
    if(server?.listening){server.closeAllConnections();await new Promise(resolve=>server.close(()=>resolve()));}
    await cluster.close();if(certDir)rmSync(certDir,{recursive:true,force:true});
  }
});
