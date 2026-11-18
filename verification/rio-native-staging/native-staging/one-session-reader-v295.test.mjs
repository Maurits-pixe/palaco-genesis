import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {startLocalClusterV279} from './local-cluster-v279.mjs';
import {createRioOneSessionReaderV295,RIO_ONE_SESSION_FORMAT_V295} from '../rio-palaco-one-session-reader-v295.mjs';

test('v295 One source reader uses native PostgreSQL security state',{timeout:60000},async t=>{
  const cluster=await startLocalClusterV279();
  const evidence={format:'rio-one-native-reader-result-v295',syntheticDataOnly:true,
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
    const now=Date.now(),state={session:{format:RIO_ONE_SESSION_FORMAT_V295,state:'ACTIVE',assurance:'SERVER_AUTHENTICATED',
      tenantRef:'STAGING_TENANT_001',subjectId:'reviewer-001',sessionRef:'one-session-001',
      credentialId:'synthetic_credential_001',ppReference:'synthetic-pp-001',deviceBindingSha256:'a'.repeat(64),
      subjectEpoch:2,sessionEpoch:3,revocationRevision:4,ppRegistryRevision:5,
      issuedAt:new Date(now-1000).toISOString(),expiresAt:new Date(now+60000).toISOString(),observedAt:new Date(now).toISOString()}};
    const pids=[];let acquired=0;
    const port=(overrides={})=>createRioOneSessionReaderV295({tenantRef:'STAGING_TENANT_001',now:()=>new Date(),
      authenticateOneRequest:async()=>({...state.session,observedAt:new Date().toISOString()}),
      acquireOneReadConnection:async()=>{
        acquired++;const c=await cluster.connect('rio_v276_reader');
        pids.push((await c.query('SELECT pg_backend_pid() AS pid')).rows[0].pid);
        return {query:(sql,values)=>c.query(sql,values),release:()=>c.end()};
      },...overrides});
    const request=()=>new Request('https://rio.example.invalid/');
    await scenario('fresh direct reader connections observe native One column contracts',async()=>{
      const p=port(),req=request();assert.ok(await p.authenticateHostRequest(req));assert.ok(await p.authenticateHostRequest(req));
      assert.notEqual(pids[0],pids[1]);evidence.distinctReaderBackendPids=pids.slice(0,2);
    });
    await scenario('a pending One intent never reaches the SQL reader or authenticates RIO',async()=>{
      const before=acquired;const p=port({authenticateOneRequest:async()=>({...state.session,state:'PENDING'})});
      assert.equal(await p.authenticateHostRequest(request()),null);assert.equal(acquired,before);
    });
    await scenario('committed native revocation is denied on the next host recheck',async()=>{
      const p=port(),req=request();assert.ok(await p.authenticateHostRequest(req));
      await writer.query("UPDATE palaco_session_v99.session_security_epochs SET revocation_state='REVOKED',session_epoch=4,revocation_revision=5");
      assert.equal(await p.authenticateHostRequest(req),null);
      await writer.query("UPDATE palaco_session_v99.session_security_epochs SET revocation_state='ACTIVE',session_epoch=3,revocation_revision=4");
    });
    await scenario('changed registry revision is not hidden by an unchanged session epoch',async()=>{
      const p=port(),req=request();assert.ok(await p.authenticateHostRequest(req));
      await writer.query('UPDATE palaco_login_v94.pp_passkey_bindings_v96 SET registry_revision=6');
      state.session.ppRegistryRevision=6;
      assert.equal(await p.authenticateHostRequest(req),null);assert.ok(await p.authenticateHostRequest(request()));
    });
    await scenario('a distinct authenticated reader is denied another synthetic tenant by FORCE RLS',async()=>{
      const c=await cluster.connect('rio_v276_reader');
      assert.equal((await c.query("SELECT count(*)::integer AS n FROM palaco_session_v99.session_security_epochs WHERE tenant_reference='OTHER_SYNTHETIC_TENANT'")).rows[0].n,0);await c.end();
      const p=port({tenantRef:'OTHER_SYNTHETIC_TENANT',authenticateOneRequest:async()=>({...state.session,tenantRef:'OTHER_SYNTHETIC_TENANT',observedAt:new Date().toISOString()})});
      assert.equal(await p.authenticateHostRequest(request()),null);
    });
    await scenario('owner connections, write grants and disabled FORCE RLS are rejected',async()=>{
      const owner=port({acquireOneReadConnection:async()=>{const c=await cluster.connect();return {query:(s,v)=>c.query(s,v),release:()=>c.end()};}});
      assert.equal(await owner.authenticateHostRequest(request()),null);
      await admin.query('GRANT UPDATE ON palaco_session_v99.session_security_epochs TO rio_v276_reader');
      assert.equal(await port().authenticateHostRequest(request()),null);
      await admin.query('REVOKE UPDATE ON palaco_session_v99.session_security_epochs FROM rio_v276_reader');
      await admin.query('ALTER TABLE palaco_session_v99.session_security_epochs NO FORCE ROW LEVEL SECURITY');
      assert.equal(await port().authenticateHostRequest(request()),null);
      await admin.query('ALTER TABLE palaco_session_v99.session_security_epochs FORCE ROW LEVEL SECURITY');
      assert.ok(await port().authenticateHostRequest(request()));
    });
    evidence.scenarioCount=evidence.scenarios.length;
    writeFileSync(new URL('../ONE-NATIVE-RESULT-v295.json',import.meta.url),JSON.stringify(evidence,null,2)+'\n');
  }finally{await cluster.close();}
});
