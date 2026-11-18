import test from 'node:test';
import assert from 'node:assert/strict';
import {createRioOneSessionReaderV295,RIO_ONE_SESSION_FORMAT_V295,
  RIO_ONE_READER_SECURITY_QUERY_V295 as ROLE,RIO_ONE_CURRENT_SECURITY_QUERY_V295 as CURRENT}
  from '../rio-palaco-one-session-reader-v295.mjs';

const TENANT='STAGING_TENANT_001',at=Date.parse('2026-11-18T05:00:00Z');
const request=()=>new Request('https://rio.example.invalid/api/rio/audit/receipt-inspection',{
  method:'POST',body:JSON.stringify({subjectId:'forged-owner',sessionRef:'forged',role:'OWNER'}),
  headers:{Cookie:'rio-staging=synthetic-handle','X-Subject':'forged-owner'}});
function setup(){
  const state={now:at,acquired:0,released:0,queries:[],
    session:{format:RIO_ONE_SESSION_FORMAT_V295,state:'ACTIVE',assurance:'SERVER_AUTHENTICATED',
      tenantRef:TENANT,subjectId:'synthetic-reviewer',sessionRef:'one-session-001',
      credentialId:'synthetic_credential_001',ppReference:'synthetic-pp-001',deviceBindingSha256:'a'.repeat(64),
      subjectEpoch:2,sessionEpoch:3,revocationRevision:4,ppRegistryRevision:5,
      issuedAt:new Date(at-60000).toISOString(),expiresAt:new Date(at+60000).toISOString(),observedAt:new Date(at).toISOString()},
    role:{principal:'fixture_reader',login_principal:'fixture_reader',isolation:'read committed',
      read_only:'on',rolsuper:false,rolbypassrls:false,safe_source_tables:3},
    row:{ownership_state:'VERIFIED',registry_revision:'5',subject_state:'ACTIVE',subject_epoch:'2',
      credential_state:'ACTIVE',session_epoch:'3',revocation_revision:'4',device_binding_sha256:'a'.repeat(64)}};
  const deps={tenantRef:TENANT,now:()=>new Date(state.now),authenticateOneRequest:async()=>state.session,
    acquireOneReadConnection:async()=>{
      state.acquired++;
      return {query:async(sql,values)=>{
        state.queries.push({sql,values});if(state.errorSql===sql)throw Error('PRIVATE_DATABASE_DETAIL');
        if(sql===ROLE)return {rowCount:1,rows:[state.role]};
        if(sql===CURRENT){state.onRead?.();return {rowCount:state.duplicate?2:1,rows:state.duplicate?[state.row,state.row]:[state.row]};}
        return {rowCount:0,rows:[]};
      },release:async()=>{state.released++;if(state.releaseError)throw Error('PRIVATE_RELEASE_DETAIL');}};
    }};
  return {state,deps,build:()=>createRioOneSessionReaderV295(deps)};
}
test('One session reader requires trusted host services and a bounded server clock policy',()=>{
  assert.throws(()=>createRioOneSessionReaderV295(),TypeError);
  const {deps}=setup();for(const age of [0,5001,Infinity,'1'])assert.throws(()=>createRioOneSessionReaderV295({...deps,maxObservationAgeMs:age}),TypeError);
});
test('current gateway refusal and pending-intent payloads never become host authentication',async t=>{
  for(const input of [{error:'AUTHENTICATION_REQUIRED',session:null},null,{state:'PENDING_COMMITTED'},
    {...setup().state.session,state:'PENDING'}, {...setup().state.session,format:'PALACO-ONE-GATE/12.1-DRAFT'}]){
    await t.test(JSON.stringify(input).slice(0,80),async()=>{const {state,build}=setup();state.session=input;
      assert.equal(await build().authenticateHostRequest(request()),null);assert.equal(state.acquired,0);});
  }
});
test('valid synthetic trusted-host contract is minimized; browser identity claims are ignored',async()=>{
  const {state,build}=setup(),port=build();const actor=await port.authenticateHostRequest(request());
  assert.deepEqual(actor,{state:'ACTIVE',assurance:'HOST_VERIFIED',tenantRef:TENANT,
    subjectId:'synthetic-reviewer',sessionRef:'one-session-001',sessionGeneration:3});
  assert.equal(Object.isFrozen(actor),true);
  assert.deepEqual(state.queries.find(x=>x.sql===CURRENT).values,
    [TENANT,'synthetic-reviewer','synthetic-pp-001','synthetic_credential_001']);
  assert.equal(JSON.stringify(actor).includes('synthetic-pp'),false);
  assert.equal(port.oneGatewayV16Compatible,false);assert.equal(port.authorization,'NONE');
});
test('each host recheck obtains and releases a reader connection and repeats current security reads',async()=>{
  const {state,build}=setup(),port=build(),req=request();
  assert.ok(await port.authenticateHostRequest(req));assert.ok(await port.authenticateHostRequest(req));
  assert.equal(state.acquired,2);assert.equal(state.released,2);
  assert.equal(state.queries.filter(x=>x.sql===CURRENT).length,2);
});
test('malformed, stale, expired, cross-tenant and privilege-bearing session contracts fail before SQL',async t=>{
  const changes=[{tenantRef:'other-tenant'},{subjectId:'one:unsupported-rio-id'},{assurance:'SELF_REPORTED'},
    {role:'OWNER'},{sessionEpoch:0},{sessionEpoch:Number.MAX_SAFE_INTEGER+1},{credentialId:'short'},
    {expiresAt:new Date(at).toISOString()},{observedAt:new Date(at+1).toISOString()},
    {observedAt:new Date(at-1001).toISOString()},{issuedAt:new Date(at+1).toISOString()}];
  for(const patch of changes)await t.test(JSON.stringify(patch),async()=>{
    const {state,build}=setup();Object.assign(state.session,patch);
    assert.equal(await build().authenticateHostRequest(request()),null);assert.equal(state.acquired,0);
  });
});
test('unsafe database principals, transactions and source table rights are refused',async t=>{
  for(const patch of [{rolsuper:true},{rolbypassrls:true},{login_principal:'another-login'},
    {isolation:'repeatable read'},{read_only:'off'},{safe_source_tables:2}])await t.test(JSON.stringify(patch),async()=>{
    const {state,build}=setup();Object.assign(state.role,patch);
    assert.equal(await build().authenticateHostRequest(request()),null);
    assert.equal(state.queries.some(x=>x.sql===CURRENT),false);assert.equal(state.released,1);
  });
});
test('every source security component is matched and ambiguous SQL rows are refused',async t=>{
  for(const patch of [{ownership_state:'REVOKED'},{subject_state:'REVOKED'},{credential_state:'REVOKED'},
    {registry_revision:'6'},{subject_epoch:'3'},{session_epoch:'4'},{revocation_revision:'5'},
    {device_binding_sha256:'b'.repeat(64)},{session_epoch:'9007199254740992'},{session_epoch:'3.0'}]){
    await t.test(JSON.stringify(patch),async()=>{const {state,build}=setup();Object.assign(state.row,patch);
      assert.equal(await build().authenticateHostRequest(request()),null);});
  }
  const {state,build}=setup();state.duplicate=true;assert.equal(await build().authenticateHostRequest(request()),null);
});
test('a changed PP revision cannot hide behind an unchanged numeric session epoch',async()=>{
  const {state,build}=setup(),port=build(),req=request();assert.ok(await port.authenticateHostRequest(req));
  state.session={...state.session,ppRegistryRevision:6};state.row.registry_revision='6';
  assert.equal(await port.authenticateHostRequest(req),null);
  // A distinct request may authenticate the new, independently supplied tuple.
  assert.ok(await port.authenticateHostRequest(request()));
});
test('denial remains attached only to that exact Request object',async()=>{
  const {state,build}=setup(),port=build(),a=request(),b=request();
  state.row.subject_state='REVOKED';assert.equal(await port.authenticateHostRequest(a),null);
  state.row.subject_state='ACTIVE';assert.equal(await port.authenticateHostRequest(a),null);
  assert.ok(await port.authenticateHostRequest(b));assert.equal(await port.authenticateHostRequest({headers:a.headers}),null);
});
test('source, SQL and cleanup errors fail closed without exposing private diagnostics',async()=>{
  for(const mode of ['provider','sql','cleanup']){
    const {state,deps}=setup();if(mode==='provider')deps.authenticateOneRequest=async()=>{throw Error('PRIVATE_IDP_DETAIL');};
    if(mode==='sql')state.errorSql=CURRENT;if(mode==='cleanup')state.releaseError=true;
    assert.equal(await createRioOneSessionReaderV295(deps).authenticateHostRequest(request()),null);
  }
});
test('expiry during a database wait and backwards server time cannot produce a host actor',async()=>{
  for(const target of [at+60000,at-1]){const {state,build}=setup();state.onRead=()=>{state.now=target;};
    assert.equal(await build().authenticateHostRequest(request()),null);}
});
test('session facts are snapshotted before database awaits and compared on the next recheck',async()=>{
  const {state,build}=setup(),port=build(),req=request();
  state.onRead=()=>{state.session.subjectId='changed-reviewer';};
  assert.equal((await port.authenticateHostRequest(req)).subjectId,'synthetic-reviewer');
  state.onRead=null;assert.equal(await port.authenticateHostRequest(req),null);
});
