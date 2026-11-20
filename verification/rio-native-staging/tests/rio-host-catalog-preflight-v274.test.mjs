import test from 'node:test';
import assert from 'node:assert/strict';
import {assessRioHostCatalogV274,createRioHostCatalogPreflightV274,RIO_HOST_CATALOG_QUERY_V274}
  from '../rio-host-catalog-preflight-v274.mjs';

const at='2026-11-16T16:00:00.000Z';
const fixture=()=>[
  ['rio_audit_keys','verification_keys',['key_id','algorithm','public_key_pem','spki_sha256','status','not_before','not_after','revoked_at']],
  ['rio_identity_gate','revocation_requests',['request_id','request_payload','status','result_generation','recorded_at']],
  ['rio_identity_gate','session_generation',['session_ref','subject_id','generation','active','updated_at']],
  ['rio_identity_gate','review_policy_generation',['subject_id','conversation_id','dossier_id','generation','review_permitted','updated_at']],
  ['auth','users',['id']],['auth','sessions',['id']],
].map(([schema_name,object_name,column_names])=>({schema_name,object_name,column_names,present:true,
  object_kind:'r',rls_enabled:false,force_rls:false,anon_select:false,authenticated_select:false}));
const assess=rows=>assessRioHostCatalogV274({catalogRows:rows,projectReference:'synthetic-project',observedAt:at});
const missing=row=>({...row,present:false,object_kind:null,rls_enabled:null,force_rls:null,
  column_names:[],anon_select:null,authenticated_select:null});
test('compatible metadata never claims provider integration or production readiness',()=>{
  const r=assess(fixture());
  assert.equal(r.ok,true);assert.equal(r.inspectionStatus,'EXECUTED');
  assert.equal(r.state,'SCHEMA_METADATA_COMPATIBLE_PROVIDERS_UNVERIFIED');
  assert.equal(r.integrationReady,false);assert.equal(r.productionReady,false);
  assert.equal(r.providerVerification,'NOT_EXECUTED');assert.equal(r.authorization,'NONE');
  assert.equal(r.acceptance,'HOLD');assert.equal(Object.isFrozen(r),true);
});
test('four absent RIO objects produce four specific blockers, despite generic auth tables',()=>{
  const rows=fixture().map(row=>row.schema_name==='auth'?row:missing(row));
  const r=assess(rows);
  assert.equal(r.ok,false);assert.equal(r.inspectionStatus,'EXECUTED');
  assert.equal(r.state,'HOST_SCHEMA_BLOCKED');assert.equal(r.missingRequiredObjectCount,4);
  assert.equal(r.blockers.length,4);assert.equal(r.blockers.every(b=>b.reason==='REQUIRED_OBJECT_MISSING'),true);
});
test('auth context is informational and cannot authorize a PALACO One session',()=>{
  const rows=fixture().map(row=>row.schema_name==='auth'?missing(row):row);
  const r=assess(rows);
  assert.equal(r.ok,true);assert.equal(r.integrationReady,false);
  assert.equal(r.observations.filter(o=>o.classification==='CONTEXT_ONLY'&&!o.present).length,2);
});
test('missing required columns are named, with no user-row content',()=>{
  const rows=fixture();rows[0].column_names=rows[0].column_names.filter(c=>c!=='spki_sha256');
  const r=assess(rows);assert.equal(r.ok,false);
  assert.deepEqual(r.observations[0].missingColumns,['spki_sha256']);
  assert.equal(r.blockers.some(b=>b.reason==='REQUIRED_COLUMNS_MISSING'),true);
});
test('a view cannot silently replace a required base table',()=>{
  const rows=fixture();rows[0].object_kind='v';
  assert.equal(assess(rows).blockers.some(b=>b.reason==='BASE_TABLE_REQUIRED'),true);
});
test('client SELECT grant or an unknown role privilege blocks required objects',()=>{
  for(const value of [true,null]){
    const rows=fixture();rows[0].anon_select=value;
    assert.equal(assess(rows).blockers.some(b=>b.reason==='CLIENT_READ_NOT_DENIED_OR_UNKNOWN'),true);
  }
});
test('duplicate, missing, unexpected or malformed metadata refuses assessment',()=>{
  const duplicate=fixture();duplicate[1]=structuredClone(duplicate[0]);
  const unexpected=fixture();unexpected[0].object_name='other';
  const malformed=fixture();malformed[0].present='true';
  const inconsistent=fixture();inconsistent[0]=missing(inconsistent[0]);inconsistent[0].column_names=['key_id'];
  for(const rows of [duplicate,fixture().slice(1),unexpected,malformed,inconsistent]){
    const r=assess(rows);assert.equal(r.inspectionStatus,'FAILED');assert.equal(r.reason,'CATALOG_RESPONSE_INVALID');
    assert.equal(r.integrationReady,false);
  }
});
test('observation context and explicit clock are required',async()=>{
  assert.equal(assessRioHostCatalogV274({catalogRows:fixture()}).reason,'TRUSTED_OBSERVATION_CONTEXT_REQUIRED');
  assert.throws(()=>createRioHostCatalogPreflightV274({query:async()=>({rows:fixture()})}),TypeError);
  const inspector=createRioHostCatalogPreflightV274({query:async()=>({rows:fixture()}),now:()=>0,projectReference:'synthetic'});
  assert.equal((await inspector.inspect()).reason,'TRUSTED_CLOCK_UNAVAILABLE');
});
test('executor supplies only the fixed catalog SELECT and no input parameters',async()=>{
  let called=0;
  const inspector=createRioHostCatalogPreflightV274({projectReference:'synthetic',now:()=>new Date(at),
    query:async(...args)=>{called++;assert.deepEqual(args,[RIO_HOST_CATALOG_QUERY_V274]);
      assert.match(args[0],/^WITH wanted/);assert.doesNotMatch(args[0],/\b(INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|GRANT|REVOKE)\b/i);
      return {rows:fixture()};}});
  assert.equal((await inspector.inspect()).ok,true);assert.equal(called,1);
});
test('query failure is contained and never leaks diagnostic contents',async()=>{
  const inspector=createRioHostCatalogPreflightV274({projectReference:'synthetic',now:()=>new Date(at),
    query:async()=>{throw Error('private-diagnostic');}});
  const r=await inspector.inspect();assert.equal(r.ok,false);assert.equal(r.reason,'CATALOG_QUERY_OR_CLOCK_FAILED');
  assert.equal(JSON.stringify(r).includes('private-diagnostic'),false);
});
