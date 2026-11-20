import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomBytes,sign} from 'node:crypto';
import {createRioOneSessionStatementIssuerV298} from '../rio-one-session-statement-issuer-v298.mjs';
import {createRioOneSignedSessionProviderV296,RIO_ONE_SESSION_AUDIENCE_V296 as AUDIENCE} from '../rio-one-signed-session-provider-v296.mjs';
import {RIO_ONE_SESSION_FORMAT_V295} from '../rio-palaco-one-session-reader-v295.mjs';
import {RIO_RECEIPT_INSPECTION_PATH_V269 as PATH} from '../rio-receipt-http-route-v269.mjs';

const origin='https://rio.example.invalid',at=Date.parse('2026-11-20T06:00:00Z');
const request=()=>new Request(origin+PATH,{method:'POST',headers:{Origin:origin,'X-RIO-Inspection':'1'}});
const challenge=()=>({format:'rio-one-session-challenge-v296-DRAFT',nonce:randomBytes(32).toString('base64url'),
  request:{origin,path:PATH,method:'POST'}});
function setup(){
  const pair=generateKeyPairSync('ed25519'),other=generateKeyPairSync('ed25519');
  const issuerKey={issuerId:'synthetic-one-issuer',keyId:'one-source-key',publicKeyPem:pair.publicKey.export({format:'pem',type:'spki'}),
    spkiSha256:createHash('sha256').update(pair.publicKey.export({format:'der',type:'spki'})).digest('hex')};
  const state={now:at,authCalls:0,keyCalls:0,signCalls:0,session:{format:RIO_ONE_SESSION_FORMAT_V295,
    state:'ACTIVE',assurance:'SERVER_AUTHENTICATED',tenantRef:'STAGING_TENANT_001',subjectId:'reviewer-001',
    sessionRef:'one-session-001',credentialId:'synthetic_credential_001',ppReference:'synthetic-pp-001',
    deviceBindingSha256:'a'.repeat(64),subjectEpoch:2,sessionEpoch:3,revocationRevision:4,ppRegistryRevision:5,
    issuedAt:new Date(at-60000).toISOString(),expiresAt:new Date(at+60000).toISOString(),observedAt:new Date(at).toISOString()},
    key:{state:'ACTIVE',issuerId:issuerKey.issuerId,keyId:issuerKey.keyId,revision:1,
      notBefore:new Date(at-60000).toISOString(),notAfter:new Date(at+60000).toISOString()}};
  const deps={tenantRef:'STAGING_TENANT_001',allowedOrigin:origin,issuerKey,now:()=>new Date(state.now),
    readAuthenticatedOneSession:async req=>{state.authCalls++;state.onAuth?.(req);return state.session===null?null:{...state.session};},
    readIssuerKeyState:async()=>{state.keyCalls++;state.onKey?.();return {...state.key};},
    signSessionStatement:async statement=>{
      state.signCalls++;assert.equal(statement.purpose,AUDIENCE);assert.equal(statement.keyId,issuerKey.keyId);
      assert.equal(Object.isFrozen(statement),true);state.statement=statement;state.onSign?.();
      return sign(null,Buffer.from(statement.payload),state.wrongKey?other.privateKey:pair.privateKey).toString('base64url');
    }};
  return {state,deps,pair,build:()=>createRioOneSessionStatementIssuerV298(deps)};
}
const decode=text=>JSON.parse(Buffer.from(JSON.parse(text).payload,'base64url'));
test('statement issuer requires existing-authentication, signer, clock and independently pinned public key',()=>{
  assert.throws(()=>createRioOneSessionStatementIssuerV298(),TypeError);
  const {deps,pair}=setup();
  assert.throws(()=>createRioOneSessionStatementIssuerV298({...deps,signSessionStatement:null}),TypeError);
  assert.throws(()=>createRioOneSessionStatementIssuerV298({...deps,issuerKey:{...deps.issuerKey,publicKeyPem:pair.privateKey.export({format:'pem',type:'pkcs8'})}}),TypeError);
  assert.throws(()=>createRioOneSessionStatementIssuerV298({...deps,issuerKey:{...deps.issuerKey,
    publicKeyPem:deps.issuerKey.publicKeyPem+pair.privateKey.export({format:'pem',type:'pkcs8'})}}),TypeError);
  assert.throws(()=>createRioOneSessionStatementIssuerV298({...deps,issuerKey:{...deps.issuerKey,spkiSha256:'0'.repeat(64)}}),TypeError);
});
test('implemented statement producer interoperates with unchanged v296 verifier using actual Ed25519',async()=>{
  const {state,deps,build}=setup(),issuer=build();
  const verifier=createRioOneSignedSessionProviderV296({tenantRef:deps.tenantRef,allowedOrigin:origin,
    issuerKey:deps.issuerKey,readIssuerKeyState:deps.readIssuerKeyState,now:deps.now,requestSignedSession:issuer.requestSignedSession});
  const result=await verifier.authenticateOneRequest(request());assert.deepEqual(result,state.session);
  assert.equal(state.authCalls,2);assert.equal(state.signCalls,1);assert.equal(state.keyCalls,4);
  assert.equal(issuer.sessionIssuance,false);assert.equal(issuer.realIdpVerified,false);assert.equal(issuer.authorization,'NONE');
});
test('challenge shape, request binding and nonce errors are refused before authentication or signing',async t=>{
  const edits=[c=>{c.nonce='bad';},c=>{c.nonce+='=';},c=>{c.request.path='/other';},
    c=>{c.request.origin='https://other.invalid';},c=>{c.request.method='GET';},
    c=>{c.audience='OWNER';},c=>{c.format='untrusted';}];
  for(const edit of edits)await t.test(String(edit),async()=>{const {state,build}=setup(),c=challenge();edit(c);
    assert.equal(await build().requestSignedSession(request(),c),null);assert.equal(state.authCalls,0);assert.equal(state.signCalls,0);});
});
test('pending, missing, stale and privilege-bearing One session facts never reach the signer',async t=>{
  const patches=[null,{state:'PENDING'},{assurance:'SELF_REPORTED'},{tenantRef:'OTHER_TENANT'},{role:'OWNER'},
    {subjectId:'unsupported:rio-id'},{sessionEpoch:0},{revocationRevision:Number.MAX_SAFE_INTEGER+1},
    {observedAt:new Date(at-1).toISOString()},{observedAt:new Date(at+1).toISOString()},
    {expiresAt:new Date(at).toISOString()}];
  for(const patch of patches)await t.test(JSON.stringify(patch),async()=>{
    const {state,build}=setup();state.session=patch===null?null:{...state.session,...patch};
    assert.equal(await build().requestSignedSession(request(),challenge()),null);assert.equal(state.signCalls,0);
  });
});
test('inactive source key stops the operation before One authentication',async()=>{
  const {state,build}=setup();state.key.state='REVOKED';assert.equal(await build().requestSignedSession(request(),challenge()),null);
  assert.equal(state.authCalls,0);assert.equal(state.signCalls,0);
});
test('signer responses must verify against the independent pinned public key',async()=>{
  const {state,build}=setup();state.wrongKey=true;assert.equal(await build().requestSignedSession(request(),challenge()),null);
  assert.equal(state.authCalls,1);assert.equal(state.signCalls,1);
});
test('a session or issuer revocation during signing withholds the resulting statement',async t=>{
  const changes=[s=>{s.session.state='REVOKED';},s=>{s.session.ppRegistryRevision++;},s=>{s.session.sessionRef='rotated-session';},
    s=>{s.key.state='REVOKED';},s=>{s.key.revision++;},s=>{s.key.notAfter=new Date(at+10000).toISOString();}];
  for(const change of changes)await t.test(String(change),async()=>{const {state,build}=setup();state.onSign=()=>change(state);
    assert.equal(await build().requestSignedSession(request(),challenge()),null);assert.equal(state.signCalls,1);});
});
test('source observation time is preserved and validity cannot outlive session or signing key',async()=>{
  for(const limit of ['session','key']){
    const {state,build}=setup();if(limit==='session')state.session.expiresAt=new Date(at+2000).toISOString();
    else state.key.notAfter=new Date(at+2000).toISOString();
    const message=decode(await build().requestSignedSession(request(),challenge()));
    assert.equal(message.issuedAt,state.session.observedAt);assert.equal(message.session.observedAt,message.issuedAt);
    assert.equal(Date.parse(message.expiresAt),at+2000);
  }
});
test('a refreshed second observation cannot relabel the first observation or extend proof lifetime',async()=>{
  const {state,build}=setup();state.onSign=()=>{state.now+=500;state.session.observedAt=new Date(state.now).toISOString();};
  const message=decode(await build().requestSignedSession(request(),challenge()));
  assert.equal(message.issuedAt,new Date(at).toISOString());assert.equal(Date.parse(message.expiresAt),at+5000);
});
test('expiry, excessive delay and backwards clock movement during signing fail closed',async()=>{
  for(const offset of [1001,60000,-1]){const {state,build}=setup();state.onSign=()=>{state.now+=offset;};
    assert.equal(await build().requestSignedSession(request(),challenge()),null);}
});
test('caller mutation cannot change the snapshotted challenge while authentication awaits',async()=>{
  const {state,build}=setup(),c=challenge(),nonce=c.nonce;
  state.onAuth=()=>{c.nonce=randomBytes(32).toString('base64url');c.request.path='/changed';};
  const message=decode(await build().requestSignedSession(request(),c));
  assert.equal(message.nonce,nonce);assert.equal(message.request.path,PATH);
});
test('provider and signing failures return no statement or private diagnostics',async()=>{
  for(const name of ['readAuthenticatedOneSession','readIssuerKeyState','signSessionStatement']){
    const {deps}=setup();deps[name]=async()=>{throw Error('PRIVATE_ONE_KEY_DETAIL');};
    assert.equal(await createRioOneSessionStatementIssuerV298(deps).requestSignedSession(request(),challenge()),null);
  }
});
