import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {createRioOneSignedSessionProviderV296,RIO_ONE_SIGNED_SESSION_FORMAT_V296 as FORMAT,
  RIO_ONE_SESSION_AUDIENCE_V296 as AUDIENCE} from '../rio-one-signed-session-provider-v296.mjs';
import {RIO_ONE_SESSION_FORMAT_V295} from '../rio-palaco-one-session-reader-v295.mjs';
import {RIO_RECEIPT_INSPECTION_PATH_V269 as PATH} from '../rio-receipt-http-route-v269.mjs';

const origin='https://rio.example.invalid',at=Date.parse('2026-11-18T05:30:00Z');
function request(path=PATH,method='POST',headers={}){
  return new Request(origin+path,{method,headers:{Origin:origin,'X-RIO-Inspection':'1',...headers}});
}
function setup(){
  const pair=generateKeyPairSync('ed25519'),other=generateKeyPairSync('ed25519');
  const issuerKey={issuerId:'synthetic-one-issuer',keyId:'one-key-001',
    publicKeyPem:pair.publicKey.export({format:'pem',type:'spki'}),
    spkiSha256:createHash('sha256').update(pair.publicKey.export({format:'der',type:'spki'})).digest('hex')};
  const state={now:at,keyReads:0,sourceCalls:0,challenges:[],responses:[],keyState:{state:'ACTIVE',
    issuerId:issuerKey.issuerId,keyId:issuerKey.keyId,revision:1,
    notBefore:new Date(at-60000).toISOString(),notAfter:new Date(at+60000).toISOString()}};
  const session={format:RIO_ONE_SESSION_FORMAT_V295,state:'ACTIVE',assurance:'SERVER_AUTHENTICATED',
    tenantRef:'STAGING_TENANT_001',subjectId:'synthetic-reviewer',sessionRef:'one-session-001',
    credentialId:'synthetic_credential_001',ppReference:'synthetic-pp-001',deviceBindingSha256:'a'.repeat(64),
    subjectEpoch:2,sessionEpoch:3,revocationRevision:4,ppRegistryRevision:5,
    issuedAt:new Date(at-60000).toISOString(),expiresAt:new Date(at+60000).toISOString(),observedAt:new Date(at).toISOString()};
  const deps={tenantRef:'STAGING_TENANT_001',allowedOrigin:origin,issuerKey,now:()=>new Date(state.now),
    readIssuerKeyState:async()=>{state.keyReads++;state.onKeyRead?.();return {...state.keyState};},
    requestSignedSession:async(req,challenge)=>{
      state.sourceCalls++;state.challenges.push(challenge);
      if(state.replay)return state.responses[0];
      const message={format:FORMAT,issuerId:issuerKey.issuerId,audience:AUDIENCE,tenantRef:'STAGING_TENANT_001',
        nonce:challenge.nonce,request:{...challenge.request},issuedAt:new Date(state.now).toISOString(),
        expiresAt:new Date(state.now+5000).toISOString(),session:{...session,observedAt:new Date(state.now).toISOString()}};
      state.edit?.(message);let text=JSON.stringify(message);
      if(state.rawPayload)text=state.rawPayload(text);
      const bytes=Buffer.from(text),envelope={format:'rio-one-session-envelope-v296-DRAFT',keyId:issuerKey.keyId,
        payload:bytes.toString('base64url'),signature:sign(null,bytes,state.wrongSigner?other.privateKey:pair.privateKey).toString('base64url')};
      state.editEnvelope?.(envelope);state.afterSign?.();
      const response=JSON.stringify(envelope);state.responses.push(response);return response;
    }};
  return {state,session,deps,build:()=>createRioOneSignedSessionProviderV296(deps)};
}
test('signed session source requires an independent Ed25519 pin and explicit trusted services',()=>{
  assert.throws(()=>createRioOneSignedSessionProviderV296(),TypeError);
  const {deps}=setup();
  assert.throws(()=>createRioOneSignedSessionProviderV296({...deps,allowedOrigin:'http://rio.example.invalid'}),TypeError);
  assert.throws(()=>createRioOneSignedSessionProviderV296({...deps,issuerKey:{...deps.issuerKey,spkiSha256:'0'.repeat(64)}}),TypeError);
  const pair=generateKeyPairSync('ed25519');
  assert.throws(()=>createRioOneSignedSessionProviderV296({...deps,issuerKey:{...deps.issuerKey,
    publicKeyPem:pair.privateKey.export({format:'pem',type:'pkcs8'}),
    spkiSha256:createHash('sha256').update(pair.publicKey.export({format:'der',type:'spki'})).digest('hex')}}),TypeError);
});
test('real Ed25519 proof returns only the signed session after fresh key-state checks',async()=>{
  const {state,session,build}=setup(),p=build();const result=await p.authenticateOneRequest(request());
  assert.deepEqual(result,session);assert.equal(Object.isFrozen(result),true);
  assert.equal(state.keyReads,2);assert.equal(state.sourceCalls,1);
  assert.equal(p.authorization,'NONE');assert.equal(p.realOneGatewayConnected,false);
  assert.equal(Object.hasOwn(result,'nonce'),false);
});
test('every request and recheck uses a fresh immutable 256-bit server challenge',async()=>{
  const {state,build}=setup(),p=build(),req=request();
  assert.ok(await p.authenticateOneRequest(req));assert.ok(await p.authenticateOneRequest(req));
  assert.ok(await p.authenticateOneRequest(request()));
  assert.equal(new Set(state.challenges.map(x=>x.nonce)).size,3);
  assert.equal(state.challenges.every(x=>Object.isFrozen(x)&&Object.isFrozen(x.request)&&Buffer.from(x.nonce,'base64url').length===32),true);
});
test('signed response replay fails for both a recheck and another Request',async()=>{
  for(const sameRequest of [true,false]){const {state,build}=setup(),p=build(),req=request();
    assert.ok(await p.authenticateOneRequest(req));state.replay=true;
    assert.equal(await p.authenticateOneRequest(sameRequest?req:request()),null);}
});
test('tampering, another signing key, algorithm/embedded-key substitution and noncanonical encodings fail',async t=>{
  const changes=[['wrong signature',s=>{s.wrongSigner=true;}],
    ['payload changed',s=>{s.editEnvelope=e=>{const p=JSON.parse(Buffer.from(e.payload,'base64url'));p.session.subjectId='forged';e.payload=Buffer.from(JSON.stringify(p)).toString('base64url');};}],
    ['embedded public key',s=>{s.editEnvelope=e=>{e.publicKeyPem='untrusted';};}],
    ['algorithm field',s=>{s.editEnvelope=e=>{e.algorithm='none';};}],
    ['wrong key id',s=>{s.editEnvelope=e=>{e.keyId='untrusted-key';};}],
    ['padded signature',s=>{s.editEnvelope=e=>{e.signature+='=';};}],
    ['short signature',s=>{s.editEnvelope=e=>{e.signature=Buffer.alloc(63).toString('base64url');};}],
    ['oversized envelope',s=>{s.editEnvelope=e=>{e.payload='A'.repeat(20000);};}],
    ['duplicate member',s=>{s.rawPayload=text=>text.replace('"audience":','"audience":"OTHER","audience":');}],
    ['pretty-printed payload',s=>{s.rawPayload=text=>JSON.stringify(JSON.parse(text),null,2);}]];
  for(const [name,change] of changes)await t.test(name,async()=>{const {state,build}=setup();change(state);assert.equal(await build().authenticateOneRequest(request()),null);});
});
test('valid signatures cannot override issuer, audience, tenant, request or authenticated-session scope',async t=>{
  const changes=[['issuer',m=>{m.issuerId='other-issuer';}],['audience',m=>{m.audience='OWNER';}],
    ['tenant',m=>{m.tenantRef='other-tenant';}],['nonce',m=>{m.nonce='forged';}],
    ['path',m=>{m.request.path='/api/other';}],['origin',m=>{m.request.origin='https://other.invalid';}],
    ['method',m=>{m.request.method='GET';}],['pending',m=>{m.session.state='PENDING';}],
    ['session tenant',m=>{m.session.tenantRef='other-tenant';}],['session privilege field',m=>{m.session.role='OWNER';}],
    ['self-reported session',m=>{m.session.assurance='SELF_REPORTED';}],
    ['stale session observation',m=>{m.session.observedAt=new Date(at-1).toISOString();}]];
  for(const [name,edit] of changes)await t.test(name,async()=>{const {state,build}=setup();state.edit=edit;assert.equal(await build().authenticateOneRequest(request()),null);});
});
test('proof validity is bounded independently from the session lifetime',async t=>{
  for(const [name,edit] of [['future',m=>{m.issuedAt=new Date(at+1).toISOString();m.session.observedAt=m.issuedAt;}],
    ['expired',m=>{m.expiresAt=new Date(at).toISOString();}],
    ['before request',m=>{m.issuedAt=new Date(at-1).toISOString();m.session.observedAt=m.issuedAt;}],
    ['long lived',m=>{m.expiresAt=new Date(at+5001).toISOString();}],
    ['session expired',m=>{m.session.expiresAt=new Date(at).toISOString();}]])await t.test(name,async()=>{
      const {state,build}=setup();state.edit=edit;assert.equal(await build().authenticateOneRequest(request()),null);
    });
});
test('source key revocation, revision change and expiry during the source call all fail closed',async()=>{
  for(const change of [s=>{s.keyState.state='REVOKED';},s=>{s.keyState.revision++;},s=>{s.now=at+60000;},s=>{s.now=at-1;}]){
    const {state,build}=setup();state.afterSign=()=>change(state);assert.equal(await build().authenticateOneRequest(request()),null);
  }
});
test('wrong request origin, method, query or missing guard headers never call the source',async()=>{
  const {state,build}=setup(),p=build();
  for(const req of [request(PATH,'GET'),request(PATH+'?x=1'),request(PATH+'#x'),request('/other'),
    request(PATH,'POST',{Origin:'https://other.invalid'}),request(PATH,'POST',{'X-RIO-Inspection':''}),{}])
    assert.equal(await p.authenticateOneRequest(req),null);
  assert.equal(state.sourceCalls,0);assert.equal(state.keyReads,0);
});
test('a revoked key is rejected before the source receives a challenge',async()=>{
  const {state,build}=setup();state.keyState.state='REVOKED';assert.equal(await build().authenticateOneRequest(request()),null);
  assert.equal(state.sourceCalls,0);
});
test('concurrent responses retain their own challenge and Request correlation',async()=>{
  const {state,deps}=setup(),source=deps.requestSignedSession;
  deps.requestSignedSession=async(req,c)=>{await new Promise(r=>setTimeout(r,req.headers.get('X-Delay')?10:0));return source(req,c);};
  const p=createRioOneSignedSessionProviderV296(deps);
  const result=await Promise.all([p.authenticateOneRequest(request(PATH,'POST',{'X-Delay':'1'})),p.authenticateOneRequest(request())]);
  assert.equal(result.every(Boolean),true);assert.equal(new Set(state.challenges.map(x=>x.nonce)).size,2);
});
test('mutable trusted configuration cannot replace a pinned key after construction',async()=>{
  const {deps}=setup(),p=createRioOneSignedSessionProviderV296(deps);
  // Mutating this source's key-id changes its messages, not the verifier's pin.
  deps.issuerKey.keyId='changed-key';assert.equal(await p.authenticateOneRequest(request()),null);
});
test('provider and key-service errors are contained without forwarding sensitive diagnostics',async()=>{
  for(const dependency of ['readIssuerKeyState','requestSignedSession']){
    const {deps}=setup();deps[dependency]=async()=>{throw Error('PRIVATE_CREDENTIAL_DETAIL');};
    assert.equal(await createRioOneSignedSessionProviderV296(deps).authenticateOneRequest(request()),null);
  }
});
