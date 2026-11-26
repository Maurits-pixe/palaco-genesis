import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createPublicKey,randomBytes,verify,webcrypto} from 'node:crypto';
import {createRioOneRestrictedSoftwareSignerV299} from '../rio-one-restricted-software-signer-v299.mjs';
import {createRioOneSessionStatementIssuerV298} from '../rio-one-session-statement-issuer-v298.mjs';
import {createRioOneSignedSessionProviderV296,RIO_ONE_SIGNED_SESSION_FORMAT_V296 as FORMAT,
  RIO_ONE_SESSION_AUDIENCE_V296 as AUDIENCE} from '../rio-one-signed-session-provider-v296.mjs';
import {RIO_ONE_SESSION_FORMAT_V295} from '../rio-palaco-one-session-reader-v295.mjs';
import {RIO_RECEIPT_INSPECTION_PATH_V269 as PATH} from '../rio-receipt-http-route-v269.mjs';

const at=Date.parse('2026-11-20T07:00:00Z'),origin='https://rio.example.invalid',tenantRef='STAGING_TENANT_001';
async function setup(){
  const pair=await webcrypto.subtle.generateKey({name:'Ed25519'},false,['sign','verify']);
  const publicKey=createPublicKey({key:Buffer.from(await webcrypto.subtle.exportKey('spki',pair.publicKey)),format:'der',type:'spki'});
  const issuerKey={issuerId:'synthetic-one-issuer',keyId:'source-key',publicKeyPem:publicKey.export({format:'pem',type:'spki'}),
    spkiSha256:createHash('sha256').update(publicKey.export({format:'der',type:'spki'})).digest('hex')};
  const session={format:RIO_ONE_SESSION_FORMAT_V295,state:'ACTIVE',assurance:'SERVER_AUTHENTICATED',tenantRef,
    subjectId:'reviewer-001',sessionRef:'one-session-001',credentialId:'synthetic_credential_001',ppReference:'synthetic-pp-001',
    deviceBindingSha256:'a'.repeat(64),subjectEpoch:2,sessionEpoch:3,revocationRevision:4,ppRegistryRevision:5,
    issuedAt:new Date(at-60000).toISOString(),expiresAt:new Date(at+60000).toISOString(),observedAt:new Date(at).toISOString()};
  const message={format:FORMAT,issuerId:issuerKey.issuerId,audience:AUDIENCE,tenantRef,nonce:randomBytes(32).toString('base64url'),
    request:{origin,path:PATH,method:'POST'},issuedAt:new Date(at).toISOString(),expiresAt:new Date(at+5000).toISOString(),session};
  const statement={purpose:AUDIENCE,issuerId:issuerKey.issuerId,keyId:issuerKey.keyId,payload:JSON.stringify(message)};
  const state={now:at,keyReads:0,key:{state:'ACTIVE',issuerId:issuerKey.issuerId,keyId:issuerKey.keyId,revision:1,
    notBefore:new Date(at-60000).toISOString(),notAfter:new Date(at+60000).toISOString()}};
  const config={tenantRef,allowedOrigin:origin,issuerKey,privateSigningKey:pair.privateKey,now:()=>new Date(state.now),
    readIssuerKeyState:async()=>{state.keyReads++;await state.onRead?.();if(state.error)throw Error('PRIVATE_BACKEND_DETAIL');return {...state.key};}};
  return {pair,publicKey,issuerKey,session,message,statement,state,config,build:()=>createRioOneRestrictedSoftwareSignerV299(config)};
}
test('software backend accepts only a genuine sign-only Ed25519 CryptoKey with WebCrypto export disabled',async()=>{
  const {config,pair}=await setup();
  assert.throws(()=>createRioOneRestrictedSoftwareSignerV299(),TypeError);
  for(const key of [pair.publicKey,'private-pem',{type:'private',extractable:false,algorithm:{name:'Ed25519'},usages:['sign']}])
    assert.throws(()=>createRioOneRestrictedSoftwareSignerV299({...config,privateSigningKey:key}),TypeError);
  const exportable=await webcrypto.subtle.generateKey({name:'Ed25519'},true,['sign','verify']);
  assert.throws(()=>createRioOneRestrictedSoftwareSignerV299({...config,privateSigningKey:exportable.privateKey}),TypeError);
  const ec=await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
  assert.throws(()=>createRioOneRestrictedSoftwareSignerV299({...config,privateSigningKey:ec.privateKey}),TypeError);
});
test('local backend exposes no private key/export API and explicitly makes no host-isolation or HSM claim',async()=>{
  const {build,pair}=await setup(),backend=build();
  await assert.rejects(webcrypto.subtle.exportKey('pkcs8',pair.privateKey));
  assert.equal(Object.hasOwn(backend,'privateSigningKey'),false);assert.equal(Object.hasOwn(backend,'exportKey'),false);
  assert.equal(backend.hostKeyIsolation,'NOT_PROVIDED');assert.equal(backend.hardwareProtection,'NOT_VERIFIED');
  assert.equal(backend.productionReady,false);assert.equal(Object.isFrozen(backend),true);
});
test('bounded concurrency and independent public pin are mandatory',async()=>{
  const {config}=await setup();for(const n of [0,17,Infinity])assert.throws(()=>createRioOneRestrictedSoftwareSignerV299({...config,maxConcurrentSignatures:n}),TypeError);
  assert.throws(()=>createRioOneRestrictedSoftwareSignerV299({...config,issuerKey:{...config.issuerKey,spkiSha256:'0'.repeat(64)}}),TypeError);
});
test('actual WebCrypto signature verifies independently against the configured public key',async()=>{
  const {statement,state,publicKey,build}=await setup(),signature=await build().signSessionStatement(statement);
  assert.equal(verify(null,Buffer.from(statement.payload),publicKey,Buffer.from(signature,'base64url')),true);
  assert.equal(state.keyReads,2);
});
test('a handle for another private key cannot satisfy the independent public pin',async()=>{
  const {config,statement}=await setup(),other=await webcrypto.subtle.generateKey({name:'Ed25519'},false,['sign','verify']);
  assert.equal(await createRioOneRestrictedSoftwareSignerV299({...config,privateSigningKey:other.privateKey}).signSessionStatement(statement),null);
});
test('full existing issuer/verifier pair works with the restricted software signing port',async()=>{
  const {config,session,build}=await setup(),backend=build();
  const issuer=createRioOneSessionStatementIssuerV298({tenantRef,allowedOrigin:origin,issuerKey:config.issuerKey,
    now:config.now,readIssuerKeyState:config.readIssuerKeyState,readAuthenticatedOneSession:async()=>({...session}),
    signSessionStatement:backend.signSessionStatement});
  const verifier=createRioOneSignedSessionProviderV296({tenantRef,allowedOrigin:origin,issuerKey:config.issuerKey,
    now:config.now,readIssuerKeyState:config.readIssuerKeyState,requestSignedSession:issuer.requestSignedSession});
  const result=await verifier.authenticateOneRequest(new Request(origin+PATH,{method:'POST',headers:{Origin:origin,'X-RIO-Inspection':'1'}}));
  assert.deepEqual(result,session);
});
test('the signing port refuses another purpose, issuer, key or an arbitrary signing payload before key-service calls',async t=>{
  for(const patch of [{purpose:'OWNER'},{issuerId:'other'},{keyId:'other'},{payload:'arbitrary bytes'},{algorithm:'none'}])
    await t.test(JSON.stringify(patch),async()=>{const {statement,state,build}=await setup();
      assert.equal(await build().signSessionStatement({...statement,...patch}),null);assert.equal(state.keyReads,0);});
});
test('canonical signed-message scope and active-session boundaries cannot be broadened',async t=>{
  const changes=[m=>{m.audience='OWNER';},m=>{m.tenantRef='OTHER';},m=>{m.issuerId='other';},m=>{m.nonce+='=';},
    m=>{m.request.path='/other';},m=>{m.request.origin='https://other.invalid';},m=>{m.request.method='GET';},
    m=>{m.session.state='PENDING';},m=>{m.session.role='OWNER';},m=>{m.session.tenantRef='OTHER';},
    m=>{m.session.assurance='SELF_REPORTED';},m=>{m.session.subjectEpoch=0;}];
  for(const change of changes)await t.test(String(change),async()=>{const {statement,message,state,build}=await setup();change(message);
    statement.payload=JSON.stringify(message);assert.equal(await build().signSessionStatement(statement),null);assert.equal(state.keyReads,0);});
});
test('duplicate JSON members, alternative whitespace and oversized inputs never become signatures',async()=>{
  const {statement,build}=await setup(),backend=build();
  for(const payload of [' '.repeat(9000),JSON.stringify(JSON.parse(statement.payload),null,2),
    statement.payload.replace('"audience":','"audience":"OWNER","audience":')])
    assert.equal(await backend.signSessionStatement({...statement,payload}),null);
});
test('expired, future, stale or overly long statements and session-expiry overrun are refused',async t=>{
  const edits=[m=>{m.expiresAt=new Date(at).toISOString();},m=>{m.issuedAt=new Date(at+1).toISOString();m.session.observedAt=m.issuedAt;},
    m=>{m.issuedAt=new Date(at-1001).toISOString();m.session.observedAt=m.issuedAt;},
    m=>{m.expiresAt=new Date(at+5001).toISOString();},m=>{m.session.expiresAt=new Date(at+1000).toISOString();}];
  for(const edit of edits)await t.test(String(edit),async()=>{const {statement,message,build}=await setup();edit(message);
    assert.equal(await build().signSessionStatement({...statement,payload:JSON.stringify(message)}),null);});
});
test('registry revocation, revision changes and time movement during signing withhold output',async()=>{
  for(const change of [s=>{s.key.state='REVOKED';},s=>{s.key.revision++;},s=>{s.now+=1001;},s=>{s.now--;}]){
    const {statement,state,build}=await setup();state.onRead=()=>{if(state.keyReads===2)change(state);};
    assert.equal(await build().signSessionStatement(statement),null);
  }
});
test('a stale job after the initial key-service wait is refused and does not occupy the slot forever',async()=>{
  const {statement,state,build}=await setup(),backend=build();state.onRead=()=>{state.now=at+1001;};
  assert.equal(await backend.signSessionStatement(statement),null);assert.equal(state.keyReads,1);
  state.onRead=null;state.now=at;assert.equal(typeof await backend.signSessionStatement(statement),'string');
});
test('in-flight capacity is bounded without a background queue',async()=>{
  const {statement,state,build}=await setup(),backend=build();let release,entered;
  const gate=new Promise(r=>{release=r;}),firstRead=new Promise(r=>{entered=r;});
  state.onRead=async()=>{if(state.keyReads===1){entered();await gate;}};
  const first=backend.signSessionStatement(statement);await firstRead;
  assert.equal(await backend.signSessionStatement(statement),null);assert.equal(state.keyReads,1);
  release();assert.equal(typeof await first,'string');assert.equal(typeof await backend.signSessionStatement(statement),'string');
});
test('registry errors release capacity and never return private diagnostics',async()=>{
  const {statement,state,build}=await setup(),backend=build();state.error=true;
  assert.equal(await backend.signSessionStatement(statement),null);state.error=false;
  assert.equal(typeof await backend.signSessionStatement(statement),'string');
});
test('caller mutation during registry awaits cannot change the snapshotted signing bytes',async()=>{
  const {statement,state,publicKey,build}=await setup(),original=statement.payload;
  state.onRead=()=>{statement.payload='changed';};const signature=await build().signSessionStatement(statement);
  assert.equal(verify(null,Buffer.from(original),publicKey,Buffer.from(signature,'base64url')),true);
  assert.equal(verify(null,Buffer.from(statement.payload),publicKey,Buffer.from(signature,'base64url')),false);
});
