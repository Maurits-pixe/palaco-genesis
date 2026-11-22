import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createPublicKey,randomBytes,verify,webcrypto} from 'node:crypto';
import {createRioOneDrainableSoftwareSignerV300} from '../rio-one-drainable-software-signer-v300.mjs';
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
  return {pair,publicKey,issuerKey,session,message,statement,state,config,build:()=>createRioOneDrainableSoftwareSignerV300(config)};
}
const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};
test('lifecycle status is local, immutable and contains no private handle or authorization',async()=>{
  const {state,build}=await setup(),backend=build(),status=backend.getStatus();
  assert.deepEqual(status,{format:'rio-one-signer-lifecycle-v300',state:'OPEN',inFlight:0,capacity:1,acceptingWork:true,acceptance:'HOLD',authorization:'NONE'});
  assert.equal(Object.isFrozen(status),true);assert.equal(state.keyReads,0);
  assert.equal(backend.hostKeyIsolation,'NOT_PROVIDED');assert.equal(backend.hardwareProtection,'NOT_VERIFIED');
  assert.equal(Object.hasOwn(status,'privateSigningKey'),false);assert.equal(Object.hasOwn(backend,'exportKey'),false);
});
test('OPEN lifecycle preserves real Ed25519 signing and releases its active slot',async()=>{
  const {statement,publicKey,state,build}=await setup(),backend=build();
  const signature=await backend.signSessionStatement(statement);
  assert.equal(verify(null,Buffer.from(statement.payload),publicKey,Buffer.from(signature,'base64url')),true);
  assert.equal(backend.getStatus().inFlight,0);assert.equal(backend.getStatus().state,'OPEN');assert.equal(state.keyReads,2);
});
test('idle stop is one-way and idempotent; subsequent requests never reach the key service',async()=>{
  const {statement,state,build}=await setup(),backend=build();
  const first=backend.stop();assert.equal(first,backend.stop());
  assert.equal((await first).state,'STOPPED');assert.equal(backend.getStatus().inFlight,0);
  assert.equal(await backend.signSessionStatement(statement),null);assert.equal(state.keyReads,0);
  assert.equal(Object.hasOwn(backend,'resume'),false);
});
test('stop while the first key lookup is pending rejects new work and waits for actual completion',async()=>{
  const {statement,state,build}=await setup(),backend=build(),entered=deferred(),release=deferred();
  state.onRead=async()=>{if(state.keyReads===1){entered.resolve();await release.promise;}};
  const job=backend.signSessionStatement(statement);await entered.promise;
  assert.equal(backend.getStatus().acceptingWork,false);
  const drained=backend.stop();let finished=false;drained.then(()=>{finished=true;});await Promise.resolve();
  assert.equal(finished,false);assert.equal(backend.getStatus().state,'DRAINING');assert.equal(backend.getStatus().inFlight,1);
  assert.equal(await backend.signSessionStatement(statement),null);assert.equal(state.keyReads,1);
  release.resolve();assert.equal(await job,null);assert.equal((await drained).state,'STOPPED');assert.equal(state.keyReads,1);
});
test('stop after real cryptography but before the final registry response withholds the signature',async()=>{
  const {statement,state,build}=await setup(),backend=build(),entered=deferred(),release=deferred();
  state.onRead=async()=>{if(state.keyReads===2){entered.resolve();await release.promise;}};
  const job=backend.signSessionStatement(statement);await entered.promise;
  const drained=backend.stop();assert.equal(backend.getStatus().state,'DRAINING');
  release.resolve();assert.equal(await job,null);assert.equal((await drained).inFlight,0);assert.equal(state.keyReads,2);
});
test('multiple in-flight jobs must all finish before STOPPED is reported',async()=>{
  const {statement,state,config}=await setup(),a=deferred(),b=deferred(),both=deferred();
  config.maxConcurrentSignatures=2;const backend=createRioOneDrainableSoftwareSignerV300(config);
  state.onRead=async()=>{const n=state.keyReads;if(n===2)both.resolve();await(n===1?a.promise:b.promise);};
  const first=backend.signSessionStatement(statement),second=backend.signSessionStatement(statement);await both.promise;
  const drained=backend.stop();assert.equal(backend.getStatus().inFlight,2);
  a.resolve();assert.equal(await first,null);assert.equal(backend.getStatus().state,'DRAINING');assert.equal(backend.getStatus().inFlight,1);
  b.resolve();assert.equal(await second,null);assert.equal((await drained).state,'STOPPED');
});
test('provider failure during draining cannot reopen the gate or leave an active slot',async()=>{
  const {statement,state,build}=await setup(),backend=build(),entered=deferred(),release=deferred();
  state.onRead=async()=>{entered.resolve();await release.promise;};
  const job=backend.signSessionStatement(statement);await entered.promise;const drained=backend.stop();state.error=true;
  release.resolve();assert.equal(await job,null);const status=await drained;
  assert.equal(status.state,'STOPPED');assert.equal(status.inFlight,0);assert.equal(JSON.stringify(status).includes('PRIVATE'),false);
});
test('a stop requested synchronously by the key provider drains without forced cancellation',async()=>{
  const {statement,state,build}=await setup(),backend=build();let drained;
  state.onRead=()=>{drained=backend.stop();assert.equal(backend.getStatus().state,'DRAINING');};
  assert.equal(await backend.signSessionStatement(statement),null);assert.equal((await drained).state,'STOPPED');assert.equal(state.keyReads,1);
});
test('a stop requested during clock validation cannot admit new work into the stopped backend',async()=>{
  const {statement,state,config}=await setup();let backend;
  config.now=()=>{backend.stop();return new Date(state.now);};backend=createRioOneDrainableSoftwareSignerV300(config);
  assert.equal(await backend.signSessionStatement(statement),null);assert.equal(backend.getStatus().state,'STOPPED');assert.equal(state.keyReads,0);
});
test('invalid messages and revoked registry states still fail closed in the OPEN lifecycle',async()=>{
  const {statement,state,build}=await setup(),backend=build();
  assert.equal(await backend.signSessionStatement({...statement,purpose:'OWNER'}),null);assert.equal(state.keyReads,0);
  state.key.state='REVOKED';assert.equal(await backend.signSessionStatement(statement),null);
  assert.equal(backend.getStatus().state,'OPEN');assert.equal(backend.getStatus().inFlight,0);
  assert.equal((await backend.stop()).state,'STOPPED');
});
test('stopping the backend withholds One statements without claiming to revoke the existing user session',async()=>{
  const {config,session,build}=await setup(),backend=build();
  const issuer=createRioOneSessionStatementIssuerV298({tenantRef,allowedOrigin:origin,issuerKey:config.issuerKey,
    now:config.now,readIssuerKeyState:config.readIssuerKeyState,readAuthenticatedOneSession:async()=>({...session}),
    signSessionStatement:backend.signSessionStatement});
  const verifier=createRioOneSignedSessionProviderV296({tenantRef,allowedOrigin:origin,issuerKey:config.issuerKey,
    now:config.now,readIssuerKeyState:config.readIssuerKeyState,requestSignedSession:issuer.requestSignedSession});
  const request=()=>new Request(origin+PATH,{method:'POST',headers:{Origin:origin,'X-RIO-Inspection':'1'}});
  assert.ok(await verifier.authenticateOneRequest(request()));await backend.stop();
  assert.equal(await verifier.authenticateOneRequest(request()),null);assert.equal(session.state,'ACTIVE');
  assert.equal(backend.sessionIssuance,false);assert.equal(backend.authorization,'NONE');
});
