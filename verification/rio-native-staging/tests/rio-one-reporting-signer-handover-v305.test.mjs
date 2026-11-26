import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createPublicKey,randomBytes,verify,webcrypto} from 'node:crypto';
import {createRioOneReportingSignerHandoverV305} from '../rio-one-reporting-signer-handover-v305.mjs';
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
  return {pair,publicKey,issuerKey,session,message,statement,state,config,build:()=>createRioOneReportingSignerHandoverV305(config)};
}
const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};
const replacement=(x,g=1)=>({expectedGeneration:g,privateSigningKey:x.pair.privateKey,
  readIssuerKeyState:x.config.readIssuerKeyState});

// Test-only scheduling seam. Every successful proof still delegates to actual WebCrypto.
async function interceptSigning(hook,work){
  const original=webcrypto.subtle.sign;
  webcrypto.subtle.sign=function(...args){return hook(()=>Reflect.apply(original,this,args),args);};
  try{return await work();}finally{webcrypto.subtle.sign=original;}
}
const cancelCommand=host=>({expectedGeneration:host.getStatus().generation,attemptId:host.getStatus().candidateAttemptId});
test('initial construction has no replacement result and reading status invokes no provider',async()=>{
  const x=await setup(),host=await x.build(),reads=x.state.keyReads;
  assert.equal(host.getLastAttemptResult(),null);assert.equal(host.getStatus().lastCompletedAttemptId,null);
  assert.equal(host.getStatus().generation,1);assert.equal(x.state.keyReads,reads);
});
test('successful installation publishes one frozen minimized completion record',async()=>{
  const x=await setup(),host=await x.build();await host.retireGeneration({expectedGeneration:1});
  const installed=await host.installReplacement(replacement(x)),record=host.getLastAttemptResult();
  assert.deepEqual(record,{format:'rio-one-completed-replacement-v305',attemptId:installed.attemptId,
    expectedGeneration:1,resultingGeneration:2,completion:'COMPLETED',outcome:'INSTALLED',
    cancellationRequested:false,acceptance:'HOLD',authorization:'NONE'});
  assert.equal(Object.isFrozen(record),true);assert.equal(host.getStatus().lastCompletedAttemptId,record.attemptId);
  assert.throws(()=>{record.outcome='CHANGED';},TypeError);
  const signature=await host.signSessionStatement(x.statement);
  assert.equal(verify(null,Buffer.from(x.statement.payload),x.publicKey,Buffer.from(signature,'base64url')),true);
});
test('commands refused before admission do not fabricate or overwrite a completed result',async()=>{
  const x=await setup(),host=await x.build();assert.equal(await host.installReplacement(replacement(x)),null);
  await host.retireGeneration({expectedGeneration:1});assert.equal(await host.installReplacement(replacement(x,2)),null);
  assert.equal(await host.installReplacement({...replacement(x),privateSigningKey:'INVALID_HANDLE'}),null);
  assert.equal(host.getLastAttemptResult(),null);await host.installReplacement(replacement(x));
  const record=host.getLastAttemptResult();assert.equal(await host.installReplacement(replacement(x)),null);
  assert.equal(host.getLastAttemptResult(),record);
});
test('an admitted provider failure has a generic result without private diagnostics or handles',async()=>{
  const x=await setup(),host=await x.build();await host.retireGeneration({expectedGeneration:1});x.state.error=true;
  assert.equal(await host.installReplacement(replacement(x)),null);const record=host.getLastAttemptResult();
  assert.equal(record.outcome,'CHECK_FAILED');assert.equal(record.completion,'COMPLETED');
  assert.equal(record.expectedGeneration,1);assert.equal(record.resultingGeneration,1);
  assert.equal(record.cancellationRequested,false);assert.equal(JSON.stringify(record).includes('PRIVATE_BACKEND_DETAIL'),false);
  assert.equal(Object.hasOwn(record,'privateSigningKey'),false);assert.equal(Object.hasOwn(record,'error'),false);
});
test('a cancellation acknowledgement is not published as completion while a provider is pending',async()=>{
  const x=await setup(),host=await x.build(),entered=deferred(),release=deferred();
  await host.retireGeneration({expectedGeneration:1});x.state.onRead=async()=>{entered.resolve();await release.promise;};
  const pending=host.installReplacement(replacement(x));await entered.promise;const ack=host.cancelReplacement(cancelCommand(host));
  assert.equal(ack.state,'CANCELLATION_REQUESTED');assert.equal(host.getLastAttemptResult(),null);
  await Promise.resolve();assert.equal(host.getStatus().candidateChecksInFlight,1);assert.equal(host.getStatus().lastCompletedAttemptId,null);
  release.resolve();assert.equal(await pending,null);const record=host.getLastAttemptResult();
  assert.equal(record.attemptId,ack.attemptId);assert.equal(record.outcome,'WITHHELD_AFTER_CANCELLATION');
  assert.equal(record.completion,'COMPLETED');assert.equal(record.cancellationRequested,true);
  assert.equal(host.getStatus().candidateChecksInFlight,0);
});
test('actual cryptographic work must settle before a withheld completion is published',async()=>{
  const x=await setup(),host=await x.build(),entered=deferred(),release=deferred();await host.retireGeneration({expectedGeneration:1});
  await interceptSigning(async run=>{const signature=await run();entered.resolve();await release.promise;return signature;},async()=>{
    const pending=host.installReplacement(replacement(x));await entered.promise;host.cancelReplacement(cancelCommand(host));
    assert.equal(host.getLastAttemptResult(),null);release.resolve();assert.equal(await pending,null);
    assert.equal(host.getLastAttemptResult().outcome,'WITHHELD_AFTER_CANCELLATION');
  });
});
test('terminal close publishes the completed result before its close promise resolves',async()=>{
  const x=await setup(),host=await x.build(),entered=deferred(),release=deferred();await host.retireGeneration({expectedGeneration:1});
  x.state.onRead=async()=>{entered.resolve();await release.promise;};const pending=host.installReplacement(replacement(x));
  await entered.promise;const closed=host.close();assert.equal(host.getLastAttemptResult(),null);
  release.resolve();assert.equal(await pending,null);const final=await closed,record=host.getLastAttemptResult();
  assert.equal(record.outcome,'WITHHELD_AFTER_CLOSE');assert.equal(record.cancellationRequested,false);
  assert.equal(record.attemptId,final.lastCompletedAttemptId);assert.equal(final.candidateChecksInFlight,0);
});
test('completion after close records both close precedence and an earlier cancellation request',async()=>{
  const x=await setup(),host=await x.build(),entered=deferred(),release=deferred();await host.retireGeneration({expectedGeneration:1});
  x.state.onRead=async()=>{entered.resolve();await release.promise;};const pending=host.installReplacement(replacement(x));
  await entered.promise;host.cancelReplacement(cancelCommand(host));const closed=host.close();
  release.resolve();await pending;await closed;const record=host.getLastAttemptResult();
  assert.equal(record.outcome,'WITHHELD_AFTER_CLOSE');assert.equal(record.cancellationRequested,true);assert.equal(record.resultingGeneration,1);
});
test('last completed result remains scoped to its own attempt while a later attempt is pending',async()=>{
  const x=await setup(),host=await x.build();await host.retireGeneration({expectedGeneration:1});x.state.error=true;
  await host.installReplacement(replacement(x));const first=host.getLastAttemptResult();x.state.error=false;
  const entered=deferred(),release=deferred();x.state.onRead=async()=>{entered.resolve();await release.promise;};
  const pending=host.installReplacement(replacement(x));await entered.promise;
  assert.equal(host.getLastAttemptResult(),first);assert.equal(host.getStatus().lastCompletedAttemptId,first.attemptId);
  assert.ok(host.getStatus().candidateAttemptId>first.attemptId);const ack=host.cancelReplacement(cancelCommand(host));
  release.resolve();await pending;const last=host.getLastAttemptResult();
  assert.equal(last.attemptId,ack.attemptId);assert.notEqual(last,first);assert.equal(first.outcome,'CHECK_FAILED');
  assert.equal(last.outcome,'WITHHELD_AFTER_CANCELLATION');assert.equal(Object.hasOwn(host,'attemptHistory'),false);
});
test('late cancellation and idle terminal close never rewrite a historical installed result',async()=>{
  const x=await setup(),host=await x.build();await host.retireGeneration({expectedGeneration:1});
  const pending=host.installReplacement(replacement(x)),command=cancelCommand(host);await pending;
  const record=host.getLastAttemptResult();assert.equal(host.cancelReplacement(command),null);
  await host.close();assert.equal(host.getLastAttemptResult(),record);assert.equal(record.outcome,'INSTALLED');
  assert.equal(host.getStatus().state,'CLOSED');
});
test('a final-continuation cancellation records withholding rather than a successful installation',async()=>{
  const x=await setup();let host,enabled=false,reads=0,returned=false;
  const original=x.config.readIssuerKeyState;x.config.readIssuerKeyState=async lookup=>{const record=await original(lookup);
    if(enabled&&++reads===2)returned=true;return record;};
  x.config.now=()=>{if(enabled&&returned){returned=false;queueMicrotask(()=>host.cancelReplacement(cancelCommand(host)));}return new Date(x.state.now);};
  host=await x.build();await host.retireGeneration({expectedGeneration:1});enabled=true;
  assert.equal(await host.installReplacement(replacement(x)),null);const record=host.getLastAttemptResult();
  assert.equal(record.outcome,'WITHHELD_AFTER_CANCELLATION');assert.equal(record.resultingGeneration,1);
});
test('reporting preserves unchanged issuer/verifier behavior and HOLD/NONE across a retry',async()=>{
  const x=await setup(),host=await x.build();
  const issuer=createRioOneSessionStatementIssuerV298({tenantRef,allowedOrigin:origin,issuerKey:x.issuerKey,
    now:x.config.now,readIssuerKeyState:x.config.readIssuerKeyState,readAuthenticatedOneSession:async()=>({...x.session}),
    signSessionStatement:host.signSessionStatement});
  const verifier=createRioOneSignedSessionProviderV296({tenantRef,allowedOrigin:origin,issuerKey:x.issuerKey,
    now:x.config.now,readIssuerKeyState:x.config.readIssuerKeyState,requestSignedSession:issuer.requestSignedSession});
  const request=()=>new Request(origin+PATH,{method:'POST',headers:{Origin:origin,'X-RIO-Inspection':'1'}});
  assert.ok(await verifier.authenticateOneRequest(request()));await host.retireGeneration({expectedGeneration:1});
  x.state.onRead=()=>host.cancelReplacement(cancelCommand(host));await host.installReplacement(replacement(x));
  assert.equal(host.getLastAttemptResult().outcome,'WITHHELD_AFTER_CANCELLATION');
  assert.equal(await verifier.authenticateOneRequest(request()),null);x.state.onRead=undefined;
  await host.installReplacement(replacement(x));assert.equal(host.getLastAttemptResult().outcome,'INSTALLED');
  assert.ok(await verifier.authenticateOneRequest(request()));assert.equal(x.session.state,'ACTIVE');
  assert.equal(host.getLastAttemptResult().authorization,'NONE');assert.equal(host.getLastAttemptResult().acceptance,'HOLD');
});
