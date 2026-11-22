import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createPublicKey,randomBytes,verify,webcrypto} from 'node:crypto';
import {createRioOneHistoryBoundSignerHandoverV307} from '../rio-one-history-bound-signer-handover-v307.mjs';
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
  return {pair,publicKey,issuerKey,session,message,statement,state,config,build:()=>createRioOneHistoryBoundSignerHandoverV307(config)};
}
const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};
const replacement=(x,host,g=host.getStatus().generation)=>({controllerId:host.getStatus().controllerId,expectedGeneration:g,expectedLastCompletedAttemptId:host.getStatus().lastCompletedAttemptId,privateSigningKey:x.pair.privateKey,
  readIssuerKeyState:x.config.readIssuerKeyState});

const scope=host=>({controllerId:host.getStatus().controllerId,expectedGeneration:host.getStatus().generation});
const cancelCommand=host=>({controllerId:host.getStatus().controllerId,expectedGeneration:host.getStatus().generation,attemptId:host.getStatus().candidateAttemptId});
test('the first admitted replacement requires an explicit null completion marker',async()=>{
  const x=await setup(),host=await x.build();await host.retireGeneration(scope(host));
  const command=replacement(x,host);assert.equal(command.expectedLastCompletedAttemptId,null);
  const installed=await host.installReplacement(command);assert.equal(installed.previousCompletedAttemptId,null);
  assert.equal(host.getLastAttemptResult().previousCompletedAttemptId,null);assert.equal(installed.generation,2);
});
test('missing, malformed and future completion markers are refused before registry work',async()=>{
  const x=await setup(),host=await x.build();await host.retireGeneration(scope(host));const reads=x.state.keyReads;
  const missing=replacement(x,host);delete missing.expectedLastCompletedAttemptId;assert.equal(await host.installReplacement(missing),null);
  for(const expectedLastCompletedAttemptId of [undefined,0,-1,1.5,NaN,'1',{},1,Number.MAX_SAFE_INTEGER+1])
    assert.equal(await host.installReplacement({...replacement(x,host),expectedLastCompletedAttemptId}),null);
  assert.equal(x.state.keyReads,reads);assert.equal(host.getLastAttemptResult(),null);assert.equal(host.getStatus().candidateAttemptId,null);
  assert.equal((await host.installReplacement(replacement(x,host))).attemptId,1);
});
test('a cached command cannot reopen a retired generation after a cancelled attempt',async()=>{
  const x=await setup(),host=await x.build();await host.retireGeneration(scope(host));const cached=replacement(x,host);
  x.state.onRead=()=>host.cancelReplacement(cancelCommand(host));assert.equal(await host.installReplacement(replacement(x,host)),null);
  x.state.onRead=undefined;const completed=host.getLastAttemptResult();assert.equal(completed.outcome,'WITHHELD_AFTER_CANCELLATION');
  assert.equal(host.getStatus().generation,1);assert.equal(host.getStatus().state,'RETIRED');let reads=0;
  assert.equal(await host.installReplacement({...cached,readIssuerKeyState:async()=>{reads++;return {...x.state.key};}}),null);
  assert.equal(reads,0);assert.equal(host.getLastAttemptResult(),completed);
  const installed=await host.installReplacement(replacement(x,host));assert.equal(installed.generation,2);
  assert.equal(installed.previousCompletedAttemptId,completed.attemptId);
});
test('a failed assessment advances the observed marker while leaving the generation unchanged',async()=>{
  const x=await setup(),host=await x.build();await host.retireGeneration(scope(host));const cached=replacement(x,host);x.state.error=true;
  assert.equal(await host.installReplacement(replacement(x,host)),null);const failed=host.getLastAttemptResult();
  assert.equal(failed.outcome,'CHECK_FAILED');assert.equal(failed.resultingGeneration,1);assert.equal(failed.previousCompletedAttemptId,null);
  x.state.error=false;const reads=x.state.keyReads;assert.equal(await host.installReplacement(cached),null);assert.equal(x.state.keyReads,reads);
  assert.equal((await host.installReplacement(replacement(x,host))).previousCompletedAttemptId,failed.attemptId);
});
test('a duplicate command is refused while pending and remains stale after failure',async()=>{
  const x=await setup(),host=await x.build(),entered=deferred(),release=deferred();await host.retireGeneration(scope(host));
  const cached=replacement(x,host);x.state.onRead=async()=>{entered.resolve();await release.promise;};
  const pending=host.installReplacement(cached);await entered.promise;assert.equal(await host.installReplacement(cached),null);
  x.state.error=true;release.resolve();assert.equal(await pending,null);x.state.error=false;x.state.onRead=undefined;
  const completed=host.getLastAttemptResult(),reads=x.state.keyReads;
  assert.equal(await host.installReplacement(cached),null);assert.equal(host.getLastAttemptResult(),completed);assert.equal(x.state.keyReads,reads);
});
test('older and future positive markers do not admit work after multiple completed attempts',async()=>{
  const x=await setup(),host=await x.build();await host.retireGeneration(scope(host));x.state.error=true;
  await host.installReplacement(replacement(x,host));const first=host.getLastAttemptResult();
  await host.installReplacement(replacement(x,host));const second=host.getLastAttemptResult();assert.ok(second.attemptId>first.attemptId);
  x.state.error=false;const reads=x.state.keyReads;
  assert.equal(await host.installReplacement({...replacement(x,host),expectedLastCompletedAttemptId:first.attemptId}),null);
  assert.equal(await host.installReplacement({...replacement(x,host),expectedLastCompletedAttemptId:second.attemptId+1}),null);
  assert.equal(x.state.keyReads,reads);assert.equal(host.getLastAttemptResult(),second);
  assert.equal((await host.installReplacement(replacement(x,host))).previousCompletedAttemptId,second.attemptId);
});
test('commands rejected before admission never invalidate an otherwise current history marker',async()=>{
  const x=await setup(),host=await x.build();await host.retireGeneration(scope(host));const current=replacement(x,host);
  assert.equal(await host.installReplacement({...current,privateSigningKey:'INVALID_HANDLE'}),null);
  assert.equal(host.getStatus().lastCompletedAttemptId,null);assert.equal(host.getLastAttemptResult(),null);
  const installed=await host.installReplacement(current);assert.equal(installed.attemptId,1);assert.equal(installed.previousCompletedAttemptId,null);
});
test('a later generation still requires the current completed attempt marker',async()=>{
  const x=await setup(),host=await x.build();await host.retireGeneration(scope(host));await host.installReplacement(replacement(x,host));
  const installed=host.getLastAttemptResult();await host.retireGeneration(scope(host));
  assert.equal(await host.installReplacement({...replacement(x,host),expectedLastCompletedAttemptId:null}),null);
  const next=await host.installReplacement(replacement(x,host));assert.equal(next.generation,3);
  assert.equal(next.previousCompletedAttemptId,installed.attemptId);assert.equal(host.getLastAttemptResult().previousCompletedAttemptId,installed.attemptId);
});
test('a cancellation request does not advance history before actual work settles',async()=>{
  const x=await setup(),host=await x.build(),entered=deferred(),release=deferred();await host.retireGeneration(scope(host));
  x.state.onRead=async()=>{entered.resolve();await release.promise;};const pending=host.installReplacement(replacement(x,host));await entered.promise;
  host.cancelReplacement(cancelCommand(host));const observedBeforeCompletion=replacement(x,host);
  assert.equal(observedBeforeCompletion.expectedLastCompletedAttemptId,null);assert.equal(host.getStatus().candidateChecksInFlight,1);
  release.resolve();await pending;x.state.onRead=undefined;const completed=host.getLastAttemptResult();
  assert.equal(await host.installReplacement(observedBeforeCompletion),null);assert.equal(host.getStatus().lastCompletedAttemptId,completed.attemptId);
  assert.equal((await host.installReplacement(replacement(x,host))).previousCompletedAttemptId,completed.attemptId);
});
test('a matching history marker does not bypass controller-instance binding',async()=>{
  const x=await setup(),a=await x.build(),b=await x.build();await a.retireGeneration(scope(a));await b.retireGeneration(scope(b));
  const foreign=replacement(x,a);assert.equal(foreign.expectedLastCompletedAttemptId,b.getStatus().lastCompletedAttemptId);
  assert.equal(await b.installReplacement(foreign),null);assert.equal(b.getLastAttemptResult(),null);
  assert.equal((await b.installReplacement(replacement(x,b))).controllerId,b.getStatus().controllerId);
});
test('a final-continuation cancellation preserves the admitted history context',async()=>{
  const x=await setup();let host,enabled=false,reads=0,returned=false;
  const original=x.config.readIssuerKeyState;x.config.readIssuerKeyState=async lookup=>{const record=await original(lookup);
    if(enabled&&++reads===2)returned=true;return record;};
  x.config.now=()=>{if(enabled&&returned){returned=false;queueMicrotask(()=>host.cancelReplacement(cancelCommand(host)));}return new Date(x.state.now);};
  host=await x.build();await host.retireGeneration(scope(host));enabled=true;
  assert.equal(await host.installReplacement(replacement(x,host)),null);const record=host.getLastAttemptResult();
  assert.equal(record.previousCompletedAttemptId,null);assert.equal(record.outcome,'WITHHELD_AFTER_CANCELLATION');
  assert.equal(record.resultingGeneration,1);assert.equal(Object.isFrozen(record),true);
});
test('history-aware explicit retry preserves the unchanged issuer/verifier callback and HOLD/NONE',async()=>{
  const x=await setup(),host=await x.build();
  const issuer=createRioOneSessionStatementIssuerV298({tenantRef,allowedOrigin:origin,issuerKey:x.issuerKey,
    now:x.config.now,readIssuerKeyState:x.config.readIssuerKeyState,readAuthenticatedOneSession:async()=>({...x.session}),
    signSessionStatement:host.signSessionStatement});
  const verifier=createRioOneSignedSessionProviderV296({tenantRef,allowedOrigin:origin,issuerKey:x.issuerKey,
    now:x.config.now,readIssuerKeyState:x.config.readIssuerKeyState,requestSignedSession:issuer.requestSignedSession});
  const request=()=>new Request(origin+PATH,{method:'POST',headers:{Origin:origin,'X-RIO-Inspection':'1'}});
  assert.ok(await verifier.authenticateOneRequest(request()));await host.retireGeneration(scope(host));
  x.state.onRead=()=>host.cancelReplacement(cancelCommand(host));await host.installReplacement(replacement(x,host));x.state.onRead=undefined;
  const previous=host.getLastAttemptResult();assert.equal(await verifier.authenticateOneRequest(request()),null);
  await host.installReplacement(replacement(x,host));assert.ok(await verifier.authenticateOneRequest(request()));
  assert.equal(host.getLastAttemptResult().previousCompletedAttemptId,previous.attemptId);
  assert.equal(host.getLastAttemptResult().acceptance,'HOLD');assert.equal(host.getLastAttemptResult().authorization,'NONE');assert.equal(x.session.state,'ACTIVE');
});
