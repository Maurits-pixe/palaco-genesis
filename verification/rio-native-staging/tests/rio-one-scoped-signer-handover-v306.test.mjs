import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createPublicKey,randomBytes,verify,webcrypto} from 'node:crypto';
import {createRioOneScopedSignerHandoverV306} from '../rio-one-scoped-signer-handover-v306.mjs';
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
  return {pair,publicKey,issuerKey,session,message,statement,state,config,build:()=>createRioOneScopedSignerHandoverV306(config)};
}
const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};
const replacement=(x,host,g=1)=>({controllerId:host.getStatus().controllerId,expectedGeneration:g,privateSigningKey:x.pair.privateKey,
  readIssuerKeyState:x.config.readIssuerKeyState});

const scope=host=>({controllerId:host.getStatus().controllerId,expectedGeneration:host.getStatus().generation});
const cancelCommand=host=>({controllerId:host.getStatus().controllerId,expectedGeneration:host.getStatus().generation,attemptId:host.getStatus().candidateAttemptId});
test('identically configured controllers receive fresh immutable correlation scopes',async()=>{
  const x=await setup(),a=await x.build(),b=await x.build(),sa=a.getStatus(),sb=b.getStatus();
  assert.match(sa.controllerId,/^[A-Za-z0-9_-]{43}$/);assert.equal(Buffer.from(sa.controllerId,'base64url').length,32);
  assert.notEqual(sa.controllerId,sb.controllerId);assert.equal(sa.generation,sb.generation);
  assert.equal(Object.isFrozen(sa),true);assert.equal(a.getStatus().controllerId,sa.controllerId);
});
test('foreign or missing scope cannot retire a serving controller',async()=>{
  const x=await setup(),a=await x.build(),b=await x.build(),reads=x.state.keyReads;
  assert.equal(b.retireGeneration(scope(a)),null);assert.equal(b.retireGeneration({expectedGeneration:1}),null);
  assert.equal(b.getStatus().state,'SERVING');assert.equal(x.state.keyReads,reads);
  const own=b.retireGeneration(scope(b));assert.equal(own,b.retireGeneration(scope(b)));await own;
  assert.equal(b.getStatus().state,'RETIRED');assert.equal(a.getStatus().state,'SERVING');
});
test('foreign or absent installation scope is refused before provider work or attempt admission',async()=>{
  const x=await setup(),a=await x.build(),b=await x.build();await b.retireGeneration(scope(b));const reads=x.state.keyReads;
  assert.equal(await b.installReplacement(replacement(x,a)),null);
  const missing=replacement(x,b);delete missing.controllerId;assert.equal(await b.installReplacement(missing),null);
  assert.equal(x.state.keyReads,reads);assert.equal(b.getStatus().candidateAttemptId,null);assert.equal(b.getLastAttemptResult(),null);
  assert.equal((await b.installReplacement(replacement(x,b))).attemptId,1);
});
test('foreign cancellation is refused even when both controllers have the same generation and attempt numbers',async()=>{
  const x=await setup(),a=await x.build(),b=await x.build(),ea=deferred(),eb=deferred(),ra=deferred(),rb=deferred();
  await a.retireGeneration(scope(a));await b.retireGeneration(scope(b));
  const pa=a.installReplacement({...replacement(x,a),readIssuerKeyState:async()=>{ea.resolve();await ra.promise;return {...x.state.key};}});
  const pb=b.installReplacement({...replacement(x,b),readIssuerKeyState:async()=>{eb.resolve();await rb.promise;return {...x.state.key};}});
  await Promise.all([ea.promise,eb.promise]);const ca=cancelCommand(a),cb=cancelCommand(b);
  assert.equal(ca.expectedGeneration,cb.expectedGeneration);assert.equal(ca.attemptId,cb.attemptId);
  assert.equal(b.cancelReplacement(ca),null);assert.equal(a.cancelReplacement(cb),null);
  assert.equal(b.getStatus().cancellationRequested,false);assert.equal(a.getStatus().cancellationRequested,false);
  const aa=a.cancelReplacement(ca),ab=b.cancelReplacement(cb);assert.equal(aa.controllerId,ca.controllerId);assert.equal(ab.controllerId,cb.controllerId);
  assert.equal(aa,a.cancelReplacement(ca));ra.resolve();rb.resolve();assert.deepEqual(await Promise.all([pa,pb]),[null,null]);
  assert.equal(a.getLastAttemptResult().controllerId,ca.controllerId);assert.equal(b.getLastAttemptResult().controllerId,cb.controllerId);
});
test('acknowledgement, installation receipt and completion records keep the same controller binding',async()=>{
  const x=await setup(),host=await x.build(),id=host.getStatus().controllerId;await host.retireGeneration(scope(host));let ack;
  x.state.onRead=()=>{ack=host.cancelReplacement(cancelCommand(host));};assert.equal(await host.installReplacement(replacement(x,host)),null);
  assert.equal(ack.controllerId,id);assert.equal(ack.format,'rio-one-scoped-cancellation-v306');
  assert.equal(host.getLastAttemptResult().controllerId,id);assert.equal(host.getLastAttemptResult().outcome,'WITHHELD_AFTER_CANCELLATION');
  x.state.onRead=undefined;const installed=await host.installReplacement(replacement(x,host));
  assert.equal(installed.controllerId,id);assert.equal(host.getStatus().controllerId,id);assert.equal(host.getLastAttemptResult().controllerId,id);
  assert.equal(installed.generation,2);assert.equal(Object.isFrozen(installed),true);
  const signature=await host.signSessionStatement(x.statement);assert.equal(verify(null,Buffer.from(x.statement.payload),x.publicKey,Buffer.from(signature,'base64url')),true);
});
test('commands from a closed controller are refused by a newly created controller with reused local numbers',async()=>{
  const x=await setup(),old=await x.build();await old.retireGeneration(scope(old));let command;
  x.state.onRead=()=>{command=cancelCommand(old);old.cancelReplacement(command);};await old.installReplacement(replacement(x,old));
  x.state.onRead=undefined;await old.close();const fresh=await x.build();await fresh.retireGeneration(scope(fresh));
  const entered=deferred(),release=deferred();x.state.onRead=async()=>{entered.resolve();await release.promise;};
  const pending=fresh.installReplacement(replacement(x,fresh));await entered.promise;
  const current=cancelCommand(fresh);assert.equal(current.expectedGeneration,command.expectedGeneration);assert.equal(current.attemptId,command.attemptId);
  assert.notEqual(current.controllerId,command.controllerId);assert.equal(fresh.cancelReplacement(command),null);
  assert.equal(fresh.getStatus().cancellationRequested,false);release.resolve();assert.equal((await pending).generation,2);
});
test('scope types and accessors are rejected without coercion or evaluation',async()=>{
  const x=await setup(),host=await x.build(),valid=scope(host);let evaluated=false;
  for(const controllerId of [null,undefined,0,{},new String(valid.controllerId),valid.controllerId+'x'])
    assert.equal(host.retireGeneration({...valid,controllerId}),null);
  const accessor={...valid};Object.defineProperty(accessor,'controllerId',{get(){evaluated=true;return valid.controllerId;},enumerable:true});
  assert.equal(host.retireGeneration(accessor),null);assert.equal(evaluated,false);await host.retireGeneration(valid);
  const command=replacement(x,host);Object.defineProperty(command,'controllerId',{get(){evaluated=true;return valid.controllerId;},enumerable:true});
  assert.equal(await host.installReplacement(command),null);assert.equal(evaluated,false);
});
test('same-controller binding preserves stale attempt and generation refusal',async()=>{
  const x=await setup(),host=await x.build();await host.retireGeneration(scope(host));let first;
  x.state.onRead=()=>{first=cancelCommand(host);host.cancelReplacement(first);};await host.installReplacement(replacement(x,host));
  const entered=deferred(),release=deferred();x.state.onRead=async()=>{entered.resolve();await release.promise;};
  const pending=host.installReplacement(replacement(x,host));await entered.promise;
  assert.equal(host.cancelReplacement(first),null);assert.equal(host.getStatus().cancellationRequested,false);
  const previous=scope(host);release.resolve();assert.equal((await pending).generation,2);
  assert.equal(host.retireGeneration(previous),null);assert.equal(host.getStatus().state,'SERVING');
});
test('cancellation before the installation continuation publishes a scoped withheld result',async()=>{
  const x=await setup();let host,enabled=false,reads=0,returned=false;
  const original=x.config.readIssuerKeyState;x.config.readIssuerKeyState=async lookup=>{const record=await original(lookup);
    if(enabled&&++reads===2)returned=true;return record;};
  x.config.now=()=>{if(enabled&&returned){returned=false;queueMicrotask(()=>host.cancelReplacement(cancelCommand(host)));}return new Date(x.state.now);};
  host=await x.build();await host.retireGeneration(scope(host));enabled=true;
  assert.equal(await host.installReplacement(replacement(x,host)),null);
  assert.equal(host.getLastAttemptResult().controllerId,host.getStatus().controllerId);
  assert.equal(host.getLastAttemptResult().outcome,'WITHHELD_AFTER_CANCELLATION');assert.equal(host.getStatus().generation,1);
});
test('reference-bound close waits for pending work and returns the same controller scope',async()=>{
  const x=await setup(),host=await x.build(),entered=deferred(),release=deferred();await host.retireGeneration(scope(host));
  x.state.onRead=async()=>{entered.resolve();await release.promise;};const pending=host.installReplacement(replacement(x,host));await entered.promise;
  const closed=host.close();assert.equal(closed,host.close());assert.equal(host.getLastAttemptResult(),null);
  release.resolve();assert.equal(await pending,null);const final=await closed;
  assert.equal(final.controllerId,host.getLastAttemptResult().controllerId);assert.equal(final.lastCompletedAttemptId,host.getLastAttemptResult().attemptId);
  assert.equal(host.getLastAttemptResult().outcome,'WITHHELD_AFTER_CLOSE');
});
test('unchanged issuer/verifier callback works across scoped control operations',async()=>{
  const x=await setup(),host=await x.build();
  const issuer=createRioOneSessionStatementIssuerV298({tenantRef,allowedOrigin:origin,issuerKey:x.issuerKey,
    now:x.config.now,readIssuerKeyState:x.config.readIssuerKeyState,readAuthenticatedOneSession:async()=>({...x.session}),
    signSessionStatement:host.signSessionStatement});
  const verifier=createRioOneSignedSessionProviderV296({tenantRef,allowedOrigin:origin,issuerKey:x.issuerKey,
    now:x.config.now,readIssuerKeyState:x.config.readIssuerKeyState,requestSignedSession:issuer.requestSignedSession});
  const request=()=>new Request(origin+PATH,{method:'POST',headers:{Origin:origin,'X-RIO-Inspection':'1'}});
  assert.ok(await verifier.authenticateOneRequest(request()));await host.retireGeneration(scope(host));
  assert.equal(await verifier.authenticateOneRequest(request()),null);await host.installReplacement(replacement(x,host));
  assert.ok(await verifier.authenticateOneRequest(request()));await host.close();assert.equal(x.session.state,'ACTIVE');
});
test('controller scope cannot be configured or reused as an identity or authority claim',async()=>{
  const x=await setup(),host=await x.build(),id=host.getStatus().controllerId;
  await assert.rejects(createRioOneScopedSignerHandoverV306({...x.config,controllerId:id}),TypeError);
  assert.equal(host.sessionIssuance,false);assert.equal(host.authorization,'NONE');assert.equal(host.acceptance,'HOLD');
  assert.equal(host.hardwareProtection,'NOT_VERIFIED');assert.equal(host.getStatus().controllerId,id);
});
