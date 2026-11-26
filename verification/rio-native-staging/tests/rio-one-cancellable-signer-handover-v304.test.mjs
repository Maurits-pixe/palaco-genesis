import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createPublicKey,randomBytes,verify,webcrypto} from 'node:crypto';
import {createRioOneCancellableSignerHandoverV304} from '../rio-one-cancellable-signer-handover-v304.mjs';
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
  return {pair,publicKey,issuerKey,session,message,statement,state,config,build:()=>createRioOneCancellableSignerHandoverV304(config)};
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
test('initial status exposes no pending attempt and cancellation does not retire a serving generation',async()=>{
  const x=await setup(),host=await x.build(),s=host.getStatus();
  assert.equal(s.state,'SERVING');assert.equal(s.candidateAttemptId,null);assert.equal(s.cancellationRequested,false);
  assert.equal(host.cancelReplacement({expectedGeneration:1,attemptId:1}),null);
  assert.equal(host.getStatus().acceptingWork,true);assert.equal(Object.isFrozen(s),true);
  assert.equal(s.registryRevisionAtInstall,1);assert.equal(host.authorization,'NONE');
});
test('cancelling a pending first lookup withholds installation and keeps its slot until the provider settles',async()=>{
  const x=await setup(),host=await x.build(),entered=deferred(),release=deferred();
  await host.retireGeneration({expectedGeneration:1});const base=x.state.keyReads;
  x.state.onRead=async()=>{entered.resolve();await release.promise;};
  const pending=host.installReplacement(replacement(x));await entered.promise;
  const command=cancelCommand(host),ack=host.cancelReplacement(command);
  assert.equal(ack.state,'CANCELLATION_REQUESTED');assert.equal(ack,host.cancelReplacement(command));assert.equal(Object.isFrozen(ack),true);
  assert.equal(host.getStatus().state,'CANCELLING_REPLACEMENT');assert.equal(host.getStatus().candidateChecksInFlight,1);
  let completed=false;pending.then(()=>{completed=true;});await Promise.resolve();assert.equal(completed,false);
  assert.equal(await host.installReplacement(replacement(x)),null);assert.equal(await host.signSessionStatement(x.statement),null);
  release.resolve();assert.equal(await pending,null);assert.equal(x.state.keyReads,base+1);
  assert.equal(host.getStatus().state,'RETIRED');assert.equal(host.getStatus().candidateAttemptId,null);
  assert.equal(host.getStatus().cancellationRequested,false);assert.equal(host.getStatus().generation,1);
  const installed=await host.installReplacement(replacement(x));assert.equal(installed.generation,2);assert.equal(installed.attemptId,command.attemptId+1);
});
test('cancellation during actual cryptography waits for the operation and skips the final registry read',async()=>{
  const x=await setup(),host=await x.build(),entered=deferred(),release=deferred();
  await host.retireGeneration({expectedGeneration:1});const base=x.state.keyReads;
  await interceptSigning(async run=>{const signature=await run();entered.resolve();await release.promise;return signature;},async()=>{
    const pending=host.installReplacement(replacement(x));await entered.promise;
    host.cancelReplacement(cancelCommand(host));let done=false;pending.then(()=>{done=true;});await Promise.resolve();
    assert.equal(done,false);assert.equal(host.getStatus().candidateChecksInFlight,1);
    release.resolve();assert.equal(await pending,null);
  });assert.equal(x.state.keyReads,base+1);assert.equal(host.getStatus().generation,1);
});
test('cancellation during final registry lookup withholds a proven candidate',async()=>{
  const x=await setup(),host=await x.build(),entered=deferred(),release=deferred();
  await host.retireGeneration({expectedGeneration:1});const base=x.state.keyReads;
  x.state.onRead=async()=>{if(x.state.keyReads===base+2){entered.resolve();await release.promise;}};
  const pending=host.installReplacement(replacement(x));await entered.promise;
  assert.ok(host.cancelReplacement(cancelCommand(host)));release.resolve();assert.equal(await pending,null);
  assert.equal(host.getStatus().state,'RETIRED');assert.equal(host.getStatus().registryRevisionAtInstall,1);
});
test('cancellation queued after final assessment still prevents the pending installation commit',async()=>{
  const x=await setup();let host,enabled=false,reads=0,finalRecordReturned=false,ack;
  const original=x.config.readIssuerKeyState;
  x.config.readIssuerKeyState=async lookup=>{const record=await original(lookup);
    if(enabled&&++reads===2)finalRecordReturned=true;return record;};
  x.config.now=()=>{if(enabled&&finalRecordReturned){finalRecordReturned=false;
    queueMicrotask(()=>{ack=host.cancelReplacement(cancelCommand(host));});}return new Date(x.state.now);};
  host=await x.build();await host.retireGeneration({expectedGeneration:1});enabled=true;
  assert.equal(await host.installReplacement(replacement(x)),null);assert.equal(ack.state,'CANCELLATION_REQUESTED');
  assert.equal(host.getStatus().generation,1);assert.equal(host.getStatus().state,'RETIRED');
});
test('a stale cancellation cannot affect a later attempt in the same retired generation',async()=>{
  const x=await setup(),host=await x.build();await host.retireGeneration({expectedGeneration:1});
  let entered=deferred(),release=deferred();x.state.onRead=async()=>{entered.resolve();await release.promise;};
  let pending=host.installReplacement(replacement(x));await entered.promise;const first=cancelCommand(host);
  host.cancelReplacement(first);release.resolve();await pending;
  entered=deferred();release=deferred();pending=host.installReplacement(replacement(x));await entered.promise;
  const second=cancelCommand(host);assert.ok(second.attemptId>first.attemptId);assert.equal(second.expectedGeneration,first.expectedGeneration);
  assert.equal(host.cancelReplacement(first),null);assert.equal(host.getStatus().cancellationRequested,false);
  assert.equal(host.getStatus().state,'CHECKING_REPLACEMENT');host.cancelReplacement(second);release.resolve();await pending;
});
test('wrong generation, invalid identifiers, extra fields and accessors cannot request cancellation',async()=>{
  const x=await setup(),host=await x.build(),entered=deferred(),release=deferred();
  await host.retireGeneration({expectedGeneration:1});x.state.onRead=async()=>{entered.resolve();await release.promise;};
  const pending=host.installReplacement(replacement(x));await entered.promise;const command=cancelCommand(host);
  for(const attemptId of [0,-1,1.5,NaN,Number.MAX_SAFE_INTEGER+1,String(command.attemptId),command.attemptId+1])
    assert.equal(host.cancelReplacement({...command,attemptId}),null);
  assert.equal(host.cancelReplacement({...command,expectedGeneration:2}),null);
  assert.equal(host.cancelReplacement({...command,extra:true}),null);let read=false;
  const accessor={...command};Object.defineProperty(accessor,'attemptId',{get(){read=true;return command.attemptId;},enumerable:true});
  assert.equal(host.cancelReplacement(accessor),null);assert.equal(read,false);assert.equal(host.getStatus().cancellationRequested,false);
  release.resolve();assert.equal((await pending).generation,2);
});
test('cancellation after successful installation cannot undo or revoke the installed generation',async()=>{
  const x=await setup(),host=await x.build();await host.retireGeneration({expectedGeneration:1});
  const pending=host.installReplacement(replacement(x)),command=cancelCommand(host),installed=await pending;
  assert.equal(host.cancelReplacement(command),null);assert.equal(installed.attemptId,command.attemptId);
  const signature=await host.signSessionStatement(x.statement);
  assert.equal(verify(null,Buffer.from(x.statement.payload),x.publicKey,Buffer.from(signature,'base64url')),true);
  assert.equal(host.getStatus().generation,2);assert.equal(x.session.state,'ACTIVE');
});
test('provider failure after cancellation releases the candidate without leaking diagnostics',async()=>{
  const x=await setup(),host=await x.build(),entered=deferred(),release=deferred();
  await host.retireGeneration({expectedGeneration:1});x.state.onRead=async()=>{entered.resolve();await release.promise;};
  const pending=host.installReplacement(replacement(x));await entered.promise;host.cancelReplacement(cancelCommand(host));x.state.error=true;
  release.resolve();assert.equal(await pending,null);assert.equal(host.getStatus().candidateChecksInFlight,0);
  assert.equal(JSON.stringify(host.getStatus()).includes('PRIVATE_BACKEND_DETAIL'),false);
  x.state.error=false;assert.equal((await host.installReplacement(replacement(x))).generation,2);
});
test('terminal close during cancellation waits for the real provider and cannot reopen',async()=>{
  const x=await setup(),host=await x.build(),entered=deferred(),release=deferred();
  await host.retireGeneration({expectedGeneration:1});x.state.onRead=async()=>{entered.resolve();await release.promise;};
  const pending=host.installReplacement(replacement(x));await entered.promise;const command=cancelCommand(host);
  host.cancelReplacement(command);const closed=host.close();assert.equal(closed,host.close());let done=false;closed.then(()=>{done=true;});
  await Promise.resolve();assert.equal(done,false);assert.equal(host.getStatus().state,'CLOSED');assert.equal(host.cancelReplacement(command),null);
  release.resolve();assert.equal(await pending,null);assert.equal((await closed).candidateChecksInFlight,0);
  assert.equal(await host.installReplacement(replacement(x)),null);
});
test('a synchronous cancellation from the trusted clock prevents even the first candidate registry read',async()=>{
  const x=await setup();let host,enabled=false,ack;
  x.config.now=()=>{if(enabled)ack=host.cancelReplacement(cancelCommand(host));return new Date(x.state.now);};
  host=await x.build();await host.retireGeneration({expectedGeneration:1});const reads=x.state.keyReads;enabled=true;
  assert.equal(await host.installReplacement(replacement(x)),null);assert.ok(ack);assert.equal(x.state.keyReads,reads);
});
test('the unchanged issuer/verifier callback works after a cancelled attempt and an explicit corrected attempt',async()=>{
  const x=await setup(),host=await x.build();
  const issuer=createRioOneSessionStatementIssuerV298({tenantRef,allowedOrigin:origin,issuerKey:x.issuerKey,
    now:x.config.now,readIssuerKeyState:x.config.readIssuerKeyState,readAuthenticatedOneSession:async()=>({...x.session}),
    signSessionStatement:host.signSessionStatement});
  const verifier=createRioOneSignedSessionProviderV296({tenantRef,allowedOrigin:origin,issuerKey:x.issuerKey,
    now:x.config.now,readIssuerKeyState:x.config.readIssuerKeyState,requestSignedSession:issuer.requestSignedSession});
  const request=()=>new Request(origin+PATH,{method:'POST',headers:{Origin:origin,'X-RIO-Inspection':'1'}});
  assert.ok(await verifier.authenticateOneRequest(request()));await host.retireGeneration({expectedGeneration:1});
  x.state.onRead=()=>{host.cancelReplacement(cancelCommand(host));};assert.equal(await host.installReplacement(replacement(x)),null);
  assert.equal(await verifier.authenticateOneRequest(request()),null);x.state.onRead=undefined;
  await host.installReplacement(replacement(x));assert.ok(await verifier.authenticateOneRequest(request()));
  await host.close();assert.equal(await verifier.authenticateOneRequest(request()),null);assert.equal(x.session.state,'ACTIVE');
});
test('cancel support retains installation registry rejection and later per-request revocation checks',async()=>{
  const x=await setup(),host=await x.build();await host.retireGeneration({expectedGeneration:1});
  x.state.key.state='REVOKED';assert.equal(await host.installReplacement(replacement(x)),null);
  assert.equal(host.getStatus().candidateAttemptId,null);x.state.key.state='ACTIVE';await host.installReplacement(replacement(x));
  x.state.key.state='REVOKED';assert.equal(await host.signSessionStatement(x.statement),null);
  assert.equal(host.getStatus().generation,2);assert.equal(host.getStatus().registryRevisionAtInstall,1);
});
