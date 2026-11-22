import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createPublicKey,randomBytes,verify,webcrypto} from 'node:crypto';
import {createRioOneKeyCheckedSignerHandoverV302} from '../rio-one-key-checked-signer-handover-v302.mjs';
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
  return {pair,publicKey,issuerKey,session,message,statement,state,config,build:()=>createRioOneKeyCheckedSignerHandoverV302(config)};
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
test('initial key proof is real but status promises neither registry readiness nor hardware custody',async()=>{
  const x=await setup();let clocks=0;x.config.now=()=>{clocks++;return new Date(x.state.now);};
  const host=await x.build(),s=host.getStatus();
  assert.equal(s.generation,1);assert.equal(s.state,'SERVING');assert.equal(s.keyChecksInFlight,0);
  assert.equal(s.keyCorrespondence,'VERIFIED_AT_INSTALL');assert.equal(s.registryReadiness,'NOT_CHECKED');
  assert.equal(s.authorization,'NONE');assert.equal(s.acceptance,'HOLD');
  assert.equal(x.state.keyReads,0);assert.equal(clocks,0);assert.equal(Object.isFrozen(s),true);
  assert.equal(Object.isFrozen(host),true);assert.equal(host.hardwareProtection,'NOT_VERIFIED');
  assert.equal(Object.hasOwn(host,'privateSigningKey'),false);assert.equal(Object.hasOwn(host,'proofSignature'),false);
});
test('a fresh domain-separated internal challenge is used for each key proof',async()=>{
  const x=await setup(),observed=[];
  await interceptSigning(async(run,args)=>{observed.push(Buffer.from(args[2]).toString());return run();},async()=>{
    const host=await x.build();await host.retireGeneration({expectedGeneration:1});
    assert.equal((await host.installReplacement(replacement(x))).generation,2);await host.close();
  });
  assert.equal(observed.length,2);assert.notEqual(observed[0],observed[1]);
  for(const text of observed){
    const prefix='RIO_ONE_SOFTWARE_KEY_CHECK_V302\0';assert.equal(text.startsWith(prefix),true);
    const c=JSON.parse(text.slice(prefix.length));assert.deepEqual(Object.keys(c),['tenantRef','origin','issuerId','keyId','nonce']);
    assert.equal(c.tenantRef,tenantRef);assert.equal(c.origin,origin);assert.equal(c.keyId,x.issuerKey.keyId);
    assert.equal(Buffer.from(c.nonce,'base64url').length,32);assert.equal(Object.hasOwn(c,'session'),false);
  }
});
test('initial mismatched private handle is refused before any signing service is returned',async()=>{
  const x=await setup(),other=await setup();
  await assert.rejects(createRioOneKeyCheckedSignerHandoverV302({...x.config,privateSigningKey:other.pair.privateKey}),
    {name:'TypeError',message:'PINNED_SOFTWARE_SIGNING_KEY_CHECK_FAILED'});
  assert.equal(x.state.keyReads,0);
});
test('bad independent public pin and unsafe handle are rejected before cryptographic proof',async()=>{
  const x=await setup();let calls=0;
  await interceptSigning(async run=>{calls++;return run();},async()=>{
    await assert.rejects(createRioOneKeyCheckedSignerHandoverV302({...x.config,
      issuerKey:{...x.issuerKey,spkiSha256:'0'.repeat(64)}}),TypeError);
    await assert.rejects(createRioOneKeyCheckedSignerHandoverV302({...x.config,privateSigningKey:'UNSAFE_HANDLE'}),TypeError);
    await assert.rejects(createRioOneKeyCheckedSignerHandoverV302({...x.config,maxConcurrentSignatures:null}),TypeError);
  });assert.equal(calls,0);
});
test('mismatched replacement remains retired without advancing generation, then a correct handle succeeds',async()=>{
  const x=await setup(),other=await setup(),host=await x.build();await host.retireGeneration({expectedGeneration:1});
  assert.equal(await host.installReplacement({...replacement(x),privateSigningKey:other.pair.privateKey}),null);
  assert.equal(host.getStatus().generation,1);assert.equal(host.getStatus().state,'RETIRED');
  assert.equal(await host.signSessionStatement(x.statement),null);assert.equal(x.state.keyReads,0);
  const r=await host.installReplacement(replacement(x));assert.equal(r.generation,2);
  assert.equal(r.keyCorrespondence,'VERIFIED_AT_INSTALL');assert.equal(r.registryReadiness,'NOT_CHECKED');assert.equal(Object.isFrozen(r),true);
});
test('same signing callback performs actual Ed25519 signing across checked replacement',async()=>{
  const x=await setup(),host=await x.build(),port=host.signSessionStatement;
  const check=async()=>assert.equal(verify(null,Buffer.from(x.statement.payload),x.publicKey,
    Buffer.from(await port(x.statement),'base64url')),true);
  await check();await host.retireGeneration({expectedGeneration:1});await host.installReplacement(replacement(x));
  assert.equal(host.signSessionStatement,port);await check();
});
test('pending key proof blocks signing and duplicate installation without a background queue',async()=>{
  const x=await setup(),host=await x.build(),entered=deferred(),release=deferred();
  await host.retireGeneration({expectedGeneration:1});
  await interceptSigning(async run=>{entered.resolve();await release.promise;return run();},async()=>{
    const pending=host.installReplacement(replacement(x));await entered.promise;
    const status=host.getStatus();assert.equal(status.state,'CHECKING_REPLACEMENT');assert.equal(status.keyChecksInFlight,1);
    assert.equal(status.acceptingWork,false);assert.equal(status.backendState,'STOPPED');
    assert.equal(await host.installReplacement(replacement(x)),null);assert.equal(await host.signSessionStatement(x.statement),null);
    assert.equal(host.retireGeneration({expectedGeneration:1}),null);
    release.resolve();assert.equal((await pending).generation,2);
  });
});
test('close during proof waits for actual cryptography and permanently withholds installation',async()=>{
  const x=await setup(),host=await x.build(),entered=deferred(),release=deferred();
  await host.retireGeneration({expectedGeneration:1});
  await interceptSigning(async run=>{entered.resolve();await release.promise;return run();},async()=>{
    const pending=host.installReplacement(replacement(x));await entered.promise;
    const closed=host.close();assert.equal(closed,host.close());let done=false;closed.then(()=>{done=true;});
    assert.equal(host.getStatus().state,'CLOSED');assert.equal(host.getStatus().keyChecksInFlight,1);
    await Promise.resolve();assert.equal(done,false);
    release.resolve();assert.equal(await pending,null);const end=await closed;
    assert.equal(end.keyChecksInFlight,0);assert.equal(end.generation,1);assert.equal(end.backendState,'STOPPED');
    assert.equal(await host.installReplacement(replacement(x)),null);
  });
});
test('crypto failure during replacement is contained without reopening or exposing private diagnostics',async()=>{
  const x=await setup(),host=await x.build();await host.retireGeneration({expectedGeneration:1});
  await interceptSigning(async()=>{throw Error('PRIVATE_CRYPTO_DETAIL');},async()=>{
    assert.equal(await host.installReplacement(replacement(x)),null);
  });
  assert.equal(host.getStatus().state,'RETIRED');assert.equal(host.getStatus().keyChecksInFlight,0);
  assert.equal(JSON.stringify(host.getStatus()).includes('PRIVATE_CRYPTO_DETAIL'),false);
  assert.equal((await host.installReplacement(replacement(x))).generation,2);
});
test('crypto failure during initial proof returns no usable controller',async()=>{
  const x=await setup();
  await interceptSigning(async()=>{throw Error('PRIVATE_CRYPTO_DETAIL');},async()=>{
    await assert.rejects(x.build(),{name:'TypeError',message:'PINNED_SOFTWARE_SIGNING_KEY_CHECK_FAILED'});
  });
});
test('verified key correspondence does not bypass the current revoked-key registry',async()=>{
  const x=await setup();x.state.key.state='REVOKED';const host=await x.build();
  assert.equal(x.state.keyReads,0);assert.equal(host.getStatus().registryReadiness,'NOT_CHECKED');
  assert.equal(await host.signSessionStatement(x.statement),null);assert.equal(x.state.keyReads,1);
  assert.equal(host.getStatus().keyCorrespondence,'VERIFIED_AT_INSTALL');
});
test('OPEN or draining old generations cannot start replacement proof',async()=>{
  const x=await setup(),host=await x.build(),entered=deferred(),release=deferred();
  assert.equal(await host.installReplacement(replacement(x)),null);
  x.state.onRead=async()=>{entered.resolve();await release.promise;};
  const job=host.signSessionStatement(x.statement);await entered.promise;
  const retired=host.retireGeneration({expectedGeneration:1});assert.equal(await host.installReplacement(replacement(x)),null);
  release.resolve();assert.equal(await job,null);await retired;
  assert.equal((await host.installReplacement(replacement(x))).generation,2);
});
test('stale generation and scope overrides cannot change the verified installation',async()=>{
  const x=await setup(),host=await x.build();await host.retireGeneration({expectedGeneration:1});
  for(const key of ['tenantRef','allowedOrigin','issuerKey','now','maxConcurrentSignatures'])
    assert.equal(await host.installReplacement({...replacement(x),[key]:x.config[key]}),null);
  assert.equal((await host.installReplacement(replacement(x))).generation,2);
  assert.equal(host.retireGeneration({expectedGeneration:1}),null);await host.retireGeneration({expectedGeneration:2});
  assert.equal(await host.installReplacement(replacement(x)),null);assert.equal(host.getStatus().generation,2);
});
test('accessor configuration is refused and reentrant close cannot start replacement proof',async()=>{
  const x=await setup(),host=await x.build();await host.retireGeneration({expectedGeneration:1});let read=false;
  const c=replacement(x);Object.defineProperty(c,'privateSigningKey',{get(){read=true;return x.pair.privateKey;},enumerable:true});
  assert.equal(await host.installReplacement(c),null);assert.equal(read,false);
  const proxy=new Proxy(replacement(x),{ownKeys(target){host.close();return Reflect.ownKeys(target);}});
  assert.equal(await host.installReplacement(proxy),null);assert.equal((await host.close()).state,'CLOSED');
});
test('terminal close includes old signing work as well as key-proof work',async()=>{
  const x=await setup(),host=await x.build(),entered=deferred(),release=deferred();
  x.state.onRead=async()=>{entered.resolve();await release.promise;};
  const job=host.signSessionStatement(x.statement);await entered.promise;const closed=host.close();
  assert.equal(host.getStatus().backendState,'DRAINING');release.resolve();assert.equal(await job,null);
  assert.equal((await closed).backendState,'STOPPED');assert.equal(await host.installReplacement(replacement(x)),null);
});
test('unchanged issuer/verifier callback survives verified same-key replacement without issuing a new session',async()=>{
  const x=await setup(),host=await x.build();
  const issuer=createRioOneSessionStatementIssuerV298({tenantRef,allowedOrigin:origin,issuerKey:x.issuerKey,
    now:x.config.now,readIssuerKeyState:x.config.readIssuerKeyState,readAuthenticatedOneSession:async()=>({...x.session}),
    signSessionStatement:host.signSessionStatement});
  const verifier=createRioOneSignedSessionProviderV296({tenantRef,allowedOrigin:origin,issuerKey:x.issuerKey,
    now:x.config.now,readIssuerKeyState:x.config.readIssuerKeyState,requestSignedSession:issuer.requestSignedSession});
  const request=()=>new Request(origin+PATH,{method:'POST',headers:{Origin:origin,'X-RIO-Inspection':'1'}});
  assert.ok(await verifier.authenticateOneRequest(request()));await host.retireGeneration({expectedGeneration:1});
  assert.equal(await verifier.authenticateOneRequest(request()),null);await host.installReplacement(replacement(x));
  assert.ok(await verifier.authenticateOneRequest(request()));await host.close();
  assert.equal(await verifier.authenticateOneRequest(request()),null);assert.equal(x.session.state,'ACTIVE');
});

