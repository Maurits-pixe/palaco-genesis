import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createPublicKey,randomBytes,verify,webcrypto} from 'node:crypto';
import {createRioOneRegistryCheckedSignerHandoverV303} from '../rio-one-registry-checked-signer-handover-v303.mjs';
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
  return {pair,publicKey,issuerKey,session,message,statement,state,config,build:()=>createRioOneRegistryCheckedSignerHandoverV303(config)};
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
const rejected={name:'TypeError',message:'PINNED_SOFTWARE_KEY_AND_REGISTRY_CHECK_FAILED'};
test('initial installation verifies two registry observations and the real key without claiming current readiness',async()=>{
  const x=await setup(),host=await x.build(),s=host.getStatus();
  assert.equal(x.state.keyReads,2);assert.equal(s.generation,1);assert.equal(s.state,'SERVING');
  assert.equal(s.keyCorrespondence,'VERIFIED_AT_INSTALL');assert.equal(s.registryReadiness,'VERIFIED_AT_INSTALL');
  assert.equal(s.registryRevisionAtInstall,1);assert.equal(s.installationCheckedAt,new Date(at).toISOString());
  assert.equal(s.candidateChecksInFlight,0);assert.equal(s.authorization,'NONE');assert.equal(s.acceptance,'HOLD');
  assert.equal(Object.isFrozen(s),true);assert.equal(host.hardwareProtection,'NOT_VERIFIED');
  assert.equal(Object.hasOwn(host,'privateSigningKey'),false);
});
test('inactive, expired, misbound or malformed initial registry records fail before cryptography',async()=>{
  const x=await setup(),k=x.state.key;let cryptoCalls=0;
  const invalid=[null,{...k,state:'REVOKED'},{...k,issuerId:'OTHER'},{...k,keyId:'OTHER'},
    {...k,revision:0},{...k,revision:Number.MAX_SAFE_INTEGER+1},
    {...k,notAfter:new Date(at).toISOString()},{...k,notBefore:new Date(at+1).toISOString()},
    {...k,extra:'DENIED'}];
  await interceptSigning(async run=>{cryptoCalls++;return run();},async()=>{
    for(const record of invalid)await assert.rejects(createRioOneRegistryCheckedSignerHandoverV303({
      ...x.config,readIssuerKeyState:async()=>record}),rejected);
  });assert.equal(cryptoCalls,0);
});
test('a different private handle still fails the real pinned-key proof after the first registry check',async()=>{
  const x=await setup(),other=await setup();
  await assert.rejects(createRioOneRegistryCheckedSignerHandoverV303({...x.config,privateSigningKey:other.pair.privateKey}),rejected);
  assert.equal(x.state.keyReads,1);
});
test('bad public pin and invalid handle fail before invoking registry providers',async()=>{
  const x=await setup();
  await assert.rejects(createRioOneRegistryCheckedSignerHandoverV303({...x.config,
    issuerKey:{...x.issuerKey,spkiSha256:'0'.repeat(64)}}),TypeError);
  await assert.rejects(createRioOneRegistryCheckedSignerHandoverV303({...x.config,privateSigningKey:'UNSAFE_HANDLE'}),TypeError);
  assert.equal(x.state.keyReads,0);
});
test('revoked replacement leaves the retired generation unchanged and a corrected attempt can proceed',async()=>{
  const x=await setup(),host=await x.build();await host.retireGeneration({expectedGeneration:1});
  x.state.key.state='REVOKED';assert.equal(await host.installReplacement(replacement(x)),null);
  assert.equal(host.getStatus().generation,1);assert.equal(host.getStatus().state,'RETIRED');
  x.state.key.state='ACTIVE';x.state.key.revision=3;
  const receipt=await host.installReplacement(replacement(x));assert.equal(receipt.generation,2);
  assert.equal(receipt.registryRevisionAtInstall,3);assert.equal(receipt.registryReadiness,'VERIFIED_AT_INSTALL');
  assert.equal(Object.isFrozen(receipt),true);
});
test('revocation or any registry revision/window change during real cryptography refuses installation',async()=>{
  const x=await setup(),host=await x.build(),original={...x.state.key};await host.retireGeneration({expectedGeneration:1});
  for(const change of [{state:'REVOKED'},{revision:2},{notAfter:new Date(at+30000).toISOString()},
    {notBefore:new Date(at-30000).toISOString()}]){
    x.state.key={...original};
    await interceptSigning(async run=>{const signature=await run();Object.assign(x.state.key,change);return signature;},async()=>{
      assert.equal(await host.installReplacement(replacement(x)),null);
    });assert.equal(host.getStatus().generation,1);assert.equal(host.getStatus().state,'RETIRED');
  }
});
test('a registry that mutates and reuses one record cannot rewrite the first observation',async()=>{
  const x=await setup();x.config.readIssuerKeyState=async()=>x.state.key;
  const host=await x.build();await host.retireGeneration({expectedGeneration:1});
  await interceptSigning(async run=>{const signature=await run();x.state.key.revision++;return signature;},async()=>{
    assert.equal(await host.installReplacement(replacement(x)),null);
  });assert.equal(host.getStatus().registryRevisionAtInstall,1);assert.equal(host.getStatus().generation,1);
});
test('the one-second installation bound accepts its boundary and refuses a stale first lookup before crypto',async()=>{
  const x=await setup();let cryptoCalls=0;
  x.state.onRead=()=>{if(x.state.keyReads===1)x.state.now+=1000;};
  const host=await x.build();assert.equal(host.getStatus().installationCheckedAt,new Date(at+1000).toISOString());
  const late=await setup();late.state.onRead=()=>{late.state.now+=1001;};
  await interceptSigning(async run=>{cryptoCalls++;return run();},async()=>{await assert.rejects(late.build(),rejected);});
  assert.equal(cryptoCalls,0);
});
test('elapsed time, expiry or a backwards clock during assessment refuses the candidate',async()=>{
  for(const delta of [1001,-1]){
    const x=await setup(),host=await x.build();await host.retireGeneration({expectedGeneration:1});
    await interceptSigning(async run=>{const signature=await run();x.state.now+=delta;return signature;},async()=>{
      assert.equal(await host.installReplacement(replacement(x)),null);
    });assert.equal(host.getStatus().state,'RETIRED');assert.equal(host.getStatus().generation,1);
  }
  const x=await setup();x.state.key.notAfter=new Date(at+50).toISOString();
  const host=await x.build();await host.retireGeneration({expectedGeneration:1});
  await interceptSigning(async run=>{const signature=await run();x.state.now+=50;return signature;},async()=>{
    assert.equal(await host.installReplacement(replacement(x)),null);
  });
  const slow=await setup(),slowHost=await slow.build();await slowHost.retireGeneration({expectedGeneration:1});
  const before=slow.state.keyReads;slow.state.onRead=()=>{if(slow.state.keyReads===before+2)slow.state.now+=1001;};
  assert.equal(await slowHost.installReplacement(replacement(slow)),null);assert.equal(slowHost.getStatus().generation,1);
});
test('invalid clock values and invalid registry accessors return no initial controller',async()=>{
  const x=await setup();await assert.rejects(createRioOneRegistryCheckedSignerHandoverV303({...x.config,now:()=>new Date(NaN)}),rejected);
  let evaluated=false;const record={...x.state.key};Object.defineProperty(record,'state',{
    get(){evaluated=true;return 'ACTIVE';},enumerable:true});
  await assert.rejects(createRioOneRegistryCheckedSignerHandoverV303({...x.config,readIssuerKeyState:async()=>record}),rejected);
  assert.equal(evaluated,false);
});
test('close during a pending first registry lookup waits for it and prevents cryptography',async()=>{
  const x=await setup(),host=await x.build(),entered=deferred(),release=deferred();
  await host.retireGeneration({expectedGeneration:1});x.state.onRead=async()=>{entered.resolve();await release.promise;};let cryptoCalls=0;
  await interceptSigning(async run=>{cryptoCalls++;return run();},async()=>{
    const pending=host.installReplacement(replacement(x));await entered.promise;
    const closed=host.close();assert.equal(closed,host.close());let done=false;closed.then(()=>{done=true;});
    assert.equal(host.getStatus().state,'CLOSED');assert.equal(host.getStatus().candidateChecksInFlight,1);
    await Promise.resolve();assert.equal(done,false);release.resolve();assert.equal(await pending,null);
    assert.equal((await closed).candidateChecksInFlight,0);
  });assert.equal(cryptoCalls,0);assert.equal(host.getStatus().generation,1);
});
test('close during the final registry lookup withholds an already proven candidate',async()=>{
  const x=await setup(),host=await x.build(),entered=deferred(),release=deferred();
  await host.retireGeneration({expectedGeneration:1});const base=x.state.keyReads;
  x.state.onRead=async()=>{if(x.state.keyReads===base+2){entered.resolve();await release.promise;}};
  const pending=host.installReplacement(replacement(x));await entered.promise;const closed=host.close();
  release.resolve();assert.equal(await pending,null);assert.equal((await closed).generation,1);
});
test('provider failure is contained, releases the check slot and permits an explicit corrected attempt',async()=>{
  const x=await setup(),host=await x.build();await host.retireGeneration({expectedGeneration:1});x.state.error=true;
  assert.equal(await host.installReplacement(replacement(x)),null);assert.equal(host.getStatus().candidateChecksInFlight,0);
  assert.equal(JSON.stringify(host.getStatus()).includes('PRIVATE_BACKEND_DETAIL'),false);
  x.state.error=false;assert.equal((await host.installReplacement(replacement(x))).generation,2);
});
test('installation observations never bypass later per-request revocation checks',async()=>{
  const x=await setup(),host=await x.build();x.state.key.state='REVOKED';x.state.key.revision=2;
  assert.equal(await host.signSessionStatement(x.statement),null);
  assert.equal(host.getStatus().registryRevisionAtInstall,1);assert.equal(host.getStatus().registryReadiness,'VERIFIED_AT_INSTALL');
});
test('duplicate, stale and scope-changing installation commands perform no new registry work',async()=>{
  const x=await setup(),host=await x.build();await host.retireGeneration({expectedGeneration:1});
  const entered=deferred(),release=deferred();x.state.onRead=async()=>{entered.resolve();await release.promise;};
  const first=host.installReplacement(replacement(x));await entered.promise;
  assert.equal(await host.installReplacement(replacement(x)),null);assert.equal(await host.signSessionStatement(x.statement),null);
  release.resolve();assert.equal((await first).generation,2);await host.retireGeneration({expectedGeneration:2});
  const reads=x.state.keyReads;assert.equal(await host.installReplacement(replacement(x)),null);
  assert.equal(await host.installReplacement({...replacement(x,2),issuerKey:x.issuerKey}),null);
  assert.equal(x.state.keyReads,reads);
});
test('initial and replacement checks use fresh internal challenges and retain the same public-key scope',async()=>{
  const x=await setup(),seen=[];
  await interceptSigning(async(run,args)=>{seen.push(Buffer.from(args[2]).toString());return run();},async()=>{
    const host=await x.build();await host.retireGeneration({expectedGeneration:1});await host.installReplacement(replacement(x));
  });assert.equal(seen.length,2);assert.notEqual(seen[0],seen[1]);
  for(const text of seen){assert.equal(text.startsWith('RIO_ONE_SOFTWARE_KEY_CHECK_V303\0'),true);
    const c=JSON.parse(text.slice(text.indexOf('\0')+1));assert.equal(c.keyId,x.issuerKey.keyId);assert.equal(c.origin,origin);}
});
test('unchanged issuer/verifier callback works across registry-checked replacement without issuing a session',async()=>{
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
