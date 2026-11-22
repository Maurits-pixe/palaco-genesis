import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createPublicKey,randomBytes,verify,webcrypto} from 'node:crypto';
import {createRioOneSignerHandoverV301} from '../rio-one-signer-handover-v301.mjs';
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
  return {pair,publicKey,issuerKey,session,message,statement,state,config,build:()=>createRioOneSignerHandoverV301(config)};
}
const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};
const replacement=(x,g=1)=>({expectedGeneration:g,privateSigningKey:x.pair.privateKey,
  readIssuerKeyState:x.config.readIssuerKeyState});

test('constructor checks explicit configuration without calling providers; status has no key references',async()=>{
  const x=await setup(),host=x.build(),s=host.getStatus();
  assert.deepEqual(s,{format:'rio-one-signer-handover-v301',generation:1,state:'SERVING',backendState:'OPEN',
    inFlight:0,capacity:1,acceptingWork:true,acceptance:'HOLD',authorization:'NONE'});
  assert.equal(x.state.keyReads,0);assert.equal(Object.isFrozen(s),true);assert.equal(Object.isFrozen(host),true);
  assert.equal(Object.hasOwn(host,'privateSigningKey'),false);assert.equal(host.keyRotation,'NOT_PROVIDED');
  assert.throws(()=>createRioOneSignerHandoverV301({...x.config,alternateTenant:'OTHER'}),TypeError);
  assert.throws(()=>createRioOneSignerHandoverV301({...x.config,maxConcurrentSignatures:null}),TypeError);
});
test('stable signing callback performs real cryptography before and after explicit replacement',async()=>{
  const x=await setup(),host=x.build(),port=host.signSessionStatement;
  const check=async()=>assert.equal(verify(null,Buffer.from(x.statement.payload),x.publicKey,
    Buffer.from(await port(x.statement),'base64url')),true);
  await check();await host.retireGeneration({expectedGeneration:1});
  assert.equal(host.getStatus().state,'RETIRED');assert.equal(await port(x.statement),null);
  const installed=host.installReplacement(replacement(x));
  assert.equal(installed.previousGeneration,1);assert.equal(installed.generation,2);
  assert.equal(installed.readiness,'NOT_CHECKED');assert.equal(Object.isFrozen(installed),true);
  assert.equal(host.signSessionStatement,port);await check();
});
test('replacement cannot bypass an OPEN generation or start provider calls',async()=>{
  const x=await setup(),host=x.build();
  assert.equal(host.installReplacement(replacement(x)),null);assert.equal(x.state.keyReads,0);
  assert.equal(host.getStatus().generation,1);assert.equal(host.getStatus().state,'SERVING');
});
test('retirement is idempotent and stale generation commands cannot stop a new generation',async()=>{
  const x=await setup(),host=x.build(),first=host.retireGeneration({expectedGeneration:1});
  assert.equal(first,host.retireGeneration({expectedGeneration:1}));await first;
  host.installReplacement(replacement(x));
  assert.equal(host.retireGeneration({expectedGeneration:1}),null);
  assert.equal(host.installReplacement(replacement(x)),null);assert.equal(host.getStatus().state,'SERVING');
  assert.ok(await host.signSessionStatement(x.statement));
});
test('pending work must finish before replacement and the retired signature is withheld',async()=>{
  const x=await setup(),host=x.build(),entered=deferred(),release=deferred();
  x.state.onRead=async()=>{if(x.state.keyReads===2){entered.resolve();await release.promise;}};
  const job=host.signSessionStatement(x.statement);await entered.promise;
  const retired=host.retireGeneration({expectedGeneration:1});let completed=false;retired.then(()=>{completed=true;});
  assert.equal(host.getStatus().state,'RETIRING');assert.equal(host.getStatus().inFlight,1);
  assert.equal(host.installReplacement(replacement(x)),null);
  assert.equal(await host.signSessionStatement(x.statement),null);await Promise.resolve();assert.equal(completed,false);
  release.resolve();assert.equal(await job,null);await retired;
  assert.equal(host.installReplacement(replacement(x)).generation,2);assert.ok(await host.signSessionStatement(x.statement));
});
test('an invalid replacement preserves the retired generation and permits an explicit corrected attempt',async()=>{
  const x=await setup(),host=x.build();await host.retireGeneration({expectedGeneration:1});
  assert.equal(host.installReplacement({...replacement(x),privateSigningKey:'PRIVATE_BACKEND_DETAIL'}),null);
  assert.equal(host.getStatus().state,'RETIRED');assert.equal(host.getStatus().generation,1);
  assert.equal(host.installReplacement(replacement(x)).generation,2);
});
test('a duplicate install command cannot replace the next generation',async()=>{
  const x=await setup(),host=x.build();await host.retireGeneration({expectedGeneration:1});
  const command=replacement(x);assert.equal(host.installReplacement(command).generation,2);
  await host.retireGeneration({expectedGeneration:2});assert.equal(host.installReplacement(command),null);
  assert.equal(host.getStatus().generation,2);assert.equal(host.installReplacement(replacement(x,2)).generation,3);
});
test('replacement cannot change tenant, origin, public pin, clock or capacity',async()=>{
  const x=await setup(),host=x.build();await host.retireGeneration({expectedGeneration:1});
  for(const key of ['tenantRef','allowedOrigin','issuerKey','now','maxConcurrentSignatures'])
    assert.equal(host.installReplacement({...replacement(x),[key]:x.config[key]}),null);
  assert.equal(x.state.keyReads,0);assert.equal(host.getStatus().generation,1);
});
test('replacement readiness is not inferred from a well-shaped but mismatched key',async()=>{
  const x=await setup(),other=await setup(),host=x.build();await host.retireGeneration({expectedGeneration:1});
  assert.equal(host.installReplacement({...replacement(x),privateSigningKey:other.pair.privateKey}).readiness,'NOT_CHECKED');
  assert.equal(await host.signSessionStatement(x.statement),null);assert.equal(host.getStatus().generation,2);
  assert.equal(host.getStatus().state,'SERVING'); // structural lifecycle, not proof of signing readiness
});
test('commands reject accessor properties without evaluating them',async()=>{
  const x=await setup(),host=x.build();let read=false;
  const command={get expectedGeneration(){read=true;return 1;}};
  assert.equal(host.retireGeneration(command),null);assert.equal(read,false);
  await host.retireGeneration({expectedGeneration:1});
  const next=replacement(x);Object.defineProperty(next,'privateSigningKey',{get(){read=true;return x.pair.privateKey;},enumerable:true});
  assert.equal(host.installReplacement(next),null);assert.equal(read,false);
});
test('reentrant install traps cannot admit two replacement generations',async()=>{
  const x=await setup(),host=x.build();await host.retireGeneration({expectedGeneration:1});let attempted=false;
  const proxy=new Proxy(replacement(x),{ownKeys(target){attempted=true;
    assert.equal(host.installReplacement(replacement(x)),null);return Reflect.ownKeys(target);}});
  assert.equal(host.installReplacement(proxy).generation,2);assert.equal(attempted,true);
});
test('terminal close from an install descriptor trap prevents installation',async()=>{
  const x=await setup(),host=x.build();await host.retireGeneration({expectedGeneration:1});
  const proxy=new Proxy(replacement(x),{ownKeys(target){host.close();return Reflect.ownKeys(target);}});
  assert.equal(host.installReplacement(proxy),null);assert.equal(host.getStatus().state,'CLOSED');
  assert.equal(host.getStatus().generation,1);assert.equal(await host.signSessionStatement(x.statement),null);
});
test('terminal close is idempotent and refuses every later replacement',async()=>{
  const x=await setup(),host=x.build(),first=host.close();assert.equal(first,host.close());await first;
  assert.equal(host.getStatus().state,'CLOSED');assert.equal(host.getStatus().backendState,'STOPPED');
  assert.equal(host.installReplacement(replacement(x)),null);assert.equal(host.retireGeneration({expectedGeneration:1}),null);
  assert.equal(await host.signSessionStatement(x.statement),null);assert.equal(x.state.keyReads,0);
});
test('terminal close during work waits for the actual provider and cannot be reopened',async()=>{
  const x=await setup(),host=x.build(),entered=deferred(),release=deferred();
  x.state.onRead=async()=>{entered.resolve();await release.promise;};
  const job=host.signSessionStatement(x.statement);await entered.promise;const stopped=host.close();
  assert.equal(host.getStatus().state,'CLOSED');assert.equal(host.getStatus().backendState,'DRAINING');
  assert.equal(host.installReplacement(replacement(x)),null);release.resolve();assert.equal(await job,null);await stopped;
  assert.equal(host.getStatus().backendState,'STOPPED');assert.equal(host.installReplacement(replacement(x)),null);
});
test('existing issuer and verifier keep their callback through same-key replacement',async()=>{
  const x=await setup(),host=x.build();
  const issuer=createRioOneSessionStatementIssuerV298({tenantRef,allowedOrigin:origin,issuerKey:x.issuerKey,
    now:x.config.now,readIssuerKeyState:x.config.readIssuerKeyState,readAuthenticatedOneSession:async()=>({...x.session}),
    signSessionStatement:host.signSessionStatement});
  const verifier=createRioOneSignedSessionProviderV296({tenantRef,allowedOrigin:origin,issuerKey:x.issuerKey,
    now:x.config.now,readIssuerKeyState:x.config.readIssuerKeyState,requestSignedSession:issuer.requestSignedSession});
  const request=()=>new Request(origin+PATH,{method:'POST',headers:{Origin:origin,'X-RIO-Inspection':'1'}});
  assert.ok(await verifier.authenticateOneRequest(request()));await host.retireGeneration({expectedGeneration:1});
  assert.equal(await verifier.authenticateOneRequest(request()),null);host.installReplacement(replacement(x));
  assert.ok(await verifier.authenticateOneRequest(request()));await host.close();
  assert.equal(await verifier.authenticateOneRequest(request()),null);assert.equal(x.session.state,'ACTIVE');
});
