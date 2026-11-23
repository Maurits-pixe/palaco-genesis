import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createPublicKey,generateKeyPairSync,webcrypto} from 'node:crypto';
import {createRioOneInspectionServiceV308} from '../rio-one-inspection-service-v308.mjs';
import {RIO_RECEIPT_INSPECTION_PATH_V269 as PATH} from '../rio-receipt-http-route-v269.mjs';

const at=Date.parse('2026-11-20T07:00:00Z'),origin='https://rio.example.invalid';
async function setup(){
  const pair=await webcrypto.subtle.generateKey({name:'Ed25519'},false,['sign','verify']);
  const pub=createPublicKey({key:Buffer.from(await webcrypto.subtle.exportKey('spki',pair.publicKey)),format:'der',type:'spki'});
  const issuerKey={issuerId:'synthetic-one',keyId:'source-key',publicKeyPem:pub.export({format:'pem',type:'spki'}),
    spkiSha256:createHash('sha256').update(pub.export({format:'der',type:'spki'})).digest('hex')};
  const receipt=generateKeyPairSync('ed25519');
  const pin={keyId:'receipt-key',algorithm:'Ed25519',spkiSha256:createHash('sha256').update(receipt.publicKey.export({format:'der',type:'spki'})).digest('hex')};
  const state={keyReads:0,authReads:0,oneReads:0,policyReads:0,key:{state:'ACTIVE',issuerId:issuerKey.issuerId,keyId:issuerKey.keyId,
    revision:1,notBefore:new Date(at-60000).toISOString(),notAfter:new Date(at+60000).toISOString()}};
  const config={tenantRef:'STAGING_TENANT_001',allowedOrigin:origin,issuerKey,privateSigningKey:pair.privateKey,
    readIssuerKeyState:async()=>{state.keyReads++;await state.onRegistry?.();return {...state.key};},
    readAuthenticatedOneSession:async()=>{state.authReads++;return null;},
    acquireOneReadConnection:async()=>{state.oneReads++;throw Error('UNAVAILABLE_ONE_DATABASE');},
    receiptServices:{keyPins:[pin],readInspectionPolicy:async()=>{state.policyReads++;return null;},
      readOriginalRevocationRequest:async()=>null,confirmCurrentRevocation:async()=>null,queryVerificationKeys:async()=>({rows:[]})},
    now:()=>new Date(at),limits:{requestTimeoutMs:5000,maxConcurrentInspections:1,maxConcurrentSignatures:1}};
  return {pair,issuerKey,pin,state,config,build:()=>createRioOneInspectionServiceV308(config)};
}
const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};
const scope=service=>{const s=service.signerControl.getStatus();return {controllerId:s.controllerId,expectedGeneration:s.generation};};
const replacement=(x,service)=>({...scope(service),expectedLastCompletedAttemptId:service.signerControl.getStatus().lastCompletedAttemptId,
  privateSigningKey:x.pair.privateKey});
const request=()=>new Request(origin+PATH,{method:'POST',headers:{Origin:origin,'X-RIO-Inspection':'1','Content-Type':'application/json'},
  body:JSON.stringify({requestId:'request-001',receiptJson:'{}'})});

test('one constructor returns frozen inspection and signer-control ports after actual key/registry checks',async()=>{
  const x=await setup(),service=await x.build();
  assert.equal(Object.isFrozen(service),true);assert.equal(Object.isFrozen(service.inspection),true);assert.equal(Object.isFrozen(service.signerControl),true);
  assert.equal(service.inspection.path,PATH);assert.equal(x.state.keyReads,2);assert.equal(x.state.authReads,0);assert.equal(x.state.oneReads,0);
  assert.equal(service.signerControl.getStatus().keyCorrespondence,'VERIFIED_AT_INSTALL');
  for(const key of ['privateSigningKey','signSessionStatement','requestSignedSession','readAuthenticatedOneSession']){
    assert.equal(Object.hasOwn(service,key),false);assert.equal(Object.hasOwn(service.inspection,key),false);assert.equal(Object.hasOwn(service.signerControl,key),false);
  }
  assert.equal(service.authorization,'NONE');assert.equal(service.acceptance,'HOLD');assert.equal(service.realOneGatewayConnected,false);
});
test('invalid root, receipt or limit configuration is rejected before provider calls',async()=>{
  const x=await setup();
  const variants=[{...x.config,requestSignedSession:async()=>null},
    {...x.config,receiptServices:{...x.config.receiptServices,authenticateHostRequest:async()=>null}},
    {...x.config,limits:{...x.config.limits,maxConcurrentInspections:0}},
    {...x.config,limits:{...x.config.limits,maxConcurrentSignatures:0}},
    {...x.config,acquireOneReadConnection:null}];
  for(const c of variants)await assert.rejects(createRioOneInspectionServiceV308(c),TypeError);
  assert.equal(x.state.keyReads,0);assert.equal(x.state.authReads,0);assert.equal(x.state.oneReads,0);
});
test('an authenticated-session service is an explicit dependency with no alternate callback fallback',async()=>{
  const x=await setup();await assert.rejects(createRioOneInspectionServiceV308({...x.config,readAuthenticatedOneSession:undefined}),TypeError);
  assert.equal(x.state.keyReads,0);assert.equal(x.state.authReads,0);
});
test('source and receipt pins remain independently separated before any private-key operation',async()=>{
  const x=await setup();await assert.rejects(createRioOneInspectionServiceV308({...x.config,
    receiptServices:{...x.config.receiptServices,keyPins:[{...x.pin,spkiSha256:x.issuerKey.spkiSha256}]}}),TypeError);
  assert.equal(x.state.keyReads,0);
});
test('nested accessor and sparse pin configuration is refused without evaluation',async()=>{
  const x=await setup();let evaluated=false;const pin={...x.pin};Object.defineProperty(pin,'keyId',{
    get(){evaluated=true;return 'receipt-key';},enumerable:true});
  await assert.rejects(createRioOneInspectionServiceV308({...x.config,receiptServices:{...x.config.receiptServices,keyPins:[pin]}}),TypeError);
  await assert.rejects(createRioOneInspectionServiceV308({...x.config,receiptServices:{...x.config.receiptServices,keyPins:new Array(1)}}),TypeError);
  assert.equal(evaluated,false);assert.equal(x.state.keyReads,0);
});
test('no existing authenticated session refuses inspection before One SQL or receipt policy',async()=>{
  const x=await setup(),service=await x.build(),response=await service.inspection.handle(request());
  assert.equal(response.status,403);const result=await response.json();assert.equal(result.authorization,'NONE');assert.equal(result.acceptance,'HOLD');
  assert.ok(x.state.authReads>0);assert.equal(x.state.oneReads,0);assert.equal(x.state.policyReads,0);
  assert.match(response.headers.get('Cache-Control'),/no-store/);assert.equal(response.headers.get('Access-Control-Allow-Origin'),null);
});
test('the original route checks reject origin and path mistakes before authentication',async()=>{
  const x=await setup(),service=await x.build();
  const wrong=new Request(origin+PATH,{method:'POST',headers:{Origin:'https://other.invalid','X-RIO-Inspection':'1','Content-Type':'application/json'},body:'{}'});
  assert.equal((await service.inspection.handle(wrong)).status,403);
  assert.equal((await service.inspection.handle(new Request(origin+'/other'))).status,404);assert.equal(x.state.authReads,0);assert.equal(x.state.oneReads,0);
});
test('all public config and receipt pin values are captured before asynchronous signer initialization',async()=>{
  const x=await setup(),entered=deferred(),release=deferred();x.state.onRegistry=async()=>{entered.resolve();await release.promise;};
  const pending=x.build();await entered.promise;
  x.config.tenantRef='OTHER';x.config.allowedOrigin='https://other.invalid';x.config.issuerKey.issuerId='OTHER';
  x.config.receiptServices.keyPins[0].spkiSha256='INVALID';x.config.limits.maxConcurrentSignatures=0;
  x.config.readAuthenticatedOneSession=async()=>{throw Error('MUTATED_CONFIGURATION');};
  release.resolve();const service=await pending;
  assert.equal(service.signerControl.getStatus().capacity,1);assert.equal((await service.inspection.handle(request())).status,403);
  assert.ok(x.state.authReads>0);assert.equal(x.state.oneReads,0);
});
test('replacement injects the fixed shared registry and refuses a caller-supplied alternate reader',async()=>{
  const x=await setup(),service=await x.build(),control=service.signerControl;await control.retireGeneration(scope(service));let alternate=0;
  const reads=x.state.keyReads;
  assert.equal(await control.installReplacement({...replacement(x,service),readIssuerKeyState:async()=>{alternate++;return {...x.state.key};}}),null);
  assert.equal(alternate,0);assert.equal(x.state.keyReads,reads);assert.equal(control.getLastAttemptResult(),null);
  x.config.readIssuerKeyState=async()=>{alternate++;return {...x.state.key};};
  const installed=await control.installReplacement(replacement(x,service));assert.equal(installed.generation,2);
  assert.equal(alternate,0);assert.equal(x.state.keyReads,reads+2);
});
test('failed initial registry checks return no partial service',async()=>{
  const x=await setup();x.state.key.state='REVOKED';await assert.rejects(x.build(),{name:'TypeError',message:'PINNED_SOFTWARE_KEY_AND_REGISTRY_CHECK_FAILED'});
  assert.equal(x.state.authReads,0);assert.equal(x.state.oneReads,0);
});
test('history and scope guards stay effective through the narrower signer-control port',async()=>{
  const x=await setup(),service=await x.build(),control=service.signerControl;await control.retireGeneration(scope(service));const cached=replacement(x,service);
  x.state.onRegistry=()=>{const s=control.getStatus();control.cancelReplacement({controllerId:s.controllerId,expectedGeneration:s.generation,attemptId:s.candidateAttemptId});};
  assert.equal(await control.installReplacement(replacement(x,service)),null);x.state.onRegistry=undefined;
  const completed=control.getLastAttemptResult(),reads=x.state.keyReads;assert.equal(completed.outcome,'WITHHELD_AFTER_CANCELLATION');
  assert.equal(await control.installReplacement(cached),null);assert.equal(x.state.keyReads,reads);
  assert.equal((await control.installReplacement(replacement(x,service))).previousCompletedAttemptId,completed.attemptId);
});
test('signer-control close preserves the controller completion semantics and refuses later replacement',async()=>{
  const x=await setup(),service=await x.build(),control=service.signerControl,closed=control.close();
  assert.equal(closed,control.close());assert.equal((await closed).state,'CLOSED');
  assert.equal(await control.installReplacement(replacement(x,service)),null);assert.equal((await service.inspection.handle(request())).status,403);
  assert.equal(service.sessionIssuance,false);assert.equal(service.productionReady,false);
});
