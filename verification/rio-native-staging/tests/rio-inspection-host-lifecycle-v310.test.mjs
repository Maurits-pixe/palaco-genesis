import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createPublicKey,generateKeyPairSync,webcrypto} from 'node:crypto';
import {createRioInspectionHostLifecycleV310} from '../rio-inspection-host-lifecycle-v310.mjs';
import {createRioManagedInspectionServiceV309} from '../rio-managed-inspection-service-v309.mjs';
import {RIO_RECEIPT_INSPECTION_PATH_V269 as PATH} from '../rio-receipt-http-route-v269.mjs';
const ORIGIN='https://rio.example.invalid',NOW=Date.parse('2026-11-23T00:00:00Z');
const fingerprint=createHash('sha256').update(generateKeyPairSync('ed25519').publicKey.export({format:'der',type:'spki'})).digest('hex');
const bounds={acceptance:'HOLD',authorization:'NONE'};
const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};
const flush=()=>new Promise(resolve=>setImmediate(resolve));
const request=()=>new Request(ORIGIN+PATH,{method:'POST',headers:{Origin:ORIGIN,'X-RIO-Inspection':'1',
 'Content-Type':'application/json'},body:JSON.stringify({requestId:'synthetic-request',receiptJson:'{}'})});
const drained=()=>({format:'rio-managed-inspection-service-status-v309',state:'CLOSED',inFlightInspections:0,
 readerCancellationsInFlight:0,inspectionCapacity:1,signer:{format:'rio-one-history-bound-handover-v307',
 state:'CLOSED',backendState:'STOPPED',inFlight:0,candidateChecksInFlight:0,acceptingWork:false,...bounds},...bounds});
function harness(){
 const calls={handle:0,stop:0,drain:0,release:0},order=[];
 const service={format:'rio-managed-inspection-service-v309',inspection:{
 handle:async()=>{calls.handle++;return new Response('{}');},path:PATH,purpose:'READ_ONLY_RECEIPT_INSPECTION_ROUTE',...bounds},
 control:{getStatus:()=>drained(),getLastAttemptResult:()=>null,retireGeneration:()=>null,
 installReplacement:async()=>null,cancelReplacement:()=>null,
 close:async()=>{calls.drain++;order.push('DRAIN');return drained();},...bounds},
 realOneGatewayConnected:false,sessionIssuance:false,productionReady:false,...bounds};
 const config={service,stopHttpAdmission:async()=>{calls.stop++;order.push('STOP');},
 releaseHostResources:async()=>{calls.release++;order.push('RELEASE');}};
 return {calls,order,service,config,build:()=>createRioInspectionHostLifecycleV310(config)};
}
test('static construction makes no calls and freezes distinct ports and status',()=>{
 const x=harness(),h=x.build();assert.deepEqual(x.calls,{handle:0,stop:0,drain:0,release:0});
 for(const v of [h,h.inspection,h.control,h.control.getStatus(),h.control.getStatus().issues])assert.ok(Object.isFrozen(v));
 assert.equal(h.control.getStatus().state,'RUNNING');assert.equal(Object.hasOwn(h.inspection,'close'),false);
 assert.equal(Object.hasOwn(h.control,'signSessionStatement'),false);assert.equal(h.sessionIssuance,false);
});
test('missing extra and accessor configuration is rejected before callbacks',()=>{
 const x=harness();let getters=0;const bad={...x.config};Object.defineProperty(bad,'stopHttpAdmission',{enumerable:true,get(){getters++;return ()=>{};}});
 for(const c of [bad,{...x.config,extra:1},{...x.config,releaseHostResources:null},
 {...x.config,service:{...x.service,format:'OTHER'}},{...x.config,service:{...x.service,authorization:'ALLOW'}},
 {...x.config,service:{...x.service,inspection:{...x.service.inspection,handle:null}}}])
 assert.throws(()=>createRioInspectionHostLifecycleV310(c),TypeError);
 assert.equal(getters,0);assert.deepEqual(x.calls,{handle:0,stop:0,drain:0,release:0});
});
test('request identity signal body and returned response are unchanged',async()=>{
 const x=harness(),r=request(),response=new Response('{}');
 x.service.inspection.handle=async v=>{x.calls.handle++;assert.equal(v,r);assert.equal(v.signal,r.signal);assert.equal(v.bodyUsed,false);return response;};
 const h=x.build();assert.equal(await h.inspection.handle(r),response);assert.equal(r.bodyUsed,false);
 assert.equal((await h.inspection.handle({})).status,400);assert.equal(x.calls.handle,1);
});
test('stop and drain start in order concurrently with stable reentrant close promise',async()=>{
 const x=harness(),gate=deferred();let nested;
 x.config.stopHttpAdmission=()=>{x.order.push('STOP');nested=h.control.close();return gate.promise;};
 const h=x.build(),done=h.control.close();assert.equal(done,nested);assert.equal(done,h.control.close());
 assert.deepEqual(x.order,['STOP','DRAIN']);assert.equal(h.control.getStatus().state,'STOPPING');assert.equal(x.calls.release,0);
 gate.resolve();assert.equal((await done).state,'CLOSED');assert.deepEqual(x.order,['STOP','DRAIN','RELEASE']);
});
test('resources wait for actual service completion after transport completes',async()=>{
 const x=harness(),gate=deferred();x.service.control.close=()=>gate.promise;const h=x.build(),done=h.control.close();
 await flush();assert.equal(x.calls.release,0);assert.equal(h.control.getStatus().httpAdmissionStop,'COMPLETED');
 assert.equal(h.control.getStatus().serviceDrain,'PENDING');gate.resolve(drained());assert.equal((await done).state,'CLOSED');
});
test('resources wait for actual transport completion after service completes',async()=>{
 const x=harness(),gate=deferred();x.config.stopHttpAdmission=()=>gate.promise;const h=x.build(),done=h.control.close();
 await flush();assert.equal(x.calls.release,0);assert.equal(h.control.getStatus().serviceDrain,'COMPLETED');
 assert.equal(h.control.getStatus().httpAdmissionStop,'PENDING');gate.resolve();assert.equal((await done).state,'CLOSED');
});
test('sync and async stop failure still drain service but skip resource disposal',async()=>{
 for(const stop of [()=>{throw Error('PRIVATE_STOP');},async()=>{throw Error('PRIVATE_STOP');}]){
 const x=harness();x.config.stopHttpAdmission=stop;const h=x.build(),done=h.control.close(),v=await done;
 assert.equal(v.state,'HELD');assert.equal(v.serviceDrain,'COMPLETED');assert.equal(x.calls.drain,1);assert.equal(x.calls.release,0);
 assert.deepEqual(v.issues,['HTTP_ADMISSION_STOP_NOT_CONFIRMED']);assert.equal(JSON.stringify(v).includes('PRIVATE_'),false);
 assert.equal(h.control.close(),done);
 }
});
test('failed malformed accessor and busy service results cannot release resources',async()=>{
 let getters=0;const accessor=drained();Object.defineProperty(accessor,'state',{enumerable:true,get(){getters++;return 'CLOSED';}});
 for(const close of [async()=>{throw Error('PRIVATE_SERVICE');},async()=>undefined,async()=>accessor,
 async()=>({...drained(),inFlightInspections:1}),async()=>({...drained(),readerCancellationsInFlight:1}),
 async()=>({...drained(),signer:{...drained().signer,candidateChecksInFlight:1}})]){
 const x=harness();x.service.control.close=close;const h=x.build(),v=await h.control.close();
 assert.equal(v.state,'HELD');assert.equal(x.calls.release,0);assert.deepEqual(v.issues,['SERVICE_DRAIN_NOT_CONFIRMED']);
 }
 assert.equal(getters,0);
});
test('pending resource release is observable and refuses new inspection before body reads',async()=>{
 const x=harness(),gate=deferred();x.config.releaseHostResources=()=>{x.calls.release++;return gate.promise;};
 const h=x.build(),done=h.control.close();await flush();assert.equal(h.control.getStatus().state,'RELEASING_RESOURCES');
 const r=request(),res=await h.inspection.handle(r);assert.equal(res.status,503);assert.equal(r.bodyUsed,false);assert.equal(x.calls.handle,0);
 assert.match(res.headers.get('Cache-Control'),/no-store/);assert.equal(res.headers.has('Access-Control-Allow-Origin'),false);
 gate.resolve();assert.equal((await done).state,'CLOSED');
});
test('resource failure stays HELD with fixed issue code and no automatic retry',async()=>{
 const x=harness();x.config.releaseHostResources=async()=>{x.calls.release++;throw Error('PRIVATE_RELEASE');};
 const h=x.build(),done=h.control.close(),v=await done;assert.equal(v.state,'HELD');assert.equal(v.hostResourceRelease,'NOT_CONFIRMED');
 assert.deepEqual(v.issues,['HOST_RESOURCE_RELEASE_NOT_CONFIRMED']);assert.equal(JSON.stringify(v).includes('PRIVATE_'),false);
 assert.equal(h.control.close(),done);assert.equal(x.calls.release,1);assert.equal((await h.inspection.handle(request())).status,503);
});
test('later caller mutation cannot redirect captured host ports',async()=>{
 const x=harness(),h=x.build();x.config.stopHttpAdmission=()=>{throw Error('MUTATED');};
 x.config.releaseHostResources=()=>{throw Error('MUTATED');};x.service.control.close=()=>{throw Error('MUTATED');};
 assert.equal((await h.control.close()).state,'CLOSED');assert.deepEqual(x.calls,{handle:0,stop:1,drain:1,release:1});
});
async function serviceHarness(){
  const pair=await webcrypto.subtle.generateKey({name:'Ed25519'},false,['sign','verify']);
  const pub=createPublicKey({key:Buffer.from(await webcrypto.subtle.exportKey('spki',pair.publicKey)),format:'der',type:'spki'});
  const issuerKey={issuerId:'synthetic-one',keyId:'source-key',publicKeyPem:pub.export({format:'pem',type:'spki'}),
    spkiSha256:createHash('sha256').update(pub.export({format:'der',type:'spki'})).digest('hex')};
  const state={keyReads:0,authReads:0,oneReads:0,key:{state:'ACTIVE',issuerId:issuerKey.issuerId,keyId:issuerKey.keyId,
    revision:1,notBefore:new Date(NOW-60000).toISOString(),notAfter:new Date(NOW+60000).toISOString()}};
  const config={tenantRef:'synthetic-tenant',allowedOrigin:ORIGIN,issuerKey,privateSigningKey:pair.privateKey,
    readIssuerKeyState:async()=>{state.keyReads++;await state.onRegistry?.();return {...state.key};},
    readAuthenticatedOneSession:async()=>{state.authReads++;await state.onAuth?.();return null;},
    acquireOneReadConnection:async()=>{state.oneReads++;throw Error('SYNTHETIC_UNAVAILABLE_SQL');},
    receiptServices:{keyPins:[{keyId:'synthetic-key',algorithm:'Ed25519',spkiSha256:fingerprint}],
      readInspectionPolicy:async()=>null,readOriginalRevocationRequest:async()=>null,
      confirmCurrentRevocation:async()=>null,queryVerificationKeys:async()=>({rows:[]})},
    now:()=>new Date(NOW),limits:{requestTimeoutMs:1000,maxConcurrentInspections:1,maxConcurrentSignatures:1}};
  return {pair,state,config,build:()=>createRioManagedInspectionServiceV309(config)};
}

test('real key-checked v309 service waits for delayed authentication before host disposal',async()=>{
 const x=await serviceHarness(),entered=deferred(),release=deferred();x.config.limits.requestTimeoutMs=25;
 x.state.onAuth=async()=>{entered.resolve();await release.promise;};const service=await x.build();let disposed=0;
 const h=createRioInspectionHostLifecycleV310({service,stopHttpAdmission:async()=>{},releaseHostResources:async()=>{disposed++;}});
 const pending=h.inspection.handle(request());await entered.promise;assert.equal((await pending).status,504);
 const done=h.control.close();await flush();assert.equal(disposed,0);assert.equal(h.control.getStatus().serviceDrain,'PENDING');
 release.resolve();assert.equal((await done).state,'CLOSED');assert.equal(disposed,1);assert.equal(x.state.oneReads,0);
});
