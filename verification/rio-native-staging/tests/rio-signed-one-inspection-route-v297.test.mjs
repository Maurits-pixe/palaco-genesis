import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {createRioSignedOneInspectionRouteV297} from '../rio-signed-one-inspection-route-v297.mjs';
import {RIO_RECEIPT_INSPECTION_PATH_V269 as PATH} from '../rio-receipt-http-route-v269.mjs';

function setup(){
  const source=generateKeyPairSync('ed25519'),receipt=generateKeyPairSync('ed25519');
  const digest=k=>createHash('sha256').update(k.export({format:'der',type:'spki'})).digest('hex');
  const calls={source:0,key:0,db:0,policy:0};
  const c={tenantRef:'STAGING_TENANT_001',allowedOrigin:'https://rio.example.invalid',
    issuerKey:{issuerId:'synthetic-one-issuer',keyId:'source-key',publicKeyPem:source.publicKey.export({format:'pem',type:'spki'}),spkiSha256:digest(source.publicKey)},
    requestSignedSession:async()=>{calls.source++;return null;},
    readIssuerKeyState:async()=>{calls.key++;return {state:'ACTIVE',issuerId:'synthetic-one-issuer',keyId:'source-key',revision:1,
      notBefore:'2026-01-01T00:00:00.000Z',notAfter:'2027-01-01T00:00:00.000Z'};},
    acquireOneReadConnection:async()=>{calls.db++;throw Error('PRIVATE_DATABASE_DETAIL');},
    now:()=>new Date('2026-11-19T10:00:00.000Z'),requestTimeoutMs:1000,maxConcurrentInspections:1,
    receiptServices:{keyPins:[{keyId:'receipt-key',algorithm:'Ed25519',spkiSha256:digest(receipt.publicKey)}],
      readInspectionPolicy:async()=>{calls.policy++;return null;},readOriginalRevocationRequest:async()=>null,
      confirmCurrentRevocation:async()=>null,queryVerificationKeys:async()=>({rows:[]})}};
  return {c,calls};
}
const request=c=>new Request(c.allowedOrigin+PATH,{method:'POST',headers:{Origin:c.allowedOrigin,
  'X-RIO-Inspection':'1','Content-Type':'application/json',Cookie:'rio-staging=synthetic-handle'},
  body:JSON.stringify({requestId:'request-001',receiptJson:'{}'})});
test('central composition performs no provider calls and reports only structural preflight',()=>{
  const {c,calls}=setup(),route=createRioSignedOneInspectionRouteV297(c);
  assert.equal(route.preflight.structuralStatus,'STRUCTURALLY_VALIDATED');
  assert.equal(route.preflight.runtimeDependencyStatus,'NOT_CHECKED');
  assert.deepEqual(calls,{source:0,key:0,db:0,policy:0});assert.equal(Object.isFrozen(route),true);
  assert.equal(route.authorization,'NONE');assert.equal(route.productionReady,false);
});
test('legacy authentication callbacks cannot be injected in place of the signed source',()=>{
  for(const location of ['root','receipt']){
    const {c}=setup();(location==='root'?c:c.receiptServices).authenticateHostRequest=async()=>({state:'ACTIVE',assurance:'HOST_VERIFIED'});
    assert.throws(()=>createRioSignedOneInspectionRouteV297(c),/EXACT_SIGNED_ONE_ROUTE_CONFIGURATION_REQUIRED/);
  }
});
test('a second tenant or clock in receipt services cannot override the central binding',()=>{
  for(const property of ['tenantRef','now']){const {c}=setup();c.receiptServices[property]=property==='now'?()=>new Date(): 'OTHER_TENANT';
    assert.throws(()=>createRioSignedOneInspectionRouteV297(c),/EXACT_SIGNED_ONE_ROUTE_CONFIGURATION_REQUIRED/);}
});
test('source and receipt signing domains require separate independent public-key pins',()=>{
  const {c,calls}=setup();c.receiptServices.keyPins[0].spkiSha256=c.issuerKey.spkiSha256;
  assert.throws(()=>createRioSignedOneInspectionRouteV297(c),/SEPARATE_SOURCE_AND_RECEIPT_KEY_PINS_REQUIRED/);
  assert.deepEqual(calls,{source:0,key:0,db:0,policy:0});
});
test('an unsigned source reply and public fixture cookie cannot reach One SQL or receipt policy',async()=>{
  const {c,calls}=setup();c.requestSignedSession=async()=>{calls.source++;return JSON.stringify({state:'ACTIVE',assurance:'HOST_VERIFIED',role:'OWNER'});};
  const response=await createRioSignedOneInspectionRouteV297(c).handle(request(c));
  assert.equal(response.status,403);assert.equal((await response.json()).authorization,'NONE');
  assert.deepEqual(calls,{source:1,key:1,db:0,policy:0});
});
test('missing real source refuses access without leaking provider diagnostics',async()=>{
  const {c,calls}=setup();c.requestSignedSession=async()=>{calls.source++;throw Error('PRIVATE_ONE_CREDENTIAL_DETAIL');};
  const result=await createRioSignedOneInspectionRouteV297(c).handle(request(c));
  assert.equal(result.status,403);assert.equal((await result.text()).includes('PRIVATE_ONE'),false);
  assert.equal(calls.db,0);assert.equal(calls.policy,0);
});
