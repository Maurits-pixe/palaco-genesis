/** Trusted-server service with terminal route and signer completion, DRAFT; no listener or IdP. */
import {createRioOneHistoryBoundSignerHandoverV307} from './rio-one-history-bound-signer-handover-v307.mjs';
import {createRioOneSessionStatementIssuerV298} from './rio-one-session-statement-issuer-v298.mjs';
import {createRioOneSignedSessionProviderV296} from './rio-one-signed-session-provider-v296.mjs';
import {createRioOneSessionReaderV295} from './rio-palaco-one-session-reader-v295.mjs';
import {createRioDrainableReceiptHttpRouteV309} from './rio-drainable-receipt-http-route-v309.mjs';

function snapshot(value,keys){
  try{
    if(value===null||typeof value!=='object'||Array.isArray(value))return null;
    const d=Object.getOwnPropertyDescriptors(value);
    if(Reflect.ownKeys(d).length!==keys.length||keys.some(k=>!Object.hasOwn(d,k)||
      !Object.hasOwn(d[k],'value')||!d[k].enumerable))return null;
    return Object.fromEntries(keys.map(k=>[k,d[k].value]));
  }catch{return null;}
}
function pinSnapshot(value){
  try{
    if(!Array.isArray(value))return null;
    const d=Object.getOwnPropertyDescriptors(value),n=d.length?.value;
    if(!Number.isSafeInteger(n)||n<1||n>32||Reflect.ownKeys(d).length!==n+1)return null;
    const pins=[];
    for(let i=0;i<n;i++){
      const p=d[String(i)];if(!p||!Object.hasOwn(p,'value')||!p.enumerable)return null;
      const pin=snapshot(p.value,['keyId','algorithm','spkiSha256']);if(!pin)return null;
      pins.push(Object.freeze(pin));
    }
    return Object.freeze(pins);
  }catch{return null;}
}

export async function createRioManagedInspectionServiceV309(configuration){
  const c=snapshot(configuration,['tenantRef','allowedOrigin','issuerKey','privateSigningKey',
    'readIssuerKeyState','readAuthenticatedOneSession','acquireOneReadConnection','receiptServices','now','limits']);
  configuration=undefined;
  const issuerKey=c&&snapshot(c.issuerKey,['issuerId','keyId','publicKeyPem','spkiSha256']);
  const receipt=c&&snapshot(c.receiptServices,['keyPins','readInspectionPolicy','readOriginalRevocationRequest',
    'confirmCurrentRevocation','queryVerificationKeys']);
  const limits=c&&snapshot(c.limits,['requestTimeoutMs','maxConcurrentInspections','maxConcurrentSignatures']);
  const pins=receipt&&pinSnapshot(receipt.keyPins);
  if(!c||!issuerKey||!receipt||!limits||!pins)throw TypeError('EXACT_TRUSTED_INSPECTION_SERVICE_CONFIGURATION_REQUIRED');
  const shared=Object.freeze({tenantRef:c.tenantRef,allowedOrigin:c.allowedOrigin,
    issuerKey:Object.freeze(issuerKey),readIssuerKeyState:c.readIssuerKeyState,now:c.now});
  let signer;
  // These constructors perform static validation before the signer invokes any provider.
  const issuer=createRioOneSessionStatementIssuerV298({...shared,
    readAuthenticatedOneSession:c.readAuthenticatedOneSession,
    signSessionStatement:statement=>signer?signer.signSessionStatement(statement):null});
  if(pins.some(pin=>pin.spkiSha256===shared.issuerKey.spkiSha256))
    throw TypeError('SEPARATE_SOURCE_AND_RECEIPT_KEY_PINS_REQUIRED');
  const source=createRioOneSignedSessionProviderV296({...shared,requestSignedSession:issuer.requestSignedSession});
  const session=createRioOneSessionReaderV295({tenantRef:shared.tenantRef,
    authenticateOneRequest:source.authenticateOneRequest,acquireOneReadConnection:c.acquireOneReadConnection,now:shared.now});
  const route=createRioDrainableReceiptHttpRouteV309({allowedOrigin:shared.allowedOrigin,
    requestTimeoutMs:limits.requestTimeoutMs,maxConcurrentInspections:limits.maxConcurrentInspections,
    host:{tenantRef:shared.tenantRef,...receipt,keyPins:pins,now:shared.now,
      authenticateHostRequest:session.authenticateHostRequest}});
  try{
    signer=await createRioOneHistoryBoundSignerHandoverV307({...shared,privateSigningKey:c.privateSigningKey,
      maxConcurrentSignatures:limits.maxConcurrentSignatures});
  }finally{c.privateSigningKey=undefined;}
  let state='OPEN',resolveClosed;
  const closed=new Promise(resolve=>{resolveClosed=resolve;});
  function getStatus(){
    const r=route.getStatus();
    return Object.freeze({format:'rio-managed-inspection-service-status-v309',state,
      inFlightInspections:r.inFlight,readerCancellationsInFlight:r.readerCancellationsInFlight,
      inspectionCapacity:r.capacity,signer:signer.getStatus(),acceptance:'HOLD',authorization:'NONE'});
  }
  function close(){
    if(state==='OPEN'){
      // Stop route admission synchronously before requesting signer shutdown.
      state='DRAINING';
      const routeClosed=route.close(),signerClosed=signer.close();
      void Promise.all([routeClosed,signerClosed]).then(()=>{
        state='CLOSED';resolveClosed(getStatus());
      });
    }
    return closed;
  }
  async function installReplacement(command){
    if(state!=='OPEN')return null;
    const next=snapshot(command,['controllerId','expectedGeneration','expectedLastCompletedAttemptId','privateSigningKey']);
    if(!next)return null;
    return signer.installReplacement({...next,readIssuerKeyState:shared.readIssuerKeyState});
  }
  const control=Object.freeze({getStatus,getLastAttemptResult:signer.getLastAttemptResult,
    retireGeneration:command=>state==='OPEN'?signer.retireGeneration(command):null,
    installReplacement,cancelReplacement:command=>state==='OPEN'?signer.cancelReplacement(command):null,close,
    acceptance:'HOLD',authorization:'NONE'});
  const inspection=Object.freeze({handle:route.handle,path:route.path,purpose:route.purpose,
    acceptance:'HOLD',authorization:'NONE'});
  return Object.freeze({format:'rio-managed-inspection-service-v309',inspection,control,
    realOneGatewayConnected:false,sessionIssuance:false,productionReady:false,acceptance:'HOLD',authorization:'NONE'});
}
