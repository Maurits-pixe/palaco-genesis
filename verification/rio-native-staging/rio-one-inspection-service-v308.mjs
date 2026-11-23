/** Trusted-server assembly of existing One/RIO components, DRAFT; no listener or IdP. */
import {createRioOneHistoryBoundSignerHandoverV307} from './rio-one-history-bound-signer-handover-v307.mjs';
import {createRioOneSessionStatementIssuerV298} from './rio-one-session-statement-issuer-v298.mjs';
import {createRioSignedOneInspectionRouteV297} from './rio-signed-one-inspection-route-v297.mjs';

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

export async function createRioOneInspectionServiceV308(configuration){
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
  const route=createRioSignedOneInspectionRouteV297({...shared,requestSignedSession:issuer.requestSignedSession,
    acquireOneReadConnection:c.acquireOneReadConnection,receiptServices:Object.freeze({...receipt,keyPins:pins}),
    requestTimeoutMs:limits.requestTimeoutMs,maxConcurrentInspections:limits.maxConcurrentInspections});
  try{
    signer=await createRioOneHistoryBoundSignerHandoverV307({...shared,privateSigningKey:c.privateSigningKey,
      maxConcurrentSignatures:limits.maxConcurrentSignatures});
  }finally{c.privateSigningKey=undefined;}
  async function installReplacement(command){
    const next=snapshot(command,['controllerId','expectedGeneration','expectedLastCompletedAttemptId','privateSigningKey']);
    if(!next)return null;
    return signer.installReplacement({...next,readIssuerKeyState:shared.readIssuerKeyState});
  }
  const signerControl=Object.freeze({getStatus:signer.getStatus,getLastAttemptResult:signer.getLastAttemptResult,
    retireGeneration:signer.retireGeneration,installReplacement,cancelReplacement:signer.cancelReplacement,close:signer.close,
    acceptance:'HOLD',authorization:'NONE'});
  const inspection=Object.freeze({handle:route.handle,path:route.path,purpose:route.purpose,
    acceptance:'HOLD',authorization:'NONE'});
  return Object.freeze({format:'rio-one-inspection-service-v308',inspection,signerControl,
    realOneGatewayConnected:false,sessionIssuance:false,productionReady:false,acceptance:'HOLD',authorization:'NONE'});
}
