/** Single trusted-server composition. No listener, IdP or live credentials. */
import {createRioOneSignedSessionProviderV296} from './rio-one-signed-session-provider-v296.mjs';
import {createRioOneSessionReaderV295} from './rio-palaco-one-session-reader-v295.mjs';
import {createRioReceiptHttpRouteV269} from './rio-receipt-http-route-v269.mjs';

const CONFIG=['tenantRef','allowedOrigin','issuerKey','requestSignedSession','readIssuerKeyState',
  'acquireOneReadConnection','receiptServices','now','requestTimeoutMs','maxConcurrentInspections'];
const RECEIPT=['keyPins','readInspectionPolicy','readOriginalRevocationRequest',
  'confirmCurrentRevocation','queryVerificationKeys'];
const exact=(v,keys)=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&
  Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));

export function createRioSignedOneInspectionRouteV297(configuration){
  if(!exact(configuration,CONFIG)||!exact(configuration.receiptServices,RECEIPT))
    throw TypeError('EXACT_SIGNED_ONE_ROUTE_CONFIGURATION_REQUIRED');
  const c=Object.freeze(Object.fromEntries(CONFIG.map(k=>[k,configuration[k]])));
  const receipt=Object.freeze(Object.fromEntries(RECEIPT.map(k=>[k,c.receiptServices[k]])));
  if(!Array.isArray(receipt.keyPins)||receipt.keyPins.some(p=>p?.spkiSha256===c.issuerKey?.spkiSha256))
    throw TypeError('SEPARATE_SOURCE_AND_RECEIPT_KEY_PINS_REQUIRED');
  const source=createRioOneSignedSessionProviderV296({tenantRef:c.tenantRef,allowedOrigin:c.allowedOrigin,
    issuerKey:c.issuerKey,requestSignedSession:c.requestSignedSession,readIssuerKeyState:c.readIssuerKeyState,now:c.now});
  const session=createRioOneSessionReaderV295({tenantRef:c.tenantRef,
    authenticateOneRequest:source.authenticateOneRequest,acquireOneReadConnection:c.acquireOneReadConnection,now:c.now});
  const route=createRioReceiptHttpRouteV269({allowedOrigin:c.allowedOrigin,
    maxConcurrentInspections:c.maxConcurrentInspections,requestTimeoutMs:c.requestTimeoutMs,
    host:{tenantRef:c.tenantRef,...receipt,now:c.now,authenticateHostRequest:session.authenticateHostRequest}});
  return Object.freeze({...route,format:'rio-signed-one-inspection-route-v297',
    composition:Object.freeze(['PINNED_SIGNED_ONE_SOURCE','FRESH_ONE_SECURITY_READER','ORIGINAL_RIO_RECEIPT_ROUTE']),
    realOneGatewayConnected:false,sessionIssuance:false});
}
