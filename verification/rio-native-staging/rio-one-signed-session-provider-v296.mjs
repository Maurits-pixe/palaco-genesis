/**
 * DRAFT authenticated service-message boundary, not an IdP or session issuer.
 * Only a separately trusted One service may sign after authenticating the user.
 * The existing One gateway does not implement this protocol.
 */
import {createHash,createPublicKey,randomBytes,verify} from 'node:crypto';
import {RIO_ONE_SESSION_FORMAT_V295} from './rio-palaco-one-session-reader-v295.mjs';
import {RIO_RECEIPT_INSPECTION_PATH_V269 as PATH} from './rio-receipt-http-route-v269.mjs';

export const RIO_ONE_SIGNED_SESSION_FORMAT_V296='palaco-one-signed-rio-session-v296-DRAFT';
export const RIO_ONE_SESSION_AUDIENCE_V296='RIO_REVOCATION_AUDIT_REVIEW_ONLY';
const ID=/^[A-Za-z0-9_-]{1,128}$/;
const B64=/^[A-Za-z0-9_-]+$/;
const MAX_BYTES=16*1024,MAX_PROOF_LIFETIME_MS=5000;
const exact=(value,keys)=>value!==null&&typeof value==='object'&&!Array.isArray(value)&&
  Object.keys(value).length===keys.length&&keys.every(k=>Object.hasOwn(value,k));
const id=v=>typeof v==='string'&&ID.test(v);
const iso=v=>typeof v==='string'&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString()===v;
function clock(now){const d=now();if(!(d instanceof Date)||!Number.isFinite(d.getTime()))throw Error('CLOCK_UNAVAILABLE');return d.getTime();}
function decode(value,maxBytes){
  if(typeof value!=='string'||!value.length||value.length>Math.ceil(maxBytes*4/3)||!B64.test(value)||value.length%4===1)return null;
  const bytes=Buffer.from(value,'base64url');
  return bytes.length<=maxBytes&&bytes.toString('base64url')===value?bytes:null;
}
function keyState(value,pin,at){
  const keys=['state','issuerId','keyId','revision','notBefore','notAfter'];
  if(!exact(value,keys))return null;
  const s=Object.freeze(Object.fromEntries(keys.map(k=>[k,value[k]])));
  return s.state==='ACTIVE'&&s.issuerId===pin.issuerId&&s.keyId===pin.keyId&&
    Number.isSafeInteger(s.revision)&&s.revision>0&&iso(s.notBefore)&&iso(s.notAfter)&&
    Date.parse(s.notBefore)<=at&&at<Date.parse(s.notAfter)?s:null;
}
const sameKey=(a,b)=>a&&b&&Object.keys(a).every(k=>a[k]===b[k]);
function descriptor(request,origin){
  if(!(request instanceof Request)||request.method!=='POST')return null;
  const url=new URL(request.url);
  if(url.origin!==origin||url.pathname!==PATH||url.username||url.password||url.search||url.hash||
    request.headers.get('Origin')!==origin||request.headers.get('X-RIO-Inspection')!=='1')return null;
  return Object.freeze({origin,path:PATH,method:'POST'});
}
function sessionSnapshot(s,tenantRef,proofIssuedAt){
  const keys=['format','state','assurance','tenantRef','subjectId','sessionRef','credentialId','ppReference',
    'deviceBindingSha256','subjectEpoch','sessionEpoch','revocationRevision','ppRegistryRevision','issuedAt','expiresAt','observedAt'];
  if(!exact(s,keys)||s.format!==RIO_ONE_SESSION_FORMAT_V295||s.state!=='ACTIVE'||s.assurance!=='SERVER_AUTHENTICATED'||
    s.tenantRef!==tenantRef||!id(s.subjectId)||!id(s.sessionRef)||typeof s.credentialId!=='string'||
    !/^[A-Za-z0-9_-]{16,1366}$/.test(s.credentialId)||typeof s.ppReference!=='string'||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/.test(s.ppReference)||typeof s.deviceBindingSha256!=='string'||
    !/^[a-f0-9]{64}$/.test(s.deviceBindingSha256)||
    !['subjectEpoch','sessionEpoch','revocationRevision','ppRegistryRevision'].every(k=>Number.isSafeInteger(s[k])&&s[k]>0)||
    !iso(s.issuedAt)||!iso(s.expiresAt)||s.observedAt!==proofIssuedAt||
    Date.parse(s.issuedAt)>Date.parse(proofIssuedAt)||Date.parse(s.expiresAt)<=Date.parse(proofIssuedAt))return null;
  return Object.freeze({...s});
}

export function createRioOneSignedSessionProviderV296({tenantRef,allowedOrigin,issuerKey,
  requestSignedSession,readIssuerKeyState,now}={}){
  if(!id(tenantRef)||[requestSignedSession,readIssuerKeyState,now].some(fn=>typeof fn!=='function')||
    !exact(issuerKey,['issuerId','keyId','publicKeyPem','spkiSha256'])||!id(issuerKey.issuerId)||!id(issuerKey.keyId)||
    typeof issuerKey.publicKeyPem!=='string'||issuerKey.publicKeyPem.length>8192||
    !issuerKey.publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----')||
    typeof issuerKey.spkiSha256!=='string'||!/^[a-f0-9]{64}$/.test(issuerKey.spkiSha256))
    throw TypeError('PINNED_ONE_SIGNER_AND_TRUSTED_SERVICES_REQUIRED');
  let origin,key;
  try{
    const u=new URL(allowedOrigin);
    if(u.protocol!=='https:'||u.origin!==allowedOrigin)throw Error('ORIGIN');
    origin=u.origin;key=createPublicKey(issuerKey.publicKeyPem);
    if(key.asymmetricKeyType!=='ed25519'||createHash('sha256').update(key.export({format:'der',type:'spki'})).digest('hex')!==issuerKey.spkiSha256)
      throw Error('KEY');
  }catch{throw TypeError('HTTPS_ORIGIN_AND_INDEPENDENT_ED25519_PIN_REQUIRED');}
  const pin=Object.freeze({...issuerKey});
  const lookup=Object.freeze({issuerId:pin.issuerId,keyId:pin.keyId});
  async function authenticateOneRequest(request){
    try{
      const binding=descriptor(request,origin);if(!binding)return null;
      const started=clock(now),before=keyState(await readIssuerKeyState(lookup),pin,clock(now));
      if(!before)return null;
      // New, server-only challenge for EVERY read, including a host recheck.
      // No cached signed response can authenticate another call or Request.
      const challenge=Object.freeze({format:'rio-one-session-challenge-v296-DRAFT',
        nonce:randomBytes(32).toString('base64url'),request:binding});
      const text=await requestSignedSession(request,challenge);
      if(typeof text!=='string'||Buffer.byteLength(text,'utf8')>MAX_BYTES)return null;
      const envelope=JSON.parse(text);
      if(!exact(envelope,['format','keyId','payload','signature'])||
        envelope.format!=='rio-one-session-envelope-v296-DRAFT'||envelope.keyId!==pin.keyId)return null;
      const payload=decode(envelope.payload,8192),signature=decode(envelope.signature,64);
      if(!payload||!signature||signature.length!==64||!verify(null,payload,key,signature))return null;
      // Reject invalid UTF-8 rather than replacing bytes before JSON parsing.
      const payloadText=new TextDecoder('utf-8',{fatal:true}).decode(payload);
      const message=JSON.parse(payloadText);
      if(JSON.stringify(message)!==payloadText)return null;
      if(!exact(message,['format','issuerId','audience','tenantRef','nonce','request','issuedAt','expiresAt','session'])||
        message.format!==RIO_ONE_SIGNED_SESSION_FORMAT_V296||message.issuerId!==pin.issuerId||
        message.audience!==RIO_ONE_SESSION_AUDIENCE_V296||message.tenantRef!==tenantRef||message.nonce!==challenge.nonce||
        !exact(message.request,['origin','path','method'])||Object.keys(binding).some(k=>message.request[k]!==binding[k])||
        !iso(message.issuedAt)||!iso(message.expiresAt))return null;
      const issued=Date.parse(message.issuedAt),expires=Date.parse(message.expiresAt);
      if(issued<started||expires<=issued||expires-issued>MAX_PROOF_LIFETIME_MS)return null;
      const session=sessionSnapshot(message.session,tenantRef,message.issuedAt);if(!session)return null;
      const after=keyState(await readIssuerKeyState(lookup),pin,clock(now)),finished=clock(now);
      if(!sameKey(before,after)||finished<started||issued>finished||finished>=expires||
        finished>=Date.parse(after.notAfter)||finished>=Date.parse(session.expiresAt)||
        finished-Date.parse(session.observedAt)>1000)return null;
      return session;
    }catch{return null;}
  }
  return Object.freeze({authenticateOneRequest,mode:'PINNED_SIGNED_ONE_SERVICE_MESSAGES_DRAFT',
    challengeBinding:'FRESH_SERVER_NONCE_PER_CALL',realOneGatewayConnected:false,
    sessionIssuance:false,productionReady:false,authorization:'NONE',acceptance:'HOLD'});
}
