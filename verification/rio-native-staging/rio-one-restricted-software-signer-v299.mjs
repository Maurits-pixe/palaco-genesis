/**
 * Local software signing backend, DRAFT. Not an HSM or a user authenticator.
 * The trusted host supplies an Ed25519 CryptoKey with extractable:false.
 * This WebCrypto flag does NOT isolate the key from a privileged Node host.
 * No key generation, file reads, persistence, enrollment or private-key export.
 */
import {createHash,createPublicKey,verify,webcrypto} from 'node:crypto';
import {types} from 'node:util';
import {RIO_ONE_SIGNED_SESSION_FORMAT_V296 as FORMAT,RIO_ONE_SESSION_AUDIENCE_V296 as AUDIENCE}
  from './rio-one-signed-session-provider-v296.mjs';
import {RIO_ONE_SESSION_FORMAT_V295} from './rio-palaco-one-session-reader-v295.mjs';
import {RIO_RECEIPT_INSPECTION_PATH_V269 as PATH} from './rio-receipt-http-route-v269.mjs';

const ID=/^[A-Za-z0-9_-]{1,128}$/;
const id=v=>typeof v==='string'&&ID.test(v);
const exact=(v,keys)=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&
  Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const iso=v=>typeof v==='string'&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString()===v;
function clock(now){const d=now();if(!(d instanceof Date)||!Number.isFinite(d.getTime()))throw Error('CLOCK_REQUIRED');return d.getTime();}
function keyState(value,pin,at){
  const fields=['state','issuerId','keyId','revision','notBefore','notAfter'];
  if(!exact(value,fields))return null;
  const s=Object.freeze(Object.fromEntries(fields.map(k=>[k,value[k]])));
  return s.state==='ACTIVE'&&s.issuerId===pin.issuerId&&s.keyId===pin.keyId&&
    Number.isSafeInteger(s.revision)&&s.revision>0&&iso(s.notBefore)&&iso(s.notAfter)&&
    Date.parse(s.notBefore)<=at&&at<Date.parse(s.notAfter)?s:null;
}
function fresh(message,at){return Date.parse(message.issuedAt)<=at&&at<Date.parse(message.expiresAt)&&at-Date.parse(message.issuedAt)<=1000;}
function payloadSnapshot(text,pin,tenantRef,origin,at){
  if(typeof text!=='string'||Buffer.byteLength(text,'utf8')>8192)return null;
  const m=JSON.parse(text);
  if(JSON.stringify(m)!==text||!exact(m,['format','issuerId','audience','tenantRef','nonce','request','issuedAt','expiresAt','session'])||
    m.format!==FORMAT||m.issuerId!==pin.issuerId||m.audience!==AUDIENCE||m.tenantRef!==tenantRef||
    typeof m.nonce!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(m.nonce)||
    Buffer.from(m.nonce,'base64url').length!==32||Buffer.from(m.nonce,'base64url').toString('base64url')!==m.nonce||
    !exact(m.request,['origin','path','method'])||m.request.origin!==origin||m.request.path!==PATH||m.request.method!=='POST'||
    !iso(m.issuedAt)||!iso(m.expiresAt)||Date.parse(m.expiresAt)<=Date.parse(m.issuedAt)||
    Date.parse(m.expiresAt)-Date.parse(m.issuedAt)>5000||!fresh(m,at))return null;
  const s=m.session;
  if(!exact(s,['format','state','assurance','tenantRef','subjectId','sessionRef','credentialId','ppReference',
    'deviceBindingSha256','subjectEpoch','sessionEpoch','revocationRevision','ppRegistryRevision','issuedAt','expiresAt','observedAt'])||
    s.format!==RIO_ONE_SESSION_FORMAT_V295||s.state!=='ACTIVE'||s.assurance!=='SERVER_AUTHENTICATED'||s.tenantRef!==tenantRef||
    !id(s.subjectId)||!id(s.sessionRef)||typeof s.credentialId!=='string'||!/^[A-Za-z0-9_-]{16,1366}$/.test(s.credentialId)||
    typeof s.ppReference!=='string'||!/^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/.test(s.ppReference)||
    typeof s.deviceBindingSha256!=='string'||!/^[a-f0-9]{64}$/.test(s.deviceBindingSha256)||
    !['subjectEpoch','sessionEpoch','revocationRevision','ppRegistryRevision'].every(k=>Number.isSafeInteger(s[k])&&s[k]>0)||
    !iso(s.issuedAt)||!iso(s.expiresAt)||s.observedAt!==m.issuedAt||Date.parse(s.issuedAt)>Date.parse(m.issuedAt)||
    Date.parse(m.expiresAt)>Date.parse(s.expiresAt))return null;
  return Object.freeze(m);
}

export function createRioOneRestrictedSoftwareSignerV299({tenantRef,allowedOrigin,issuerKey,privateSigningKey,
  readIssuerKeyState,now,maxConcurrentSignatures=1}={}){
  if(!id(tenantRef)||[readIssuerKeyState,now].some(f=>typeof f!=='function')||
    !Number.isSafeInteger(maxConcurrentSignatures)||maxConcurrentSignatures<1||maxConcurrentSignatures>16||
    !types.isCryptoKey(privateSigningKey)||privateSigningKey.type!=='private'||privateSigningKey.extractable!==false||
    privateSigningKey.algorithm.name!=='Ed25519'||privateSigningKey.usages.length!==1||privateSigningKey.usages[0]!=='sign'||
    !exact(issuerKey,['issuerId','keyId','publicKeyPem','spkiSha256'])||!id(issuerKey.issuerId)||!id(issuerKey.keyId)||
    typeof issuerKey.publicKeyPem!=='string'||issuerKey.publicKeyPem.length>8192||
    !/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\r?\n?$/.test(issuerKey.publicKeyPem)||
    typeof issuerKey.spkiSha256!=='string'||!/^[a-f0-9]{64}$/.test(issuerKey.spkiSha256))
    throw TypeError('RESTRICTED_SOFTWARE_SIGNING_HANDLE_AND_TRUSTED_CONFIGURATION_REQUIRED');
  let origin,publicKey;
  try{
    const u=new URL(allowedOrigin);if(u.protocol!=='https:'||u.origin!==allowedOrigin)throw Error('ORIGIN');origin=u.origin;
    publicKey=createPublicKey(issuerKey.publicKeyPem);
    if(publicKey.asymmetricKeyType!=='ed25519'||createHash('sha256').update(publicKey.export({format:'der',type:'spki'})).digest('hex')!==issuerKey.spkiSha256)throw Error('PIN');
  }catch{throw TypeError('INDEPENDENT_PUBLIC_PIN_AND_HTTPS_ORIGIN_REQUIRED');}
  const pin=Object.freeze({...issuerKey}),lookup=Object.freeze({issuerId:pin.issuerId,keyId:pin.keyId});
  let active=0;
  async function signSessionStatement(input){
    if(active>=maxConcurrentSignatures)return null;
    let payload,message,started;
    try{
      if(!exact(input,['purpose','issuerId','keyId','payload'])||input.purpose!==AUDIENCE||
        input.issuerId!==pin.issuerId||input.keyId!==pin.keyId)return null;
      payload=input.payload;started=clock(now);message=payloadSnapshot(payload,pin,tenantRef,origin,started);if(!message)return null;
    }catch{return null;}
    active++;
    try{
      const before=keyState(await readIssuerKeyState(lookup),pin,clock(now));
      if(!before||Date.parse(message.issuedAt)<Date.parse(before.notBefore)||Date.parse(message.expiresAt)>Date.parse(before.notAfter))return null;
      const ready=clock(now);if(ready<started||!fresh(message,ready))return null;
      const signature=Buffer.from(await webcrypto.subtle.sign('Ed25519',privateSigningKey,Buffer.from(payload)));
      if(signature.length!==64||!verify(null,Buffer.from(payload),publicKey,signature))return null;
      const after=keyState(await readIssuerKeyState(lookup),pin,clock(now)),finished=clock(now);
      if(!after||Object.keys(before).some(k=>before[k]!==after[k])||finished<started||!fresh(message,finished)||
        finished>=Date.parse(after.notAfter))return null;
      return signature.toString('base64url');
    }catch{return null;}
    finally{active--;}
  }
  return Object.freeze({signSessionStatement,keyStorage:'WEBCRYPTO_HANDLE_SOFTWARE_ONLY',webCryptoExtractable:false,
    hostKeyIsolation:'NOT_PROVIDED',hardwareProtection:'NOT_VERIFIED',keyEnrollment:'NOT_PROVIDED',sessionIssuance:false,
    productionReady:false,authorization:'NONE',acceptance:'HOLD'});
}
