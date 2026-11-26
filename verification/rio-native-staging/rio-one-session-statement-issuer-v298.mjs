/**
 * Trusted-server statement producer, DRAFT. No IdP, listener or session issuance.
 * readAuthenticatedOneSession must authenticate an EXISTING session independently.
 * Signing is delegated; private keys are never accepted by this module.
 */
import {createHash,createPublicKey,verify} from 'node:crypto';
import {RIO_ONE_SESSION_FORMAT_V295} from './rio-palaco-one-session-reader-v295.mjs';
import {RIO_ONE_SIGNED_SESSION_FORMAT_V296 as FORMAT,RIO_ONE_SESSION_AUDIENCE_V296 as AUDIENCE}
  from './rio-one-signed-session-provider-v296.mjs';
import {RIO_RECEIPT_INSPECTION_PATH_V269 as PATH} from './rio-receipt-http-route-v269.mjs';

const ID=/^[A-Za-z0-9_-]{1,128}$/;
const exact=(v,keys)=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&
  Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const id=v=>typeof v==='string'&&ID.test(v);
const iso=v=>typeof v==='string'&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString()===v;
function clock(now){const d=now();if(!(d instanceof Date)||!Number.isFinite(d.getTime()))throw Error('CLOCK_REQUIRED');return d.getTime();}
function currentKey(value,pin,at){
  const keys=['state','issuerId','keyId','revision','notBefore','notAfter'];
  if(!exact(value,keys))return null;
  const s=Object.freeze(Object.fromEntries(keys.map(k=>[k,value[k]])));
  return s.state==='ACTIVE'&&s.issuerId===pin.issuerId&&s.keyId===pin.keyId&&
    Number.isSafeInteger(s.revision)&&s.revision>0&&iso(s.notBefore)&&iso(s.notAfter)&&
    Date.parse(s.notBefore)<=at&&at<Date.parse(s.notAfter)?s:null;
}
const SESSION_KEYS=['format','state','assurance','tenantRef','subjectId','sessionRef','credentialId','ppReference',
  'deviceBindingSha256','subjectEpoch','sessionEpoch','revocationRevision','ppRegistryRevision','issuedAt','expiresAt','observedAt'];
function session(value,tenantRef,at){
  if(!exact(value,SESSION_KEYS))return null;
  const s=Object.freeze(Object.fromEntries(SESSION_KEYS.map(k=>[k,value[k]])));
  if(s.format!==RIO_ONE_SESSION_FORMAT_V295||s.state!=='ACTIVE'||s.assurance!=='SERVER_AUTHENTICATED'||
    s.tenantRef!==tenantRef||!id(s.subjectId)||!id(s.sessionRef)||typeof s.credentialId!=='string'||
    !/^[A-Za-z0-9_-]{16,1366}$/.test(s.credentialId)||typeof s.ppReference!=='string'||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/.test(s.ppReference)||typeof s.deviceBindingSha256!=='string'||
    !/^[a-f0-9]{64}$/.test(s.deviceBindingSha256)||
    !['subjectEpoch','sessionEpoch','revocationRevision','ppRegistryRevision'].every(k=>Number.isSafeInteger(s[k])&&s[k]>0)||
    !iso(s.issuedAt)||!iso(s.expiresAt)||!iso(s.observedAt)||Date.parse(s.issuedAt)>Date.parse(s.observedAt)||
    Date.parse(s.observedAt)>at||at-Date.parse(s.observedAt)>1000||at>=Date.parse(s.expiresAt))return null;
  return s;
}
const same=(a,b,keys)=>a&&b&&keys.every(k=>a[k]===b[k]);
function challengeSnapshot(request,value,origin){
  if(!(request instanceof Request)||!exact(value,['format','nonce','request'])||
    value.format!=='rio-one-session-challenge-v296-DRAFT'||typeof value.nonce!=='string'||
    !/^[A-Za-z0-9_-]{43}$/.test(value.nonce)||Buffer.from(value.nonce,'base64url').length!==32||
    Buffer.from(value.nonce,'base64url').toString('base64url')!==value.nonce||
    !exact(value.request,['origin','path','method']))return null;
  const u=new URL(request.url);
  const binding=Object.freeze({origin:value.request.origin,path:value.request.path,method:value.request.method});
  if(request.method!=='POST'||u.origin!==origin||u.pathname!==PATH||u.search||u.hash||u.username||u.password||
    request.headers.get('Origin')!==origin||request.headers.get('X-RIO-Inspection')!=='1'||
    binding.origin!==origin||binding.path!==PATH||binding.method!=='POST')return null;
  return Object.freeze({nonce:value.nonce,request:binding});
}

export function createRioOneSessionStatementIssuerV298({tenantRef,allowedOrigin,issuerKey,
  readAuthenticatedOneSession,readIssuerKeyState,signSessionStatement,now}={}){
  if(!id(tenantRef)||[readAuthenticatedOneSession,readIssuerKeyState,signSessionStatement,now].some(fn=>typeof fn!=='function')||
    !exact(issuerKey,['issuerId','keyId','publicKeyPem','spkiSha256'])||!id(issuerKey.issuerId)||!id(issuerKey.keyId)||
    typeof issuerKey.publicKeyPem!=='string'||issuerKey.publicKeyPem.length>8192||
    !/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\r?\n?$/.test(issuerKey.publicKeyPem)||typeof issuerKey.spkiSha256!=='string'||
    !/^[a-f0-9]{64}$/.test(issuerKey.spkiSha256))throw TypeError('TRUSTED_ONE_ISSUER_DEPENDENCIES_REQUIRED');
  let origin,key;
  try{
    const u=new URL(allowedOrigin);if(u.protocol!=='https:'||u.origin!==allowedOrigin)throw Error('ORIGIN');origin=u.origin;
    key=createPublicKey(issuerKey.publicKeyPem);
    if(key.asymmetricKeyType!=='ed25519'||createHash('sha256').update(key.export({format:'der',type:'spki'})).digest('hex')!==issuerKey.spkiSha256)throw Error('PIN');
  }catch{throw TypeError('INDEPENDENT_ED25519_PIN_AND_HTTPS_ORIGIN_REQUIRED');}
  const pin=Object.freeze({...issuerKey}),lookup=Object.freeze({issuerId:pin.issuerId,keyId:pin.keyId});
  async function requestSignedSession(request,input){
    try{
      const c=challengeSnapshot(request,input,origin);if(!c)return null;
      const started=clock(now),before=currentKey(await readIssuerKeyState(lookup),pin,clock(now));if(!before)return null;
      const first=session(await readAuthenticatedOneSession(request),tenantRef,clock(now));
      // Preserve the source's observation timestamp; never relabel cached facts as fresh.
      if(!first||Date.parse(first.observedAt)<started)return null;
      const issuedAt=first.observedAt,expiresAt=new Date(Math.min(Date.parse(issuedAt)+5000,
        Date.parse(first.expiresAt),Date.parse(before.notAfter))).toISOString();
      if(Date.parse(expiresAt)<=clock(now))return null;
      const payload=JSON.stringify({format:FORMAT,issuerId:pin.issuerId,audience:AUDIENCE,tenantRef,
        nonce:c.nonce,request:c.request,issuedAt,expiresAt,session:first});
      if(Buffer.byteLength(payload,'utf8')>8192)return null;
      const signature=await signSessionStatement(Object.freeze({purpose:AUDIENCE,issuerId:pin.issuerId,keyId:pin.keyId,payload}));
      if(typeof signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(signature))return null;
      const bytes=Buffer.from(signature,'base64url');
      if(bytes.length!==64||bytes.toString('base64url')!==signature||!verify(null,Buffer.from(payload),key,bytes))return null;
      const afterSession=session(await readAuthenticatedOneSession(request),tenantRef,clock(now));
      const afterKey=currentKey(await readIssuerKeyState(lookup),pin,clock(now)),finished=clock(now);
      if(!same(first,afterSession,SESSION_KEYS.filter(k=>k!=='observedAt'))||!same(before,afterKey,Object.keys(before))||
        finished<started||finished>=Date.parse(expiresAt)||finished-Date.parse(first.observedAt)>1000||
        finished>=Date.parse(afterSession.expiresAt)||finished>=Date.parse(afterKey.notAfter))return null;
      const envelope=JSON.stringify({format:'rio-one-session-envelope-v296-DRAFT',keyId:pin.keyId,
        payload:Buffer.from(payload).toString('base64url'),signature});
      return Buffer.byteLength(envelope,'utf8')<=16384?envelope:null;
    }catch{return null;}
  }
  return Object.freeze({requestSignedSession,mode:'EXISTING_ONE_SESSION_STATEMENTS_DRAFT',
    existingAuthenticationRequired:true,sessionIssuance:false,realIdpVerified:false,
    productionReady:false,authorization:'NONE',acceptance:'HOLD'});
}
