/**
 * Same-key software-backend installation with bounded key/registry checks, DRAFT.
 * Installation observations are not ongoing readiness, user authentication or authority.
 */
import {createPublicKey,randomBytes,verify,webcrypto} from 'node:crypto';
import {createRioOneDrainableSoftwareSignerV300} from './rio-one-drainable-software-signer-v300.mjs';

function snapshot(value,keys){
  try{
    if(value===null||typeof value!=='object'||Array.isArray(value))return null;
    const descriptors=Object.getOwnPropertyDescriptors(value);
    if(Reflect.ownKeys(descriptors).length!==keys.length||keys.some(k=>
      !Object.hasOwn(descriptors,k)||!Object.hasOwn(descriptors[k],'value')||!descriptors[k].enumerable))return null;
    return Object.fromEntries(keys.map(k=>[k,descriptors[k].value]));
  }catch{return null;}
}
const generationMatches=(expected,current)=>Number.isSafeInteger(expected)&&expected>0&&expected===current;
const registryFields=['state','issuerId','keyId','revision','notBefore','notAfter'];
const iso=v=>typeof v==='string'&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString()===v;
function clock(now){
  const d=now();if(!(d instanceof Date)||!Number.isFinite(d.getTime()))throw Error('CLOCK_REQUIRED');return d.getTime();
}
function activeRegistry(s,pin,at){
  return s&&s.state==='ACTIVE'&&s.issuerId===pin.issuerId&&s.keyId===pin.keyId&&
    Number.isSafeInteger(s.revision)&&s.revision>0&&iso(s.notBefore)&&iso(s.notAfter)&&
    Date.parse(s.notBefore)<=at&&at<Date.parse(s.notAfter);
}
async function keyMatches(handle,publicKey,fixed){
  // This distinct domain is not a v296 session statement; no caller controls its bytes.
  try{
    const challenge=Buffer.from('RIO_ONE_SOFTWARE_KEY_CHECK_V303\0'+JSON.stringify({
      tenantRef:fixed.tenantRef,origin:fixed.allowedOrigin,issuerId:fixed.issuerKey.issuerId,
      keyId:fixed.issuerKey.keyId,nonce:randomBytes(32).toString('base64url'),
    }));
    const signature=Buffer.from(await webcrypto.subtle.sign('Ed25519',handle,challenge));
    return signature.length===64&&verify(null,challenge,publicKey,signature);
  }catch{return false;}
}
async function checkCandidate(handle,registry,publicKey,fixed,isClosed){
  try{
    if(isClosed())return null;
    const started=clock(fixed.now);let observed=started;
    const sample=()=>{
      const at=clock(fixed.now);
      if(at<observed||at-started>1000)throw Error('BOUNDED_MONOTONIC_INSTALLATION_REQUIRED');
      observed=at;return at;
    };
    const lookup=Object.freeze({issuerId:fixed.issuerKey.issuerId,keyId:fixed.issuerKey.keyId});
    if(isClosed())return null;
    // Copy data immediately after each lookup, before another trusted callback can mutate it.
    const before=snapshot(await registry(lookup),registryFields);
    if(!activeRegistry(before,fixed.issuerKey,sample())||isClosed())return null;
    Object.freeze(before);
    if(!activeRegistry(before,fixed.issuerKey,sample())||isClosed())return null;
    if(!await keyMatches(handle,publicKey,fixed)||isClosed())return null;
    if(!activeRegistry(before,fixed.issuerKey,sample())||isClosed())return null;
    const after=snapshot(await registry(lookup),registryFields);
    const finished=sample();
    if(!activeRegistry(after,fixed.issuerKey,finished)||isClosed()||
      registryFields.some(k=>before[k]!==after[k]))return null;
    return Object.freeze({revision:after.revision,verifiedAt:new Date(finished).toISOString()});
  }catch{return null;}
}

export async function createRioOneRegistryCheckedSignerHandoverV303(configuration){
  const required=['tenantRef','allowedOrigin','issuerKey','privateSigningKey','readIssuerKeyState','now'];
  const config=snapshot(configuration,required)??snapshot(configuration,[...required,'maxConcurrentSignatures']);
  const issuer=config&&snapshot(config.issuerKey,['issuerId','keyId','publicKeyPem','spkiSha256']);
  configuration=undefined;
  if(!config||!issuer)throw TypeError('EXPLICIT_TRUSTED_SIGNER_CONFIGURATION_REQUIRED');
  const fixed=Object.freeze({tenantRef:config.tenantRef,allowedOrigin:config.allowedOrigin,
    issuerKey:Object.freeze(issuer),now:config.now,
    maxConcurrentSignatures:config.maxConcurrentSignatures===undefined?1:config.maxConcurrentSignatures});
  let backend=createRioOneDrainableSoftwareSignerV300({...fixed,
    privateSigningKey:config.privateSigningKey,readIssuerKeyState:config.readIssuerKeyState});
  // The v300 constructor validates the independent SPKI pin before any proof is attempted.
  const publicKey=createPublicKey(fixed.issuerKey.publicKeyPem);
  let initialHandle=config.privateSigningKey,initialRegistry=config.readIssuerKeyState,assessment;
  config.privateSigningKey=undefined;config.readIssuerKeyState=undefined;
  try{
    assessment=await checkCandidate(initialHandle,initialRegistry,publicKey,fixed,()=>false);
    if(!assessment){
      await backend.stop();throw TypeError('PINNED_SOFTWARE_KEY_AND_REGISTRY_CHECK_FAILED');
    }
  }finally{initialHandle=undefined;initialRegistry=undefined;}
  let generation=1,closed=false,installing=false,resolveClosed;
  const closedCompletion=new Promise(resolve=>{resolveClosed=resolve;});
  function getStatus(){
    const s=backend.getStatus();
    return Object.freeze({format:'rio-one-registry-checked-handover-v303',generation,
      state:closed?'CLOSED':installing?'CHECKING_REPLACEMENT':s.state==='OPEN'?'SERVING':s.state==='DRAINING'?'RETIRING':'RETIRED',
      backendState:s.state,inFlight:s.inFlight,candidateChecksInFlight:installing?1:0,capacity:s.capacity,
      acceptingWork:!closed&&!installing&&s.acceptingWork,
      keyCorrespondence:'VERIFIED_AT_INSTALL',registryReadiness:'VERIFIED_AT_INSTALL',
      registryRevisionAtInstall:assessment.revision,installationCheckedAt:assessment.verifiedAt,
      acceptance:'HOLD',authorization:'NONE'});
  }
  function finishClose(){
    if(closed&&!installing&&backend.getStatus().state==='STOPPED')resolveClosed(getStatus());
  }
  async function signSessionStatement(statement){
    if(closed||installing)return null;
    return backend.signSessionStatement(statement);
  }
  function retireGeneration(command){
    const c=snapshot(command,['expectedGeneration']);
    if(!c||closed||installing||!generationMatches(c.expectedGeneration,generation))return null;
    return backend.stop();
  }
  async function installReplacement(command){
    if(closed||installing)return null;
    installing=true;let candidate,handle,registry;
    try{
      const c=snapshot(command,['expectedGeneration','privateSigningKey','readIssuerKeyState']);
      command=undefined;
      if(!c||closed||!generationMatches(c.expectedGeneration,generation)||generation===Number.MAX_SAFE_INTEGER||
        backend.getStatus().state!=='STOPPED')return null;
      candidate=createRioOneDrainableSoftwareSignerV300({...fixed,
        privateSigningKey:c.privateSigningKey,readIssuerKeyState:c.readIssuerKeyState});
      handle=c.privateSigningKey;registry=c.readIssuerKeyState;
      c.privateSigningKey=undefined;c.readIssuerKeyState=undefined;
      const checked=await checkCandidate(handle,registry,publicKey,fixed,()=>closed);
      handle=undefined;registry=undefined;
      if(!checked||closed)return null;
      const previousGeneration=generation;backend=candidate;candidate=undefined;assessment=checked;generation++;
      return Object.freeze({format:'rio-one-registry-checked-installation-v303',previousGeneration,generation,
        keyCorrespondence:'VERIFIED_AT_INSTALL',registryReadiness:'VERIFIED_AT_INSTALL',
        registryRevisionAtInstall:assessment.revision,installationCheckedAt:assessment.verifiedAt,
        acceptance:'HOLD',authorization:'NONE'});
    }catch{return null;}
    finally{
      handle=undefined;registry=undefined;
      if(candidate)await candidate.stop();
      installing=false;finishClose();
    }
  }
  function close(){
    closed=true;backend.stop().then(finishClose);finishClose();return closedCompletion;
  }
  return Object.freeze({signSessionStatement,retireGeneration,installReplacement,close,getStatus,
    keyRotation:'NOT_PROVIDED',hostKeyIsolation:'NOT_PROVIDED',hardwareProtection:'NOT_VERIFIED',
    sessionIssuance:false,productionReady:false,authorization:'NONE',acceptance:'HOLD'});
}
