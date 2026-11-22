/**
 * Same-key software-backend handover with a local key-correspondence proof, DRAFT.
 * Proof is not registry readiness, user authentication, key custody or authority.
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
async function keyMatches(handle,publicKey,fixed){
  // This distinct domain is not a v296 session statement; no caller controls its bytes.
  try{
    const challenge=Buffer.from('RIO_ONE_SOFTWARE_KEY_CHECK_V302\0'+JSON.stringify({
      tenantRef:fixed.tenantRef,origin:fixed.allowedOrigin,issuerId:fixed.issuerKey.issuerId,
      keyId:fixed.issuerKey.keyId,nonce:randomBytes(32).toString('base64url'),
    }));
    const signature=Buffer.from(await webcrypto.subtle.sign('Ed25519',handle,challenge));
    return signature.length===64&&verify(null,challenge,publicKey,signature);
  }catch{return false;}
}

export async function createRioOneKeyCheckedSignerHandoverV302(configuration){
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
  let initialHandle=config.privateSigningKey;
  config.privateSigningKey=undefined;config.readIssuerKeyState=undefined;
  try{
    if(!await keyMatches(initialHandle,publicKey,fixed)){
      await backend.stop();throw TypeError('PINNED_SOFTWARE_SIGNING_KEY_CHECK_FAILED');
    }
  }finally{initialHandle=undefined;}
  let generation=1,closed=false,installing=false,resolveClosed;
  const closedCompletion=new Promise(resolve=>{resolveClosed=resolve;});
  function getStatus(){
    const s=backend.getStatus();
    return Object.freeze({format:'rio-one-key-checked-handover-v302',generation,
      state:closed?'CLOSED':installing?'CHECKING_REPLACEMENT':s.state==='OPEN'?'SERVING':s.state==='DRAINING'?'RETIRING':'RETIRED',
      backendState:s.state,inFlight:s.inFlight,keyChecksInFlight:installing?1:0,capacity:s.capacity,
      acceptingWork:!closed&&!installing&&s.acceptingWork,
      keyCorrespondence:'VERIFIED_AT_INSTALL',registryReadiness:'NOT_CHECKED',
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
    installing=true;let candidate,handle;
    try{
      const c=snapshot(command,['expectedGeneration','privateSigningKey','readIssuerKeyState']);
      command=undefined;
      if(!c||closed||!generationMatches(c.expectedGeneration,generation)||generation===Number.MAX_SAFE_INTEGER||
        backend.getStatus().state!=='STOPPED')return null;
      candidate=createRioOneDrainableSoftwareSignerV300({...fixed,
        privateSigningKey:c.privateSigningKey,readIssuerKeyState:c.readIssuerKeyState});
      handle=c.privateSigningKey;c.privateSigningKey=undefined;c.readIssuerKeyState=undefined;
      const matched=await keyMatches(handle,publicKey,fixed);handle=undefined;
      if(!matched||closed)return null;
      const previousGeneration=generation;backend=candidate;candidate=undefined;generation++;
      return Object.freeze({format:'rio-one-key-checked-installation-v302',previousGeneration,generation,
        keyCorrespondence:'VERIFIED_AT_INSTALL',registryReadiness:'NOT_CHECKED',
        acceptance:'HOLD',authorization:'NONE'});
    }catch{return null;}
    finally{
      handle=undefined;
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
