/**
 * Explicit same-key software-backend handover, DRAFT; trusted host configuration only.
 * Owns its v300 instances. No key rotation, user authentication or hardware custody.
 */
import {createRioOneDrainableSoftwareSignerV300} from './rio-one-drainable-software-signer-v300.mjs';

// Configuration commands accept only own data properties; getters are not invoked.
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

export function createRioOneSignerHandoverV301(configuration){
  const required=['tenantRef','allowedOrigin','issuerKey','privateSigningKey','readIssuerKeyState','now'];
  const config=snapshot(configuration,required)??snapshot(configuration,[...required,'maxConcurrentSignatures']);
  const issuer=config&&snapshot(config.issuerKey,['issuerId','keyId','publicKeyPem','spkiSha256']);
  if(!config||!issuer)throw TypeError('EXPLICIT_TRUSTED_SIGNER_CONFIGURATION_REQUIRED');
  const fixed=Object.freeze({tenantRef:config.tenantRef,allowedOrigin:config.allowedOrigin,
    issuerKey:Object.freeze(issuer),now:config.now,
    maxConcurrentSignatures:config.maxConcurrentSignatures===undefined?1:config.maxConcurrentSignatures});
  let backend=createRioOneDrainableSoftwareSignerV300({...fixed,
    privateSigningKey:config.privateSigningKey,readIssuerKeyState:config.readIssuerKeyState});
  // Do not retain an extra copy of host key/service references in this controller.
  config.privateSigningKey=undefined;config.readIssuerKeyState=undefined;configuration=undefined;
  let generation=1,closed=false,installing=false;
  function getStatus(){
    const s=backend.getStatus();
    return Object.freeze({format:'rio-one-signer-handover-v301',generation,
      state:closed?'CLOSED':s.state==='OPEN'?'SERVING':s.state==='DRAINING'?'RETIRING':'RETIRED',
      backendState:s.state,inFlight:s.inFlight,capacity:s.capacity,acceptingWork:!closed&&s.acceptingWork,
      acceptance:'HOLD',authorization:'NONE'});
  }
  async function signSessionStatement(statement){
    if(closed)return null;
    return backend.signSessionStatement(statement);
  }
  function retireGeneration(command){
    const c=snapshot(command,['expectedGeneration']);
    if(!c||closed||installing||!generationMatches(c.expectedGeneration,generation))return null;
    return backend.stop();
  }
  function installReplacement(command){
    if(closed||installing)return null;
    // Covers even reentrant Proxy descriptor traps on trusted configuration objects.
    installing=true;
    try{
      const c=snapshot(command,['expectedGeneration','privateSigningKey','readIssuerKeyState']);
      if(!c||closed||!generationMatches(c.expectedGeneration,generation)||generation===Number.MAX_SAFE_INTEGER||
        backend.getStatus().state!=='STOPPED')return null;
      const next=createRioOneDrainableSoftwareSignerV300({...fixed,
        privateSigningKey:c.privateSigningKey,readIssuerKeyState:c.readIssuerKeyState});
      const previousGeneration=generation;backend=next;generation++;
      return Object.freeze({format:'rio-one-signer-installation-v301',previousGeneration,generation,
        readiness:'NOT_CHECKED',acceptance:'HOLD',authorization:'NONE'});
    }catch{return null;}
    finally{installing=false;}
  }
  function close(){closed=true;return backend.stop();}
  return Object.freeze({signSessionStatement,retireGeneration,installReplacement,close,getStatus,
    keyRotation:'NOT_PROVIDED',hostKeyIsolation:'NOT_PROVIDED',hardwareProtection:'NOT_VERIFIED',
    sessionIssuance:false,productionReady:false,authorization:'NONE',acceptance:'HOLD'});
}
