/**
 * Same-key software-backend handover with one completed-attempt record, DRAFT.
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
async function checkCandidate(handle,registry,publicKey,fixed,isStopped){
  try{
    if(isStopped())return null;
    const started=clock(fixed.now);let observed=started;
    const sample=()=>{
      const at=clock(fixed.now);
      if(at<observed||at-started>1000)throw Error('BOUNDED_MONOTONIC_INSTALLATION_REQUIRED');
      observed=at;return at;
    };
    const lookup=Object.freeze({issuerId:fixed.issuerKey.issuerId,keyId:fixed.issuerKey.keyId});
    if(isStopped())return null;
    // Copy data immediately after each lookup, before another trusted callback can mutate it.
    const before=snapshot(await registry(lookup),registryFields);
    if(!activeRegistry(before,fixed.issuerKey,sample())||isStopped())return null;
    Object.freeze(before);
    if(!activeRegistry(before,fixed.issuerKey,sample())||isStopped())return null;
    if(!await keyMatches(handle,publicKey,fixed)||isStopped())return null;
    if(!activeRegistry(before,fixed.issuerKey,sample())||isStopped())return null;
    const after=snapshot(await registry(lookup),registryFields);
    const finished=sample();
    if(!activeRegistry(after,fixed.issuerKey,finished)||isStopped()||
      registryFields.some(k=>before[k]!==after[k]))return null;
    return Object.freeze({revision:after.revision,verifiedAt:new Date(finished).toISOString()});
  }catch{return null;}
}

export async function createRioOneReportingSignerHandoverV305(configuration){
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
  let generation=1,closed=false,installing=false,resolveClosed,attemptSequence=0,pendingAttempt,lastAttemptResult;
  const closedCompletion=new Promise(resolve=>{resolveClosed=resolve;});
  function getStatus(){
    const s=backend.getStatus();
    return Object.freeze({format:'rio-one-reporting-handover-v305',generation,
      state:closed?'CLOSED':pendingAttempt?.cancelled?'CANCELLING_REPLACEMENT':installing?'CHECKING_REPLACEMENT':s.state==='OPEN'?'SERVING':s.state==='DRAINING'?'RETIRING':'RETIRED',
      backendState:s.state,inFlight:s.inFlight,candidateChecksInFlight:installing?1:0,capacity:s.capacity,
      candidateAttemptId:pendingAttempt?.id??null,cancellationRequested:pendingAttempt?.cancelled??false,
      lastCompletedAttemptId:lastAttemptResult?.attemptId??null,
      acceptingWork:!closed&&!installing&&s.acceptingWork,
      keyCorrespondence:'VERIFIED_AT_INSTALL',registryReadiness:'VERIFIED_AT_INSTALL',
      registryRevisionAtInstall:assessment.revision,installationCheckedAt:assessment.verifiedAt,
      acceptance:'HOLD',authorization:'NONE'});
  }
  function finishClose(){
    if(closed&&!installing&&backend.getStatus().state==='STOPPED')resolveClosed(getStatus());
  }
  function getLastAttemptResult(){return lastAttemptResult??null;}
  async function signSessionStatement(statement){
    if(closed||installing)return null;
    return backend.signSessionStatement(statement);
  }
  function retireGeneration(command){
    const c=snapshot(command,['expectedGeneration']);
    if(!c||closed||installing||!generationMatches(c.expectedGeneration,generation))return null;
    return backend.stop();
  }
  function cancelReplacement(command){
    const c=snapshot(command,['expectedGeneration','attemptId']),a=pendingAttempt;
    if(!c||closed||!installing||!a||!generationMatches(c.expectedGeneration,generation)||
      a.generation!==c.expectedGeneration||!Number.isSafeInteger(c.attemptId)||c.attemptId!==a.id)return null;
    if(!a.cancelled){
      a.cancelled=true;
      a.receipt=Object.freeze({format:'rio-one-replacement-cancellation-v304',generation,attemptId:a.id,
        state:'CANCELLATION_REQUESTED',acceptance:'HOLD',authorization:'NONE'});
    }
    return a.receipt;
  }
  async function installReplacement(command){
    if(closed||installing)return null;
    installing=true;let candidate,handle,registry,attempt,installed=false;
    try{
      const c=snapshot(command,['expectedGeneration','privateSigningKey','readIssuerKeyState']);
      command=undefined;
      if(!c||closed||!generationMatches(c.expectedGeneration,generation)||generation===Number.MAX_SAFE_INTEGER||
        attemptSequence===Number.MAX_SAFE_INTEGER||
        backend.getStatus().state!=='STOPPED')return null;
      candidate=createRioOneDrainableSoftwareSignerV300({...fixed,
        privateSigningKey:c.privateSigningKey,readIssuerKeyState:c.readIssuerKeyState});
      attempt={id:++attemptSequence,generation,cancelled:false};pendingAttempt=attempt;
      handle=c.privateSigningKey;registry=c.readIssuerKeyState;
      c.privateSigningKey=undefined;c.readIssuerKeyState=undefined;
      const checked=await checkCandidate(handle,registry,publicKey,fixed,()=>closed||attempt.cancelled);
      handle=undefined;registry=undefined;
      if(!checked||closed||attempt.cancelled)return null;
      const previousGeneration=generation;backend=candidate;candidate=undefined;assessment=checked;generation++;
      installed=true;
      return Object.freeze({format:'rio-one-reporting-installation-v305',previousGeneration,generation,attemptId:attempt.id,
        keyCorrespondence:'VERIFIED_AT_INSTALL',registryReadiness:'VERIFIED_AT_INSTALL',
        registryRevisionAtInstall:assessment.revision,installationCheckedAt:assessment.verifiedAt,
        acceptance:'HOLD',authorization:'NONE'});
    }catch{return null;}
    finally{
      handle=undefined;registry=undefined;
      if(candidate)await candidate.stop();
      if(pendingAttempt===attempt)pendingAttempt=undefined;
      installing=false;
      if(attempt)lastAttemptResult=Object.freeze({format:'rio-one-completed-replacement-v305',
        attemptId:attempt.id,expectedGeneration:attempt.generation,resultingGeneration:generation,
        completion:'COMPLETED',outcome:installed?'INSTALLED':closed?'WITHHELD_AFTER_CLOSE':
          attempt.cancelled?'WITHHELD_AFTER_CANCELLATION':'CHECK_FAILED',
        cancellationRequested:attempt.cancelled,acceptance:'HOLD',authorization:'NONE'});
      finishClose();
    }
  }
  function close(){
    closed=true;backend.stop().then(finishClose);finishClose();return closedCompletion;
  }
  return Object.freeze({signSessionStatement,retireGeneration,installReplacement,cancelReplacement,close,getStatus,getLastAttemptResult,
    keyRotation:'NOT_PROVIDED',hostKeyIsolation:'NOT_PROVIDED',hardwareProtection:'NOT_VERIFIED',
    sessionIssuance:false,productionReady:false,authorization:'NONE',acceptance:'HOLD'});
}
