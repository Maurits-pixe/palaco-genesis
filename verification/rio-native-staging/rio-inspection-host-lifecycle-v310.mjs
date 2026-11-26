/** Fetch host integration for v309. Trusted callbacks own transport and resources. */
import {RIO_RECEIPT_INSPECTION_PATH_V269 as PATH} from './rio-receipt-http-route-v269.mjs';
function data(value,keys,exact=true){
  try{
    if(value===null||typeof value!=='object'||Array.isArray(value))return null;
    const d=Object.getOwnPropertyDescriptors(value);
    if((exact&&Reflect.ownKeys(d).length!==keys.length)||keys.some(k=>!Object.hasOwn(d,k)||
      !Object.hasOwn(d[k],'value')||!d[k].enumerable))return null;
    return Object.fromEntries(keys.map(k=>[k,d[k].value]));
  }catch{return null;}
}
const boundaries=Object.freeze({acceptance:'HOLD',authorization:'NONE',productionReady:false});
function unavailable(status=503){
  return new Response(JSON.stringify({ok:false,code:status===400?'INVALID_REQUEST':'HOST_INSPECTION_NOT_AVAILABLE',...boundaries}),
    {status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'private, no-store, max-age=0',
      Pragma:'no-cache',Expires:'0','X-Content-Type-Options':'nosniff','Cross-Origin-Resource-Policy':'same-origin',
      'Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'"}});
}
function drained(value){
  const s=data(value,['format','state','inFlightInspections','readerCancellationsInFlight','inspectionCapacity',
    'signer','acceptance','authorization']);
  const key=s&&data(s.signer,['format','state','backendState','inFlight','candidateChecksInFlight',
    'acceptingWork','acceptance','authorization'],false);
  return Boolean(s&&key&&s.format==='rio-managed-inspection-service-status-v309'&&s.state==='CLOSED'&&
    s.inFlightInspections===0&&s.readerCancellationsInFlight===0&&
    Number.isSafeInteger(s.inspectionCapacity)&&s.inspectionCapacity>=1&&s.inspectionCapacity<=16&&
    key.format==='rio-one-history-bound-handover-v307'&&key.state==='CLOSED'&&key.backendState==='STOPPED'&&
    key.inFlight===0&&key.candidateChecksInFlight===0&&key.acceptingWork===false&&
    [s,key].every(v=>v.acceptance==='HOLD'&&v.authorization==='NONE'));
}
export function createRioInspectionHostLifecycleV310(configuration){
  const c=data(configuration,['service','stopHttpAdmission','releaseHostResources']);
  const s=c&&data(c.service,['format','inspection','control','realOneGatewayConnected','sessionIssuance',
    'productionReady','acceptance','authorization']);
  const inspection=s&&data(s.inspection,['handle','path','purpose','acceptance','authorization']);
  const control=s&&data(s.control,['getStatus','getLastAttemptResult','retireGeneration','installReplacement',
    'cancelReplacement','close','acceptance','authorization']);
  if(!c||!s||!inspection||!control||s.format!=='rio-managed-inspection-service-v309'||
    s.realOneGatewayConnected!==false||s.sessionIssuance!==false||s.productionReady!==false||
    inspection.path!==PATH||inspection.purpose!=='READ_ONLY_RECEIPT_INSPECTION_ROUTE'||
    [s,inspection,control].some(v=>v.acceptance!=='HOLD'||v.authorization!=='NONE')||
    [inspection.handle,control.getStatus,control.getLastAttemptResult,control.retireGeneration,
      control.installReplacement,control.cancelReplacement,control.close,c.stopHttpAdmission,
      c.releaseHostResources].some(fn=>typeof fn!=='function'))
    throw TypeError('EXACT_TRUSTED_MANAGED_SERVICE_AND_HOST_PORTS_REQUIRED');
  configuration=undefined;
  const handleInspection=inspection.handle,closeService=control.close;
  const stopAdmission=c.stopHttpAdmission,releaseResources=c.releaseHostResources;
  let state='RUNNING',httpAdmissionStop='NOT_STARTED',serviceDrain='NOT_STARTED',hostResourceRelease='NOT_STARTED';
  let resolveCompletion;
  const completion=new Promise(resolve=>{resolveCompletion=resolve;});
  function getStatus(){
    const issues=[];
    if(httpAdmissionStop==='NOT_CONFIRMED')issues.push('HTTP_ADMISSION_STOP_NOT_CONFIRMED');
    if(serviceDrain==='NOT_CONFIRMED')issues.push('SERVICE_DRAIN_NOT_CONFIRMED');
    if(hostResourceRelease==='NOT_CONFIRMED')issues.push('HOST_RESOURCE_RELEASE_NOT_CONFIRMED');
    return Object.freeze({format:'rio-inspection-host-lifecycle-status-v310',state,httpAdmissionStop,serviceDrain,
      hostResourceRelease,issues:Object.freeze(issues),...boundaries});
  }
  async function handle(request){
    if(state!=='RUNNING')return unavailable();
    if(!(request instanceof Request))return unavailable(400);
    try{
      // Preserve request identity, signal, body and the host's existing session binding.
      const result=await handleInspection(request);
      return result instanceof Response?result:unavailable();
    }catch{return unavailable();}
  }
  async function stopTransport(){
    httpAdmissionStop='PENDING';
    try{await stopAdmission();httpAdmissionStop='COMPLETED';}
    catch{httpAdmissionStop='NOT_CONFIRMED';}
  }
  async function stopService(){
    serviceDrain='PENDING';
    try{serviceDrain=drained(await closeService())?'COMPLETED':'NOT_CONFIRMED';}
    catch{serviceDrain='NOT_CONFIRMED';}
  }
  async function finish(stop,drain){
    await Promise.all([stop,drain]);
    if(httpAdmissionStop!=='COMPLETED'||serviceDrain!=='COMPLETED'){
      state='HELD';resolveCompletion(getStatus());return;
    }
    state='RELEASING_RESOURCES';hostResourceRelease='PENDING';
    try{await releaseResources();hostResourceRelease='COMPLETED';state='CLOSED';}
    catch{hostResourceRelease='NOT_CONFIRMED';state='HELD';}
    resolveCompletion(getStatus());
  }
  function close(){
    if(state==='RUNNING'){
      state='STOPPING';
      // Start transport shutdown first; do not await it before starting the service drain.
      const stop=stopTransport(),drain=stopService();void finish(stop,drain);
    }
    return completion;
  }
  return Object.freeze({format:'rio-inspection-host-lifecycle-v310',
    inspection:Object.freeze({handle,path:inspection.path,purpose:inspection.purpose,acceptance:'HOLD',authorization:'NONE'}),
    control:Object.freeze({getStatus,close,acceptance:'HOLD',authorization:'NONE'}),
    realOneGatewayConnected:false,sessionIssuance:false,...boundaries});
}
