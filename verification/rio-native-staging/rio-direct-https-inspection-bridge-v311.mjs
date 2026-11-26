/** Direct Node HTTPS/1 transport for the existing Fetch inspection port. DRAFT. */
import {IncomingMessage,ServerResponse} from 'node:http';
import {Readable} from 'node:stream';
import {RIO_RECEIPT_INSPECTION_PATH_V269 as PATH} from './rio-receipt-http-route-v269.mjs';
const B=Object.freeze({acceptance:'HOLD',authorization:'NONE',productionReady:false});
const HEADERS=Object.freeze({'Content-Type':'application/json; charset=utf-8',
 'Cache-Control':'private, no-store, max-age=0',Pragma:'no-cache',Expires:'0',
 'X-Content-Type-Options':'nosniff','Cross-Origin-Resource-Policy':'same-origin',
 'Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'",Connection:'close'});
function snapshot(v,keys){
 try{if(v===null||typeof v!=='object'||Array.isArray(v))return null;
 const d=Object.getOwnPropertyDescriptors(v);
 if(Reflect.ownKeys(d).length!==keys.length||keys.some(k=>!d[k]||!Object.hasOwn(d[k],'value')||!d[k].enumerable))return null;
 return Object.fromEntries(keys.map(k=>[k,d[k].value]));}catch{return null;}
}
function requestHeaders(raw){
 if(!Array.isArray(raw)||raw.length<2||raw.length>128||raw.length%2)return null;
 const h=Object.create(null);let bytes=0;
 for(let i=0;i<raw.length;i+=2){
  const name=raw[i],value=raw[i+1];
  if(typeof name!=='string'||typeof value!=='string'||!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)||/[\r\n\0]/.test(value))return null;
  const key=name.toLowerCase();bytes+=Buffer.byteLength(name)+Buffer.byteLength(value);
  if(bytes>16384||Object.hasOwn(h,key)||key==='forwarded'||key.startsWith('x-forwarded-'))return null;
  h[key]=value;
 }
 return Object.freeze(h);
}
const failure=(code='TRANSPORT_INSPECTION_NOT_AVAILABLE')=>Buffer.from(JSON.stringify({ok:false,code,...B}));
export function createRioDirectHttpsInspectionBridgeV311(configuration){
 const c=snapshot(configuration,['allowedOrigin','inspection','maxConcurrentRequests']);
 const port=c&&snapshot(c.inspection,['handle','path','purpose','acceptance','authorization']);
 let origin;try{origin=new URL(c?.allowedOrigin);}catch{}
 if(!c||!port||typeof port.handle!=='function'||port.path!==PATH||port.purpose!=='READ_ONLY_RECEIPT_INSPECTION_ROUTE'||
 port.acceptance!=='HOLD'||port.authorization!=='NONE'||typeof c.allowedOrigin!=='string'||!origin||
 origin.protocol!=='https:'||origin.origin!==c.allowedOrigin||origin.username||origin.password||
 !Number.isSafeInteger(c.maxConcurrentRequests)||c.maxConcurrentRequests<1||c.maxConcurrentRequests>16)
 throw TypeError('EXACT_DIRECT_HTTPS_INSPECTION_CONFIGURATION_REQUIRED');
 const fixedOrigin=c.allowedOrigin,host=origin.host,capacity=c.maxConcurrentRequests,inspect=port.handle;
 configuration=undefined;
 const contexts=new WeakMap();let state='OPEN',active=0,resolveClosed;
 const closed=new Promise(resolve=>{resolveClosed=resolve;});
 function getStatus(){return Object.freeze({format:'rio-direct-https-bridge-status-v311',state,inFlightTransport:active,capacity,...B});}
 function complete(){if(state==='DRAINING'&&active===0){state='CLOSED';resolveClosed(getStatus());}}
 function close(){if(state==='OPEN'){state='DRAINING';complete();}return closed;}
 function readRequestContext(request){return request instanceof Request?contexts.get(request)??null:null;}
 async function handleIncoming(incoming,outgoing){
  if(!(incoming instanceof IncomingMessage)||!(outgoing instanceof ServerResponse)||outgoing.req!==incoming)return false;
  // Native Node request/response objects and the host process are trusted prerequisites.
  if(state!=='OPEN'||active>=capacity){
   if(!outgoing.destroyed&&!outgoing.headersSent){const body=failure();outgoing.writeHead(503,{...HEADERS,'Content-Length':body.length});outgoing.end(body);}
   return false;
  }
  active++;
  const abort=new AbortController();let finished=false,resolveWriter;
  const writer=new Promise(resolve=>{resolveWriter=resolve;});
  const onFinish=()=>{finished=true;resolveWriter();};
  const onClose=()=>{if(!outgoing.writableFinished)abort.abort();resolveWriter();};
  const onRequestClose=()=>{if(!incoming.complete)abort.abort();};
  const onError=()=>{abort.abort();resolveWriter();};
  outgoing.once('finish',onFinish);outgoing.once('close',onClose);outgoing.once('error',onError);
  incoming.once('close',onRequestClose);incoming.once('error',onError);
  async function write(status,bytes,allow){
   if(outgoing.destroyed)return;
   outgoing.writeHead(status,{...HEADERS,'Content-Length':bytes.length,...(allow?{Allow:allow}:{})});
   outgoing.end(bytes);await writer;
  }
  try{
   const h=requestHeaders(incoming.rawHeaders);
   if(incoming.httpVersionMajor!==1||incoming.socket?.encrypted!==true||incoming.socket.getProtocol?.()!=='TLSv1.3'){
    await write(403,failure('DIRECT_TLS13_REQUIRED'));return false;
   }
   if(!h||h.host?.toLowerCase()!==host){await write(400,failure('UNAMBIGUOUS_DIRECT_HOST_REQUIRED'));return false;}
   if(incoming.url!==PATH){await write(404,failure('ROUTE_NOT_FOUND'));return false;}
   if(incoming.method!=='POST'){await write(405,failure('POST_REQUIRED'),'POST');return false;}
   if(h.origin!==fixedOrigin||h['x-rio-inspection']!=='1'||
    (h['sec-fetch-site']!==undefined&&h['sec-fetch-site']!=='same-origin')){
    await write(403,failure('ORIGIN_CHECK_FAILED'));return false;
   }
   if(!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(h['content-type']??'')||h['content-encoding']!==undefined){
    await write(415,failure('JSON_UTF8_REQUIRED'));return false;
   }
   if(h['content-length']!==undefined&&(!/^(0|[1-9][0-9]*)$/.test(h['content-length'])||Number(h['content-length'])>32768)){
    await write(413,failure('BODY_LIMIT_EXCEEDED'));return false;
   }
   if(Readable.isDisturbed(incoming)||incoming.readableEncoding||incoming.readableEnded){
    await write(400,failure('UNREAD_BODY_REQUIRED'));return false;
   }
   const request=new Request(fixedOrigin+PATH,{method:'POST',headers:h,signal:abort.signal,
    body:Readable.toWeb(incoming,{strategy:{highWaterMark:16384,size:chunk=>chunk.byteLength}}),duplex:'half'});
   contexts.set(request,Object.freeze({format:'rio-direct-https-request-context-v311',origin:fixedOrigin,
    method:'POST',target:PATH,tlsProtocol:'TLSv1.3',headers:h,sessionAuthentication:'NOT_PROVIDED'}));
   const response=await inspect(request);
   if(!(response instanceof Response)||!new Set([200,400,403,404,405,408,413,415,503,504]).has(response.status))throw Error('RESPONSE_REQUIRED');
   const reader=response.body?.getReader();const chunks=[];let total=0;
   try{if(reader)while(true){const next=await reader.read();if(next.done)break;
    if(!(next.value instanceof Uint8Array))throw Error('RESPONSE_BYTES_REQUIRED');
    total+=next.value.byteLength;if(total>16384)throw Error('RESPONSE_LIMIT');
    chunks.push(Buffer.from(next.value));}}
   catch(error){try{await reader?.cancel();}catch{}throw error;}
   finally{try{reader?.releaseLock();}catch{}}
   const bytes=Buffer.concat(chunks),result=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
   if(!result||result.acceptance!=='HOLD'||result.authorization!=='NONE'||result.productionReady!==false)throw Error('BOUNDARIES_REQUIRED');
   await write(response.status,bytes,response.status===405?'POST':undefined);return finished;
  }catch{
   if(!outgoing.destroyed&&!outgoing.headersSent){try{await write(503,failure());}catch{outgoing.destroy();}}
   else if(!outgoing.destroyed)outgoing.destroy();
   return false;
  }finally{
   outgoing.removeListener('finish',onFinish);outgoing.removeListener('close',onClose);outgoing.removeListener('error',onError);
   incoming.removeListener('close',onRequestClose);incoming.removeListener('error',onError);
   active--;complete();
  }
 }
 return Object.freeze({format:'rio-direct-https-inspection-bridge-v311',
  transport:Object.freeze({handleIncoming}),context:Object.freeze({readRequestContext}),
  control:Object.freeze({getStatus,close}),realOneGatewayConnected:false,sessionIssuance:false,...B});
}
