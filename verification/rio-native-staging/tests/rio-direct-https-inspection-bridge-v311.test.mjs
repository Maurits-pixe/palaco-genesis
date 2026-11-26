import test from 'node:test';
import assert from 'node:assert/strict';
import {IncomingMessage,ServerResponse} from 'node:http';
import {PassThrough} from 'node:stream';
import {createRioDirectHttpsInspectionBridgeV311} from '../rio-direct-https-inspection-bridge-v311.mjs';
import {RIO_RECEIPT_INSPECTION_PATH_V269 as PATH} from '../rio-receipt-http-route-v269.mjs';
const origin='https://rio.example.invalid',host='rio.example.invalid',B={acceptance:'HOLD',authorization:'NONE',productionReady:false};
const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};
const flush=()=>new Promise(r=>setImmediate(r));
const response=()=>new Response(JSON.stringify({ok:true,...B}),{status:200});
function setup(){
 let calls=0;const config={allowedOrigin:origin,maxConcurrentRequests:1,inspection:{
 handle:async()=>{calls++;return response();},path:PATH,purpose:'READ_ONLY_RECEIPT_INSPECTION_ROUTE',acceptance:'HOLD',authorization:'NONE'}};
 return {config,calls:()=>calls,build:()=>createRioDirectHttpsInspectionBridgeV311(config)};
}
function pair(overrides={}){
 const socket=new PassThrough();socket.encrypted=true;socket.getProtocol=()=>'TLSv1.3';
 const incoming=new IncomingMessage(socket);incoming.httpVersionMajor=1;incoming.method='POST';incoming.url=PATH;incoming.complete=true;
 incoming.rawHeaders=['Host',host,'Origin',origin,'X-RIO-Inspection','1','Content-Type','application/json'];
 const outgoing=new ServerResponse(incoming);outgoing.assignSocket(socket);const wire=[];
 socket.on('data',chunk=>wire.push(Buffer.from(chunk)));const body=overrides.body??'{}';
 if(overrides.rawHeaders)incoming.rawHeaders=overrides.rawHeaders;
 if(overrides.url)incoming.url=overrides.url;if(overrides.method)incoming.method=overrides.method;
 if(overrides.protocol)socket.getProtocol=()=>overrides.protocol;if(overrides.plain)socket.encrypted=false;
 if(!overrides.stalled){incoming.push(Buffer.from(body));incoming.push(null);}
 return {incoming,outgoing,socket,text:()=>Buffer.concat(wire).toString('utf8')};
}
const status=p=>Number(p.text().match(/^HTTP\/1.1 (\d+)/)?.[1]);
test('static exact config validation and frozen separated ports perform no dispatch',async()=>{
 const x=setup();let getters=0;const bad={...x.config};Object.defineProperty(bad,'allowedOrigin',{enumerable:true,get(){getters++;return origin;}});
 for(const c of [bad,{...x.config,extra:1},{...x.config,allowedOrigin:'http://rio.example.invalid'},
 {...x.config,maxConcurrentRequests:0},{...x.config,inspection:{...x.config.inspection,handle:null}}])
 assert.throws(()=>createRioDirectHttpsInspectionBridgeV311(c),TypeError);
 const b=x.build();for(const o of [b,b.transport,b.context,b.control,b.control.getStatus()])assert.ok(Object.isFrozen(o));
 assert.equal(getters,0);assert.equal(x.calls(),0);assert.equal((await b.control.close()).state,'CLOSED');
});
test('mismatched or non-native request response objects cannot dispatch',async()=>{
 const x=setup(),b=x.build(),p=pair(),other=pair();assert.equal(await b.transport.handleIncoming({},{}),false);
 assert.equal(await b.transport.handleIncoming(p.incoming,other.outgoing),false);assert.equal(x.calls(),0);
 p.socket.destroy();other.socket.destroy();
});
test('plaintext and older TLS are refused before Fetch context or dispatch',async()=>{
 const x=setup(),b=x.build();
 for(const o of [{plain:true},{protocol:'TLSv1.2'}]){const p=pair(o);await b.transport.handleIncoming(p.incoming,p.outgoing);assert.equal(status(p),403);}
 assert.equal(x.calls(),0);
});
test('Host aliases absolute targets query and encoded paths cannot change the configured route',async()=>{
 const x=setup(),b=x.build();
 const wrong=pair();wrong.incoming.rawHeaders[1]='other.invalid';await b.transport.handleIncoming(wrong.incoming,wrong.outgoing);assert.equal(status(wrong),400);
 for(const url of ['https://rio.example.invalid'+PATH,'//other.invalid'+PATH,PATH+'?x=1',PATH.replace('rio','%72io')]){
 const p=pair({url});await b.transport.handleIncoming(p.incoming,p.outgoing);assert.equal(status(p),404);}
 assert.equal(x.calls(),0);
});
test('duplicate and forwarded headers are refused without selecting one interpretation',async()=>{
 const x=setup(),b=x.build();
 for(const extra of [['Cookie','a','cookie','b'],['Forwarded','proto=https'],['X-Forwarded-Host',host],['Host',host]]){
 const p=pair();p.incoming.rawHeaders.push(...extra);await b.transport.handleIncoming(p.incoming,p.outgoing);assert.equal(status(p),400);}
 assert.equal(x.calls(),0);
});
test('origin media declared length method and unread body guards precede dispatch',async()=>{
 const x=setup(),b=x.build();
 for(const [name,value,code] of [['Origin','https://other.invalid',403],['Content-Type','text/plain',415],
 ['Content-Length','32769',413],['Content-Encoding','identity',415]]){
 const p=pair();const i=p.incoming.rawHeaders.findIndex(v=>v.toLowerCase()===name.toLowerCase());
 if(i<0)p.incoming.rawHeaders.push(name,value);else p.incoming.rawHeaders[i+1]=value;
 await b.transport.handleIncoming(p.incoming,p.outgoing);assert.equal(status(p),code);
 }
 const get=pair({method:'GET'});await b.transport.handleIncoming(get.incoming,get.outgoing);assert.equal(status(get),405);
 const consumed=pair();consumed.incoming.read();await b.transport.handleIncoming(consumed.incoming,consumed.outgoing);assert.equal(status(consumed),400);
 assert.equal(x.calls(),0);
});
test('streaming bytes reach one Fetch request with immutable context and no session claim',async()=>{
 const x=setup();let received,ctx;const b=createRioDirectHttpsInspectionBridgeV311({...x.config,inspection:{...x.config.inspection,
 handle:async r=>{received=r;ctx=b.context.readRequestContext(r);assert.equal(await r.text(),'{"synthetic":true}');return response();}}});
 const p=pair({body:'{"synthetic":true}'});p.incoming.rawHeaders.push('Cookie','synthetic-session=active');
 await b.transport.handleIncoming(p.incoming,p.outgoing);assert.equal(status(p),200);assert.ok(Object.isFrozen(ctx));assert.ok(Object.isFrozen(ctx.headers));
 assert.equal(ctx.sessionAuthentication,'NOT_PROVIDED');assert.equal(ctx.tlsProtocol,'TLSv1.3');
 assert.equal(ctx.headers.cookie,'synthetic-session=active');assert.equal(b.context.readRequestContext(new Request(origin+PATH)),null);
 assert.equal(b.context.readRequestContext({}),null);assert.equal(b.context.readRequestContext(received),ctx);
 assert.equal(JSON.stringify(b.control.getStatus()).includes('synthetic-session'),false);
});
test('caller mutation cannot redirect captured origin port or capacity',async()=>{
 const x=setup(),b=x.build();x.config.allowedOrigin='https://other.invalid';x.config.maxConcurrentRequests=0;
 x.config.inspection.handle=()=>{throw Error('MUTATED');};const p=pair();await b.transport.handleIncoming(p.incoming,p.outgoing);
 assert.equal(status(p),200);assert.equal(x.calls(),1);assert.equal(b.control.getStatus().capacity,1);
});
test('transport capacity bounds an admitted response operation',async()=>{
 const x=setup(),entered=deferred(),gate=deferred();let calls=0;
 x.config.inspection.handle=async()=>{calls++;entered.resolve();await gate.promise;return response();};
 const b=x.build(),p=pair(),pending=b.transport.handleIncoming(p.incoming,p.outgoing);await entered.promise;
 const other=pair();await b.transport.handleIncoming(other.incoming,other.outgoing);assert.equal(status(other),503);assert.equal(calls,1);
 gate.resolve();await pending;assert.equal(b.control.getStatus().inFlightTransport,0);
});
test('terminal transport close waits for admitted dispatch and refuses new requests',async()=>{
 const x=setup(),entered=deferred(),gate=deferred();x.config.inspection.handle=async()=>{entered.resolve();await gate.promise;return response();};
 const b=x.build(),p=pair(),pending=b.transport.handleIncoming(p.incoming,p.outgoing);await entered.promise;
 let completed=false;const done=b.control.close();done.then(()=>{completed=true;});assert.equal(done,b.control.close());await flush();
 assert.equal(completed,false);assert.equal(b.control.getStatus().state,'DRAINING');const other=pair();await b.transport.handleIncoming(other.incoming,other.outgoing);
 assert.equal(status(other),503);gate.resolve();await pending;assert.equal((await done).state,'CLOSED');
});
test('peer disconnect propagates abort while request context stays bound to pending Fetch work',async()=>{
 const x=setup(),entered=deferred(),gate=deferred();let received;
 x.config.inspection.handle=async r=>{received=r;entered.resolve();await gate.promise;return response();};
 const b=x.build(),p=pair(),pending=b.transport.handleIncoming(p.incoming,p.outgoing);await entered.promise;
 p.outgoing.destroy();await flush();assert.equal(received.signal.aborted,true);assert.ok(b.context.readRequestContext(received));
 const done=b.control.close();assert.equal(b.control.getStatus().state,'DRAINING');gate.resolve();await pending;await done;
});
test('oversized response cancellation remains in the transport completion barrier and diagnostics are minimized',async()=>{
 const x=setup(),entered=deferred(),gate=deferred();x.config.inspection.handle=async()=>new Response(new ReadableStream({
 start(c){c.enqueue(new Uint8Array(17000));},cancel(){entered.resolve();return gate.promise;}}));
 const b=x.build(),p=pair(),pending=b.transport.handleIncoming(p.incoming,p.outgoing);await entered.promise;
 let complete=false;const done=b.control.close();done.then(()=>{complete=true;});await flush();assert.equal(complete,false);
 gate.resolve();await pending;await done;assert.equal(status(p),503);assert.equal(p.text().includes('17000'),false);
});
