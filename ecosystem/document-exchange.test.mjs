import test from 'node:test';
import assert from 'node:assert/strict';
import {SCHEMA,MAX_BYTES,REPOSITORIES,encodeDocument,decodeDocument} from './document-exchange.mjs';
const ref = {repository:REPOSITORIES[0],commitSha:'a'.repeat(40),path:'README.md'};
const doc = {documentId:'fixture-1',title:'Document fixture',content:'Synthetic exchange content.',status:'draft'};
test('all six public participants round-trip bounded data with closed authority',async()=>{
  for (const repository of REPOSITORIES) {
    const encoded = await encodeDocument({...ref,repository},doc), result = await decodeDocument(encoded);
    assert.equal(result.schema,SCHEMA);assert.deepEqual(result.document,doc);
    assert.equal(result.reference.repository,repository);assert.equal(result.boundary.sourceVerified,false);
    assert.equal(result.boundary.accountActive,false);assert.equal(result.boundary.canOpenContact,false);
    assert.equal(result.boundary.operativeAuthority,'NONE');assert.equal(result.boundary.statusProvidedBy,'USER');
    assert.ok(Object.isFrozen(result.document));assert.ok(encoded.length<=MAX_BYTES);
  }
});
test('content tampering, metadata/authority promotion and duplicate keys fail closed',async()=>{
  const bytes = await encodeDocument(ref,doc), raw = new TextDecoder().decode(bytes);
  for (const changed of [raw.replace('Synthetic exchange','Altered exchange'),raw.replace('"sourceVerified":false','"sourceVerified":true'),
    raw.replace('"accountActive":false','"accountActive":true'),raw.replace('"NONE"','"ADMIN"'),
    raw.replace('"USER"','"VERIFIER"'),raw.replace('"documentId":','"owner":"other","documentId":'),
    raw.replace('"status":"draft"','"status":"draft","status":"draft"'),raw+' ',
    raw.replace('"draft"','"published"'),raw.replace('"mode":"SYNTHETIC_ONLY"','"mode":"PRODUCTION"')]) {
    await assert.rejects(decodeDocument(changed),/DOCUMENT_EXCHANGE_REJECTED/);
  }
});
test('unsupported sources, traversal, unstable revisions and coercion are rejected',async()=>{
  for (const changed of [{...ref,repository:'attacker/project'},{...ref,commitSha:'main'},
    {...ref,path:'../README.md'},{...ref,path:'/README.md'},{...ref,path:'a//b'},
    {...ref,path:'a%2fb'},{...ref,owner:'other'}]) await assert.rejects(encodeDocument(changed,doc));
  for(const changed of [{...doc,title:''},{...doc,title:' spaced '},{...doc,content:'bad\ud800'},
    {...doc,content:'x'.repeat(12001)},{...doc,status:null},{...doc,title:4},{...doc,documentId:true}]) await assert.rejects(encodeDocument(ref,changed));
});
test('invalid UTF8 and total packet capacity close access',async()=>{
  await assert.rejects(decodeDocument(new Uint8Array([0xff])));
  const canonical=await encodeDocument(ref,doc);
  await assert.rejects(decodeDocument(new Uint8Array([0xef,0xbb,0xbf,...canonical])));
  await assert.rejects(decodeDocument('\ufeff'+new TextDecoder().decode(canonical)));
  await assert.rejects(decodeDocument(new Uint8Array(MAX_BYTES+1)));
  await assert.rejects(decodeDocument(' '));await assert.rejects(decodeDocument({}));
  // JSON escaping has its own byte cost even when the content itself fits.
  await assert.rejects(encodeDocument(ref,{...doc,content:'"'.repeat(10000)}));
});
test('input is snapshotted before digest await and decoded results are immutable',async()=>{
  const bytes=await encodeDocument(ref,doc);const pending=decodeDocument(bytes);bytes.fill(0);
  const result=await pending;assert.deepEqual(result.document,doc);
  assert.throws(()=>{result.document.status='specificatie';},TypeError);
});
