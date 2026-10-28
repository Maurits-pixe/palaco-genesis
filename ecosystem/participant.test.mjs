import test from 'node:test';
import assert from 'node:assert/strict';
import {REPOSITORY,exportDocument,readDocument} from './participant.mjs';
test('participant preserves its source and cannot export another repository identity',async()=>{
 const ref={repository:REPOSITORY,commitSha:'b'.repeat(40),path:'README.md'};
 const doc={documentId:'participant-fixture',title:'Fixture',content:'Synthetic participant fixture.',status:'draft'};
 const data=await readDocument(await exportDocument(doc,ref));
 assert.equal(data.reference.repository,REPOSITORY);assert.deepEqual(data.document,doc);
 assert.equal(data.boundary.sourceVerified,false);
 await assert.rejects(exportDocument(doc,{...ref,repository:'attacker/project'}));
});
