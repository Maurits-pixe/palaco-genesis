import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {PGlite} from '@electric-sql/pglite';
import {createLocalFixtureHostV276} from './local-provider-ports-v276.mjs';
import {createRioReceiptHttpRouteV269} from '../rio-receipt-http-route-v269.mjs';
import {RIO_HOST_CATALOG_QUERY_V274,assessRioHostCatalogV274} from '../rio-host-catalog-preflight-v274.mjs';

// Always a fresh memory:// engine. No URL, hostname, env secret or real account.
test('v276 disposable PostgreSQL schema and provider integration',async t=>{
  const db=await PGlite.create('memory://');
  const results={format:'rio-disposable-staging-result-v276',engine:'PGlite 0.5.16',
    storage:'IN_MEMORY_ONLY',sourceProject:'NONE_LOCAL_FIXTURE_ONLY',externalConnections:false,
    syntheticAuthentication:true,authorization:'NONE',acceptance:'HOLD',productionReady:false,
    scenarios:[]};
  const scenario=async(name,fn)=>{
    await t.test(name,async()=>{await fn();results.scenarios.push({name,result:'PASS'});});
  };
  try{
    results.postgresVersion=(await db.query('SELECT version() AS version')).rows[0].version;
    const fixture=readFileSync(new URL('./isolated-schema-fixture-v276.sql',import.meta.url),'utf8');
    await scenario('fresh catalog actually reports four missing RIO objects',async()=>{
      const response=await db.query(RIO_HOST_CATALOG_QUERY_V274);
      const report=assessRioHostCatalogV274({catalogRows:response.rows,projectReference:'LOCAL_FIXTURE_V276',
        observedAt:'2026-11-16T16:00:00.000Z'});
      assert.equal(report.missingRequiredObjectCount,4);assert.equal(report.ok,false);
      results.before=report;
    });
    await scenario('schema refuses an absent local scope marker',async()=>{
      await assert.rejects(db.exec(fixture),/LOCAL_STAGING_SCOPE_REQUIRED/);
      await db.exec('ROLLBACK');
      assert.equal((await db.query("SELECT to_regnamespace('rio_identity_gate') IS NULL AS absent")).rows[0].absent,true);
    });
    await scenario('reference schemas and local privilege policies execute in real WASM Postgres',async()=>{
      await db.query("SELECT set_config('palaco.rio_staging_scope',$1,false)",['RIO_V276_DISPOSABLE_MEMORY_ONLY']);
      await db.exec(fixture);
      const response=await db.query(RIO_HOST_CATALOG_QUERY_V274);
      const report=assessRioHostCatalogV274({catalogRows:response.rows,projectReference:'LOCAL_FIXTURE_V276',
        observedAt:'2026-11-16T16:00:00.000Z'});
      assert.equal(report.ok,true);assert.equal(report.missingRequiredObjectCount,0);
      assert.equal(report.integrationReady,false);results.after=report;
      assert.equal(report.observations.filter(o=>o.classification==='REQUIRED_RIO').every(o=>o.rlsEnabled&&o.forceRls),true);
    });
    await scenario('schema refuses reuse of a database containing the fixture',async()=>{
      await assert.rejects(db.exec(fixture),/FRESH_DISPOSABLE_DATABASE_REQUIRED/);
      await db.exec('ROLLBACK');
    });
    await scenario('anon and authenticated cannot read the private key registry',async()=>{
      for(const role of ['anon','authenticated']){
        await db.exec('SET ROLE '+role);
        try{await assert.rejects(db.query('SELECT key_id FROM rio_audit_keys.verification_keys'),e=>e.code==='42501');}
        finally{await db.exec('RESET ROLE');}
      }
    });
    const pair=generateKeyPairSync('ed25519');
    const keyId='synthetic-key-v276';
    const publicKeyPem=pair.publicKey.export({format:'pem',type:'spki'});
    const spkiSha256=createHash('sha256').update(pair.publicKey.export({format:'der',type:'spki'})).digest('hex');
    const request={kind:'session',requestId:'synthetic-request-v276',actorAuditRef:'synthetic-revoker',
      subjectId:'synthetic-target',sessionRef:'synthetic-target-session',reason:'REVOKED'};
    const policyRequest={kind:'policy',requestId:'synthetic-policy-v276',actorAuditRef:'synthetic-revoker',
      subjectId:'synthetic-target',conversationId:'synthetic-conversation',dossierId:'synthetic-dossier',reason:'POLICY_CHANGED'};
    await db.exec('SET ROLE rio_v276_writer');
    await db.query(`INSERT INTO rio_audit_keys.verification_keys
      (key_id,algorithm,public_key_pem,spki_sha256,status,not_before,not_after)
      VALUES ($1,'Ed25519',$2,$3,'ACTIVE','2026-11-01T00:00:00.000Z','2026-12-01T00:00:00.000Z')`,[keyId,publicKeyPem,spkiSha256]);
    await db.query(`INSERT INTO rio_identity_gate.revocation_requests
      (request_id,request_payload,status,result_generation,recorded_at)
      VALUES ($1,$2::jsonb,'COMPLETE',9,'2026-11-16T15:00:00.000Z')`,[request.requestId,JSON.stringify(request)]);
    await db.query(`INSERT INTO rio_identity_gate.session_generation(session_ref,subject_id,generation,active)
      VALUES($1,$2,9,false)`,[request.sessionRef,request.subjectId]);
    await db.query(`INSERT INTO rio_identity_gate.review_policy_generation
      (subject_id,conversation_id,dossier_id,generation,review_permitted)
      VALUES('synthetic-target','synthetic-conversation','synthetic-dossier',5,false)`);
    await db.query(`INSERT INTO rio_staging_host.review_sessions VALUES
      ('synthetic-handle','SYNTHETIC_RIO_V276','synthetic-reviewer','synthetic-review-session',3,true)`);
    await db.query(`INSERT INTO rio_staging_host.inspection_policies VALUES
      ('SYNTHETIC_RIO_V276','synthetic-reviewer','synthetic-review-session',3,$1,1,true)`,[request.requestId]);
    await db.query(`INSERT INTO rio_staging_host.request_bindings VALUES
      ('SYNTHETIC_RIO_V276',$1,1,'synthetic-authority-v276')`,[request.requestId]);
    await db.query(`INSERT INTO rio_identity_gate.revocation_requests
      (request_id,request_payload,status,result_generation,recorded_at)
      VALUES($1,$2::jsonb,'COMPLETE',5,'2026-11-16T15:00:00.000Z')`,[policyRequest.requestId,JSON.stringify(policyRequest)]);
    await db.query(`INSERT INTO rio_staging_host.inspection_policies VALUES
      ('SYNTHETIC_RIO_V276','synthetic-reviewer','synthetic-review-session',3,$1,1,true)`,[policyRequest.requestId]);
    await db.query(`INSERT INTO rio_staging_host.request_bindings VALUES
      ('SYNTHETIC_RIO_V276',$1,1,'synthetic-policy-authority-v276')`,[policyRequest.requestId]);
    await db.exec('RESET ROLE');
    await scenario('SQL rejects duplicate idempotency keys and incomplete COMPLETE records',async()=>{
      await db.exec('SET ROLE rio_v276_writer');
      try{
        await assert.rejects(db.query(`INSERT INTO rio_identity_gate.revocation_requests
          (request_id,request_payload,status,result_generation) VALUES($1,$2::jsonb,'COMPLETE',9)`,
          [request.requestId,JSON.stringify(request)]),e=>e.code==='23505');
        await assert.rejects(db.query(`INSERT INTO rio_identity_gate.revocation_requests
          (request_id,request_payload,status,result_generation) VALUES('synthetic-invalid','{}'::jsonb,'COMPLETE',NULL)`),e=>e.code==='23514');
      }finally{await db.exec('RESET ROLE');}
    });
    await scenario('reader can SELECT but cannot UPDATE or TRUNCATE fixture state',async()=>{
      await db.exec('SET ROLE rio_v276_reader');
      try{
        assert.equal((await db.query('SELECT key_id FROM rio_audit_keys.verification_keys')).rows.length,1);
        await assert.rejects(db.query("UPDATE rio_audit_keys.verification_keys SET status='RETIRED'"),e=>e.code==='42501');
        await assert.rejects(db.query('TRUNCATE rio_identity_gate.revocation_requests'),e=>e.code==='42501');
      }finally{await db.exec('RESET ROLE');}
    });
    const evidence={format:'rio-revocation-evidence-v242',requestId:request.requestId,kind:request.kind,
      actorAuditRef:request.actorAuditRef,subjectId:request.subjectId,sessionRef:request.sessionRef,
      reason:request.reason,generation:9,committedAt:'2026-11-16T15:00:00.000Z',
      authorityEvidenceRef:'synthetic-authority-v276',acceptance:'HOLD',authorization:'NONE',retriedRevocation:false,mayMigrate:false};
    const payload=JSON.stringify(evidence);
    const receipt={ok:true,format:'rio-revocation-receipt-v242',evidence,
      sha256:createHash('sha256').update(payload).digest('hex'),
      signature:sign(null,Buffer.from(payload),pair.privateKey).toString('base64url'),
      keyId,algorithm:'Ed25519',signatureValidation:'NOT_VERIFIED_IN_THIS_MODULE',
      acceptance:'HOLD',authorization:'NONE',mayMigrate:false,mayRollback:false,mayDelete:false};
    let queryCount=0;
    const host=createLocalFixtureHostV276({query:async(sql,values)=>{
      queryCount++;assert.match(sql.trim(),/^SELECT\b/);return db.query(sql,values);
    },publicKeyPin:{keyId,algorithm:'Ed25519',spkiSha256},now:()=>new Date('2026-11-16T16:00:00.000Z')});
    const origin='https://rio.staging.invalid';
    const route=createRioReceiptHttpRouteV269({allowedOrigin:origin,maxConcurrentInspections:1,requestTimeoutMs:5000,host});
    const run=(selected=receipt)=>route.handle(new Request(origin+route.path,{method:'POST',headers:{
      Origin:origin,'X-RIO-Inspection':'1','Content-Type':'application/json',Cookie:'rio-staging=synthetic-handle'},
      body:JSON.stringify({requestId:selected.evidence.requestId,receiptJson:JSON.stringify(selected)})}));
    await scenario('Request route and real SQL providers verify the synthetic signed receipt',async()=>{
      await db.exec('SET ROLE rio_v276_reader');
      try{
        const response=await run();const body=await response.json();
        assert.equal(response.status,200);assert.equal(body.signatureStatus,'CRYPTOGRAPHICALLY_VALID');
        assert.equal(body.authorization,'NONE');assert.equal(body.productionReady,false);
        assert.ok(queryCount>=10);results.routeResult=body;
      }finally{await db.exec('RESET ROLE');}
    });
    await scenario('policy receipt follows SQL policy-generation state and rejects restored permission',async()=>{
      const policyEvidence={format:'rio-revocation-evidence-v242',requestId:policyRequest.requestId,kind:policyRequest.kind,
        actorAuditRef:policyRequest.actorAuditRef,subjectId:policyRequest.subjectId,
        conversationId:policyRequest.conversationId,dossierId:policyRequest.dossierId,reason:policyRequest.reason,
        generation:5,committedAt:'2026-11-16T15:00:00.000Z',authorityEvidenceRef:'synthetic-policy-authority-v276',
        acceptance:'HOLD',authorization:'NONE',retriedRevocation:false,mayMigrate:false};
      const policyPayload=JSON.stringify(policyEvidence);
      const policyReceipt={...receipt,evidence:policyEvidence,
        sha256:createHash('sha256').update(policyPayload).digest('hex'),
        signature:sign(null,Buffer.from(policyPayload),pair.privateKey).toString('base64url')};
      await db.exec('SET ROLE rio_v276_reader');
      try{assert.equal((await run(policyReceipt)).status,200);}finally{await db.exec('RESET ROLE');}
      await db.exec('SET ROLE rio_v276_writer');
      await db.query('UPDATE rio_identity_gate.review_policy_generation SET review_permitted=true');
      await db.exec('SET ROLE rio_v276_reader');
      try{assert.equal((await run(policyReceipt)).status,403);}finally{await db.exec('RESET ROLE');}
      await db.exec('SET ROLE rio_v276_writer');
      await db.query('UPDATE rio_identity_gate.review_policy_generation SET review_permitted=false');
      await db.exec('RESET ROLE');
    });
    await scenario('actual SQL policy revocation blocks the same valid signature',async()=>{
      await db.exec('SET ROLE rio_v276_writer');
      await db.query('UPDATE rio_staging_host.inspection_policies SET permitted=false,revision=revision+1');
      await db.exec('SET ROLE rio_v276_reader');
      try{assert.equal((await run()).status,403);}finally{await db.exec('RESET ROLE');}
      await db.exec('SET ROLE rio_v276_writer');
      await db.query('UPDATE rio_staging_host.inspection_policies SET permitted=true,revision=revision+1');
      await db.exec('RESET ROLE');
    });
    await scenario('actual SQL key revocation blocks the same signed receipt',async()=>{
      await db.exec('SET ROLE rio_v276_writer');
      await db.query("UPDATE rio_audit_keys.verification_keys SET status='REVOKED',revoked_at=clock_timestamp()");
      await db.exec('SET ROLE rio_v276_reader');
      try{assert.equal((await run()).status,403);}finally{await db.exec('RESET ROLE');}
    });
    await scenario('read-only fixtures do not grant DELETE to the staging writer',async()=>{
      await db.exec('SET ROLE rio_v276_writer');
      try{await assert.rejects(db.query('DELETE FROM rio_identity_gate.revocation_requests'),e=>e.code==='42501');}
      finally{await db.exec('RESET ROLE');}
    });
    results.queryCount=queryCount;
    results.distributedConcurrencyTested=false;results.realIdpTested=false;results.tlsTested=false;
    writeFileSync(new URL('../STAGING-RESULT-v276.json',import.meta.url),JSON.stringify(results,null,2)+'\n');
  }finally{await db.close();}
});
