import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {PGlite} from '@electric-sql/pglite';
import {createRioRevocationOutcomeCoordinatorV279} from '../rio-revocation-outcome-coordinator-v279.mjs';
import {createRioRevocationReconcilerV242} from '../rio-revocation-reconciler-v242.mjs';

test('v279 real SQL transaction outcome checks in permitted in-memory engine',async t=>{
  const db=await PGlite.create('memory://');
  const evidence={format:'rio-transaction-outcome-result-v279',engine:'PGlite 0.5.16',
    transport:'IN_PROCESS_NO_SOCKETS',syntheticDataOnly:true,parallelNativeVerification:'BLOCKED_SOCKET_CREATION_DENIED',
    authorization:'NONE',acceptance:'HOLD',productionReady:false,scenarios:[]};
  const scenario=async(name,fn)=>t.test(name,async()=>{await fn();evidence.scenarios.push({name,result:'PASS'});});
  try{
    await db.query("SELECT set_config('palaco.rio_staging_scope','RIO_V276_DISPOSABLE_MEMORY_ONLY',false)");
    await db.exec(readFileSync(new URL('./isolated-schema-fixture-v276.sql',import.meta.url),'utf8'));
    await db.exec(`CREATE SCHEMA rio_outcome_fixture;
      CREATE TABLE rio_outcome_fixture.authority_state(session_ref text PRIMARY KEY,subject_id text,
        active boolean,generation bigint,mutation_count integer,last_request_id text);
      REVOKE ALL ON SCHEMA rio_outcome_fixture FROM PUBLIC;
      GRANT USAGE ON SCHEMA rio_outcome_fixture TO rio_v276_writer;
      GRANT SELECT,INSERT,UPDATE ON rio_outcome_fixture.authority_state TO rio_v276_writer;
      ALTER TABLE rio_outcome_fixture.authority_state ENABLE ROW LEVEL SECURITY;
      ALTER TABLE rio_outcome_fixture.authority_state FORCE ROW LEVEL SECURITY;
      CREATE POLICY local_writer ON rio_outcome_fixture.authority_state TO rio_v276_writer USING(true) WITH CHECK(true);`);
    const seed=async tag=>{
      const r={requestId:'request-'+tag,actorAuditRef:'synthetic-actor',subjectId:'subject-'+tag,sessionRef:'session-'+tag,reason:'REVOKED'};
      await db.query('INSERT INTO rio_identity_gate.session_generation(session_ref,subject_id,generation,active) VALUES($1,$2,1,true)',[r.sessionRef,r.subjectId]);
      await db.query('INSERT INTO rio_outcome_fixture.authority_state VALUES($1,$2,true,1,0,NULL)',[r.sessionRef,r.subjectId]);return r;
    };
    const mutate=async(tx,r)=>{
      const q=await tx.query(`UPDATE rio_outcome_fixture.authority_state SET active=false,generation=generation+1,
        mutation_count=mutation_count+1,last_request_id=$3 WHERE session_ref=$1 AND subject_id=$2 AND active=true RETURNING generation`,
        [r.sessionRef,r.subjectId,r.requestId]);
      return {state:'AUTHORITY_MUTATED',changed:q.rows.length===1};
    };
    const coordinator=({mutation=mutate,override,cleanupFailure=false}={})=>createRioRevocationOutcomeCoordinatorV279({
      acquireConnection:async()=>{
        await db.exec('SET ROLE rio_v276_writer');
        return {query:(sql,values)=>override?override(sql,values):db.query(sql,values),
          release:async()=>{await db.exec('RESET ROLE');if(cleanupFailure)throw Error('SYNTHETIC_CLEANUP_FAILURE');}};
      },applySessionAuthorityMutation:mutation,applyPolicyAuthorityMutation:async()=>{throw Error('POLICY_NOT_TESTED_HERE');}});
    const state=async r=>({
      auth:(await db.query('SELECT active,generation,mutation_count,last_request_id FROM rio_outcome_fixture.authority_state WHERE session_ref=$1',[r.sessionRef])).rows[0],
      audit:(await db.query('SELECT status FROM rio_identity_gate.revocation_requests WHERE request_id=$1',[r.requestId])).rows});
    await scenario('confirmed COMMIT persists one authority mutation and audit record',async()=>{
      const r=await seed('confirmed'),result=await coordinator().revokeSession(r);
      assert.equal(result.ok,true);assert.equal(result.transactionOutcome,'COMMIT_CONFIRMED');
      const actual=await state(r);assert.equal(actual.auth.mutation_count,1);assert.equal(actual.audit[0].status,'COMPLETE');
    });
    await scenario('failure after mutation produces a confirmed all-or-nothing rollback',async()=>{
      const r=await seed('rollback');
      const result=await coordinator({mutation:async(tx,q)=>{await mutate(tx,q);throw Error('INJECTED_FAILURE');}}).revokeSession(r);
      assert.equal(result.transactionOutcome,'ROLLBACK_CONFIRMED');
      const actual=await state(r);assert.equal(actual.auth.active,true);assert.equal(actual.auth.mutation_count,0);assert.equal(actual.audit.length,0);
    });
    await scenario('real COMMIT plus injected missing application reply stays UNKNOWN and reconciles read-only',async()=>{
      const r=await seed('lost-reply');
      const result=await coordinator({override:async(sql,values)=>{
        const answer=await db.query(sql,values);if(sql==='COMMIT')throw Error('INJECTED_APPLICATION_REPLY_LOSS');return answer;
      }}).revokeSession(r);
      assert.equal(result.ok,false);assert.equal(result.reason,'COMMIT_OUTCOME_UNKNOWN');
      assert.equal(result.transactionOutcome,'UNKNOWN_COMMIT_OUTCOME');assert.equal(result.automaticRetryAllowed,false);
      assert.equal(result.requiresReadOnlyReconciliation,true);
      const checked=await createRioRevocationReconcilerV242({query:(sql,values)=>db.query(sql,values),
        verifyCurrentAuthority:async({generation})=>{
          const actual=await state(r);return !actual.auth.active&&Number(actual.auth.generation)===generation?
            {state:'REVOKED_CONFIRMED',requestId:actual.auth.last_request_id,generation,evidenceRef:'synthetic-outcome-evidence'}:null;
        }}).reconcile('session',r);
      assert.equal(checked.ok,true);assert.equal((await state(r)).auth.mutation_count,1);
      evidence.commitFaultScope='ACTUAL_IN_MEMORY_SQL_COMMIT_THEN_INJECTED_APPLICATION_RESPONSE_LOSS_NOT_REAL_NETWORK_LOSS';
    });
    await scenario('missing rollback reply also remains unknown despite the actual rollback',async()=>{
      const r=await seed('rollback-reply');
      const result=await coordinator({mutation:async(tx,q)=>{await mutate(tx,q);throw Error('INJECTED_FAILURE');},
        override:async(sql,values)=>{const answer=await db.query(sql,values);if(sql==='ROLLBACK')throw Error('INJECTED_ROLLBACK_REPLY_LOSS');return answer;}}).revokeSession(r);
      assert.equal(result.transactionOutcome,'ROLLBACK_OUTCOME_UNKNOWN');assert.equal(result.automaticRetryAllowed,false);
      assert.equal(result.requiresReadOnlyReconciliation,true);assert.equal((await state(r)).auth.mutation_count,0);
    });
    await scenario('cleanup failure preserves confirmed COMMIT instead of inventing a rollback',async()=>{
      const r=await seed('cleanup');
      const result=await coordinator({cleanupFailure:true}).revokeSession(r);
      assert.equal(result.ok,true);assert.equal(result.transactionOutcome,'COMMIT_CONFIRMED');
      assert.equal(result.connectionCleanup,'FAILED');assert.equal(result.automaticRetryAllowed,false);
      assert.equal((await state(r)).auth.mutation_count,1);
    });
    writeFileSync(new URL('../TRANSACTION-OUTCOME-RESULT-v279.json',import.meta.url),JSON.stringify(evidence,null,2)+'\n');
  }finally{await db.close();}
});
