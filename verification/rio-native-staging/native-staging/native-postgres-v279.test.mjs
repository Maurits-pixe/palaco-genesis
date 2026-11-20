import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {generateKeyPairSync,createHash,sign} from 'node:crypto';
import {startLocalClusterV279} from './local-cluster-v279.mjs';
import {createRioRevocationOutcomeCoordinatorV279} from '../rio-revocation-outcome-coordinator-v279.mjs';
import {createRioRevocationReconcilerV242} from '../rio-revocation-reconciler-v242.mjs';
import {createRioReceiptHttpRouteV269} from '../rio-receipt-http-route-v269.mjs';
import {createLocalFixtureHostV276} from '../staging/local-provider-ports-v276.mjs';

const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};
test('v279 native PostgreSQL multi-connection staging',async t=>{
  const cluster=await startLocalClusterV279();
  const evidence={format:'rio-native-staging-result-v279',transport:'PRIVATE_UNIX_SOCKET_ONLY',
    publicListener:false,syntheticDataOnly:true,realIdpVerified:false,remoteTlsVerified:false,
    sourceProject:'NONE_LOCAL_TEMP_CLUSTER',authorization:'NONE',acceptance:'HOLD',productionReady:false,scenarios:[]};
  const scenario=async(name,fn)=>{await t.test(name,async()=>{await fn();evidence.scenarios.push({name,result:'PASS'});});};
  let admin,reader;
  try{
    admin=await cluster.connect();
    evidence.postgresVersion=(await admin.query('SELECT version() AS v')).rows[0].v;
    await admin.query("SELECT set_config('palaco.rio_staging_scope','RIO_V279_LOCAL_SOCKET_DISPOSABLE_ONLY',false)");
    await admin.query(readFileSync(new URL('./native-schema-fixture-v279.sql',import.meta.url),'utf8'));
    await admin.query(`CREATE SCHEMA rio_native_fixture;
      CREATE TABLE rio_native_fixture.authority_sessions(
        session_ref text PRIMARY KEY,subject_id text NOT NULL,active boolean NOT NULL,
        generation bigint NOT NULL,mutation_count integer NOT NULL DEFAULT 0,last_request_id text,evidence_ref text NOT NULL);
      REVOKE ALL ON SCHEMA rio_native_fixture FROM PUBLIC,anon,authenticated;
      GRANT USAGE ON SCHEMA rio_native_fixture TO rio_v276_reader,rio_v276_writer;
      GRANT SELECT ON rio_native_fixture.authority_sessions TO rio_v276_reader,rio_v276_writer;
      GRANT INSERT,UPDATE ON rio_native_fixture.authority_sessions TO rio_v276_writer;
      ALTER TABLE rio_native_fixture.authority_sessions ENABLE ROW LEVEL SECURITY;
      ALTER TABLE rio_native_fixture.authority_sessions FORCE ROW LEVEL SECURITY;
      CREATE POLICY fixture_read ON rio_native_fixture.authority_sessions FOR SELECT
        TO rio_v276_reader,rio_v276_writer USING(true);
      CREATE POLICY fixture_insert ON rio_native_fixture.authority_sessions FOR INSERT
        TO rio_v276_writer WITH CHECK(true);
      CREATE POLICY fixture_update ON rio_native_fixture.authority_sessions FOR UPDATE
        TO rio_v276_writer USING(true) WITH CHECK(true);`);
    await cluster.provisionLogin(admin,'rio_v276_reader');
    await cluster.provisionLogin(admin,'rio_v276_writer');
    reader=await cluster.connect('rio_v276_reader');
    const seed=async tag=>{
      const request={requestId:'request-'+tag,actorAuditRef:'synthetic-revoker',subjectId:'subject-'+tag,
        sessionRef:'session-'+tag,reason:'REVOKED'};
      await admin.query(`INSERT INTO rio_identity_gate.session_generation(session_ref,subject_id,generation,active)
        VALUES($1,$2,1,true)`,[request.sessionRef,request.subjectId]);
      await admin.query(`INSERT INTO rio_native_fixture.authority_sessions
        (session_ref,subject_id,active,generation,evidence_ref) VALUES($1,$2,true,1,$3)`,
        [request.sessionRef,request.subjectId,'evidence-'+tag]);
      return request;
    };
    const authorityMutation=async(tx,request)=>{
      const r=await tx.query(`UPDATE rio_native_fixture.authority_sessions SET active=false,
        generation=generation+1,mutation_count=mutation_count+1,last_request_id=$3
        WHERE session_ref=$1 AND subject_id=$2 AND active=true RETURNING generation`,
        [request.sessionRef,request.subjectId,request.requestId]);
      return {state:'AUTHORITY_MUTATED',changed:r.rowCount===1};
    };
    const coordinator=({connection,mutation=authorityMutation,queryOverride,releaseOverride}={})=>
      createRioRevocationOutcomeCoordinatorV279({
        acquireConnection:async()=>{
          const client=connection??await cluster.connect('rio_v276_writer');
          return {query:queryOverride?(sql,values)=>queryOverride(client,sql,values):(sql,values)=>client.query(sql,values),
            release:releaseOverride?()=>releaseOverride(client):()=>client.end()};
        },applySessionAuthorityMutation:mutation,applyPolicyAuthorityMutation:async()=>{throw Error('POLICY_NOT_IN_NATIVE_SCOPE');}});
    const state=async request=>{
      const auth=(await reader.query('SELECT * FROM rio_native_fixture.authority_sessions WHERE session_ref=$1',[request.sessionRef])).rows[0];
      const ledger=await reader.query('SELECT status,result_generation FROM rio_identity_gate.revocation_requests WHERE request_id=$1',[request.requestId]);
      return {auth,ledger:ledger.rows};
    };
    const reconcile=request=>createRioRevocationReconcilerV242({
      query:(sql,values)=>reader.query(sql,values),
      verifyCurrentAuthority:async({request:original,generation})=>{
        const r=await reader.query(`SELECT active,generation,last_request_id,evidence_ref
          FROM rio_native_fixture.authority_sessions WHERE session_ref=$1 AND subject_id=$2`,
          [original.sessionRef,original.subjectId]);
        const row=r.rows[0];
        return row&&!row.active&&Number(row.generation)===generation?
          {state:'REVOKED_CONFIRMED',requestId:row.last_request_id,generation:Number(row.generation),evidenceRef:row.evidence_ref}:null;
      }}).reconcile('session',request);
    await scenario('native server uses private sockets and a direct least-privilege SCRAM login',async()=>{
      assert.equal((await admin.query('SHOW listen_addresses')).rows[0].listen_addresses,'');
      assert.equal((await admin.query('SHOW fsync')).rows[0].fsync,'on');
      assert.equal((await admin.query('SHOW synchronous_commit')).rows[0].synchronous_commit,'on');
      const r=(await reader.query(`SELECT session_user,current_user,r.rolsuper,r.rolbypassrls
        FROM pg_roles r WHERE r.rolname=current_user`)).rows[0];
      assert.equal(r.session_user,'rio_v276_reader');assert.equal(r.current_user,'rio_v276_reader');
      assert.equal(r.rolsuper,false);assert.equal(r.rolbypassrls,false);
      assert.equal((await reader.query(`SELECT count(*)::integer AS n FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname LIKE 'rio_%' AND c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)`)).rows[0].n,0);
      await assert.rejects(cluster.connect('rio_v276_reader','synthetic-wrong-password'),e=>e.code==='28P01');
      evidence.databasePrincipalVerifiedLocally=true;
    });
    await scenario('two physical writer backends contend on one idempotency key, mutating once',async()=>{
      const request=await seed('concurrent');
      const a=await cluster.connect('rio_v276_writer'),b=await cluster.connect('rio_v276_writer');
      const pidA=(await a.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
      const pidB=(await b.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
      assert.notEqual(pidA,pidB);evidence.distinctWriterBackendPids=[pidA,pidB];
      const entered=deferred(),release=deferred();
      const first=coordinator({connection:a,mutation:async(tx,r)=>{const x=await authorityMutation(tx,r);entered.resolve();await release.promise;return x;}}).revokeSession(request);
      await entered.promise;
      const second=coordinator({connection:b}).revokeSession(request);
      let blocked=false;
      try{
        for(let i=0;i<100;i++){
          const r=await admin.query('SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1',[pidB]);
          if(r.rows[0]?.wait_event_type==='Lock'){blocked=true;break;}
          await new Promise(resolve=>setTimeout(resolve,10));
        }
        assert.equal(blocked,true);
      }finally{release.resolve();}
      const outcomes=await Promise.all([first,second]);
      assert.equal(outcomes.every(r=>r.ok&&r.transactionOutcome==='COMMIT_CONFIRMED'),true);
      assert.equal(outcomes.some(r=>r.state==='ALREADY_COMMITTED_NO_SECOND_MUTATION'),true);
      const actual=await state(request);
      assert.equal(actual.auth.mutation_count,1);assert.equal(Number(actual.auth.generation),2);
      assert.equal(actual.ledger.length,1);assert.equal(Number(actual.ledger[0].result_generation),2);
      evidence.concurrentIdempotency='ACTUAL_TWO_BACKENDS_LOCK_WAIT_OBSERVED_ONE_MUTATION';
    });
    await scenario('reusing a committed key with another payload rolls back and cannot mutate',async()=>{
      const request={requestId:'request-concurrent',actorAuditRef:'another-revoker',subjectId:'subject-concurrent',sessionRef:'session-concurrent',reason:'REVOKED'};
      const r=await coordinator().revokeSession(request);
      assert.equal(r.ok,false);assert.equal(r.transactionOutcome,'ROLLBACK_CONFIRMED');
      assert.equal((await state(request)).auth.mutation_count,1);
    });
    await scenario('an error after authority mutation rolls back authority, generation and audit together',async()=>{
      const request=await seed('rollback');
      const r=await coordinator({mutation:async(tx,q)=>{await authorityMutation(tx,q);throw Error('SYNTHETIC_FAILURE');}}).revokeSession(request);
      assert.equal(r.transactionOutcome,'ROLLBACK_CONFIRMED');
      const actual=await state(request);assert.equal(actual.auth.active,true);assert.equal(actual.auth.mutation_count,0);
      assert.equal(actual.ledger.length,0);
    });
    await scenario('connection closes before sending COMMIT: outcome stays unknown and reconciliation does not retry',async()=>{
      const request=await seed('disconnect');
      const r=await coordinator({queryOverride:async(client,sql,values)=>{
        if(sql==='COMMIT'){await client.end();throw Error('SYNTHETIC_SOCKET_CLOSE_BEFORE_SEND');}
        return client.query(sql,values);
      }}).revokeSession(request);
      assert.equal(r.transactionOutcome,'UNKNOWN_COMMIT_OUTCOME');assert.equal(r.automaticRetryAllowed,false);
      assert.equal(r.requiresReadOnlyReconciliation,true);
      // Server rollback after the real socket close can finish asynchronously.
      let actual;
      for(let i=0;i<100;i++){actual=await state(request);if(actual.auth.mutation_count===0)break;await new Promise(r=>setTimeout(r,10));}
      assert.equal(actual.auth.mutation_count,0);assert.equal(actual.ledger.length,0);
      assert.equal((await reconcile(request)).ok,false);
    });
    let lostReplyRequest;
    await scenario('actual COMMIT plus injected lost application reply is reconciled read-only without a second mutation',async()=>{
      lostReplyRequest=await seed('lost-reply');
      const r=await coordinator({queryOverride:async(client,sql,values)=>{
        const result=await client.query(sql,values);
        if(sql==='COMMIT')throw Error('SYNTHETIC_APPLICATION_REPLY_LOSS_AFTER_COMMIT');
        return result;
      }}).revokeSession(lostReplyRequest);
      assert.equal(r.ok,false);assert.equal(r.reason,'COMMIT_OUTCOME_UNKNOWN');
      assert.equal(r.transactionOutcome,'UNKNOWN_COMMIT_OUTCOME');assert.equal(r.automaticRetryAllowed,false);
      const checked=await reconcile(lostReplyRequest);
      assert.equal(checked.ok,true);assert.equal(checked.state,'COMMIT_FOUND_AND_AUTHORITY_CONFIRMED');
      assert.equal((await state(lostReplyRequest)).auth.mutation_count,1);
      evidence.commitFaultInjection='REAL_COMMIT_THEN_INJECTED_APPLICATION_REPLY_LOSS_NOT_REAL_NETWORK_ACK_LOSS';
    });
    await scenario('cleanup failure cannot relabel a confirmed COMMIT as an aborted transaction',async()=>{
      const request=await seed('cleanup');
      const r=await coordinator({releaseOverride:async client=>{await client.end();throw Error('SYNTHETIC_RELEASE_FAILURE');}}).revokeSession(request);
      assert.equal(r.ok,true);assert.equal(r.transactionOutcome,'COMMIT_CONFIRMED');
      assert.equal(r.connectionCleanup,'FAILED');assert.equal(r.automaticRetryAllowed,false);
      assert.equal((await state(request)).auth.mutation_count,1);
    });
    await scenario('native read-only transaction and reader grants reject writes',async()=>{
      await reader.query('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
      try{
        assert.equal((await reader.query('SHOW transaction_read_only')).rows[0].transaction_read_only,'on');
        await assert.rejects(reader.query('UPDATE rio_identity_gate.session_generation SET active=true'),e=>['25006','42501'].includes(e.code));
      }finally{await reader.query('ROLLBACK');}
      await assert.rejects(reader.query('TRUNCATE rio_identity_gate.revocation_requests'),e=>e.code==='42501');
    });
    const pair=generateKeyPairSync('ed25519'),keyId='native-key';
    const fingerprint=createHash('sha256').update(pair.publicKey.export({format:'der',type:'spki'})).digest('hex');
    await admin.query(`INSERT INTO rio_audit_keys.verification_keys
      (key_id,algorithm,public_key_pem,spki_sha256,status,not_before,not_after)
      VALUES($1,'Ed25519',$2,$3,'ACTIVE',clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 day')`,
      [keyId,pair.publicKey.export({format:'pem',type:'spki'}),fingerprint]);
    await admin.query(`INSERT INTO rio_staging_host.review_sessions VALUES
      ('synthetic-handle','SYNTHETIC_RIO_V276','native-reviewer','native-review-session',1,true)`);
    await admin.query(`INSERT INTO rio_staging_host.inspection_policies VALUES
      ('SYNTHETIC_RIO_V276','native-reviewer','native-review-session',1,$1,1,true)`,[lostReplyRequest.requestId]);
    await admin.query(`INSERT INTO rio_staging_host.request_bindings VALUES
      ('SYNTHETIC_RIO_V276',$1,1,'evidence-lost-reply')`,[lostReplyRequest.requestId]);
    await scenario('unchanged host route verifies a real native-ledger receipt and rejects a revoked key',async()=>{
      const reconciled=await reconcile(lostReplyRequest),ev=reconciled.evidence,payload=JSON.stringify(ev);
      const receipt={ok:true,format:'rio-revocation-receipt-v242',evidence:ev,sha256:reconciled.sha256,
        signature:sign(null,Buffer.from(payload),pair.privateKey).toString('base64url'),keyId,algorithm:'Ed25519',
        signatureValidation:'NOT_VERIFIED_IN_THIS_MODULE',acceptance:'HOLD',authorization:'NONE',
        mayMigrate:false,mayRollback:false,mayDelete:false};
      const host=createLocalFixtureHostV276({query:(sql,values)=>reader.query(sql,values),
        publicKeyPin:{keyId,algorithm:'Ed25519',spkiSha256:fingerprint},now:()=>new Date()});
      const origin='https://rio.native-fixture.invalid';
      const route=createRioReceiptHttpRouteV269({allowedOrigin:origin,maxConcurrentInspections:1,requestTimeoutMs:5000,host});
      const run=()=>route.handle(new Request(origin+route.path,{method:'POST',headers:{Origin:origin,
        'X-RIO-Inspection':'1','Content-Type':'application/json',Cookie:'rio-staging=synthetic-handle'},
        body:JSON.stringify({requestId:lostReplyRequest.requestId,receiptJson:JSON.stringify(receipt)})}));
      const result=await run();assert.equal(result.status,200);assert.equal((await result.json()).authorization,'NONE');
      await admin.query("UPDATE rio_audit_keys.verification_keys SET status='REVOKED',revoked_at=clock_timestamp() WHERE key_id=$1",[keyId]);
      assert.equal((await run()).status,403);
    });
    await scenario('repeatable-read snapshot can be stale after revocation; a fresh transaction sees it',async()=>{
      await admin.query(`INSERT INTO rio_native_fixture.authority_sessions VALUES
        ('snapshot-session','snapshot-subject',true,1,0,NULL,'snapshot-evidence')`);
      const other=await cluster.connect('rio_v276_writer');
      await reader.query('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
      const sql="SELECT active FROM rio_native_fixture.authority_sessions WHERE session_ref='snapshot-session'";
      assert.equal((await reader.query(sql)).rows[0].active,true);
      await other.query("UPDATE rio_native_fixture.authority_sessions SET active=false WHERE session_ref='snapshot-session'");
      assert.equal((await reader.query(sql)).rows[0].active,true);
      await reader.query('ROLLBACK');
      assert.equal((await reader.query(sql)).rows[0].active,false);await other.end();
      evidence.snapshotLimitationObserved=true;
    });
    await scenario('clean native server restart preserves the committed audit and one mutation',async()=>{
      await cluster.stop();await cluster.start();
      admin=await cluster.connect();reader=await cluster.connect('rio_v276_reader');
      const actual=await state(lostReplyRequest);
      assert.equal(actual.ledger[0].status,'COMPLETE');assert.equal(actual.auth.mutation_count,1);
      evidence.cleanRestartPersistenceObserved=true;
    });
    evidence.nativeScenarioCount=evidence.scenarios.length;
    evidence.crashOrPowerFailureTested=false;
    writeFileSync(new URL('../NATIVE-STAGING-RESULT-v279.json',import.meta.url),JSON.stringify(evidence,null,2)+'\n');
  }finally{await cluster.close();}
});
