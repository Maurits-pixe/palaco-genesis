/** Native PostgreSQL single-user SQL probe; no socket or server listener. */
import {execFileSync} from 'node:child_process';
import {mkdtempSync,readFileSync,writeFileSync,rmSync,appendFileSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {initdb,postgres} from '@embedded-postgres/linux-x64';
import {hydrateSymlinks} from './node_modules/@embedded-postgres/linux-x64/scripts/hydrate-symlinks.js';

await hydrateSymlinks();
const root=mkdtempSync(join(tmpdir(),'rio-single-v279-')),data=join(root,'data');
const markers=['NATIVE_SCHEMA_PASS','NATIVE_CONSTRAINT_PASS','NATIVE_ROLLBACK_PASS','NATIVE_GRANT_METADATA_PASS'];
try{
  execFileSync(initdb,['-D',data,'--username=rio_fixture_owner','--encoding=UTF8','--no-locale','--auth-local=trust','--auth-host=reject'],{stdio:'pipe',timeout:20000});
  appendFileSync(join(data,'postgresql.conf'),"\nlisten_addresses = ''\nunix_socket_directories = ''\n");
  const fixture=readFileSync(new URL('./native-schema-fixture-v279.sql',import.meta.url),'utf8').replace(/\n\s*\n/g,'\n');
  const commands=[
    "SELECT set_config('palaco.rio_staging_scope','RIO_V279_LOCAL_SOCKET_DISPOSABLE_ONLY',false);",
    fixture,
    `DO $$ BEGIN IF (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname IN ('rio_audit_keys','rio_identity_gate') AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity)<>4
      THEN RAISE EXCEPTION 'SCHEMA_METADATA_MISMATCH'; END IF; END $$;
      SELECT 'NATIVE_SCHEMA_PASS' AS marker;`,
    `DO $$ DECLARE rejected boolean=false; BEGIN
      BEGIN INSERT INTO rio_identity_gate.revocation_requests(request_id,request_payload,status,result_generation)
      VALUES('native-invalid','{}'::jsonb,'COMPLETE',NULL);
      EXCEPTION WHEN check_violation THEN rejected=true; END;
      IF NOT rejected THEN RAISE EXCEPTION 'CONSTRAINT_NOT_ENFORCED'; END IF;
      END $$; SELECT 'NATIVE_CONSTRAINT_PASS' AS marker;`,
    `INSERT INTO rio_identity_gate.session_generation(session_ref,subject_id,generation,active)
      VALUES('native-single-session','native-single-subject',1,true);`,
    `BEGIN; UPDATE rio_identity_gate.session_generation SET generation=2 WHERE session_ref='native-single-session'; ROLLBACK;`,
    `DO $$ BEGIN IF (SELECT generation FROM rio_identity_gate.session_generation WHERE session_ref='native-single-session') IS DISTINCT FROM 1
      THEN RAISE EXCEPTION 'ROLLBACK_NOT_OBSERVED'; END IF; END $$;
      SELECT 'NATIVE_ROLLBACK_PASS' AS marker;`,
    `DO $$ BEGIN IF has_table_privilege('anon','rio_audit_keys.verification_keys','SELECT') OR
      has_table_privilege('authenticated','rio_audit_keys.verification_keys','SELECT')
      THEN RAISE EXCEPTION 'CLIENT_SELECT_NOT_REVOKED'; END IF; END $$;
      SELECT 'NATIVE_GRANT_METADATA_PASS' AS marker;`,
  ];
  const input=commands.map(s=>s.trim()+'\n\n').join('');
  // Spawn directly with pipes; no server socket or alternate network listener.
  const {spawnSync}=await import('node:child_process');
  const result=spawnSync(postgres,['--single','-j','-D',data,'postgres'],{input,encoding:'utf8',timeout:20000,maxBuffer:2*1024*1024});
  const transcript=(result.stdout??'')+'\n'+(result.stderr??'');
  writeFileSync(new URL('../native-standalone-transcript-v279.txt',import.meta.url),transcript);
  if(result.status!==0||/\b(ERROR|FATAL|PANIC):/.test(result.stderr??'')||!markers.every(m=>(result.stdout??'').includes(m)))
    throw Error('NATIVE_SINGLE_USER_SQL_PROBE_FAILED');
  const version=execFileSync(postgres,['--version'],{encoding:'utf8'}).trim();
  writeFileSync(new URL('../NATIVE-STANDALONE-RESULT-v279.json',import.meta.url),JSON.stringify({
    format:'rio-native-single-user-result-v279',version,mode:'NATIVE_SINGLE_USER_STDIN_STDOUT',
    checks:markers.map(name=>({name,result:'PASS'})),serverListenerStarted:false,socketUsed:false,
    nativeConnectionAuthenticationTested:false,multipleBackendsTested:false,
    authorization:'NONE',acceptance:'HOLD',productionReady:false,
  },null,2)+'\n');
  process.stdout.write(JSON.stringify({version,checks:markers.length,result:'PASS',socketUsed:false})+'\n');
}finally{rmSync(root,{recursive:true,force:true});}
