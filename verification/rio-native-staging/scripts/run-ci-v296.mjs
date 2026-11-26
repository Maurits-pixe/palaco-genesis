import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync,mkdirSync,readdirSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {join,relative} from 'node:path';

const root=fileURLToPath(new URL('../',import.meta.url));
const output=join(root,'evidence');
mkdirSync(output,{recursive:true});
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const sources={};
function inventory(dir){
  for(const item of readdirSync(dir,{withFileTypes:true})){
    if(['node_modules','evidence'].includes(item.name)||item.name.endsWith('-RESULT-v279.json')||
      item.name.endsWith('-RESULT-v276.json')||['NATIVE-STAGING-RESULT-v281.json','ONE-NATIVE-RESULT-v295.json','ONE-SIGNED-NATIVE-RESULT-v296.json','native-standalone-transcript-v279.txt'].includes(item.name))continue;
    const path=join(dir,item.name);
    if(item.isDirectory())inventory(path);
    else if(item.isFile())sources[relative(root,path)]=hash(readFileSync(path));
  }
}
inventory(root);
const report={format:'rio-one-signed-session-ci-result-v296',startedAt:new Date().toISOString(),
  sourceHeadSha:process.env.RIO_CI_HEAD_SHA??'LOCAL_UNBOUND',
  workflowRunId:process.env.GITHUB_RUN_ID??null,workflowRunAttempt:process.env.GITHUB_RUN_ATTEMPT??null,
  nodeVersion:process.version,platform:process.platform,arch:process.arch,
  syntheticDataOnly:true,realIdpVerified:false,remoteTlsVerified:false,
  authorization:'NONE',acceptance:'HOLD',productionReady:false,sources,phases:[]};
function run(name,args){
  const result=spawnSync(process.execPath,args,{cwd:root,encoding:'utf8',timeout:120000,maxBuffer:8*1024*1024});
  const transcript=(result.stdout??'')+(result.stderr??'');
  const filename=name+'.log';
  writeFileSync(join(output,filename),transcript);
  report.phases.push({name,result:result.status===0&&!result.error?'PASS':'FAIL',
    exitCode:result.status,signal:result.signal,errorCode:result.error?.code??null,
    transcript:filename,transcriptSha256:hash(transcript)});
  process.stdout.write(transcript);
}
const tests=readdirSync(join(root,'tests')).filter(x=>x.endsWith('.test.mjs')).sort().map(x=>'tests/'+x);
run('regressions',['--test',...tests,'staging/isolated-postgres-v276.test.mjs','staging/outcome-atomicity-v279.test.mjs']);
run('native-standalone',['native-staging/standalone-schema-v279.mjs']);
run('native-parallel',['--test','native-staging/native-postgres-v281.test.mjs']);
run('one-native-reader',['--test','native-staging/one-session-reader-v295.test.mjs']);
run('one-signed-source',['--test','native-staging/one-signed-source-v296.test.mjs']);
const evidenceFiles=['STAGING-RESULT-v276.json','TRANSACTION-OUTCOME-RESULT-v279.json',
  'NATIVE-STANDALONE-RESULT-v279.json','NATIVE-STAGING-RESULT-v281.json','ONE-NATIVE-RESULT-v295.json','ONE-SIGNED-NATIVE-RESULT-v296.json'];
for(const name of evidenceFiles){
  try{
    const bytes=readFileSync(join(root,name));
    JSON.parse(bytes);writeFileSync(join(output,name),bytes);
  }catch{report.phases.push({name:'required-evidence:'+name,result:'FAIL'});}
}
try{
  const native=JSON.parse(readFileSync(join(output,'NATIVE-STAGING-RESULT-v281.json')));
  if(native.nativeScenarioCount!==11||native.scenarios.length!==11||native.scenarios.some(x=>x.result!=='PASS'))
    report.phases.push({name:'native-scenario-completeness',result:'FAIL'});
}catch{/* Missing evidence already marks this run failed. */}
try{
  const one=JSON.parse(readFileSync(join(output,'ONE-NATIVE-RESULT-v295.json')));
  if(one.scenarioCount!==6||one.scenarios.length!==6||one.scenarios.some(x=>x.result!=='PASS'))
    report.phases.push({name:'one-native-scenario-completeness',result:'FAIL'});
}catch{/* Missing evidence already marks this run failed. */}
try{
  const signed=JSON.parse(readFileSync(join(output,'ONE-SIGNED-NATIVE-RESULT-v296.json')));
  if(signed.scenarioCount!==7||signed.scenarios.length!==7||signed.scenarios.some(x=>x.result!=='PASS')||signed.originalRioRouteExecuted!==true)
    report.phases.push({name:'one-signed-source-completeness',result:'FAIL'});
}catch{/* Missing evidence already marks this run failed. */}
report.finishedAt=new Date().toISOString();
report.result=report.phases.every(x=>x.result==='PASS')?'PASS':'FAIL';
writeFileSync(join(output,'CI-RESULT-v296.json'),JSON.stringify(report,null,2)+'\n');
process.stdout.write(JSON.stringify(report,null,2)+'\n');
if(report.result!=='PASS')process.exitCode=1;
