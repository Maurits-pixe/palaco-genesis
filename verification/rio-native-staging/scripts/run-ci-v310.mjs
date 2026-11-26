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
      item.name.endsWith('-RESULT-v276.json')||['NATIVE-STAGING-RESULT-v281.json','ONE-NATIVE-RESULT-v295.json','ONE-SIGNED-NATIVE-RESULT-v296.json','SIGNED-ONE-COMPOSITION-NATIVE-RESULT-v297.json','ONE-STATEMENT-ISSUER-NATIVE-RESULT-v298.json','SOFTWARE-SIGNER-NATIVE-RESULT-v299.json','DRAINABLE-SIGNER-NATIVE-RESULT-v300.json','SIGNER-HANDOVER-NATIVE-RESULT-v301.json','KEY-CHECKED-HANDOVER-NATIVE-RESULT-v302.json','REGISTRY-CHECKED-HANDOVER-NATIVE-RESULT-v303.json','CANCELLABLE-HANDOVER-NATIVE-RESULT-v304.json','REPORTING-HANDOVER-NATIVE-RESULT-v305.json','SCOPED-HANDOVER-NATIVE-RESULT-v306.json','HISTORY-BOUND-HANDOVER-NATIVE-RESULT-v307.json','INSPECTION-SERVICE-NATIVE-RESULT-v308.json','MANAGED-INSPECTION-NATIVE-RESULT-v309.json','HOST-LIFECYCLE-NATIVE-RESULT-v310.json','native-standalone-transcript-v279.txt'].includes(item.name))continue;
    const path=join(dir,item.name);
    if(item.isDirectory())inventory(path);
    else if(item.isFile())sources[relative(root,path)]=hash(readFileSync(path));
  }
}
inventory(root);
const report={format:'rio-inspection-host-lifecycle-ci-result-v310',startedAt:new Date().toISOString(),
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
run('signed-one-entry',['--test','native-staging/signed-one-composition-v297.test.mjs']);
run('one-statement-issuer',['--test','native-staging/one-statement-issuer-v298.test.mjs']);
run('software-signer',['--test','native-staging/restricted-software-signer-v299.test.mjs']);
run('drainable-signer',['--test','native-staging/drainable-software-signer-v300.test.mjs']);
run('signer-handover',['--test','native-staging/signer-handover-v301.test.mjs']);
run('key-checked-handover',['--test','native-staging/key-checked-handover-v302.test.mjs']);
run('registry-checked-handover',['--test','native-staging/registry-checked-handover-v303.test.mjs']);
run('cancellable-handover',['--test','native-staging/cancellable-handover-v304.test.mjs']);
run('reporting-handover',['--test','native-staging/reporting-handover-v305.test.mjs']);
run('scoped-handover',['--test','native-staging/scoped-handover-v306.test.mjs']);
run('history-bound-handover',['--test','native-staging/history-bound-handover-v307.test.mjs']);
run('inspection-service',['--test','native-staging/inspection-service-v308.test.mjs']);
run('managed-inspection-service',['--test','native-staging/managed-inspection-service-v309.test.mjs']);
run('inspection-host-lifecycle',['--test','native-staging/inspection-host-lifecycle-v310.test.mjs']);
const evidenceFiles=['STAGING-RESULT-v276.json','TRANSACTION-OUTCOME-RESULT-v279.json',
  'NATIVE-STANDALONE-RESULT-v279.json','NATIVE-STAGING-RESULT-v281.json','ONE-NATIVE-RESULT-v295.json','ONE-SIGNED-NATIVE-RESULT-v296.json','SIGNED-ONE-COMPOSITION-NATIVE-RESULT-v297.json','ONE-STATEMENT-ISSUER-NATIVE-RESULT-v298.json','SOFTWARE-SIGNER-NATIVE-RESULT-v299.json','DRAINABLE-SIGNER-NATIVE-RESULT-v300.json','SIGNER-HANDOVER-NATIVE-RESULT-v301.json','KEY-CHECKED-HANDOVER-NATIVE-RESULT-v302.json','REGISTRY-CHECKED-HANDOVER-NATIVE-RESULT-v303.json','CANCELLABLE-HANDOVER-NATIVE-RESULT-v304.json','REPORTING-HANDOVER-NATIVE-RESULT-v305.json','SCOPED-HANDOVER-NATIVE-RESULT-v306.json','HISTORY-BOUND-HANDOVER-NATIVE-RESULT-v307.json','INSPECTION-SERVICE-NATIVE-RESULT-v308.json','MANAGED-INSPECTION-NATIVE-RESULT-v309.json','HOST-LIFECYCLE-NATIVE-RESULT-v310.json'];
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
try{
  const entry=JSON.parse(readFileSync(join(output,'SIGNED-ONE-COMPOSITION-NATIVE-RESULT-v297.json')));
  if(entry.scenarioCount!==2||entry.scenarios.length!==2||entry.scenarios.some(x=>x.result!=='PASS')||entry.centralFactoryRouteExecuted!==true)
    report.phases.push({name:'central-entry-completeness',result:'FAIL'});
}catch{/* Missing evidence already marks this run failed. */}
try{
  const issuer=JSON.parse(readFileSync(join(output,'ONE-STATEMENT-ISSUER-NATIVE-RESULT-v298.json')));
  if(issuer.scenarioCount!==4||issuer.scenarios.length!==4||issuer.scenarios.some(x=>x.result!=='PASS')||issuer.statementIssuerExecuted!==true)
    report.phases.push({name:'statement-issuer-completeness',result:'FAIL'});
}catch{/* Missing evidence already marks this run failed. */}
try{
  const signer=JSON.parse(readFileSync(join(output,'SOFTWARE-SIGNER-NATIVE-RESULT-v299.json')));
  if(signer.scenarioCount!==6||signer.scenarios.length!==6||signer.scenarios.some(x=>x.result!=='PASS')||signer.restrictedSoftwareSignerExecuted!==true||signer.runtimeKeyProtection?.webCryptoPrivateExportBlocked!==true)
    report.phases.push({name:'software-signer-completeness',result:'FAIL'});
}catch{/* Missing evidence already marks this run failed. */}
try{
  const lifecycle=JSON.parse(readFileSync(join(output,'DRAINABLE-SIGNER-NATIVE-RESULT-v300.json')));
  if(lifecycle.scenarioCount!==3||lifecycle.scenarios.length!==3||lifecycle.scenarios.some(x=>x.result!=='PASS')||lifecycle.drainableSoftwareSignerExecuted!==true||lifecycle.stoppedState!=='STOPPED'||lifecycle.authorityUnaffectedObserved!==true)
    report.phases.push({name:'draining-lifecycle-completeness',result:'FAIL'});
}catch{/* Missing evidence already marks this run failed. */}
try{
  const handover=JSON.parse(readFileSync(join(output,'SIGNER-HANDOVER-NATIVE-RESULT-v301.json')));
  if(handover.scenarioCount!==4||handover.scenarios.length!==4||handover.scenarios.some(x=>x.result!=='PASS')||
    handover.handoverControllerExecuted!==true||handover.retiredBeforeReplacementObserved!==true||
    handover.installedGeneration!==2||handover.stableRouteReused!==true||handover.closedState!=='CLOSED'||
    handover.authorityUnaffectedObserved!==true)
    report.phases.push({name:'signer-handover-completeness',result:'FAIL'});
}catch{/* Missing evidence already marks this run failed. */}
try{
  const checked=JSON.parse(readFileSync(join(output,'KEY-CHECKED-HANDOVER-NATIVE-RESULT-v302.json')));
  if(checked.scenarioCount!==5||checked.scenarios.length!==5||checked.scenarios.some(x=>x.result!=='PASS')||
    checked.keyCheckedHandoverExecuted!==true||checked.initialKeyCorrespondence!=='VERIFIED_AT_INSTALL'||
    checked.mismatchedReplacementRefused!==true||checked.registryReadiness!=='NOT_CHECKED'||
    checked.installedGeneration!==2||checked.stableRouteReused!==true||checked.closedState!=='CLOSED'||
    checked.closedDuringKeyProof!==true||checked.authorityUnaffectedObserved!==true)
    report.phases.push({name:'key-checked-handover-completeness',result:'FAIL'});
}catch{/* Missing evidence already marks this run failed. */}
try{
  const registry=JSON.parse(readFileSync(join(output,'REGISTRY-CHECKED-HANDOVER-NATIVE-RESULT-v303.json')));
  if(registry.scenarioCount!==6||registry.scenarios.length!==6||registry.scenarios.some(x=>x.result!=='PASS')||
    registry.registryCheckedHandoverExecuted!==true||registry.initialRegistryRevision!==1||
    registry.revokedCandidateRefused!==true||registry.changedRegistryCandidateRefused!==true||
    registry.registryReadiness!=='VERIFIED_AT_INSTALL'||registry.installedRegistryRevision!==5||
    registry.installedGeneration!==2||registry.stableRouteReused!==true||registry.closedState!=='CLOSED'||
    registry.closedDuringRegistryLookup!==true||registry.sessionAuthorityUnaffectedObserved!==true||
    registry.keyRegistryRevisionAtEnd!==5)
    report.phases.push({name:'registry-checked-handover-completeness',result:'FAIL'});
}catch{/* Missing evidence already marks this run failed. */}
try{
  const cancellation=JSON.parse(readFileSync(join(output,'CANCELLABLE-HANDOVER-NATIVE-RESULT-v304.json')));
  if(cancellation.scenarioCount!==6||cancellation.scenarios.length!==6||cancellation.scenarios.some(x=>x.result!=='PASS')||
    cancellation.cancellableHandoverExecuted!==true||cancellation.cancelledBeforeProof!==true||
    cancellation.cancelledAfterProof!==true||cancellation.staleCancellationRefused!==true||cancellation.attemptIdsDistinct!==true||
    !Number.isSafeInteger(cancellation.firstCancellationAttemptId)||cancellation.firstCancellationAttemptId<1||
    !(cancellation.secondCancellationAttemptId>cancellation.firstCancellationAttemptId)||
    !(cancellation.installedAttemptId>cancellation.secondCancellationAttemptId)||
    cancellation.installedGeneration!==2||cancellation.stableRouteReused!==true||cancellation.closedState!=='CLOSED'||
    cancellation.authorityUnaffectedObserved!==true)
    report.phases.push({name:'cancellable-handover-completeness',result:'FAIL'});
}catch{/* Missing evidence already marks this run failed. */}
try{
  const reporting=JSON.parse(readFileSync(join(output,'REPORTING-HANDOVER-NATIVE-RESULT-v305.json')));
  if(reporting.scenarioCount!==6||reporting.scenarios.length!==6||reporting.scenarios.some(x=>x.result!=='PASS')||
    reporting.reportingHandoverExecuted!==true||reporting.noPrematureResultObserved!==true||
    reporting.databaseErrorCodeObserved!=='42P01'||reporting.cancelledResult?.outcome!=='WITHHELD_AFTER_CANCELLATION'||
    reporting.failedResult?.outcome!=='CHECK_FAILED'||reporting.installedResult?.outcome!=='INSTALLED'||
    reporting.closedResult?.outcome!=='WITHHELD_AFTER_CLOSE'||
    [reporting.cancelledResult,reporting.failedResult,reporting.installedResult,reporting.closedResult].some(x=>x?.completion!=='COMPLETED')||
    reporting.installedResult?.resultingGeneration!==2||reporting.closedResult?.attemptId!==reporting.closedStatus?.lastCompletedAttemptId||
    reporting.closedStatus?.candidateChecksInFlight!==0||reporting.closedStatus?.state!=='CLOSED'||
    reporting.stableRouteReused!==true||reporting.authorityUnaffectedObserved!==true)
    report.phases.push({name:'reporting-handover-completeness',result:'FAIL'});
}catch{/* Missing evidence already marks this run failed. */}
try{
  const scoped=JSON.parse(readFileSync(join(output,'SCOPED-HANDOVER-NATIVE-RESULT-v306.json')));
  if(scoped.scenarioCount!==6||scoped.scenarios.length!==6||scoped.scenarios.some(x=>x.result!=='PASS')||
    scoped.scopedHandoverExecuted!==true||scoped.foreignRetirementRefused!==true||scoped.foreignInstallationRefused!==true||
    scoped.foreignCancellationRefused!==true||scoped.matchingLocalNumbersObserved!==true||scoped.completedScopesMatch!==true||
    scoped.newLifetimeRefusalObserved!==true||scoped.controllerIds?.length!==3||new Set(scoped.controllerIds).size!==3||
    scoped.cancelledResults?.length!==2||scoped.cancelledResults.some(x=>x.completion!=='COMPLETED'||x.outcome!=='WITHHELD_AFTER_CANCELLATION')||
    scoped.cancelledResults[0]?.controllerId!==scoped.controllerIds[0]||scoped.cancelledResults[1]?.controllerId!==scoped.controllerIds[1]||
    scoped.installedResult?.controllerId!==scoped.controllerIds[0]||scoped.installedResult?.resultingGeneration!==2||
    scoped.closedResult?.controllerId!==scoped.controllerIds[2]||scoped.closedStatus?.controllerId!==scoped.controllerIds[2]||
    scoped.closedResult?.attemptId!==scoped.closedStatus?.lastCompletedAttemptId||scoped.closedStatus?.candidateChecksInFlight!==0||
    scoped.stableRouteReused!==true||scoped.authorityUnaffectedObserved!==true)
    report.phases.push({name:'scoped-handover-completeness',result:'FAIL'});
}catch{report.phases.push({name:'scoped-handover-evidence-invalid',result:'FAIL'});}
try{
  const history=JSON.parse(readFileSync(join(output,'HISTORY-BOUND-HANDOVER-NATIVE-RESULT-v307.json')));
  if(history.scenarioCount!==6||history.scenarios.length!==6||history.scenarios.some(x=>x.result!=='PASS')||
    history.historyBoundHandoverExecuted!==true||history.cancelledStaleCommandRefused!==true||history.failedStaleCommandRefused!==true||
    history.sameGenerationStateObserved!==true||history.noStaleRegistryWorkObserved!==true||history.databaseErrorCodeObserved!=='42P01'||
    history.cancelledResult?.previousCompletedAttemptId!==null||history.failedResult?.previousCompletedAttemptId!==history.cancelledResult?.attemptId||
    history.installedResult?.previousCompletedAttemptId!==history.failedResult?.attemptId||history.closedResult?.previousCompletedAttemptId!==history.installedResult?.attemptId||
    history.cancelledResult?.outcome!=='WITHHELD_AFTER_CANCELLATION'||history.failedResult?.outcome!=='CHECK_FAILED'||
    history.installedResult?.outcome!=='INSTALLED'||history.installedResult?.resultingGeneration!==2||history.closedResult?.outcome!=='WITHHELD_AFTER_CLOSE'||
    [history.cancelledResult,history.failedResult,history.installedResult,history.closedResult].some(x=>x?.completion!=='COMPLETED')||
    history.closedResult?.attemptId!==history.closedStatus?.lastCompletedAttemptId||history.closedStatus?.candidateChecksInFlight!==0||
    history.stableRouteReused!==true||history.authorityUnaffectedObserved!==true)
    report.phases.push({name:'history-bound-handover-completeness',result:'FAIL'});
}catch{report.phases.push({name:'history-bound-handover-evidence-invalid',result:'FAIL'});}
try{
  const service=JSON.parse(readFileSync(join(output,'INSPECTION-SERVICE-NATIVE-RESULT-v308.json')));
  if(service.scenarioCount!==6||service.scenarios.length!==6||service.scenarios.some(x=>x.result!=='PASS')||
    service.singleServiceFactoryExecuted!==true||service.completedChainObserved!==true||service.initialRegistryReads!==2||
    service.missingAuthenticatedSessionRefused!==true||service.signerControlCancellationObserved!==true||
    service.staleContextRefused!==true||service.alternateRegistryRejected!==true||service.singleRegistryUsedForReplacement!==true||
    service.sameInspectionPortReused!==true||service.closeRemainsSignerScoped!==true||service.authorityUnaffectedObserved!==true||
    service.cancelledResult?.outcome!=='WITHHELD_AFTER_CANCELLATION'||service.installedResult?.outcome!=='INSTALLED'||
    service.installedResult?.previousCompletedAttemptId!==service.cancelledResult?.attemptId||service.installedResult?.resultingGeneration!==2||
    service.serviceSurface?.inspection?.includes('signSessionStatement')||service.serviceSurface?.signerControl?.includes('signSessionStatement'))
    report.phases.push({name:'inspection-service-completeness',result:'FAIL'});
}catch{report.phases.push({name:'inspection-service-evidence-invalid',result:'FAIL'});}
try{
  const managed=JSON.parse(readFileSync(join(output,'MANAGED-INSPECTION-NATIVE-RESULT-v309.json')));
  const flags=['managedFactoryExecuted','completedChainObserved','sameInspectionPortReused',
    'actualConnectionHeldAfterDeadline','deadlineDidNotDrain','closeWaitedForConnectionRelease',
    'postCloseProviderWorkRefused','actualConnectionReleasedBeforeCompletion',
    'closeWaitedForReplacementAssessment','authorityUnaffectedObserved','terminalCompletionObserved'];
  if(managed.scenarioCount!==6||managed.scenarios.length!==6||managed.scenarios.some(x=>x.result!=='PASS')||
    flags.some(k=>managed[k]!==true)||managed.installedGeneration!==2||
    managed.closedReplacementResult?.outcome!=='WITHHELD_AFTER_CLOSE'||
    managed.closedReplacementResult?.resultingGeneration!==1||
    [managed.closedStatus,managed.candidateClosedStatus].some(x=>x?.state!=='CLOSED'||
      x.inFlightInspections!==0||x.readerCancellationsInFlight!==0||x.signer?.backendState!=='STOPPED'||
      x.signer?.candidateChecksInFlight!==0||x.signer?.inFlight!==0)||
    managed.serviceSurface?.inspection?.includes('close')||
    managed.serviceSurface?.control?.includes('signSessionStatement'))
    report.phases.push({name:'managed-inspection-service-completeness',result:'FAIL'});
}catch{report.phases.push({name:'managed-inspection-service-evidence-invalid',result:'FAIL'});}
try{
  const host=JSON.parse(readFileSync(join(output,'HOST-LIFECYCLE-NATIVE-RESULT-v310.json')));
  const flags=['hostFactoryExecuted','httpToSqlChainExecuted','httpDeadlineBeforeActualRelease',
    'newWorkRefusedBeforeProviders','actualHttpListenerStopped','resourceReleaseWithheldWhileDrainPending',
    'serviceClosedBeforeResourceRelease','actualResourceConnectionReleased','singleReleaseObserved',
    'stopFailureHeld','disposalSkippedAfterStopFailure','releaseFailureHeld','partialResourceEffectObserved',
    'noAutomaticRetryObserved','authorityUnaffectedObserved'];
  if(host.scenarioCount!==6||host.scenarios.length!==6||host.scenarios.some(x=>x.result!=='PASS')||
    flags.some(k=>host[k]!==true)||host.loopbackHttpTransport!==true||host.productionHostBridgeImplemented!==false||
    host.transportTlsVerified!==false||host.closedStatus?.state!=='CLOSED'||
    ['httpAdmissionStop','serviceDrain','hostResourceRelease'].some(k=>host.closedStatus?.[k]!=='COMPLETED')||
    host.stopFailureStatus?.state!=='HELD'||host.stopFailureStatus?.hostResourceRelease!=='NOT_STARTED'||
    host.releaseFailureStatus?.state!=='HELD'||host.releaseFailureStatus?.hostResourceRelease!=='NOT_CONFIRMED'||
    host.serviceClosedStatus?.state!=='CLOSED'||host.serviceClosedStatus?.inFlightInspections!==0||
    host.serviceClosedStatus?.readerCancellationsInFlight!==0||host.serviceClosedStatus?.signer?.inFlight!==0||
    host.serviceClosedStatus?.signer?.candidateChecksInFlight!==0||host.serviceClosedStatus?.signer?.backendState!=='STOPPED'||
    host.hostSurface?.inspection?.includes('close')||host.hostSurface?.control?.includes('signSessionStatement')||
    JSON.stringify(host.shutdownOrder)!==JSON.stringify(['STOP_BEGIN','STOP_COMPLETED','RELEASE_BEGIN','RELEASE_COMPLETED']))
    report.phases.push({name:'inspection-host-lifecycle-completeness',result:'FAIL'});
}catch{report.phases.push({name:'inspection-host-lifecycle-evidence-invalid',result:'FAIL'});}
report.finishedAt=new Date().toISOString();
report.result=report.phases.every(x=>x.result==='PASS')?'PASS':'FAIL';
writeFileSync(join(output,'CI-RESULT-v310.json'),JSON.stringify(report,null,2)+'\n');
process.stdout.write(JSON.stringify(report,null,2)+'\n');
if(report.result!=='PASS')process.exitCode=1;

