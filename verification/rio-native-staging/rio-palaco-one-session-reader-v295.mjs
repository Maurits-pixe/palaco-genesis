/**
 * Trusted-host session port, DRAFT. The current One gateway cannot supply it.
 * An authenticated One service must supply the session; pending intents, browser
 * claims and fixture cookies are not authentication. No sessions are issued.
 */
const ID=/^[A-Za-z0-9_-]{1,128}$/;
const REF=/^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/;
const CREDENTIAL=/^[A-Za-z0-9_-]{16,1366}$/;
const HEX=/^[a-f0-9]{64}$/;
export const RIO_ONE_SESSION_FORMAT_V295='palaco-one-authenticated-host-session-v295-DRAFT';
const KEYS=['format','state','assurance','tenantRef','subjectId','sessionRef',
  'credentialId','ppReference','deviceBindingSha256','subjectEpoch','sessionEpoch',
  'revocationRevision','ppRegistryRevision','issuedAt','expiresAt','observedAt'];
const positive=n=>Number.isSafeInteger(n)&&n>0;
const generation=value=>{
  if(typeof value==='string'&&!/^[1-9][0-9]*$/.test(value))return null;
  if(typeof value!=='string'&&typeof value!=='number')return null;
  const n=Number(value);return positive(n)?n:null;
};
const instant=value=>typeof value==='string'&&Number.isFinite(Date.parse(value))?Date.parse(value):NaN;
function clock(now){const d=now();if(!(d instanceof Date)||!Number.isFinite(d.getTime()))throw Error('CLOCK_REQUIRED');return d.getTime();}
function validAt(s,at,age){
  const issued=instant(s.issuedAt),expires=instant(s.expiresAt),observed=instant(s.observedAt);
  return Number.isFinite(issued)&&Number.isFinite(expires)&&Number.isFinite(observed)&&
    issued<=observed&&observed<=at&&at-observed<=age&&issued<=at&&at<expires&&issued<expires;
}
function snapshot(value,tenantRef,at,age){
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length!==KEYS.length||
    !KEYS.every(k=>Object.hasOwn(value,k)))return null;
  const s=Object.freeze(Object.fromEntries(KEYS.map(k=>[k,value[k]])));
  return s.format===RIO_ONE_SESSION_FORMAT_V295&&s.state==='ACTIVE'&&s.assurance==='SERVER_AUTHENTICATED'&&
    s.tenantRef===tenantRef&&ID.test(s.subjectId)&&typeof s.subjectId==='string'&&
    ID.test(s.sessionRef)&&typeof s.sessionRef==='string'&&typeof s.credentialId==='string'&&CREDENTIAL.test(s.credentialId)&&
    typeof s.ppReference==='string'&&REF.test(s.ppReference)&&typeof s.deviceBindingSha256==='string'&&HEX.test(s.deviceBindingSha256)&&
    ['subjectEpoch','sessionEpoch','revocationRevision','ppRegistryRevision'].every(k=>positive(s[k]))&&validAt(s,at,age)?s:null;
}

export const RIO_ONE_READER_SECURITY_QUERY_V295=`SELECT current_user AS principal, session_user AS login_principal,
  current_setting('transaction_isolation') AS isolation,
  current_setting('transaction_read_only') AS read_only,r.rolsuper,r.rolbypassrls,
  (SELECT count(*)::integer FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE (n.nspname,c.relname) IN (
      ('palaco_login_v94','pp_passkey_bindings_v96'),('palaco_login_v94','subject_session_security'),
      ('palaco_session_v99','session_security_epochs'))
      AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity
      AND c.relowner<>r.oid
      AND has_table_privilege(current_user,c.oid,'SELECT')
      AND NOT has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE')) AS safe_source_tables
  FROM pg_roles r WHERE r.rolname=current_user`;
export const RIO_ONE_CURRENT_SECURITY_QUERY_V295=`SELECT b.ownership_state,b.registry_revision,
  s.revocation_state AS subject_state,s.session_epoch AS subject_epoch,
  e.revocation_state AS credential_state,e.session_epoch,e.revocation_revision,e.device_binding_sha256
  FROM palaco_login_v94.pp_passkey_bindings_v96 b
  JOIN palaco_login_v94.subject_session_security s
    ON s.tenant_reference=b.tenant_reference AND s.subject_reference=b.subject_reference
  JOIN palaco_session_v99.session_security_epochs e
    ON e.tenant_reference=b.tenant_reference AND e.subject_reference=b.subject_reference
      AND e.pp_reference=b.pp_reference AND e.credential_id_base64url=b.credential_id_base64url
  WHERE b.tenant_reference=$1 AND b.subject_reference=$2 AND b.pp_reference=$3
    AND b.credential_id_base64url=$4`;
function one(result){return result?.rowCount===1&&result?.rows?.length===1?result.rows[0]:null;}
function sameSecurity(row,s){
  return row&&row.ownership_state==='VERIFIED'&&row.subject_state==='ACTIVE'&&row.credential_state==='ACTIVE'&&
    generation(row.registry_revision)===s.ppRegistryRevision&&generation(row.subject_epoch)===s.subjectEpoch&&
    generation(row.session_epoch)===s.sessionEpoch&&generation(row.revocation_revision)===s.revocationRevision&&
    row.device_binding_sha256===s.deviceBindingSha256;
}

export function createRioOneSessionReaderV295({tenantRef,authenticateOneRequest,acquireOneReadConnection,
  now,maxObservationAgeMs=1000}={}){
  if(typeof tenantRef!=='string'||!ID.test(tenantRef)||
    [authenticateOneRequest,acquireOneReadConnection,now].some(f=>typeof f!=='function')||
    !Number.isSafeInteger(maxObservationAgeMs)||maxObservationAgeMs<1||maxObservationAgeMs>5000)
    throw TypeError('TRUSTED_ONE_SESSION_DEPENDENCIES_REQUIRED');
  const pinned=new WeakMap();
  async function checkSecurity(session){
    let connection,open=false,discard=false,valid=false,clean=true;
    try{
      // The trusted port must return an exclusively owned reader connection.
      connection=await acquireOneReadConnection();
      if(typeof connection?.query!=='function'||typeof connection?.release!=='function')throw Error('READER_PORT_REQUIRED');
      await connection.query('BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY');open=true;
      const role=one(await connection.query(RIO_ONE_READER_SECURITY_QUERY_V295));
      if(!role||!role.principal||role.principal!==role.login_principal||role.rolsuper!==false||role.rolbypassrls!==false||
        role.isolation!=='read committed'||role.read_only!=='on'||role.safe_source_tables!==3)throw Error('UNSAFE_READER');
      valid=sameSecurity(one(await connection.query(RIO_ONE_CURRENT_SECURITY_QUERY_V295,
        [tenantRef,session.subjectId,session.ppReference,session.credentialId])),session);
      await connection.query('ROLLBACK');open=false;
    }catch{valid=false;discard=true;}
    finally{
      if(open){try{await connection.query('ROLLBACK');}catch{discard=true;}}
      if(connection){try{await connection.release(discard?new Error('DISCARD_ONE_READER'):undefined);}catch{clean=false;}}
    }
    return valid&&clean;
  }
  async function authenticateHostRequest(request){
    if(!(request instanceof Request))return null;
    if(pinned.has(request)&&pinned.get(request)===null)return null;
    try{
      const started=clock(now);
      const session=snapshot(await authenticateOneRequest(request),tenantRef,clock(now),maxObservationAgeMs);
      if(!session)throw Error('AUTHENTICATED_SESSION_UNAVAILABLE');
      // Pin the full security tuple for this Request, not merely one numeric epoch.
      // Only observedAt may change during the host adapter's mandatory recheck.
      const binding=JSON.stringify(KEYS.filter(k=>k!=='observedAt').map(k=>session[k]));
      if(pinned.has(request)&&pinned.get(request)!==binding)throw Error('REQUEST_SESSION_CHANGED');
      if(!await checkSecurity(session))throw Error('ONE_SECURITY_UNCONFIRMED');
      const finished=clock(now);
      if(finished<started||!validAt(session,finished,maxObservationAgeMs))throw Error('SESSION_EXPIRED_DURING_READ');
      // Another concurrent check of this same Request may already have denied it.
      if(pinned.has(request)&&pinned.get(request)!==binding)throw Error('REQUEST_SESSION_CHANGED');
      pinned.set(request,binding);
      return Object.freeze({state:'ACTIVE',assurance:'HOST_VERIFIED',tenantRef,
        subjectId:session.subjectId,sessionRef:session.sessionRef,sessionGeneration:session.sessionEpoch});
    }catch{pinned.set(request,null);return null;}
  }
  return Object.freeze({authenticateHostRequest,mode:'TRUSTED_HOST_READ_ONLY_DRAFT',
    oneGatewayV16Compatible:false,requiresAuthenticatedOneService:true,
    acceptance:'HOLD',authorization:'NONE',productionReady:false,sessionIssuance:false});
}
