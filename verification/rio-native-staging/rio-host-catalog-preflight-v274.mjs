/** Metadata-only host preparation. No row reads, migrations or authorization. */
const DEFINITIONS = Object.freeze([
  ['rio_audit_keys', 'verification_keys', ['key_id','algorithm','public_key_pem','spki_sha256','status','not_before','not_after','revoked_at']],
  ['rio_identity_gate', 'revocation_requests', ['request_id','request_payload','status','result_generation','recorded_at']],
  ['rio_identity_gate', 'session_generation', ['session_ref','subject_id','generation','active','updated_at']],
  ['rio_identity_gate', 'review_policy_generation', ['subject_id','conversation_id','dossier_id','generation','review_permitted','updated_at']],
  ['auth', 'users', null], ['auth', 'sessions', null],
].map(([schema, name, columns]) => Object.freeze({schema, name,
  columns: columns === null ? null : Object.freeze(columns)})));
const BOUNDARIES = Object.freeze({acceptance:'HOLD',authorization:'NONE',integrationReady:false,
  productionReady:false,mayExecute:false,mayMigrate:false,mayRollback:false,mayDelete:false});
export const RIO_HOST_CATALOG_QUERY_V274 = `WITH wanted(schema_name,object_name) AS (
  VALUES ('rio_audit_keys','verification_keys'),
         ('rio_identity_gate','revocation_requests'),
         ('rio_identity_gate','session_generation'),
         ('rio_identity_gate','review_policy_generation'),
         ('auth','users'),('auth','sessions')
)
SELECT w.schema_name,w.object_name,(c.oid IS NOT NULL) AS present,
       c.relkind::text AS object_kind,c.relrowsecurity AS rls_enabled,
       c.relforcerowsecurity AS force_rls,
       COALESCE((SELECT jsonb_agg(a.attname ORDER BY a.attnum)
                   FROM pg_catalog.pg_attribute a
                  WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),
                '[]'::jsonb) AS column_names,
       CASE WHEN c.oid IS NULL OR NOT EXISTS
         (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='anon') THEN NULL
         ELSE has_table_privilege('anon',c.oid,'SELECT') END AS anon_select,
       CASE WHEN c.oid IS NULL OR NOT EXISTS
         (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='authenticated') THEN NULL
         ELSE has_table_privilege('authenticated',c.oid,'SELECT') END AS authenticated_select
  FROM wanted w
  LEFT JOIN pg_catalog.pg_namespace n ON n.nspname=w.schema_name
  LEFT JOIN pg_catalog.pg_class c ON c.relnamespace=n.oid AND c.relname=w.object_name
 ORDER BY w.schema_name,w.object_name;`;
const fields = ['schema_name','object_name','present','object_kind','rls_enabled','force_rls',
  'column_names','anon_select','authenticated_select'];
const isObject = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const fail = reason => Object.freeze({ok:false,format:'rio-host-catalog-preflight-v274',
  inspectionStatus:'FAILED',state:'BLOCKED_UNVERIFIED_CATALOG',reason,
  providerVerification:'NOT_EXECUTED',...BOUNDARIES});
const iso = value => typeof value === 'string' && Number.isFinite(Date.parse(value)) &&
  new Date(value).toISOString() === value;
export function assessRioHostCatalogV274({catalogRows,projectReference,observedAt}={}) {
  if (typeof projectReference !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(projectReference) ||
      !iso(observedAt)) return fail('TRUSTED_OBSERVATION_CONTEXT_REQUIRED');
  if (!Array.isArray(catalogRows) || catalogRows.length !== DEFINITIONS.length) return fail('CATALOG_RESPONSE_INVALID');
  const rows = new Map();
  for (const r of catalogRows) {
    if (!isObject(r) || Object.keys(r).length !== fields.length || !fields.every(k=>Object.hasOwn(r,k)) ||
        typeof r.schema_name !== 'string' || typeof r.object_name !== 'string' ||
        typeof r.present !== 'boolean' || !Array.isArray(r.column_names) || r.column_names.length>256 ||
        !r.column_names.every(c=>typeof c==='string'&&/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(c)) ||
        new Set(r.column_names).size!==r.column_names.length) return fail('CATALOG_RESPONSE_INVALID');
    const definition=DEFINITIONS.find(d=>d.schema===r.schema_name&&d.name===r.object_name);
    const key=r.schema_name+'.'+r.object_name;
    if (!definition || rows.has(key)) return fail('CATALOG_RESPONSE_INVALID');
    if (r.present ? (typeof r.object_kind!=='string'||typeof r.rls_enabled!=='boolean'||
      typeof r.force_rls!=='boolean'||
      ![true,false,null].includes(r.anon_select)||![true,false,null].includes(r.authenticated_select)) :
      r.object_kind!==null||r.rls_enabled!==null||r.force_rls!==null||r.column_names.length!==0||
      r.anon_select!==null||r.authenticated_select!==null) return fail('CATALOG_RESPONSE_INVALID');
    rows.set(key,r);
  }
  const blockers=[], observations=[];
  for (const d of DEFINITIONS) {
    const key=d.schema+'.'+d.name, r=rows.get(key), required=d.columns!==null;
    const missingColumns=required&&r.present?d.columns.filter(c=>!r.column_names.includes(c)):[];
    const reasons=[];
    if (required) {
      if (!r.present) reasons.push('REQUIRED_OBJECT_MISSING');
      else {
        if (!['r','p'].includes(r.object_kind)) reasons.push('BASE_TABLE_REQUIRED');
        if (missingColumns.length) reasons.push('REQUIRED_COLUMNS_MISSING');
        if (r.anon_select!==false||r.authenticated_select!==false) reasons.push('CLIENT_READ_NOT_DENIED_OR_UNKNOWN');
      }
    }
    for (const reason of reasons) blockers.push(Object.freeze({objectName:key,reason}));
    observations.push(Object.freeze({objectName:key,classification:required?'REQUIRED_RIO':'CONTEXT_ONLY',
      present:r.present,objectKind:r.object_kind,rlsEnabled:r.rls_enabled,forceRls:r.force_rls,
      missingColumns:Object.freeze(missingColumns),anonSelect:r.anon_select,authenticatedSelect:r.authenticated_select}));
  }
  return Object.freeze({ok:blockers.length===0,format:'rio-host-catalog-preflight-v274',
    inspectionStatus:'EXECUTED',state:blockers.length?'HOST_SCHEMA_BLOCKED':'SCHEMA_METADATA_COMPATIBLE_PROVIDERS_UNVERIFIED',
    projectReference,observedAt,requiredObjectCount:4,
    missingRequiredObjectCount:observations.filter(o=>o.classification==='REQUIRED_RIO'&&!o.present).length,
    blockers:Object.freeze(blockers),observations:Object.freeze(observations),
    proofScope:'CATALOG_METADATA_ONLY_NOT_DATA_OR_PROVIDER_VALIDATION',
    providerVerification:'NOT_EXECUTED',...BOUNDARIES});
}
export function createRioHostCatalogPreflightV274({query,now,projectReference}={}) {
  if (typeof query!=='function'||typeof now!=='function'||typeof projectReference!=='string'||
      !/^[A-Za-z0-9_-]{1,128}$/.test(projectReference)) throw TypeError('TRUSTED_READ_ONLY_CATALOG_SOURCE_REQUIRED');
  async function inspect() {
    try {
      const at=now();
      if (!(at instanceof Date)||!Number.isFinite(at.getTime())) return fail('TRUSTED_CLOCK_UNAVAILABLE');
      const result=await query(RIO_HOST_CATALOG_QUERY_V274);
      return assessRioHostCatalogV274({catalogRows:result?.rows,projectReference,observedAt:at.toISOString()});
    } catch {return fail('CATALOG_QUERY_OR_CLOCK_FAILED');}
  }
  return Object.freeze({inspect,purpose:'READ_ONLY_SYSTEM_CATALOG_INSPECTION',...BOUNDARIES});
}
