/**
 * PALACO RIO v244 — trusted key registry resolver (server-only, read-only).
 * Requires a backend-owned PostgreSQL connection, not a client/anon role.
 * Keys from receipts, URLs, or browser payloads are NEVER trusted.
 */
import {createPublicKey,createHash} from 'node:crypto';

const ID=/^[A-Za-z0-9_-]{1,128}$/;
const ALG=new Set(['Ed25519','ES256','RS256']);
const HEX=/^[a-f0-9]{64}$/;
const ISO=v=>typeof v==='string' && !Number.isNaN(Date.parse(v)) &&
  new Date(v).toISOString()===v;
const safeTime=value=>value instanceof Date?value.toISOString():value;
function ensurePublicPem(pem,alg){
  if(typeof pem!=='string'||pem.length>8192||
     !pem.startsWith('-----BEGIN PUBLIC KEY-----'))throw Error('INVALID_PUBLIC_KEY');
  const key=createPublicKey(pem);
  if(key.type!=='public')throw Error('PRIVATE_KEY_FORBIDDEN');
  const valid=alg==='Ed25519'
    ?key.asymmetricKeyType==='ed25519'
    :alg==='ES256'
      ?key.asymmetricKeyType==='ec'&&key.asymmetricKeyDetails?.namedCurve==='prime256v1'
      :key.asymmetricKeyType==='rsa'&&
        Number.isSafeInteger(key.asymmetricKeyDetails?.modulusLength)&&
        key.asymmetricKeyDetails.modulusLength>=2048;
  if(!valid)throw Error('KEY_TYPE_MISMATCH');
  const der=key.export({type:'spki',format:'der'});
  return createHash('sha256').update(der).digest('hex');
}
export function createRioTrustedKeyResolverV244({
  query,now=()=>new Date()
}={}){
  if(typeof query!=='function')throw TypeError('TRUSTED_PG_READ_REQUIRED');
  async function resolveVerificationKey({keyId,algorithm}={}){
    if(typeof keyId!=='string'||!ID.test(keyId)||!ALG.has(algorithm))return null;
    try{
      const date=now();
      if(!(date instanceof Date)||!Number.isFinite(date.getTime()))return null;
      // Fail-closed: only ACTIVE and nonrevoked keys may be used.
      const result=await query(
        `SELECT key_id,algorithm,public_key_pem,spki_sha256,
                status,not_before,not_after,revoked_at
           FROM rio_audit_keys.verification_keys
          WHERE key_id=$1 AND algorithm=$2
          LIMIT 2`,[keyId,algorithm]);
      if(result?.rows?.length!==1)return null;
      const r=result.rows[0];
      if(r.key_id!==keyId||r.algorithm!==algorithm||
        r.status!=='ACTIVE'||r.revoked_at!==null||
        typeof r.spki_sha256!=='string'||!HEX.test(r.spki_sha256))return null;
      const before=safeTime(r.not_before),after=safeTime(r.not_after);
      if(!ISO(before)||!ISO(after)||
        Date.parse(before)>=Date.parse(after)||
        date.getTime()<Date.parse(before)||date.getTime()>=Date.parse(after))
        return null;
      if(ensurePublicPem(r.public_key_pem,algorithm)!==r.spki_sha256)return null;
      // Recheck registry row after async and crypto work; non-atomic with
      // later use; callers MUST recheck at the protected action boundary.
      const check=await query(
        `SELECT status,revoked_at,spki_sha256,not_before,not_after
           FROM rio_audit_keys.verification_keys
          WHERE key_id=$1 AND algorithm=$2 LIMIT 2`,[keyId,algorithm]);
      if(check?.rows?.length!==1)return null;
      const fresh=check.rows[0];
      if(fresh.status!=='ACTIVE'||fresh.revoked_at!==null||
        fresh.spki_sha256!==r.spki_sha256||
        safeTime(fresh.not_before)!==before||safeTime(fresh.not_after)!==after)return null;
      return Object.freeze({
        state:'ACTIVE',keyId,algorithm,revoked:false,
        publicKeyPem:r.public_key_pem,notBefore:before,notAfter:after
      });
    }catch{return null;}
  }
  return Object.freeze({resolveVerificationKey,
    mode:'TRUSTED_SERVER_READ_ONLY',authorization:'NONE'});
}
