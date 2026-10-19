// PALACO document exchange v1. Identical bounded data codec in each participant.
// Integrity of user-supplied bytes never grants identity, authorization or source truth.
export const SCHEMA = 'PALACO_DOCUMENT_EXCHANGE_V1';
export const MAX_BYTES = 16384;
export const REPOSITORIES = Object.freeze([
  'Maurits-pixe/PALACO', 'Maurits-pixe/palaco-genesis',
  'Maurits-pixe/PALACO-BOOK-1', 'Maurits-pixe/PALACO-INDUSTRIE',
  'Maurits-pixe/PALACO-Citadel', 'III6V9-Architect/local-qa',
]);
const statuses = ['draft', 'historisch', 'specificatie'];
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', {fatal:true});
const fail = () => { throw new Error('DOCUMENT_EXCHANGE_REJECTED'); };
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value,key));
const text = (value, max) => typeof value === 'string' && value.length > 0
  && value === value.trim() && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\ud800-\udfff]/u.test(value)
  && encoder.encode(value).length <= max;
const frozen = value => { for (const child of Object.values(value)) if (child && typeof child === 'object') frozen(child); return Object.freeze(value); };
export async function sha256(bytes) {
  if (!(bytes instanceof Uint8Array)) fail();
  return Array.from(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256',bytes)), n=>n.toString(16).padStart(2,'0')).join('');
}
export function sourceUrl(reference) {
  if (!exact(reference,['repository','commitSha','path']) || !REPOSITORIES.includes(reference.repository)
    || typeof reference.commitSha !== 'string' || !/^[a-f0-9]{40}$/.test(reference.commitSha) || !text(reference.path,240)
    || !/^[A-Za-z0-9._/-]+$/.test(reference.path)
    || reference.path.split('/').some(part=>!part || part==='.' || part==='..')) fail();
  return `https://github.com/${reference.repository}/blob/${reference.commitSha}/${reference.path}`;
}
function documentFields(document) {
  if (!exact(document,['documentId','title','content','status'])
    || typeof document.documentId !== 'string' || !/^[A-Za-z0-9_-]{1,80}$/.test(document.documentId)
    || !text(document.title,160) || !text(document.content,12000) || !statuses.includes(document.status)) fail();
  return {documentId:document.documentId,title:document.title,content:document.content,status:document.status};
}
function canonical(reference, document, contentSha256) {
  sourceUrl(reference);
  return {schema:SCHEMA,mode:'SYNTHETIC_ONLY',
    reference:{repository:reference.repository,commitSha:reference.commitSha,path:reference.path},
    document:documentFields(document),contentSha256,
    boundary:{operativeAuthority:'NONE',accountActive:false,canOpenContact:false,sourceVerified:false,statusProvidedBy:'USER'}};
}
export async function encodeDocument(reference, document) {
  sourceUrl(reference);
  const ref = {repository:reference.repository,commitSha:reference.commitSha,path:reference.path};
  const fields = documentFields(document);
  const digest = await sha256(encoder.encode(fields.content));
  const bytes = encoder.encode(JSON.stringify(canonical(ref,fields,digest)));
  if (bytes.length > MAX_BYTES) fail();
  return bytes;
}
export async function decodeDocument(input) {
  let bytes;
  if (typeof input === 'string') {
    if (input.length > MAX_BYTES || /[\ud800-\udfff]/u.test(input)) fail();
    bytes = encoder.encode(input);
  } else if (input instanceof Uint8Array) {
    if (input.length > MAX_BYTES) fail();
    bytes = Uint8Array.from(input); // Snapshot before asynchronous digest verification.
  } else fail();
  if (!bytes.length || bytes.length > MAX_BYTES) fail();
  try {
    const raw = decoder.decode(bytes), packet = JSON.parse(raw);
    if (!exact(packet,['schema','mode','reference','document','contentSha256','boundary'])
      || !exact(packet.boundary,['operativeAuthority','accountActive','canOpenContact','sourceVerified','statusProvidedBy'])
      || typeof packet.contentSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(packet.contentSha256)) fail();
    const expected = canonical(packet.reference,packet.document,await sha256(encoder.encode(documentFields(packet.document).content)));
    // This deliberately narrow canonical encoding rejects duplicate/unknown keys,
    // coercion, alternate encodings, reordered fields and authority promotion.
    if (raw !== JSON.stringify(expected)) fail();
    return frozen({...expected,origin:sourceUrl(expected.reference)});
  } catch { fail(); }
}
