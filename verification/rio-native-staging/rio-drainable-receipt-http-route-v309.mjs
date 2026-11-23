/**
 * Fetch-compatible inspection route with terminal admission and real-work draining.
 * Derived from v269; original route preserved unchanged.
 * No listener, publication, IdP, production keys or authorization supplied.
 */
import {createRioReceiptHostAdapterV267} from './rio-palaco-one-receipt-host-adapter-v267.mjs';

const RIO_RECEIPT_INSPECTION_PATH_V269 = '/api/rio/audit/receipt-inspection';
const MAX_BODY_BYTES = 32 * 1024;
const HEADERS = Object.freeze({
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'private, no-store, max-age=0',
  'Pragma': 'no-cache', 'Expires': '0',
  'X-Content-Type-Options': 'nosniff',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
});
const BOUNDARIES = Object.freeze({acceptance: 'HOLD', authorization: 'NONE', productionReady: false,
  mayExecute: false, mayMigrate: false, mayRollback: false, mayDelete: false, retriedRevocation: false});
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const exact = (v, keys) => object(v) && Object.keys(v).length === keys.length &&
  keys.every(key => Object.hasOwn(v, key));
function response(status, code, extra = {}) {
  return new Response(JSON.stringify({ok: status === 200, code, ...extra, ...BOUNDARIES}),
    {status, headers: status === 405 ? {...HEADERS, Allow: 'POST'} : HEADERS});
}
function prepare(options) {
  const issues = [];
  if (!exact(options, ['allowedOrigin', 'maxConcurrentInspections', 'requestTimeoutMs', 'host'])) {
    return {issues: ['EXACT_ROUTE_CONFIGURATION_REQUIRED']};
  }
  try {
    const url = new URL(options.allowedOrigin);
    if (typeof options.allowedOrigin !== 'string' || url.protocol !== 'https:' ||
        url.origin !== options.allowedOrigin || url.username || url.password || url.origin === 'null') {
      issues.push('ONE_EXACT_HTTPS_ORIGIN_REQUIRED');
    }
  } catch { issues.push('ONE_EXACT_HTTPS_ORIGIN_REQUIRED'); }
  if (!Number.isSafeInteger(options.maxConcurrentInspections) ||
      options.maxConcurrentInspections < 1 || options.maxConcurrentInspections > 16) {
    issues.push('INVALID_CONCURRENCY_LIMIT');
  }
  if (!Number.isSafeInteger(options.requestTimeoutMs) || options.requestTimeoutMs < 10 ||
      options.requestTimeoutMs > 30000) issues.push('INVALID_REQUEST_DEADLINE');
  if (issues.length) return {issues};
  let adapter;
  try { adapter = createRioReceiptHostAdapterV267(options.host); }
  catch { return {issues: ['HOST_CONFIGURATION_INVALID']}; }
  return {issues, adapter, allowedOrigin: options.allowedOrigin,
    maxConcurrentInspections: options.maxConcurrentInspections, requestTimeoutMs: options.requestTimeoutMs};
}
function preflight(issues) {
  return Object.freeze({ok: issues.length === 0, format: 'rio-drainable-receipt-route-preflight-v309',
    structuralStatus: issues.length === 0 ? 'STRUCTURALLY_VALIDATED' : 'BLOCKED',
    runtimeDependencyStatus: 'NOT_CHECKED', issues: Object.freeze([...issues]),
    providerCallsPerformed: false, listenerStarted: false,
    routePath: RIO_RECEIPT_INSPECTION_PATH_V269, maxBodyBytes: MAX_BODY_BYTES, ...BOUNDARIES});
}
export function inspectRioDrainableReceiptRouteConfigV309(options) {
  return preflight(prepare(options).issues);
}
export function createRioDrainableReceiptHttpRouteV309(options) {
  const setup = prepare(options);
  if (setup.issues.length) throw TypeError('RIO_ROUTE_PREFLIGHT_REJECTED:' + setup.issues.join(','));
  const {adapter, allowedOrigin, maxConcurrentInspections, requestTimeoutMs} = setup;
  let active = 0, readerCancellations = 0, state = 'OPEN', resolveClosed;
  const closed = new Promise(resolve => { resolveClosed = resolve; });
  function getStatus() {
    return Object.freeze({format:'rio-drainable-receipt-route-status-v309',state,
      inFlight:active,readerCancellationsInFlight:readerCancellations,
      capacity:maxConcurrentInspections,...BOUNDARIES});
  }
  function completeDrain() {
    if(state==='DRAINING'&&active===0&&readerCancellations===0) {
      state='CLOSED';resolveClosed(getStatus());
    }
  }
  function close() {
    if(state==='OPEN') {state='DRAINING';completeDrain();}
    return closed;
  }
  const unavailable = () => response(503,'INSPECTION_SERVICE_CLOSING');
  async function handle(request) {
    if(state!=='OPEN')return unavailable();
    if (!(request instanceof Request)) return response(400, 'INVALID_REQUEST');
    let url;
    try { url = new URL(request.url); } catch { return response(400, 'INVALID_REQUEST'); }
    if (url.pathname !== RIO_RECEIPT_INSPECTION_PATH_V269 || url.search || url.hash) {
      return response(404, 'ROUTE_NOT_FOUND');
    }
    if (url.origin !== allowedOrigin || request.headers.get('Origin') !== allowedOrigin ||
        request.headers.get('X-RIO-Inspection') !== '1' ||
        (request.headers.has('Sec-Fetch-Site') && request.headers.get('Sec-Fetch-Site') !== 'same-origin')) {
      return response(403, 'ORIGIN_CHECK_FAILED');
    }
    if (request.method !== 'POST') return response(405, 'POST_REQUIRED');
    if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers.get('Content-Type') ?? '') ||
        request.headers.has('Content-Encoding')) return response(415, 'JSON_UTF8_REQUIRED');
    const length = request.headers.get('Content-Length');
    if (length !== null && (!/^(0|[1-9][0-9]*)$/.test(length) || Number(length) > MAX_BODY_BYTES)) {
      return response(413, 'BODY_LIMIT_EXCEEDED');
    }
    if (request.signal.aborted) return response(408, 'REQUEST_ABORTED');
    if (request.bodyUsed || !request.body) return response(400, 'UNREAD_BODY_REQUIRED');
    // An unresolved stream cancellation also occupies admission capacity.
    if (active + readerCancellations >= maxConcurrentInspections) return response(503, 'INSPECTION_CAPACITY_REACHED');
    active++;
    let cancelled = false, reader, timer, onAbort, readerCancellationStarted = false;
    function cancelReader() {
      if (!reader || readerCancellationStarted) return;
      readerCancellationStarted = true; readerCancellations++;
      // Keep the cancellation callback in the drain barrier even if read() already ended.
      let work;try {work=reader.cancel();} catch {work=undefined;}
      void Promise.resolve(work).catch(()=>{}).finally(()=>{
        readerCancellations--;completeDrain();
      });
    }
    async function execute() {
      if (cancelled) return response(408, 'REQUEST_ABORTED');
      let input;
      try {
        reader = request.body.getReader();
        let size = 0;
        const chunks = [];
        while (true) {
          const item = await reader.read();
          if (item.done) break;
          if (!(item.value instanceof Uint8Array)) { cancelReader(); return response(400, 'INVALID_BODY_BYTES'); }
          size += item.value.byteLength;
          if (size > MAX_BODY_BYTES) { cancelReader(); return response(413, 'BODY_LIMIT_EXCEEDED'); }
          chunks.push(item.value.slice());
        }
        if (cancelled) return response(408, 'REQUEST_ABORTED');
        if (length !== null && Number(length) !== size) return response(400, 'BODY_LENGTH_MISMATCH');
        const bytes = new Uint8Array(size);
        let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
        input = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes));
      } catch { return response(400, 'INVALID_JSON_BODY'); }
      finally { try { reader?.releaseLock(); } catch {} }
      if (!exact(input, ['requestId', 'receiptJson']) || typeof input.requestId !== 'string' ||
          !/^[A-Za-z0-9_-]{1,128}$/.test(input.requestId) || typeof input.receiptJson !== 'string' ||
          input.receiptJson.length > 16384 || new TextEncoder().encode(input.receiptJson).length > 16384) {
        return response(400, 'INVALID_INSPECTION_INPUT');
      }
      if (cancelled) return response(408, 'REQUEST_ABORTED');
      const report = await adapter.inspect(request, input);
      if (!report.ok) return response(403, 'INSPECTION_NOT_CONFIRMED');
      if (report.authorization !== 'NONE' || report.acceptance !== 'HOLD' || report.productionReady !== false ||
          ['mayExecute', 'mayMigrate', 'mayRollback', 'mayDelete', 'retriedRevocation'].some(key => report[key] !== false)) {
        return response(503, 'INSPECTION_NOT_AVAILABLE');
      }
      return response(200, 'RECEIPT_INSPECTED', {
        format: 'rio-receipt-http-inspection-v309', state: report.state,
        algorithm: report.algorithm, sha256: report.sha256, inspectedAt: report.inspectedAt,
        signatureStatus: report.signatureStatus, authorityStatus: report.authorityStatus,
        domainBinding: report.domainBinding,
      });
    }
    const interrupted = new Promise(resolve => {
      timer = setTimeout(() => {
        cancelled = true; cancelReader(); resolve(response(504, 'INSPECTION_DEADLINE_REACHED'));
      }, requestTimeoutMs);
      onAbort = () => {
        cancelled = true; cancelReader(); resolve(response(408, 'REQUEST_ABORTED'));
      };
      request.signal.addEventListener('abort', onAbort, {once: true});
      if (request.signal.aborted) onAbort();
    });
    // A timed-out provider call cannot be cancelled by v267. Keep its slot
    // until it actually settles; do not accumulate unbounded background work.
    function detachInterrupts() {
      clearTimeout(timer); request.signal.removeEventListener('abort', onAbort);
    }
    const job = execute().catch(() => response(503, 'INSPECTION_NOT_AVAILABLE')).finally(() => {
      detachInterrupts(); active--; completeDrain();
    });
    try { const result=await Promise.race([job, interrupted]);return state==='OPEN'?result:unavailable(); }
    finally { detachInterrupts(); }
  }
  return Object.freeze({handle, getStatus, close, preflight: preflight([]), path: RIO_RECEIPT_INSPECTION_PATH_V269,
    purpose: 'READ_ONLY_RECEIPT_INSPECTION_ROUTE', ...BOUNDARIES});
}
