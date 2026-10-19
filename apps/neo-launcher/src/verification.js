export const PROTOCOL = 'palaco-app/v1'
export const MAX_AGE_MS = 60_000
const MAX_JSON_BYTES = 4096
const MAX_TIMEOUT_MS = 5000
const LOCAL_HTTP_ORIGINS = new Set([
  'http://127.0.0.1:5174',
  'http://127.0.0.1:5175',
])

export const TRUSTED_MODULES = Object.freeze([
  Object.freeze({
    id: 'aether',
    name: 'AETHER',
    origin: 'http://127.0.0.1:5174',
    manifestPath: '/verify/aether/.well-known/palaco-app.json',
    healthPath: '/verify/aether/health',
    description: 'Versleutelde records opslaan en teruglezen.',
  }),
  Object.freeze({
    id: 'bastion',
    name: 'BASTION',
    origin: 'http://127.0.0.1:5175',
    manifestPath: '/verify/bastion/.well-known/palaco-app.json',
    healthPath: '/verify/bastion/health',
    description: 'Tijdelijke tickets en een commandologboek.',
  }),
])

export function isAllowedOrigin(value) {
  try {
    const url = new URL(value)
    return value === url.origin && !url.username && !url.password &&
      (url.protocol === 'https:' || LOCAL_HTTP_ORIGINS.has(value))
  } catch {
    return false
  }
}

function trustedModule(module) {
  return TRUSTED_MODULES.find((candidate) => candidate === module)
}

export function validateManifest(manifest, module) {
  if (!trustedModule(module) || !manifest || typeof manifest !== 'object' ||
      Array.isArray(manifest) || Object.keys(manifest).length > 16 ||
      manifest.id !== module.id || manifest.name !== module.name ||
      manifest.protocol !== PROTOCOL) {
    throw new Error('Manifest komt niet overeen met de vaste moduleconfiguratie.')
  }
  return true
}

function abortable(promise, signal) {
  return new Promise((resolve, reject) => {
    const cleanup = () => signal.removeEventListener('abort', abort)
    const abort = () => {
      cleanup()
      reject(signal.reason)
    }
    if (signal.aborted) {
      abort()
    } else {
      signal.addEventListener('abort', abort, { once: true })
    }
    Promise.resolve(promise).then(
      (value) => { cleanup(); resolve(value) },
      (error) => { cleanup(); reject(error) },
    )
  })
}

function cancelBody(body) {
  try {
    Promise.resolve(body?.cancel()).catch(() => {})
  } catch {
    // Cancellation is best effort; it must never block local invalidation.
  }
}

async function boundedJson(response, signal) {
  if (!response.body || Number(response.headers.get('content-length')) > MAX_JSON_BYTES) {
    cancelBody(response.body)
    throw new Error('Ongeldig JSON-antwoord.')
  }
  const reader = response.body.getReader()
  const chunks = []
  let size = 0
  let cancelled = false
  const cancel = () => {
    if (cancelled) return
    cancelled = true
    cancelBody(reader)
  }
  signal.addEventListener('abort', cancel, { once: true })
  try {
    while (true) {
      signal.throwIfAborted()
      const { done, value } = await abortable(reader.read(), signal)
      signal.throwIfAborted()
      if (done) break
      size += value.byteLength
      if (size > MAX_JSON_BYTES) throw new Error('JSON-antwoord is te groot.')
      chunks.push(value)
    }
  } catch (error) {
    cancel()
    throw error
  } finally {
    signal.removeEventListener('abort', cancel)
    reader.releaseLock()
  }
  const bytes = new Uint8Array(size)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
}

export async function verifyModule(module, fetcher = fetch, timeoutMs = 5000, signal) {
  if (!trustedModule(module) || !isAllowedOrigin(module.origin)) {
    throw new Error('Moduleconfiguratie is niet toegestaan.')
  }
  const controller = new AbortController()
  const abort = () => controller.abort(signal.reason)
  if (signal?.aborted) abort()
  else signal?.addEventListener('abort', abort, { once: true })
  const budget = Number.isFinite(timeoutMs) && timeoutMs > 0
    ? Math.min(timeoutMs, MAX_TIMEOUT_MS) : MAX_TIMEOUT_MS
  const timer = setTimeout(() => controller.abort(), budget)
  async function fetchJson(path) {
    controller.signal.throwIfAborted()
    const request = Promise.resolve(fetcher(path, {
      redirect: 'error',
      cache: 'no-store',
      credentials: 'omit',
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    }))
    request.then((response) => {
      if (controller.signal.aborted) cancelBody(response.body)
    }).catch(() => {})
    const response = await abortable(request, controller.signal)
    if (controller.signal.aborted) {
      cancelBody(response.body)
      controller.signal.throwIfAborted()
    }
    if (response.status !== 200 || response.redirected ||
        response.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !== 'application/json') {
      cancelBody(response.body)
      throw new Error('Ongeldig JSON-antwoord.')
    }
    return boundedJson(response, controller.signal)
  }
  try {
    validateManifest(await fetchJson(module.manifestPath), module)
    const health = await fetchJson(module.healthPath)
    if (!health || typeof health !== 'object' || Array.isArray(health) ||
        Object.keys(health).length !== 1 || health.status !== 'ok') {
      throw new Error('Ongeldig health-antwoord.')
    }
    controller.signal.throwIfAborted()
    return { status: 'verified', moduleId: module.id, health: 'ok', verifiedAt: Date.now() }
  } catch {
    throw new Error('Verificatie mislukt. Controleer of de lokale service actief is en probeer opnieuw.')
  } finally {
    clearTimeout(timer)
    signal?.removeEventListener('abort', abort)
  }
}

export function launchUrl(module, verification, now = Date.now()) {
  const age = now - verification?.verifiedAt
  return trustedModule(module) && isAllowedOrigin(module.origin) &&
    verification?.status === 'verified' && verification.moduleId === module.id &&
    verification.health === 'ok' && Number.isFinite(verification.verifiedAt) &&
    age >= 0 && age < MAX_AGE_MS
    ? module.origin : null
}
