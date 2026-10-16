export const PROTOCOL = 'palaco-app/v1'
export const MAX_AGE_MS = 60_000
const MAX_MANIFEST_BYTES = 4096
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
    description: 'Versleutelde records opslaan en teruglezen.',
  }),
  Object.freeze({
    id: 'bastion',
    name: 'BASTION',
    origin: 'http://127.0.0.1:5175',
    manifestPath: '/verify/bastion/.well-known/palaco-app.json',
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

async function boundedJson(response) {
  if (!response.body || Number(response.headers.get('content-length')) > MAX_MANIFEST_BYTES) {
    throw new Error('Ongeldig manifest.')
  }
  const reader = response.body.getReader()
  const chunks = []
  let size = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      size += value.byteLength
      if (size > MAX_MANIFEST_BYTES) throw new Error('Manifest is te groot.')
      chunks.push(value)
    }
  } catch (error) {
    await reader.cancel().catch(() => {})
    throw error
  } finally {
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

export async function verifyModule(module, fetcher = fetch, timeoutMs = 5000) {
  if (!trustedModule(module) || !isAllowedOrigin(module.origin)) {
    throw new Error('Moduleconfiguratie is niet toegestaan.')
  }
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const response = await fetcher(module.manifestPath, {
      redirect: 'error',
      cache: 'no-store',
      credentials: 'omit',
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    })
    if (!response.ok || response.redirected ||
        !response.headers.get('content-type')?.includes('application/json')) {
      throw new Error('Ongeldig manifestantwoord.')
    }
    validateManifest(await boundedJson(response), module)
    return { status: 'verified', verifiedAt: Date.now() }
  } catch {
    throw new Error('Verificatie mislukt. Controleer of de lokale service actief is en probeer opnieuw.')
  } finally {
    clearTimeout(timer)
  }
}

export function launchUrl(module, verification, now = Date.now()) {
  const age = now - verification?.verifiedAt
  return trustedModule(module) && isAllowedOrigin(module.origin) &&
    verification?.status === 'verified' && age >= 0 && age < MAX_AGE_MS
    ? module.origin : null
}
