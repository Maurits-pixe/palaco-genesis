import test from 'node:test'
import assert from 'node:assert/strict'
import { isAllowedOrigin, launchUrl, MAX_AGE_MS, PROTOCOL, TRUSTED_MODULES, validateManifest, verifyModule } from '../src/verification.js'
import config from '../vite.config.js'

const [aether, bastion] = TRUSTED_MODULES
const manifest = (module) => ({ id: module.id, name: module.name, protocol: PROTOCOL })
const json = (value) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } })

test('both exact module identities and protocols must match', () => {
  for (const module of TRUSTED_MODULES) {
    assert.equal(validateManifest(manifest(module), module), true)
    for (const value of [
      null, [], 'aether', {},
      { ...manifest(module), id: 'other' },
      { ...manifest(module), name: 'other' },
      { ...manifest(module), protocol: 'palaco-app/v2' },
      { ...manifest(module), protocol: null },
    ]) assert.throws(() => validateManifest(value, module))
  }
  assert.throws(() => validateManifest(manifest(aether), { ...aether }))
})

test('URL policy permits HTTPS and only explicit local HTTP exceptions', () => {
  for (const origin of ['https://example.org', aether.origin, bastion.origin]) {
    assert.equal(isAllowedOrigin(origin), true)
  }
  for (const origin of [
    'http://example.org', 'http://localhost:5174', 'http://127.0.0.1:9999',
    'http://127.0.0.1:5174/path', 'http://127.0.0.1:5174?token=value',
    'http://127.0.0.1:5174#fragment', 'https://user@example.org',
    '//example.org', 'javascript:alert(1)', 'file:///etc/passwd', 'not a URL',
  ]) assert.equal(isAllowedOrigin(origin), false, origin)
})

test('verification fetches only fixed proxy paths and forbids redirects', async () => {
  for (const module of TRUSTED_MODULES) {
    const result = await verifyModule(module, async (url, options) => {
      assert.equal(url, module.manifestPath)
      assert.equal(options.redirect, 'error')
      assert.equal(options.cache, 'no-store')
      assert.equal(options.credentials, 'omit')
      assert.ok(options.signal instanceof AbortSignal)
      return json(manifest(module))
    })
    assert.equal(result.status, 'verified')
    assert.equal(launchUrl(module, result), module.origin)
  }
})

test('manifest URL fields never control launch links', async () => {
  const result = await verifyModule(aether, async () => json({ ...manifest(aether), url: 'https://untrusted.example' }))
  assert.equal(launchUrl(aether, result), aether.origin)
  assert.equal(launchUrl({ ...aether, origin: 'https://untrusted.example' }, result), null)
})

test('links fail closed while pending, failed, expired, or timestamp is in the future', () => {
  const now = 100_000
  assert.equal(launchUrl(aether, { status: 'verified', verifiedAt: now }, now), aether.origin)
  for (const state of [
    undefined, { status: 'idle' }, { status: 'verifying', verifiedAt: now },
    { status: 'error', verifiedAt: now },
    { status: 'verified', verifiedAt: now - MAX_AGE_MS },
    { status: 'verified', verifiedAt: now + 1 },
    { status: 'verified', verifiedAt: NaN },
  ]) assert.equal(launchUrl(aether, state, now), null)
})

test('mismatch, HTTP errors, redirects, invalid JSON, fetch failure, and unbounded schemas reject', async () => {
  const factories = [
    () => json(manifest(bastion)),
    () => json({ ...manifest(aether), protocol: 'other' }),
    () => new Response('private error', { status: 500 }),
    () => new Response(null, { status: 302, headers: { Location: 'https://example.org' } }),
    () => new Response('{', { headers: { 'Content-Type': 'application/json' } }),
    () => new Response('{}'),
    () => json({ ...manifest(aether), padding: 'x'.repeat(4097) }),
    () => json(Object.fromEntries(Array.from({ length: 17 }, (_, i) => [`key${i}`, i]))),
    () => { throw new Error('sensitive network details') },
    () => ({ ok: true, redirected: true }),
  ]
  for (const factory of factories) {
    await assert.rejects(verifyModule(aether, async () => factory()), (error) => {
      assert.match(error.message, /Verificatie mislukt/)
      assert.ok(!error.message.includes('sensitive'))
      return true
    })
  }
})

test('oversized declared body and streamed body both reject', async () => {
  await assert.rejects(verifyModule(aether, async () => new Response('{}', {
    headers: { 'Content-Type': 'application/json', 'Content-Length': '5000' },
  })))
  await assert.rejects(verifyModule(aether, async () => json({ ...manifest(aether), padding: 'x'.repeat(5000) })))
})

test('timeout aborts a hanging verification', async () => {
  await assert.rejects(verifyModule(aether, (_url, { signal }) => new Promise((_resolve, reject) => {
    signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true })
  }), 10), /Verificatie mislukt/)
})

test('untrusted module cannot trigger a fetch', async () => {
  let called = false
  await assert.rejects(verifyModule({ ...aether, manifestPath: 'https://untrusted.example' }, () => { called = true }))
  assert.equal(called, false)
})

test('Vite binds strict local port with immutable service targets and prefix rewrites', () => {
  assert.equal(config.server.host, '127.0.0.1')
  assert.equal(config.server.port, 5173)
  assert.equal(config.server.strictPort, true)
  for (const module of TRUSTED_MODULES) {
    const proxy = config.server.proxy[`/verify/${module.id}/`]
    assert.equal(proxy.target, `http://127.0.0.1:${module === aether ? 8787 : 8788}`)
    assert.equal(proxy.followRedirects, false)
    assert.equal(proxy.rewrite(module.manifestPath), '/.well-known/palaco-app.json')
  }
})
