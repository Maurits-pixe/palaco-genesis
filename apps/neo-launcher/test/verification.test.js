import test from 'node:test'
import assert from 'node:assert/strict'
import { isAllowedOrigin, launchUrl, MAX_AGE_MS, PROTOCOL, TRUSTED_MODULES, validateManifest, verifyModule } from '../src/verification.js'
import config from '../vite.config.js'

const [aether, bastion] = TRUSTED_MODULES
const manifest = (module) => ({ id: module.id, name: module.name, protocol: PROTOCOL })
const json = (value) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } })
const evidence = (module, verifiedAt) => ({ status: 'verified', moduleId: module.id, health: 'ok', verifiedAt })
const failure = (error) => {
  assert.equal(error.message, 'Verificatie mislukt. Controleer of de lokale service actief is en probeer opnieuw.')
  return true
}

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
    const calls = []
    const result = await verifyModule(module, async (url, options) => {
      calls.push({ url, signal: options.signal })
      assert.equal(options.redirect, 'error')
      assert.equal(options.cache, 'no-store')
      assert.equal(options.credentials, 'omit')
      assert.deepEqual(options.headers, { Accept: 'application/json' })
      assert.ok(options.signal instanceof AbortSignal)
      assert.equal(options.signal.aborted, false)
      if (url === module.manifestPath) return json(manifest(module))
      assert.equal(url, module.healthPath)
      return json({ status: 'ok' })
    })
    assert.deepEqual(calls.map(({ url }) => url), [module.manifestPath, `/verify/${module.id}/health`])
    assert.equal(calls[0].signal, calls[1].signal)
    assert.deepEqual(result, evidence(module, result.verifiedAt))
    assert.equal(launchUrl(module, result), module.origin)
    assert.equal(launchUrl(module === aether ? bastion : aether, result), null)
  }
})

test('manifest URL fields never control launch links', async () => {
  const result = await verifyModule(aether, async (url) => url === aether.manifestPath
    ? json({ ...manifest(aether), url: 'https://untrusted.example' }) : json({ status: 'ok' }))
  assert.equal(launchUrl(aether, result), aether.origin)
  assert.equal(launchUrl({ ...aether, origin: 'https://untrusted.example' }, result), null)
})

test('links fail closed while pending, failed, expired, or timestamp is in the future', () => {
  const now = 100_000
  assert.equal(launchUrl(aether, evidence(aether, now), now), aether.origin)
  for (const state of [
    undefined, { status: 'idle' }, { status: 'verifying', verifiedAt: now },
    { status: 'error', verifiedAt: now },
    { status: 'verified', verifiedAt: now - MAX_AGE_MS },
    { status: 'verified', verifiedAt: now + 1 },
    { status: 'verified', verifiedAt: NaN },
    { status: 'verified', verifiedAt: now },
    { ...evidence(aether, now), moduleId: bastion.id },
    { ...evidence(aether, now), health: undefined },
    { ...evidence(aether, now), health: 'bad' },
    evidence(aether, now - MAX_AGE_MS),
    evidence(aether, now + 1),
    evidence(aether, NaN),
    evidence(aether, Infinity),
    evidence(aether, String(now)),
  ]) assert.equal(launchUrl(aether, state, now), null)
  assert.equal(launchUrl(aether, evidence(aether, now - MAX_AGE_MS + 1), now), aether.origin)
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
    let calls = 0
    await assert.rejects(verifyModule(aether, async () => { calls++; return factory() }), failure)
    assert.equal(calls, 1)
  }
})

test('health fails closed for unavailable, malformed, redirected, or non-JSON responses for both modules', async () => {
  const factories = [
    () => json({ status: 'bad' }),
    () => json({ status: 'OK' }),
    () => json({ status: 'ok', extra: true }),
    () => json({}),
    () => json(null),
    () => json([]),
    () => json('ok'),
    () => new Response('{"status":"ok"}', { status: 503, headers: { 'Content-Type': 'application/json' } }),
    () => new Response('{"status":"ok"}', { status: 201, headers: { 'Content-Type': 'application/json' } }),
    () => new Response(null, { status: 204 }),
    () => new Response(null, { status: 302, headers: { Location: 'https://example.org' } }),
    () => {
      const response = json({ status: 'ok' })
      Object.defineProperty(response, 'redirected', { value: true })
      return response
    },
    () => new Response('{"status":"ok"}', { headers: { 'Content-Type': 'text/plain' } }),
    () => new Response('{"status":"ok"}', { headers: { 'Content-Type': 'text/application/json' } }),
    () => new Response('{', { headers: { 'Content-Type': 'application/json' } }),
    () => new Response(new Uint8Array([0xff]), { headers: { 'Content-Type': 'application/json' } }),
    () => { throw new Error('sensitive network details') },
  ]
  for (const module of TRUSTED_MODULES) {
    for (const factory of factories) {
      const paths = []
      await assert.rejects(verifyModule(module, async (path) => {
        paths.push(path)
        return path === module.manifestPath ? json(manifest(module)) : factory()
      }), failure)
      assert.deepEqual(paths, [module.manifestPath, module.healthPath])
    }
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

test('one deadline covers a successful manifest followed by a hanging health fetch', async () => {
  const signals = []
  await assert.rejects(verifyModule(aether, async (path, { signal }) => {
    signals.push(signal)
    if (path === aether.manifestPath) {
      await new Promise((resolve) => setTimeout(resolve, 70))
      return json(manifest(aether))
    }
    await new Promise((resolve) => setTimeout(resolve, 60))
    return json({ status: 'ok' })
  }, 100), failure)
  assert.equal(signals.length, 2)
  assert.equal(signals[0], signals[1])
  assert.equal(signals[1].aborted, true)
})

test('shared deadline cancels a stalled health body without waiting for cancellation to settle', async () => {
  let cancelled = false
  let healthSignal
  await assert.rejects(verifyModule(aether, async (path, { signal }) => {
    if (path === aether.manifestPath) {
      await new Promise((resolve) => setTimeout(resolve, 70))
      return json(manifest(aether))
    }
    healthSignal = signal
    return new Response(new ReadableStream({
      start(controller) { controller.enqueue(new TextEncoder().encode('{"status":')) },
      cancel() { cancelled = true; return new Promise(() => {}) },
    }), { headers: { 'Content-Type': 'application/json' } })
  }, 100), failure)
  assert.equal(healthSignal.aborted, true)
  assert.equal(cancelled, true)
})

test('oversized health bodies are cancelled for declared and streamed limits', async () => {
  for (const declared of [false, true]) {
    let cancelled = false
    await assert.rejects(verifyModule(aether, async (path) => {
      if (path === aether.manifestPath) return json(manifest(aether))
      return new Response(new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(' '.repeat(4097)))
        },
        cancel() { cancelled = true; return new Promise(() => {}) },
      }), { headers: { 'Content-Type': 'application/json', ...(declared ? { 'Content-Length': '4097' } : {}) } })
    }), failure)
    assert.equal(cancelled, true)
  }
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
    assert.equal(proxy.rewrite(module.healthPath), '/health')
  }
})
