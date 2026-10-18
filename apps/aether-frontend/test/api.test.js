import test from 'node:test'
import assert from 'node:assert/strict'
import { getEventListeners } from 'node:events'
import { createRecord, MAX_PLAINTEXT_BYTES, plaintextBytes, readRecord, request } from '../src/api.js'
import config from '../vite.config.js'

const inputToken = 'test-only-user-input'
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })

test('create sends exact plaintext and bearer only in headers', async () => {
  const result = await createRecord('  hallo  ', inputToken, async (url, options) => {
    assert.equal(url, '/v1/records')
    assert.equal(options.method, 'POST')
    assert.equal(options.headers.Authorization, ['Bearer', inputToken].join(' '))
    assert.deepEqual(JSON.parse(options.body), { plaintext: '  hallo  ' })
    assert.equal(options.redirect, 'error')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.credentials, 'omit')
    return json({ id: 'record-1' }, 201)
  })
  assert.deepEqual(result, { id: 'record-1' })
})

test('read matches ID and returns plaintext without interpreting markup', async () => {
  assert.deepEqual(await readRecord('record-1', inputToken, async (url) => {
    assert.equal(url, '/v1/records/record-1')
    return json({ id: 'record-1', plaintext: '<script>nothing executes</script>' })
  }), { id: 'record-1', plaintext: '<script>nothing executes</script>' })
})

test('empty token, plaintext, and unsafe IDs reject before network access', async () => {
  const never = () => assert.fail('must not fetch')
  await assert.rejects(createRecord('hello', '', never), /token/)
  await assert.rejects(createRecord('hello', 'bad\r\nheader', never), /token/)
  await assert.rejects(createRecord(' ', inputToken, never))
  for (const id of ['', '../health', 'a?token=bad', 'a/b', 'x'.repeat(201)]) {
    await assert.rejects(readRecord(id, inputToken, never))
  }
  await assert.rejects(request('https://example.org', { token: inputToken, fetcher: never }))
})

test('plaintext limit is 16 KiB of UTF-8, not a broad character count', async () => {
  assert.equal(MAX_PLAINTEXT_BYTES, 16384)
  assert.equal(plaintextBytes('é'), 2)
  const accepted = 'é'.repeat(8192)
  await createRecord(accepted, inputToken, async () => json({ id: 'id' }, 201))
  for (const plaintext of ['x'.repeat(16385), accepted + 'x', '😀'.repeat(4097)]) {
    await assert.rejects(createRecord(plaintext, inputToken, () => assert.fail('must not fetch')), /16384/)
  }
})

test('API errors do not reflect server bodies or network details', async () => {
  for (const status of [400, 401, 403, 404, 413, 429, 500]) {
    await assert.rejects(readRecord('id', inputToken, async () => new Response('SECRET SERVER DETAIL', { status })), (error) => {
      assert.ok(!error.message.includes('SECRET'))
      assert.ok(!error.message.includes(inputToken))
      return true
    })
  }
  await assert.rejects(readRecord('id', inputToken, async () => { throw new Error(inputToken) }), /Geen geldig antwoord/)
})

test('malformed JSON, redirects, unexpected status and mismatched schema reject', async () => {
  for (const response of [
    new Response('{'),
    new Response(null, { status: 302 }),
    json({ id: 'other', plaintext: 'hello' }),
    json({ id: 'id', plaintext: null }),
    json({ id: 'id', plaintext: 'hello' }, 201),
  ]) await assert.rejects(readRecord('id', inputToken, async () => response))
  await assert.rejects(createRecord('hello', inputToken, async () => json({ id: 'ok' })))
  await assert.rejects(createRecord('hello', inputToken, async () => json({ id: '../bad' }, 201)))
})

test('timeout aborts hanging requests with a non-secret message', async () => {
  await assert.rejects(request('/v1/records', {
    token: inputToken, timeoutMs: 10,
    fetcher: (_url, { signal }) => new Promise((_resolve, reject) => {
      signal.addEventListener('abort', () => reject(new Error(inputToken)), { once: true })
    }),
  }), /Geen geldig antwoord/)
})

test('create and read propagate an optional signal without changing the fetcher argument', async () => {
  for (const action of ['create', 'read']) {
    const controller = new AbortController()
    let networkSignal
    const fetcher = (_url, { signal }) => {
      networkSignal = signal
      return new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(new Error('cancelled')), { once: true })
      })
    }
    const pending = action === 'create'
      ? createRecord('text', inputToken, fetcher, controller.signal)
      : readRecord('id', inputToken, fetcher, controller.signal)
    assert.equal(networkSignal.aborted, false)
    assert.equal(getEventListeners(controller.signal, 'abort').length, 1)
    controller.abort()
    assert.equal(networkSignal.aborted, true)
    await assert.rejects(pending, /Geen geldig antwoord/)
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0)
  }
})

test('already aborted signals prevent all network calls', async () => {
  const signal = AbortSignal.abort()
  const never = () => assert.fail('must not fetch')
  await assert.rejects(request('/v1/records', { token: inputToken, signal, fetcher: never }))
  await assert.rejects(createRecord('text', inputToken, never, signal))
  await assert.rejects(readRecord('id', inputToken, never, signal))
  assert.equal(getEventListeners(signal, 'abort').length, 0)
})

test('external listeners are removed on success and failure', async () => {
  for (const fetcher of [
    async () => json({ id: 'id', plaintext: 'text' }),
    async () => new Response(null, { status: 403 }),
    async () => { throw new Error('network failure') },
    async () => new Response('{'),
  ]) {
    const controller = new AbortController()
    await readRecord('id', inputToken, fetcher, controller.signal).catch(() => {})
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0)
  }
})

test('external abort rejects a late body even when the body ignores abort', async () => {
  const controller = new AbortController()
  let finishBody
  let startBody
  const started = new Promise(resolve => { startBody = resolve })
  const pending = readRecord('id', inputToken, async () => ({
    ok: true, status: 200,
    json: () => {
      startBody()
      return new Promise(resolve => { finishBody = resolve })
    },
  }), controller.signal)
  await started
  controller.abort()
  finishBody({ id: 'id', plaintext: 'late private text' })
  await assert.rejects(pending, /Geen geldig antwoord/)
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0)
})

test('timeout stays active while reading the body and cleans external listeners', async () => {
  const controller = new AbortController()
  let networkSignal
  const pending = request('/v1/records/id', {
    token: inputToken, timeoutMs: 10, signal: controller.signal,
    fetcher: async (_url, { signal }) => {
      networkSignal = signal
      return {
        ok: true, status: 200,
        json: () => new Promise((_resolve, reject) => {
          signal.addEventListener('abort', () => reject(new Error('body aborted')), { once: true })
        }),
      }
    },
  })
  await assert.rejects(pending, /Geen geldig antwoord/)
  assert.equal(networkSignal.aborted, true)
  assert.equal(controller.signal.aborted, false)
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0)
})

test('Vite proxies only fixed local backend targets on a strict port', () => {
  assert.equal(config.server.host, '127.0.0.1')
  assert.equal(config.server.port, 5174)
  assert.equal(config.server.strictPort, true)
  assert.deepEqual(Object.keys(config.server.proxy), ['/v1', '/.well-known', '/health'])
  for (const proxy of Object.values(config.server.proxy)) {
    assert.equal(proxy.target, 'http://127.0.0.1:8787')
    assert.equal(proxy.followRedirects, false)
  }
})
