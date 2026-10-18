import test from 'node:test'
import assert from 'node:assert/strict'
import { getEventListeners } from 'node:events'
import { createRecord, MAX_PLAINTEXT_BYTES, MAX_RESPONSE_BYTES, plaintextBytes, readRecord, request } from '../src/api.js'
import config from '../vite.config.js'

const inputToken = 'test-only-user-input'
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
const encoder = new TextEncoder()
const tick = () => new Promise(resolve => setImmediate(resolve))

function deferred() {
  let resolve, reject
  const promise = new Promise((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}

function streamed(chunks, headers = {}) {
  return new Response(new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk)
      controller.close()
    },
  }), { headers: { 'Content-Type': 'application/json', ...headers } })
}

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
    new Response('{', { headers: { 'Content-Type': 'application/json' } }),
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
  const body = deferred()
  const started = deferred()
  const response = new Response(new ReadableStream({
    pull() {
      started.resolve()
      return body.promise
    },
  }), { headers: { 'Content-Type': 'application/json' } })
  const pending = readRecord('id', inputToken, async () => response, controller.signal)
  await started.promise
  controller.abort()
  await assert.rejects(pending, /Geen geldig antwoord/)
  body.resolve()
  assert.equal(response.body.locked, false)
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0)
})

test('timeout stays active while reading the body and cleans external listeners', async () => {
  const controller = new AbortController()
  let networkSignal
  const pending = request('/v1/records/id', {
    token: inputToken, timeoutMs: 10, signal: controller.signal,
    fetcher: async (_url, { signal }) => {
      networkSignal = signal
      return new Response(new ReadableStream({
        pull: () => new Promise(() => {}),
      }), { headers: { 'Content-Type': 'application/json' } })
    },
  })
  await assert.rejects(pending, /Geen geldig antwoord/)
  assert.equal(networkSignal.aborted, true)
  assert.equal(controller.signal.aborted, false)
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0)
})

test('only JSON MIME is accepted, case-insensitively with optional parameters', async () => {
  for (const mime of ['application/json', 'APPLICATION/JSON', 'Application/Json; charset=UTF-8', 'application/json ; charset=utf-8']) {
    assert.deepEqual(await readRecord('id', inputToken, async () =>
      streamed([encoder.encode('{"id":"id","plaintext":"ok"}')], { 'Content-Type': mime })),
    { id: 'id', plaintext: 'ok' })
  }
  for (const mime of ['', 'text/plain', 'text/html', 'application/jsonp', 'application/problem+json']) {
    await assert.rejects(readRecord('id', inputToken, async () =>
      streamed([encoder.encode('{"id":"id","plaintext":"ok"}')], { 'Content-Type': mime })), /Onverwacht antwoord/)
  }
  await assert.rejects(readRecord('id', inputToken, async () =>
    new Response(encoder.encode('{"id":"id","plaintext":"ok"}'))), /Onverwacht antwoord/)
})

test('response byte cap is exact across chunks regardless of absent or lying content-length', async () => {
  assert.equal(MAX_RESPONSE_BYTES, 131072)
  const prefix = '{"id":"id","plaintext":"ok","padding":"'
  const suffix = '"}'
  for (const length of [MAX_RESPONSE_BYTES, MAX_RESPONSE_BYTES + 1]) {
    const bytes = encoder.encode(prefix + 'x'.repeat(length - prefix.length - suffix.length) + suffix)
    for (const headers of [{}, { 'Content-Length': '1' }, { 'Content-Length': String(MAX_RESPONSE_BYTES + 100) }]) {
      const response = streamed([bytes.slice(0, 17), bytes.slice(17, 64000), bytes.slice(64000)], headers)
      const pending = readRecord('id', inputToken, async () => response)
      if (length === MAX_RESPONSE_BYTES) assert.deepEqual(await pending, { id: 'id', plaintext: 'ok' })
      else await assert.rejects(pending, /Onverwacht antwoord/)
      assert.equal(response.body.locked, false)
    }
  }
})

test('missing bodies, malformed UTF-8, malformed JSON and non-object JSON reject safely', async () => {
  const invalid = [
    null,
    encoder.encode('{'),
    encoder.encode('null'),
    encoder.encode('[]'),
    encoder.encode('"text"'),
    encoder.encode('42'),
    encoder.encode('true'),
    new Uint8Array([...encoder.encode('{"id":"id","plaintext":"'), 0xc3, 0x28, ...encoder.encode('"}')]),
    new Uint8Array([...encoder.encode('{"id":"id","plaintext":"'), 0xc3]),
  ]
  for (const bytes of invalid) {
    for (const action of ['create', 'read']) {
      const response = new Response(bytes, {
        status: action === 'create' ? 201 : 200,
        headers: { 'Content-Type': 'application/json' },
      })
      await assert.rejects(action === 'create'
        ? createRecord('text', inputToken, async () => response)
        : readRecord('id', inputToken, async () => response),
      error => !error.message.includes(inputToken))
      assert.equal(response.body?.locked || false, false)
    }
  }
})

test('read enforces decoded UTF-8 plaintext limit while accepting worst-case escaped control text', async () => {
  for (const plaintext of ['x'.repeat(16385), 'é'.repeat(8193), '😀'.repeat(4097)]) {
    await assert.rejects(readRecord('id', inputToken, async () => json({ id: 'id', plaintext })), /Onverwacht antwoord/)
  }
  const plaintext = '\u0000'.repeat(MAX_PLAINTEXT_BYTES)
  const value = { id: 'i'.repeat(200), plaintext }
  assert.ok(encoder.encode(JSON.stringify(value)).length > 6 * MAX_PLAINTEXT_BYTES)
  assert.deepEqual(await readRecord(value.id, inputToken, async () => json(value)), value)
  await createRecord(plaintext, inputToken, async () => json({ id: value.id }, 201))
  const bytes = encoder.encode(JSON.stringify({ id: 'id', plaintext: '😀é' }))
  assert.deepEqual(await readRecord('id', inputToken, async () =>
    streamed(Array.from(bytes, byte => new Uint8Array([byte])))), { id: 'id', plaintext: '😀é' })
})

test('timeout and external abort reject stalled headers and clean listeners before late settlement', { timeout: 1000 }, async () => {
  for (const [external, outcome] of [false, true].flatMap(external =>
    ['success', 'failure', 'never'].map(outcome => [external, outcome]))) {
    const controller = new AbortController()
    const late = deferred()
    let networkSignal
    const pending = request('/v1/records/id', {
      token: inputToken, timeoutMs: external ? 8000 : 10, signal: controller.signal,
      fetcher: (_url, { signal }) => {
        networkSignal = signal
        return late.promise
      },
    })
    if (external) controller.abort()
    await assert.rejects(pending, /Geen geldig antwoord/)
    assert.equal(networkSignal.aborted, true)
    assert.equal(getEventListeners(networkSignal, 'abort').length, 0)
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0)
    if (outcome === 'success') {
      let cancelled = false
      const response = new Response(new ReadableStream({
        cancel() {
          cancelled = true
          return new Promise(() => {})
        },
      }))
      late.resolve(response)
      await tick()
      assert.equal(cancelled, true)
      assert.equal(response.body.locked, false)
    } else if (outcome === 'failure') {
      late.reject(new Error('late private network detail'))
      await tick()
    }
  }
})

test('rejected MIME, HTTP errors and oversized streams cancel without waiting for hanging cancellation', { timeout: 1000 }, async () => {
  for (const reason of ['mime', 'http', 'size']) {
    let cancelled = false
    const response = new Response(new ReadableStream({
      start(controller) {
        if (reason === 'size') {
          controller.enqueue(new Uint8Array(MAX_RESPONSE_BYTES))
          controller.enqueue(new Uint8Array([32]))
        }
      },
      cancel() {
        cancelled = true
        return new Promise(() => {})
      },
    }), {
      status: reason === 'http' ? 403 : 200,
      headers: { 'Content-Type': reason === 'mime' ? 'text/html' : 'application/json' },
    })
    await assert.rejects(readRecord('id', inputToken, async () => response))
    assert.equal(cancelled, true)
    assert.equal(response.body.locked, false)
  }
})

test('stalled stream cancellation never delays timeout or external abort and releases locks', { timeout: 1000 }, async () => {
  for (const external of [false, true]) {
    const controller = new AbortController()
    const started = deferred()
    const latePull = deferred()
    let networkSignal
    let cancelled = false
    const response = new Response(new ReadableStream({
      pull() {
        started.resolve()
        return latePull.promise
      },
      cancel() {
        cancelled = true
        return new Promise(() => {})
      },
    }), { headers: { 'Content-Type': 'application/json' } })
    const pending = request('/v1/records/id', {
      token: inputToken, timeoutMs: external ? 8000 : 10, signal: controller.signal,
      fetcher: async (_url, { signal }) => {
        networkSignal = signal
        return response
      },
    })
    await started.promise
    if (external) controller.abort()
    await assert.rejects(pending, /Geen geldig antwoord/)
    assert.equal(cancelled, true)
    assert.equal(response.body.locked, false)
    assert.equal(getEventListeners(networkSignal, 'abort').length, 0)
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0)
    latePull.reject(new Error('late stream detail'))
    await tick()
  }
})

test('abort wrapper listeners are removed on ordinary header and stream settlement', async () => {
  for (const fail of [false, true]) {
    let networkSignal
    const response = fail
      ? new Response(new ReadableStream({
        start(controller) { controller.error(new Error('private stream detail')) },
      }), { headers: { 'Content-Type': 'application/json' } })
      : json({ id: 'id', plaintext: 'ok' })
    const pending = readRecord('id', inputToken, async (_url, { signal }) => {
      networkSignal = signal
      return response
    })
    if (fail) await assert.rejects(pending, /Geen geldig antwoord/)
    else await pending
    assert.equal(getEventListeners(networkSignal, 'abort').length, 0)
    assert.equal(response.body.locked, false)
  }
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
