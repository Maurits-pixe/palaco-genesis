import test from 'node:test'
import assert from 'node:assert/strict'
import { getEventListeners } from 'node:events'
import { setImmediate as nextTurn, setTimeout as delay } from 'node:timers/promises'
import { listCommands, MAX_RESPONSE_BYTES, request } from '../src/api.js'

const token = 'test-only-input'
const headers = { 'Content-Type': 'application/json' }
const encoder = new TextEncoder()
const read = (fetcher, options = {}) => request('/v1/commands', { token, fetcher, ...options })
const deferred = () => {
  let resolve, reject
  const promise = new Promise((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
function streamed(chunks, options = {}, cancel = () => {}) {
  let index = 0
  return new Response(new ReadableStream({
    pull(controller) {
      if (index < chunks.length) controller.enqueue(chunks[index++])
      else controller.close()
    },
    cancel,
  }, { highWaterMark: 0 }), { headers, ...options })
}
const noListeners = signal => assert.equal(getEventListeners(signal, 'abort').length, 0)
const safe = error => {
  assert.match(error.message, /^(Geen geldig antwoord|Onverwacht antwoord)/)
  assert.ok(!error.message.includes(token))
  return true
}

test('response budget is one MiB and JSON MIME accepts case and optional parameters', async () => {
  assert.equal(MAX_RESPONSE_BYTES, 1024 * 1024)
  for (const type of ['application/json', 'APPLICATION/JSON', 'Application/Json; charset=utf-8', 'application/json ; profile="local"']) {
    assert.deepEqual(await read(async () => new Response('{}', { headers: { 'Content-Type': type } })), {})
  }
})

test('successful responses require JSON MIME and a body, cancelling rejected streams', async () => {
  for (const type of [undefined, '', 'text/plain', 'application/problem+json', 'application/jsonp', 'text/application/json']) {
    let cancelled = 0
    const response = streamed([], { headers: type === undefined ? {} : { 'Content-Type': type } }, () => { cancelled++ })
    await assert.rejects(read(async () => response), safe)
    assert.equal(cancelled, 1)
    assert.equal(response.body.locked, false)
  }
  await assert.rejects(read(async () => new Response(null, { headers })), safe)
})

test('JSON roots must be non-null non-array objects; malformed JSON is sanitized', async () => {
  for (const text of ['null', '[]', '[{}]', '"private"', '1', 'true', '', '{', `{"private":"${token}"`]) {
    await assert.rejects(read(async () => streamed([encoder.encode(text)])), safe)
  }
  assert.deepEqual(await read(async () => streamed([encoder.encode('{"commands":[]}')])), { commands: [] })
})

test('streaming UTF-8 preserves split multibyte sequences and rejects invalid or truncated encoding', async () => {
  const bytes = encoder.encode('{"value":"é😀"}')
  assert.deepEqual(await read(async () => streamed(Array.from(bytes, byte => Uint8Array.of(byte)))), { value: 'é😀' })
  for (const chunks of [
    [encoder.encode('{"value":"'), Uint8Array.of(0xc3, 0x28), encoder.encode('"}')],
    [encoder.encode('{}'), Uint8Array.of(0xe2, 0x82)],
  ]) {
    const response = streamed(chunks)
    await assert.rejects(read(async () => response), safe)
    assert.equal(response.body.locked, false)
  }
})

test('actual streamed bytes enforce exact cap and cap+1 regardless of absent or lying Content-Length', async () => {
  for (const length of [undefined, '1', String(MAX_RESPONSE_BYTES * 2)]) {
    for (const extra of [0, 1]) {
      const bytes = encoder.encode(`{"value":"${'x'.repeat(MAX_RESPONSE_BYTES - 12 + extra)}"}`)
      assert.equal(bytes.byteLength, MAX_RESPONSE_BYTES + extra)
      let cancelled = 0
      const chunks = []
      for (let index = 0; index < bytes.length; index += 32768) chunks.push(bytes.subarray(index, index + 32768))
      const response = streamed(chunks, {
        headers: { ...headers, ...(length === undefined ? {} : { 'Content-Length': length }) },
      }, () => { cancelled++ })
      if (extra) {
        await assert.rejects(read(async () => response), safe)
        assert.equal(cancelled, 1)
      } else {
        assert.equal((await read(async () => response)).value.length, MAX_RESPONSE_BYTES - 12)
        assert.equal(cancelled, 0)
      }
      assert.equal(response.body.locked, false)
    }
  }
})

test('full 100-record worst-case escaped journal fits and listCommands returns every row', async () => {
  const commands = Array.from({ length: 100 }, (_, index) => ({
    id: `${'i'.repeat(196)}-${index}`, command: '\u0000'.repeat(1024), committed_at: '2026-10-19T00:00:00.000Z',
  }))
  const bytes = encoder.encode(JSON.stringify({ commands }))
  assert.ok(bytes.byteLength > 600 * 1024)
  assert.ok(bytes.byteLength < MAX_RESPONSE_BYTES)
  const chunks = []
  for (let index = 0; index < bytes.length; index += 4096) chunks.push(bytes.subarray(index, index + 4096))
  assert.deepEqual(await listCommands(token, async () => streamed(chunks)), commands)
})

test('response cap counts UTF-8 bytes rather than JavaScript string length', async () => {
  const value = 'é'.repeat((MAX_RESPONSE_BYTES - 12) / 2)
  for (const extra of ['', 'x']) {
    const bytes = encoder.encode(JSON.stringify({ value: value + extra }))
    assert.equal(bytes.byteLength, MAX_RESPONSE_BYTES + extra.length)
    const response = streamed([bytes.subarray(0, 65535), bytes.subarray(65535)])
    if (extra) await assert.rejects(read(async () => response), safe)
    else assert.deepEqual(await read(async () => response), { value })
    assert.equal(response.body.locked, false)
  }
})

test('only POST 201 and GET/DELETE 200 succeed, and redirects and HTTP failures cancel unread bodies', async () => {
  for (const method of ['GET', 'DELETE', 'POST']) {
    const expected = method === 'POST' ? 201 : 200
    assert.deepEqual(await read(async () => new Response('{}', { headers, status: expected }), { method }), {})
    for (const status of [200, 201, 202, 400, 401, 409, 410, 500].filter(value => value !== expected)) {
      let cancelled = 0, calls = 0
      const response = streamed([encoder.encode(token)], { status }, () => { cancelled++ })
      await assert.rejects(read(async () => { calls++; return response }, { method }), error => !error.message.includes(token))
      assert.equal(calls, 1)
      assert.equal(cancelled, 1)
      assert.equal(response.body.locked, false)
    }
  }
  let cancelled = 0
  const response = streamed([], {}, () => { cancelled++ })
  Object.defineProperty(response, 'redirected', { value: true })
  await assert.rejects(read(async () => response), safe)
  assert.equal(cancelled, 1)
})

test('timeout promptly rejects fetch ignoring abort and cleans listeners before late settlement', { timeout: 2000 }, async () => {
  for (const late of ['resolve', 'reject', 'never']) {
    const pending = deferred()
    let signal, calls = 0, cancelled = 0
    await assert.rejects(read((_path, options) => {
      signal = options.signal
      calls++
      return pending.promise
    }, { timeoutMs: 15 }), safe)
    assert.equal(signal.aborted, true)
    noListeners(signal)
    assert.equal(calls, 1)
    if (late === 'resolve') {
      const response = streamed([], {}, () => { cancelled++; return new Promise(() => {}) })
      pending.resolve(response)
      await nextTurn()
      assert.equal(cancelled, 1)
      assert.equal(response.body.locked, false)
    } else if (late === 'reject') {
      pending.reject(new Error(token))
      await nextTurn()
    }
    noListeners(signal)
  }
})

test('one timeout covers both headers and body, including an abort-ignoring stream and hanging cancellation', { timeout: 2000 }, async () => {
  let signal, cancelled = 0
  const response = new Response(new ReadableStream({
    start(controller) { controller.enqueue(encoder.encode('{"value":')) },
    cancel() { cancelled++; return new Promise(() => {}) },
  }), { headers })
  await assert.rejects(read(async (_path, options) => {
    signal = options.signal
    await delay(20)
    return response
  }, { timeoutMs: 45 }), safe)
  assert.equal(signal.aborted, true)
  assert.equal(cancelled, 1)
  assert.equal(response.body.locked, false)
  noListeners(signal)
})

test('header time is not reset when a finite delayed body starts', { timeout: 2000 }, async () => {
  let controller, signal
  const response = new Response(new ReadableStream({ start(value) { controller = value } }), { headers })
  const operation = read(async (_path, options) => {
    signal = options.signal
    await delay(30)
    return response
  }, { timeoutMs: 60 })
  const lateBody = delay(75).then(() => {
    // Timeout cancels the real stream before these otherwise valid bytes arrive.
    assert.throws(() => controller.enqueue(encoder.encode('{}')), TypeError)
  })
  await assert.rejects(operation, safe)
  noListeners(signal)
  assert.equal(response.body.locked, false)
  await lateBody
})

test('all settled reads remove abort listeners and release locks on success and stream failure', async () => {
  for (const outcome of ['success', 'malformed', 'error']) {
    let signal
    const response = new Response(new ReadableStream({
      start(controller) {
        if (outcome === 'error') controller.error(new Error(token))
        else {
          controller.enqueue(encoder.encode(outcome === 'success' ? '{}' : '{'))
          controller.close()
        }
      },
    }), { headers })
    const operation = read(async (_path, options) => { signal = options.signal; return response })
    if (outcome === 'success') assert.deepEqual(await operation, {})
    else await assert.rejects(operation, safe)
    assert.equal(signal.aborted, false)
    noListeners(signal)
    assert.equal(response.body.locked, false)
  }
})

test('rejected and throwing cancellation are best effort and never leak unhandled rejection', { timeout: 2000 }, async () => {
  for (const cancel of [
    () => Promise.reject(new Error(token)),
    () => { throw new Error(token) },
    () => new Promise(() => {}),
  ]) {
    const response = streamed([], { headers: { 'Content-Type': 'text/plain' } }, cancel)
    await assert.rejects(read(async () => response), safe)
    await nextTurn()
    assert.equal(response.body.locked, false)
  }
})
