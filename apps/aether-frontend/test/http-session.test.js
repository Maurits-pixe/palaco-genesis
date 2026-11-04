import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer } from 'node:http'
import { effectScope } from 'vue'
import { createRecord, readRecord } from '../src/api.js'
import { useRecordSession } from '../src/session.js'

// This loopback fixture exercises Node fetch, not the Rust backend or a browser.
const inputToken = 'test-only-http-input'
const receipt = 1700000000123
const fields = ['token', 'plaintext', 'recordId', 'lastCreatedId', 'result', 'resultReceivedAt', 'busy', 'message', 'error']
const state = session => Object.fromEntries(fields.map(key => [key, session[key].value]))
const empty = { token: '', plaintext: '', recordId: '', lastCreatedId: '', result: null, resultReceivedAt: null, busy: '', message: '', error: '' }

function deferred() {
  let resolve
  const promise = new Promise(yes => { resolve = yes })
  return { promise, resolve }
}

function json(response, value, status = 200) {
  response.writeHead(status, { 'Content-Type': 'application/json' })
  response.end(JSON.stringify(value))
}

async function fixture(t, handle) {
  const requests = []
  const failures = []
  const sockets = new Set()
  const server = createServer(async (request, response) => {
    try {
      const chunks = []
      for await (const chunk of request) chunks.push(chunk)
      const received = { method: request.method, url: request.url, headers: request.headers, body: Buffer.concat(chunks).toString('utf8') }
      requests.push(received)
      handle(received, response)
    } catch (error) {
      failures.push(error)
      response.destroy()
    }
  })
  server.on('connection', socket => {
    sockets.add(socket)
    socket.once('close', () => sockets.delete(socket))
  })
  t.after(async () => {
    if (server.listening) {
      await new Promise(resolve => {
        server.close(resolve)
        server.closeAllConnections()
        for (const socket of sockets) socket.destroy()
      })
    } else {
      for (const socket of sockets) socket.destroy()
    }
    assert.deepEqual(failures, [])
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const origin = `http://127.0.0.1:${server.address().port}`
  const fetcher = (path, options) => {
    assert.match(path, /^\/v1\/records(?:\/[a-zA-Z0-9_-]+)?$/)
    return fetch(new URL(path, origin), options)
  }
  return { requests, fetcher }
}

function setup(t, fetcher) {
  const scope = effectScope()
  t.after(() => scope.stop())
  const session = scope.run(() => useRecordSession({
    create: (plaintext, token, _fetcher, signal) => createRecord(plaintext, token, fetcher, signal),
    read: (id, token, _fetcher, signal) => readRecord(id, token, fetcher, signal),
    eventTarget: new EventTarget(),
    getNow: () => receipt,
  }))
  session.token.value = inputToken
  return { session, scope }
}

test('HTTP fixture: explicit create/read preserve the wire contract and receipt; clearDraft is local', { timeout: 5000 }, async (t) => {
  const plaintext = '  privé 😀 <script>inert</script>\n'
  const { requests, fetcher } = await fixture(t, (request, response) => {
    if (request.method === 'POST') json(response, { id: 'record-1' }, 201)
    else json(response, { id: 'record-1', plaintext })
  })
  const network = t.mock.fn(fetcher)
  const { session } = setup(t, network)
  session.plaintext.value = plaintext
  assert.equal(requests.length, 0)
  assert.equal(network.mock.callCount(), 0)
  await session.perform('create')
  assert.equal(session.lastCreatedId.value, 'record-1')
  assert.equal(session.recordId.value, 'record-1')
  assert.equal(session.plaintext.value, '')
  assert.equal(session.result.value, null)
  assert.equal(session.resultReceivedAt.value, null)
  assert.equal(session.error.value, '')
  assert.equal(session.message.value, 'Record opgeslagen. Bewaar het record-ID om het later terug te lezen.')
  assert.equal(requests.length, 1)

  await session.perform('read')
  assert.deepEqual(session.result.value, { id: 'record-1', plaintext })
  assert.equal(session.resultReceivedAt.value, receipt)
  assert.equal(session.message.value, 'Record opgehaald.')
  assert.equal(session.error.value, '')
  assert.equal(session.busy.value, '')
  assert.deepEqual(requests.map(({ method, url, body }) => ({ method, url, body })), [
    { method: 'POST', url: '/v1/records', body: JSON.stringify({ plaintext }) },
    { method: 'GET', url: '/v1/records/record-1', body: '' },
  ])
  for (const request of requests) {
    assert.equal(request.headers.authorization, ['Bearer', inputToken].join(' '))
    assert.equal(request.headers.accept, 'application/json')
    assert.ok(!request.url.includes(inputToken))
    assert.ok(!request.body.includes(inputToken))
  }
  assert.equal(requests[0].headers['content-type'], 'application/json')
  assert.equal(requests[1].headers['content-type'], undefined)

  session.plaintext.value = 'unsaved local draft'
  const before = state(session)
  const received = session.result.value
  session.clearDraft()
  assert.deepEqual(state(session), { ...before, plaintext: '' })
  assert.equal(session.result.value, received)
  assert.equal(network.mock.callCount(), 2)
  assert.equal(requests.length, 2)
})

test('HTTP fixture: an accepted create with a lost response preserves the last confirmed ID without retrying', { timeout: 5000 }, async (t) => {
  // This map is fixture memory, not evidence of persistence in the Rust database.
  const records = new Map()
  const { requests, fetcher } = await fixture(t, (request, response) => {
    if (request.method === 'POST') {
      const id = `record-${records.size + 1}`
      records.set(id, JSON.parse(request.body).plaintext)
      if (id === 'record-2') response.destroy()
      else json(response, { id }, 201)
    } else {
      const id = request.url.split('/').at(-1)
      assert.equal(id, 'record-1')
      json(response, { id, plaintext: records.get(id) })
    }
  })
  const network = t.mock.fn(fetcher)
  const { session } = setup(t, network)
  session.plaintext.value = 'first confirmed text'
  await session.perform('create')
  assert.equal(session.lastCreatedId.value, 'record-1')
  assert.equal(session.recordId.value, 'record-1')
  assert.equal(requests.length, 1)

  const uncertainDraft = 'accepted but not confirmed 😀'
  session.plaintext.value = uncertainDraft
  await session.perform('create')
  assert.deepEqual([...records], [
    ['record-1', 'first confirmed text'],
    ['record-2', uncertainDraft],
  ])
  assert.deepEqual(state(session), {
    ...empty,
    token: inputToken,
    plaintext: uncertainDraft,
    recordId: 'record-1',
    lastCreatedId: 'record-1',
    error: 'Geen geldig antwoord. Controleer de lokale service en probeer opnieuw.',
  })
  assert.equal(requests.length, 2)
  assert.equal(network.mock.callCount(), 2)

  await session.readLastCreated()
  assert.deepEqual(session.result.value, { id: 'record-1', plaintext: 'first confirmed text' })
  assert.equal(session.plaintext.value, uncertainDraft)
  assert.equal(session.lastCreatedId.value, 'record-1')
  assert.equal(requests.length, 3)

  session.plaintext.value = 'explicit new create'
  await session.perform('create')
  assert.equal(session.recordId.value, 'record-3')
  assert.equal(session.lastCreatedId.value, 'record-3')
  assert.equal(session.plaintext.value, '')
  assert.equal(session.error.value, '')
  assert.equal(session.message.value, 'Record opgeslagen. Bewaar het record-ID om het later terug te lezen.')
  assert.equal(records.get('record-3'), 'explicit new create')
  assert.equal(network.mock.callCount(), 4)
  assert.deepEqual(requests.map(({ method, url, body }) => ({ method, url, body })), [
    { method: 'POST', url: '/v1/records', body: JSON.stringify({ plaintext: 'first confirmed text' }) },
    { method: 'POST', url: '/v1/records', body: JSON.stringify({ plaintext: uncertainDraft }) },
    { method: 'GET', url: '/v1/records/record-1', body: '' },
    { method: 'POST', url: '/v1/records', body: JSON.stringify({ plaintext: 'explicit new create' }) },
  ])
})

for (const newerCreate of [false, true]) {
  test(`HTTP fixture: a delayed create confirmation cannot restore ${newerCreate ? 'or overwrite a newer explicit create' : 'a cleared session'}`, { timeout: 5000 }, async (t) => {
    const arrived = deferred()
    const discarded = deferred()
    const { requests, fetcher } = await fixture(t, (request, response) => {
      assert.equal(request.method, 'POST')
      if (requests.length === 1) arrived.resolve(response)
      else json(response, { id: 'new-confirmed' }, 201)
    })
    let oldSignal
    const { session } = setup(t, async (path, options) => {
      if (oldSignal) return fetcher(path, options)
      oldSignal = options.signal
      // Keep the accepted POST alive despite cancellation, as with delayed reads.
      const response = await fetcher(path, { ...options, signal: undefined })
      const cancel = response.body.cancel.bind(response.body)
      t.mock.method(response.body, 'cancel', (...args) => {
        const pending = cancel(...args)
        discarded.resolve()
        return pending
      })
      return response
    })
    session.plaintext.value = 'old accepted draft'
    const oldPending = session.perform('create')
    const oldResponse = await arrived.promise
    assert.equal(requests.length, 1)
    assert.equal(session.busy.value, 'create')
    assert.equal(oldSignal.aborted, false)

    session.clearSession()
    assert.equal(oldSignal.aborted, true)
    assert.deepEqual(state(session), empty)
    // The session operation settles on abort, before the held HTTP response.
    await oldPending
    assert.equal(oldResponse.writableEnded, false)
    assert.deepEqual(state(session), empty)
    assert.equal(requests.length, 1)

    if (newerCreate) {
      session.token.value = inputToken
      session.plaintext.value = 'fresh explicit create'
      await session.perform('create')
      assert.equal(session.lastCreatedId.value, 'new-confirmed')
      assert.equal(session.recordId.value, 'new-confirmed')
      assert.equal(session.message.value, 'Record opgeslagen. Bewaar het record-ID om het later terug te lezen.')
      assert.equal(session.error.value, '')
      session.plaintext.value = 'fresh unsaved draft'
    }
    const current = state(session)
    json(oldResponse, { id: 'old-unconfirmed' }, 201)
    // Wait until the production API discards the late real fetch response.
    await discarded.promise
    assert.deepEqual(state(session), current)
    assert.deepEqual(requests.map(({ method, url, body }) => ({ method, url, body })), [
      { method: 'POST', url: '/v1/records', body: JSON.stringify({ plaintext: 'old accepted draft' }) },
      ...(newerCreate ? [{ method: 'POST', url: '/v1/records', body: JSON.stringify({ plaintext: 'fresh explicit create' }) }] : []),
    ])
  })
}

for (const invalid of ['mismatched ID', 'malformed JSON', 'wrong content type', 'unexpected status']) {
  test(`HTTP fixture: ${invalid} never publishes plaintext or a receipt`, { timeout: 5000 }, async (t) => {
    const secret = 'must never be published'
    const { requests, fetcher } = await fixture(t, (_request, response) => {
      if (requests.length === 1) return json(response, { id: 'record-1', plaintext: 'previously received' })
      if (invalid === 'mismatched ID') return json(response, { id: 'other', plaintext: secret })
      if (invalid === 'unexpected status') return json(response, { id: 'record-1', plaintext: secret }, 201)
      response.writeHead(200, { 'Content-Type': invalid === 'wrong content type' ? 'text/plain' : 'application/json' })
      response.end(invalid === 'malformed JSON' ? `{"plaintext":"${secret}"` : JSON.stringify({ id: 'record-1', plaintext: secret }))
    })
    const { session } = setup(t, fetcher)
    session.recordId.value = 'record-1'
    await session.perform('read')
    assert.equal(session.resultReceivedAt.value, receipt)
    const pending = session.perform('read')
    assert.equal(session.result.value, null)
    assert.equal(session.resultReceivedAt.value, null)
    await pending
    assert.equal(session.result.value, null)
    assert.equal(session.resultReceivedAt.value, null)
    assert.equal(session.message.value, '')
    assert.equal(session.busy.value, '')
    assert.ok(session.error.value)
    assert.ok(!session.error.value.includes(secret))
    assert.equal(requests.length, 2)
  })
}

for (const outcome of ['success', 'failure']) {
  test(`HTTP fixture: delayed old ${outcome} ignoring fetch abort cannot overwrite a new explicit read`, { timeout: 5000 }, async (t) => {
    const arrived = deferred()
    const { requests, fetcher } = await fixture(t, (request, response) => {
      if (request.url.endsWith('/old')) arrived.resolve(response)
      else json(response, { id: 'new', plaintext: 'newly received' })
    })
    let oldSignal, oldNetwork
    const { session } = setup(t, (path, options) => {
      if (!path.endsWith('/old')) return fetcher(path, options)
      oldSignal = options.signal
      // Deliberately keep the real HTTP exchange alive after session cancellation.
      oldNetwork = fetcher(path, { ...options, signal: undefined })
      return oldNetwork
    })
    session.recordId.value = 'old'
    const oldPending = session.perform('read')
    const oldResponse = await arrived.promise
    session.clearSession()
    assert.equal(oldSignal.aborted, true)
    assert.deepEqual(state(session), empty)
    await oldPending

    session.token.value = inputToken
    session.recordId.value = 'new'
    await session.perform('read')
    const current = state(session)
    assert.deepEqual(current.result, { id: 'new', plaintext: 'newly received' })
    assert.equal(current.resultReceivedAt, receipt)
    assert.equal(current.message, 'Record opgehaald.')
    assert.equal(current.error, '')
    json(oldResponse, { id: 'old', plaintext: 'obsolete private contents' }, outcome === 'success' ? 200 : 403)
    await oldNetwork
    assert.deepEqual(state(session), current)
    assert.equal(requests.length, 2)
  })
}

for (const cleanup of ['clearSession', 'scope disposal']) {
  test(`HTTP fixture: ${cleanup} aborts a streaming body without restoring session state`, { timeout: 5000 }, async (t) => {
    const chunkRead = deferred()
    const closed = deferred()
    let streamingResponse, networkSignal
    const { requests, fetcher } = await fixture(t, (_request, response) => {
      streamingResponse = response
      response.once('close', () => closed.resolve())
      response.writeHead(200, { 'Content-Type': 'application/json' })
      response.write('{"id":"stream","plaintext":"private unfinished contents')
    })
    const { session, scope } = setup(t, async (path, options) => {
      networkSignal = options.signal
      const response = await fetcher(path, options)
      // Observe a real network chunk reaching the production reader, without replacing it.
      const getReader = response.body.getReader.bind(response.body)
      t.mock.method(response.body, 'getReader', (...args) => {
        const reader = getReader(...args)
        const read = reader.read.bind(reader)
        t.mock.method(reader, 'read', async () => {
          const chunk = await read()
          if (!chunk.done) chunkRead.resolve()
          return chunk
        })
        return reader
      })
      return response
    })
    session.recordId.value = 'stream'
    const pending = session.perform('read')
    await chunkRead.promise
    assert.equal(session.busy.value, 'read')
    assert.equal(networkSignal.aborted, false)
    if (cleanup === 'clearSession') session.clearSession()
    else scope.stop()
    assert.equal(networkSignal.aborted, true)
    assert.deepEqual(state(session), empty)
    await pending
    await closed.promise
    assert.equal(streamingResponse.writableFinished, false)
    assert.deepEqual(state(session), empty)
    assert.equal(requests.length, 1)
  })
}
