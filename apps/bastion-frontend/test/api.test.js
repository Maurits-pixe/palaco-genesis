import test from 'node:test'
import assert from 'node:assert/strict'
import { commandLength, commitCommand, issueTicket, listCommands, MAX_COMMAND_LENGTH, mergeCommands, request, ticketUsable } from '../src/api.js'
import config from '../vite.config.js'

const inputToken = 'test-only-user-input'
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
const ticket = () => ({
  id: 'ticket-1', command: 'registreer wijziging',
  not_before: new Date(Date.now() - 1000).toISOString(),
  expires_at: new Date(Date.now() + 30_000).toISOString(),
})
const entry = () => ({ id: 'command-1', command: 'registreer wijziging', committed_at: new Date().toISOString() })

test('ticket issuance sends the exact command and integer TTL', async () => {
  const data = ticket()
  const result = await issueTicket(data.command, 5000, inputToken, async (url, options) => {
    assert.equal(url, '/v1/tickets')
    assert.equal(options.method, 'POST')
    assert.deepEqual(JSON.parse(options.body), { command: data.command, ttl_ms: 5000 })
    assert.equal(options.headers.Authorization, ['Bearer', inputToken].join(' '))
    assert.equal(options.redirect, 'error')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.credentials, 'omit')
    return json(data, 201)
  })
  assert.deepEqual(result, data)
})

test('invalid TTL and blank command never reach the service', async () => {
  const never = () => assert.fail('must not fetch')
  for (const ttl of [0, -1, 60001, 1.5, NaN, '1000']) {
    await assert.rejects(issueTicket('hello', ttl, inputToken, never))
  }
  await assert.rejects(issueTicket(' ', 1000, inputToken, never))
  for (const ttl of [1, 60000]) {
    assert.ok(await issueTicket('hello', ttl, inputToken, async () => json(ticket(), 201)))
  }
})

test('command limit matches backend JavaScript length of 1024 UTF-16 code units', async () => {
  assert.equal(MAX_COMMAND_LENGTH, 1024)
  assert.equal(commandLength('😀'), 2)
  for (const command of ['x'.repeat(1024), 'é'.repeat(1024), '😀'.repeat(512)]) {
    await issueTicket(command, 1000, inputToken, async () => json(ticket(), 201))
    assert.equal(mergeCommands([], { ...entry(), command })[0].command, command)
  }
  for (const command of ['x'.repeat(1025), 'é'.repeat(1025), '😀'.repeat(513)]) {
    await assert.rejects(issueTicket(command, 1000, inputToken, () => assert.fail('must not fetch')), /1024/)
    await assert.rejects(commitCommand({ ...ticket(), command }, command, inputToken, () => assert.fail('must not submit')), /1024/)
  }
})

test('command merging replaces duplicate IDs and caps retained records at 100', async () => {
  const current = Array.from({ length: 100 }, (_, i) => ({ ...entry(), id: `command-${i}` }))
  const updated = { ...entry(), id: 'command-50', command: 'gewijzigd' }
  const merged = mergeCommands(current, updated)
  assert.equal(merged.length, 100)
  assert.deepEqual(merged[0], updated)
  assert.equal(merged.filter(({ id }) => id === updated.id).length, 1)
  const added = mergeCommands(merged, { ...entry(), id: 'new' })
  assert.equal(added.length, 100)
  assert.equal(added[0].id, 'new')
  assert.equal(mergeCommands(current, { invalid: true }), current)
  assert.equal((await listCommands(inputToken, async () => json({
    commands: Array.from({ length: 120 }, (_, i) => ({ ...entry(), id: `command-${i}` })),
  }))).length, 100)
})

test('ticket validity checks not-before, expiry and exact command', () => {
  const data = { id: 'id', command: 'hello', not_before: 100, expires_at: 200 }
  assert.equal(ticketUsable(data, 'hello', 100), true)
  assert.equal(ticketUsable(data, 'hello', 199), true)
  assert.equal(ticketUsable(data, 'hello', 99), false)
  assert.equal(ticketUsable(data, 'hello', 200), false)
  assert.equal(ticketUsable(data, 'hello ', 150), false)
  assert.equal(ticketUsable(null, 'hello', 150), false)
})

test('submission is a distinct request carrying ticket ID and command', async () => {
  const data = ticket()
  const result = entry()
  assert.deepEqual(await commitCommand(data, data.command, inputToken, async (url, options) => {
    assert.equal(url, '/v1/commands')
    assert.equal(options.method, 'POST')
    assert.deepEqual(JSON.parse(options.body), { ticket_id: data.id, command: data.command })
    return json(result, 201)
  }), result)
})

test('stale, premature, changed and absent tickets reject without submitting', async () => {
  const never = () => assert.fail('must not submit')
  const data = ticket()
  for (const current of [
    null, { ...data, expires_at: Date.now() - 1 },
    { ...data, not_before: Date.now() + 60_000 },
    { ...data, command: 'different' }, { ...data, id: '../bad' },
  ]) await assert.rejects(commitCommand(current, data.command, inputToken, never))
})

test('list validates each command and excludes unrelated response fields', async () => {
  const item = entry()
  assert.deepEqual(await listCommands(inputToken, async (url) => {
    assert.equal(url, '/v1/commands')
    return json({ commands: [{ ...item, ignored: 'value' }] })
  }), [item])
  for (const result of [{}, { commands: [null] }, { commands: [{ ...item, committed_at: null }] }]) {
    await assert.rejects(listCommands(inputToken, async () => json(result)))
  }
})

test('journal accepts 600 multibyte é characters and rejects over 1024 JavaScript units', async () => {
  const multibyte = { ...entry(), command: 'é'.repeat(600) }
  assert.deepEqual(await listCommands(inputToken, async () => json({ commands: [multibyte] })), [multibyte])
  for (const command of ['é'.repeat(1025), '😀'.repeat(513)]) {
    await assert.rejects(listCommands(inputToken, async () => json({ commands: [{ ...entry(), command }] })))
  }
})

test('malformed tickets and commit responses reject', async () => {
  const data = ticket()
  for (const result of [
    {}, { ...data, id: '../bad' }, { ...data, not_before: null },
    { ...data, expires_at: 'bad' }, { ...data, expires_at: data.not_before },
  ]) await assert.rejects(issueTicket(data.command, 1000, inputToken, async () => json(result, 201)))
  await assert.rejects(commitCommand(data, data.command, inputToken, async () => json({ ...entry(), command: 'different' }, 201)))
})

test('API failures never reflect backend bodies or token details; no automatic retry', async () => {
  for (const status of [400, 401, 403, 404, 409, 410, 422, 429, 500]) {
    let calls = 0
    await assert.rejects(listCommands(inputToken, async () => {
      calls++
      return new Response('SECRET SERVER DETAIL', { status })
    }), (error) => {
      assert.ok(!error.message.includes('SECRET'))
      assert.ok(!error.message.includes(inputToken))
      return true
    })
    assert.equal(calls, 1)
  }
  await assert.rejects(listCommands(inputToken, async () => { throw new Error(inputToken) }), /Geen geldig antwoord/)
  await assert.rejects(listCommands(inputToken, async () => new Response('{')), /Geen geldig antwoord/)
  await assert.rejects(listCommands(inputToken, async () => new Response(null, { status: 302 })))
})

test('empty token and nonlocal paths fail before fetch; timeout aborts', async () => {
  const never = () => assert.fail('must not fetch')
  await assert.rejects(listCommands('', never), /token/)
  await assert.rejects(listCommands('bad\r\nheader', never), /token/)
  await assert.rejects(request('https://example.org', { token: inputToken, fetcher: never }))
  await assert.rejects(request('/v1/commands', {
    token: inputToken, timeoutMs: 10,
    fetcher: (_url, { signal }) => new Promise((_resolve, reject) => {
      signal.addEventListener('abort', () => reject(new Error(inputToken)), { once: true })
    }),
  }), /Geen geldig antwoord/)
})

test('Vite uses strict local port, fixed backend and websocket proxy', () => {
  assert.equal(config.server.host, '127.0.0.1')
  assert.equal(config.server.port, 5175)
  assert.equal(config.server.strictPort, true)
  assert.deepEqual(Object.keys(config.server.proxy), ['/v1', '/.well-known', '/health', '/socket.io'])
  for (const proxy of Object.values(config.server.proxy)) {
    assert.equal(proxy.target, 'http://127.0.0.1:8788')
    assert.equal(proxy.followRedirects, false)
  }
  assert.equal(config.server.proxy['/socket.io'].ws, true)
})
