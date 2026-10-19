import test from 'node:test'
import assert from 'node:assert/strict'
import { commitCommand } from '../src/api.js'

const token = 'test-only-commit-input'
const command = ' registreer é😀 wijziging '
const start = 1_000
const end = 2_000
const ticket = () => ({ id: 'ticket-original', command, not_before: start, expires_at: end })
const record = committed_at => ({ id: 'record-original', command, committed_at })
const json = value => new Response(JSON.stringify(value), {
  status: 201, headers: { 'Content-Type': 'application/json' },
})
const invalidResponse = { message: 'Onverwacht commandoantwoord van de service.' }

test('commit accepts the inclusive start and last millisecond for numeric and legacy ISO ticket windows', async t => {
  t.mock.method(Date, 'now', () => start)
  for (const iso of [false, true]) {
    const data = ticket()
    if (iso) {
      data.not_before = new Date(start).toISOString()
      data.expires_at = new Date(end).toISOString()
    }
    for (const time of [start, end - 1]) {
      const result = { ...record(time), id: 'r'.repeat(128) }
      assert.deepEqual(await commitCommand(data, command, token, async () => json({
        ...result, ignored: 'not part of the command record',
      })), result)
    }
  }
})

test('commit rejects timestamps before the start and at the exclusive end without retrying', async t => {
  t.mock.method(Date, 'now', () => start)
  for (const iso of [false, true]) {
    const data = ticket()
    if (iso) {
      data.not_before = new Date(start).toISOString()
      data.expires_at = new Date(end).toISOString()
    }
    for (const time of [start - 1, end]) {
      let calls = 0
      await assert.rejects(commitCommand(data, command, token, async (url, options) => {
        calls++
        assert.equal(url, '/v1/commands')
        assert.equal(options.method, 'POST')
        return json(record(time))
      }), invalidResponse)
      assert.equal(calls, 1)
    }
  }
})

test('commit requires a nonnegative safe integer Date-representable numeric epoch', async t => {
  t.mock.method(Date, 'now', () => start)
  // Broad bounds isolate timestamp validation from window membership.
  const data = { ...ticket(), not_before: -100, expires_at: Number.MAX_SAFE_INTEGER + 2 }
  for (const time of [
    new Date(start).toISOString(), String(start), start + 0.5, -1,
    Number.MAX_SAFE_INTEGER + 1, 8_640_000_000_000_001,
    null, true,
  ]) {
    await assert.rejects(commitCommand(data, command, token, async () => json(record(time))), invalidResponse)
  }
})

test('commit rejects oversized IDs, invalid records and nonexact commands with sanitized single-POST failures', async t => {
  t.mock.method(Date, 'now', () => start)
  for (const result of [
    {}, { ...record(start), id: 'r'.repeat(129) }, { ...record(start), id: '../bad' },
    { ...record(start), command: command.trim() }, { ...record(start), command: token },
    { ...record(start), command: 'x'.repeat(1025) },
  ]) {
    let calls = 0
    await assert.rejects(commitCommand(ticket(), command, token, async (url, options) => {
      calls++
      assert.equal(url, '/v1/commands')
      assert.equal(options.method, 'POST')
      return json(result)
    }), invalidResponse)
    assert.equal(calls, 1)
  }
})

test('commit accepts an in-window server decision even when the response arrives after local expiry', async t => {
  let now = start
  t.mock.method(Date, 'now', () => now)
  let respond
  const result = record(end - 1)
  const pending = commitCommand(ticket(), command, token, () => new Promise(resolve => { respond = resolve }))
  now = end + 1
  respond(json(result))
  assert.deepEqual(await pending, result)
})

test('pending commit captures the original ticket ID, command and window despite caller mutation', async t => {
  t.mock.method(Date, 'now', () => start)
  for (const accepted of [true, false]) {
    const data = ticket()
    let respond, sent
    let calls = 0
    const result = record(accepted ? end - 1 : end)
    const pending = commitCommand(data, data.command, token, (url, options) => {
      calls++
      assert.equal(url, '/v1/commands')
      assert.equal(options.method, 'POST')
      sent = options
      return new Promise(resolve => { respond = resolve })
    })
    Object.assign(data, {
      id: 'ticket-changed', command: 'changed',
      not_before: accepted ? end + 10 : start - 10,
      expires_at: accepted ? end + 20 : end + 10,
    })
    assert.deepEqual(JSON.parse(sent.body), { ticket_id: 'ticket-original', command })
    respond(json(result))
    if (accepted) assert.deepEqual(await pending, result)
    else await assert.rejects(pending, invalidResponse)
    assert.equal(calls, 1)
  }
})
