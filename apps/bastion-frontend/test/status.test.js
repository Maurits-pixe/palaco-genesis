import test from 'node:test'
import assert from 'node:assert/strict'
import { beginSubmission, getTicketStatus, reconcileTicketStatus, validateTicketStatus } from '../src/api.js'

const token = 'test-only-token'
const snapshot = (changes = {}) => ({
  id: 'ticket-1', command: 'journal only', not_before: 1000, expires_at: 1100,
  checked_at: 1000, revoked: false, status: 'active', record: null, ...changes,
})
const record = { id: 'record-1', command: 'journal only', committed_at: 1010 }
const maxDate = 8_640_000_000_000_000
const response = (value, status = 200) => new Response(JSON.stringify(value), {
  status, headers: { 'Content-Type': 'application/json' },
})

test('manual status lookup makes exactly one authenticated GET and accepts all consistent states', async () => {
  for (const value of [
    snapshot({ checked_at: 999, status: 'pending' }),
    snapshot(),
    snapshot({ checked_at: 1099 }),
    snapshot({ checked_at: 1100, status: 'expired' }),
    snapshot({ checked_at: 999, revoked: true, status: 'revoked' }),
    snapshot({ checked_at: 1200, revoked: true, status: 'revoked' }),
    snapshot({ checked_at: 1010, status: 'committed', record }),
    snapshot({ checked_at: 1200, status: 'committed', revoked: true, record }),
  ]) {
    let calls = 0
    assert.deepEqual(await getTicketStatus(value.id, token, async (path, options) => {
      calls++
      assert.equal(path, '/v1/tickets/ticket-1')
      assert.equal(options.method, 'GET')
      assert.equal(options.headers.Authorization, ['Bearer', token].join(' '))
      assert.equal(options.body, undefined)
      assert.equal(options.redirect, 'error')
      assert.equal(options.cache, 'no-store')
      assert.equal(options.credentials, 'omit')
      return response(value)
    }), value)
    assert.equal(calls, 1)
  }
})

test('lookup validates IDs and tokens before fetching', async () => {
  const never = () => assert.fail('must not fetch')
  for (const id of [undefined, null, {}, '', '../commands', 'id?token=secret', 'a/b', 'a'.repeat(129)]) {
    await assert.rejects(getTicketStatus(id, token, never), /ticket-ID/)
  }
  for (const invalid of ['', '\r\n', null]) await assert.rejects(getTicketStatus('id', invalid, never), /token/)
})

test('status response rejects malformed schemas, commands, times and windows', async () => {
  const invalid = [
    null, [], {}, snapshot({ extra: 'hidden subject' }), snapshot({ id: 'other' }),
    snapshot({ command: '' }), snapshot({ command: ' ' }), snapshot({ command: '😀'.repeat(513) }),
    snapshot({ revoked: 0 }), snapshot({ record: undefined }),
  ]
  for (const field of ['not_before', 'expires_at', 'checked_at']) {
    for (const value of ['1970-01-01T00:00:01Z', '1000', null, NaN, Infinity, -1, 1000.5,
      maxDate + 1, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER + 1]) {
      invalid.push(snapshot({ [field]: value }))
    }
  }
  invalid.push(snapshot({ expires_at: 1000 }), snapshot({ expires_at: 999 }), snapshot({ expires_at: 61001 }))
  for (const value of invalid) {
    assert.equal(validateTicketStatus(value, 'ticket-1'), null)
    let calls = 0
    await assert.rejects(getTicketStatus('ticket-1', token, async () => {
      calls++
      return response(value)
    }), value === null || Array.isArray(value) ? /Onverwacht antwoord/ : /ticketstatusantwoord/)
    assert.equal(calls, 1)
  }
})

test('status response rejects precedence conflicts, missing records and wrong record binding', async () => {
  const invalid = [
    snapshot({ status: 'unknown' }), snapshot({ status: 'pending' }),
    snapshot({ status: 'expired' }), snapshot({ status: 'revoked' }),
    snapshot({ status: 'committed' }), snapshot({ checked_at: 1100 }),
    snapshot({ revoked: true }), snapshot({ record, checked_at: 1020 }),
  ]
  for (const change of [
    { id: '' }, { id: 'a'.repeat(129) }, { command: 'different' }, { extra: true },
    { committed_at: 999 }, { committed_at: 1100 }, { committed_at: 1021 },
    { committed_at: '1970-01-01T00:00:01Z' }, { committed_at: 1010.5 },
    { committed_at: -1 }, { committed_at: maxDate + 1 },
    { committed_at: Number.MAX_SAFE_INTEGER }, { committed_at: Number.MAX_SAFE_INTEGER + 1 },
  ]) invalid.push(snapshot({ checked_at: 1020, status: 'committed', record: { ...record, ...change } }))
  for (const value of invalid) {
    assert.equal(validateTicketStatus(value, 'ticket-1'), null)
    await assert.rejects(getTicketStatus('ticket-1', token, async () => response(value)), /ticketstatusantwoord/)
  }
})

test('status accepts zero and the inclusive Date limit without consulting the client clock', async () => {
  for (const value of [
    snapshot({ not_before: 0, expires_at: 1, checked_at: 0 }),
    snapshot({
      not_before: 0, expires_at: 60_000, checked_at: 0, status: 'committed',
      record: { ...record, committed_at: 0 },
    }),
    snapshot({ not_before: maxDate - 60_000, expires_at: maxDate, checked_at: maxDate - 1 }),
    snapshot({ not_before: maxDate - 1, expires_at: maxDate, checked_at: maxDate, status: 'expired' }),
    snapshot({
      not_before: maxDate - 1, expires_at: maxDate, checked_at: maxDate, status: 'committed',
      record: { ...record, committed_at: maxDate - 1 },
    }),
  ]) {
    assert.equal(validateTicketStatus(value, value.id), value)
    let calls = 0
    assert.deepEqual(await getTicketStatus(value.id, token, async () => {
      calls++
      return response(value)
    }), value)
    assert.equal(calls, 1)
    const held = { id: value.id, command: value.command }
    const commands = [record]
    const terminal = value.status !== 'active'
    assert.deepEqual(reconcileTicketStatus(held, true, commands, value), {
      ticket: terminal ? null : held, revocationUncertain: !terminal, commands,
    })
  }
})

test('Date-invalid consistent snapshots cannot retire held authority or uncertainty', async () => {
  const invalid = []
  for (const limit of [maxDate, Number.MAX_SAFE_INTEGER - 100]) {
    const nearLimit = { not_before: limit - 99, expires_at: limit + 1, checked_at: limit }
    const aboveLimit = { not_before: limit + 1, expires_at: limit + 100, checked_at: limit + 50 }
    for (const times of [nearLimit, aboveLimit]) {
      invalid.push(
        snapshot({ ...times, status: 'active' }),
        snapshot({ ...times, status: 'revoked', revoked: true }),
        snapshot({ ...times, checked_at: times.expires_at, status: 'expired' }),
        snapshot({
          ...times, status: 'committed', revoked: true,
          record: { ...record, committed_at: times.checked_at },
        }),
      )
    }
  }
  for (const checked_at of [maxDate + 1, Number.MAX_SAFE_INTEGER]) {
    invalid.push(
      snapshot({ checked_at, status: 'expired' }),
      snapshot({ checked_at, status: 'revoked', revoked: true }),
      snapshot({ checked_at, status: 'committed', record }),
    )
  }
  for (const value of invalid) {
    assert.equal(validateTicketStatus(value, value.id), null)
    let calls = 0
    await assert.rejects(getTicketStatus(value.id, token, async () => {
      calls++
      return response(value)
    }), /ticketstatusantwoord/)
    assert.equal(calls, 1)
    const held = {
      id: value.id, command: value.command, not_before: value.not_before, expires_at: value.expires_at,
    }
    const commands = [record]
    for (const uncertain of [false, true]) {
      const state = reconcileTicketStatus(held, uncertain, commands, value)
      assert.equal(state.ticket, held)
      assert.equal(state.revocationUncertain, uncertain)
      assert.equal(state.commands, commands)
    }
  }
})

test('lookup sanitizes HTTP, network, JSON and wrong-success failures without retry', async () => {
  for (const fetcher of [
    ...[400, 401, 403, 404, 409, 410, 429, 500, 503].map(status => async () => response({ error: token }, status)),
    async () => { throw new Error(token) },
    async () => new Response(token, { headers: { 'Content-Type': 'application/json' } }),
    async () => response(snapshot(), 201),
    async () => {
      const result = response(snapshot())
      Object.defineProperty(result, 'redirected', { value: true })
      return result
    },
  ]) {
    let calls = 0
    await assert.rejects(getTicketStatus('ticket-1', token, async (...args) => {
      calls++
      return fetcher(...args)
    }), failure => !failure.message.includes(token))
    assert.equal(calls, 1)
  }
})

test('reconciliation only retires the same held ticket on authoritative terminal status', () => {
  const held = { id: 'ticket-1', command: 'journal only', not_before: 1000, expires_at: 1100 }
  const commands = []
  for (const uncertain of [false, true]) {
    for (const value of [
      snapshot(), snapshot({ checked_at: 999, status: 'pending' }),
      snapshot({ status: 'expired', checked_at: 1100, id: 'other-ticket' }),
      snapshot({ status: 'revoked', revoked: true, command: 'different' }),
      null, { error: 'Ticket not found' }, snapshot({ status: 'committed' }),
    ]) assert.deepEqual(reconcileTicketStatus(held, uncertain, commands, value), {
      ticket: held, revocationUncertain: uncertain, commands,
    })
    for (const value of [
      snapshot({ checked_at: 1100, status: 'expired' }),
      snapshot({ status: 'revoked', revoked: true }),
      snapshot({ checked_at: 1020, status: 'committed', record }),
    ]) {
      const state = reconcileTicketStatus(held, uncertain, commands, value)
      assert.equal(state.ticket, null)
      assert.equal(state.revocationUncertain, false)
      assert.equal(state.commands, commands)
    }
  }
  assert.deepEqual(reconcileTicketStatus(null, false, commands, snapshot()), {
    ticket: null, revocationUncertain: false, commands,
  })
  const committed = snapshot({ checked_at: 1020, status: 'committed', record })
  assert.deepEqual(reconcileTicketStatus(held, true, commands, { ...committed, id: 'other' }), {
    ticket: held, revocationUncertain: true, commands,
  })
  assert.deepEqual(reconcileTicketStatus(null, false, [record], committed).commands, [record])
})

test('historical committed lookup preserves all 100 current journal rows and their order', () => {
  const commands = Array.from({ length: 100 }, (_, index) => ({
    id: `current-${index}`, command: `current command ${index}`, committed_at: 2000 - index,
  }))
  const before = structuredClone(commands)
  const old = snapshot({ checked_at: 3000, status: 'committed', record })
  const state = reconcileTicketStatus(null, false, commands, old)
  assert.equal(state.commands, commands)
  assert.deepEqual(state.commands, before)
  assert.equal(state.commands.length, 100)
  assert.equal(state.commands.some(value => value.id === record.id), false)
})

test('submission retires local authority and retains its ID even when the response is lost', async () => {
  const held = { id: 'ticket-1', command: 'journal only' }
  const state = beginSubmission(held)
  await assert.rejects(Promise.reject(new Error('response lost')))
  assert.deepEqual(state, { ticket: null, lastSubmissionId: 'ticket-1' })
  assert.equal(reconcileTicketStatus(state.ticket, false, [], snapshot()).ticket, null)
})
