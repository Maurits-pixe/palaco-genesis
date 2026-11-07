import test from 'node:test'
import assert from 'node:assert/strict'
import { issueTicket } from '../src/api.js'

const token = 'test-issuance-input'
const command = '  registreer 😀 wijziging  '
const headers = { 'Content-Type': 'application/json' }
const response = value => new Response(JSON.stringify(value), { status: 201, headers })
const valid = { id: 'ticket-1', not_before: 1000, expires_at: 2000 }

for (const field of ['not_before', 'expires_at']) {
  for (const [name, literal] of [
    ['ISO date', '"2026-10-19T00:00:00.000Z"'],
    ['numeric string', '"1000"'],
    ['null', 'null'],
    ['fractional', '1000.5'],
    ['negative', '-1'],
    ['unsafe integer', '9007199254740992'],
    ['positive infinity', '1e400'],
    ['negative infinity', '-1e400'],
    ['outside Date range', '8640000000000001'],
  ]) {
    test(`issuance rejects ${field}: ${name}, without retry or response detail leakage`, async () => {
      let calls = 0
      const body = JSON.stringify({ ...valid, private: token }).replace(`"${field}":${valid[field]}`, `"${field}":${literal}`)
      await assert.rejects(issueTicket(command, 1000, token, async () => {
        calls++
        return new Response(body, { status: 201, headers })
      }), { message: 'Onverwacht ticketantwoord van de service.' })
      assert.equal(calls, 1)
    })
  }
}

for (const [name, values] of [
  ['reversed interval', { not_before: 2000, expires_at: 1000 }],
  ['zero duration', { expires_at: 1000 }],
  ['too short within maximum', { expires_at: 1999 }],
  ['too long within maximum', { expires_at: 2001 }],
  ['maximum duration does not match requested TTL', { expires_at: 61000 }],
  ['duration exceeds maximum', { expires_at: 61001 }],
  ['fractional interval with exact TTL', { not_before: 1000.5, expires_at: 2000.5 }],
  ['negative start with exact TTL', { not_before: -1, expires_at: 999 }],
  ['unsafe interval with exact TTL', { not_before: 9007199254740992, expires_at: 9007199254741992 }],
  ['unrepresentable dates with exact TTL', { not_before: 8640000000000001, expires_at: 8640000000001001 }],
  ['ID longer than backend lookup limit', { id: 'a'.repeat(129) }],
  ['invalid ID characters', { id: '../private' }],
  ['empty ID', { id: '' }],
  ['nonstring ID', { id: 123 }],
]) {
  test(`issuance rejects ${name}`, async () => {
    let calls = 0
    await assert.rejects(issueTicket(command, 1000, token, async () => {
      calls++
      return response({ ...valid, ...values, private: token })
    }), { message: 'Onverwacht ticketantwoord van de service.' })
    assert.equal(calls, 1)
  })
}

for (const ttlMs of [1, 60000]) {
  for (const start of [0, 8640000000000000 - ttlMs]) {
    test(`issuance accepts exact TTL ${ttlMs} at ${start} without consulting the client clock`, async t => {
      t.mock.method(Date, 'now', () => { throw new Error('client clock must not decide issuance') })
      const issued = { id: 'a'.repeat(128), not_before: start, expires_at: start + ttlMs }
      let calls = 0
      const result = await issueTicket(command, ttlMs, token, async (url, options) => {
        calls++
        assert.equal(url, '/v1/tickets')
        assert.equal(options.method, 'POST')
        assert.deepEqual(JSON.parse(options.body), { command, ttl_ms: ttlMs })
        return response(issued)
      })
      assert.equal(calls, 1)
      assert.deepEqual(result, { ...issued, command })
    })
  }
}

test('issuance ignores extra response fields and retains only the exact client-associated command', async () => {
  const result = await issueTicket(command, 1000, token, async () =>
    response({ ...valid, command: 'server field is not authority', extra: true }))
  assert.deepEqual(result, { ...valid, command })
})
