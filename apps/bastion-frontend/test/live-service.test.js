import test from 'node:test'
import assert from 'node:assert/strict'
import { once, getEventListeners } from 'node:events'
import { createServer } from 'node:net'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { effectScope } from 'vue'
import * as productionApi from '../src/api.js'
import { useSession } from '../src/useSession.js'
import { createBastion } from '../../../services/bastion-core/service.js'

const token = 'test-only-live-service-operator-secret'
const now = 1000

async function bounded(pending, label) {
  let timer
  try {
    return await Promise.race([
      pending,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out`)), 5000)
      }),
    ])
  } finally {
    clearTimeout(timer)
  }
}

async function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'palaco-bastion-live-test-'))
  const probe = createServer()
  const scope = effectScope()
  const eventTarget = new EventTarget()
  const intervals = new Set()
  const calls = []
  let app, db, session, dropNext
  let losses = 0
  t.after(async () => {
    try {
      scope.stop()
      if (session) {
        assert.equal(session.token.value, '')
        assert.equal(session.ticket.value, null)
        assert.equal(session.lastSubmissionId.value, '')
        assert.equal(session.revocationUncertain.value, false)
        assert.equal(session.busy.value, '')
        assert.deepEqual(session.commands.value, [])
      }
      assert.equal(intervals.size, 0)
      assert.equal(getEventListeners(eventTarget, 'pagehide').length, 0)
    } finally {
      try {
        db?.close()
        if (app) await bounded(app.close(), 'service shutdown')
      } finally {
        if (probe.listening) {
          await bounded(new Promise(resolve => probe.close(resolve)), 'port probe shutdown')
        }
        rmSync(dir, { recursive: true, force: true })
      }
    }
  })

  const listening = once(probe, 'listening')
  probe.listen(0, '127.0.0.1')
  await bounded(listening, 'port allocation')
  const port = probe.address().port
  await bounded(new Promise(resolve => probe.close(resolve)), 'port release')
  const dbPath = join(dir, 'journal.db')
  app = createBastion({ token, port, dbPath }, { clock: () => now })
  await bounded(app.listen(), 'service startup')
  db = new DatabaseSync(dbPath)
  const origin = `http://127.0.0.1:${app.port}`
  const fetcher = async (path, options) => {
    assert.ok(options.signal instanceof AbortSignal)
    calls.push({ path, method: options.method })
    const response = await fetch(origin + path, options)
    if (`${options.method} ${path}` === dropNext) {
      dropNext = undefined
      assert.equal(response.status, options.method === 'POST' ? 201 : 200)
      // The mutation really committed before its successful response is lost.
      if (options.method === 'POST') {
        const { ticket_id: id } = JSON.parse(options.body)
        assert.equal(db.prepare('SELECT consumed FROM tickets WHERE id = ?').get(id).consumed, 1)
        assert.equal(db.prepare('SELECT COUNT(*) AS count FROM commands WHERE ticket_id = ?').get(id).count, 1)
      } else {
        const id = path.split('/').at(-1)
        assert.equal(db.prepare('SELECT revoked FROM tickets WHERE id = ?').get(id).revoked, 1)
        assert.equal(db.prepare('SELECT COUNT(*) AS count FROM commands WHERE ticket_id = ?').get(id).count, 0)
      }
      await bounded(response.body.cancel(), 'lost response body cancellation')
      losses++
      throw new TypeError('Successful response lost in transit')
    }
    return response
  }
  // Only replace the optional transport; preserve every argument, including the session's signal.
  const api = Object.fromEntries([
    ['issueTicket', 3], ['commitCommand', 3], ['revokeTicket', 2],
    ['getTicketStatus', 2], ['listCommands', 1],
  ].map(([name, position]) => [name, (...args) => {
    assert.equal(args[position], undefined)
    assert.ok(args[position + 1] instanceof AbortSignal)
    args[position] = fetcher
    return productionApi[name](...args)
  }]))
  t.mock.method(Date, 'now', () => now)
  session = scope.run(() => useSession({
    api,
    eventTarget,
    scheduler: {
      now: () => now,
      setInterval(callback, milliseconds) {
        assert.equal(typeof callback, 'function')
        assert.equal(milliseconds, 100)
        const handle = Symbol('manual clock')
        intervals.add(handle)
        return handle
      },
      clearInterval(handle) {
        assert.equal(intervals.delete(handle), true)
      },
    },
  }))
  assert.equal(intervals.size, 1)
  assert.equal(getEventListeners(eventTarget, 'pagehide').length, 1)
  // Realtime stays disconnected: these tests deliberately exercise only real HTTP.
  assert.equal(session.realtimeStatus.value, 'disconnected')
  session.token.value = token
  session.command.value = ' registreer é😀 wijziging '
  return {
    session, db, calls,
    count: (method, path) => calls.filter(call => call.method === method && call.path === path).length,
    loseNext: (method, path) => { dropNext = `${method} ${path}` },
    get losses() { return losses },
    run: action => bounded(session.perform(action), action),
  }
}

test('live service: ticket, commit, explicit status and journal use the same persisted record', { timeout: 15000 }, async t => {
  const f = await fixture(t)
  const s = f.session
  await f.run('ticket')
  assert.equal(s.error.value, '')
  const issued = { ...s.ticket.value }
  assert.equal(issued.command, s.command.value)
  assert.equal(issued.not_before, now)
  assert.equal(issued.expires_at, now + s.ttlMs.value)
  assert.equal(s.canCommit.value, true)
  assert.equal(f.db.prepare('SELECT consumed FROM tickets WHERE id = ?').get(issued.id).consumed, 0)

  await f.run('commit')
  assert.equal(s.error.value, '')
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, issued.id)
  assert.equal(s.commands.value.length, 1)
  const record = { ...s.commands.value[0] }
  assert.deepEqual(record, {
    id: record.id, command: issued.command, committed_at: now,
  })
  assert.deepEqual({ ...f.db.prepare('SELECT id, command, committed_at FROM commands WHERE ticket_id = ?').get(issued.id) }, record)

  await bounded(s.checkLastSubmission(), 'committed status')
  assert.equal(s.error.value, '')
  assert.equal(s.outcome.value.id, issued.id)
  assert.equal(s.outcome.value.status, 'committed')
  assert.equal(s.outcome.value.checked_at, now)
  assert.deepEqual(s.outcome.value.record, record)
  assert.equal(s.outcomeReceivedAt.value, now)
  await f.run('list')
  assert.equal(s.hasLoaded.value, true)
  assert.equal(s.lastJournalRefreshAt.value, now)
  assert.deepEqual(s.commands.value, [record])
  assert.equal(f.count('POST', '/v1/tickets'), 1)
  assert.equal(f.count('POST', '/v1/commands'), 1)
  assert.equal(f.count('GET', `/v1/tickets/${issued.id}`), 1)
  assert.equal(f.count('GET', '/v1/commands'), 1)
  assert.equal(f.calls.length, 4)
})

test('live service: a lost successful commit consumes local authority without retry; explicit lookup recovers its record', { timeout: 15000 }, async t => {
  const f = await fixture(t)
  const s = f.session
  await f.run('ticket')
  const id = s.ticket.value.id
  f.loseNext('POST', '/v1/commands')
  await f.run('commit')
  assert.equal(f.losses, 1)
  assert.match(s.error.value, /Geen geldig antwoord/)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, id)
  assert.equal(s.lookupId.value, id)
  assert.equal(s.outcome.value, null)
  assert.deepEqual(s.commands.value, [])
  const persisted = { ...f.db.prepare('SELECT id, command, committed_at FROM commands WHERE ticket_id = ?').get(id) }
  assert.equal(persisted.command, s.command.value)
  assert.equal(persisted.committed_at, now)
  assert.equal(f.db.prepare('SELECT consumed FROM tickets WHERE id = ?').get(id).consumed, 1)
  assert.equal(f.calls.length, 2, 'no automatic retry or status lookup')

  await f.run('commit')
  assert.equal(f.calls.length, 2, 'recommit cannot send a second POST')
  assert.equal(s.lastSubmissionId.value, id)
  await bounded(s.checkLastSubmission(), 'lost commit reconciliation')
  assert.equal(s.error.value, '')
  assert.equal(s.outcome.value.id, id)
  assert.equal(s.outcome.value.status, 'committed')
  assert.deepEqual(s.outcome.value.record, persisted)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, id)
  await f.run('list')
  assert.equal(s.hasLoaded.value, true)
  assert.deepEqual(s.commands.value, [persisted])
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM commands').get().count, 1)
  assert.equal(f.count('POST', '/v1/commands'), 1)
  assert.equal(f.count('GET', `/v1/tickets/${id}`), 1)
  assert.equal(f.calls.length, 4)
})

test('live service: a lost successful revocation blocks authority until explicit terminal status permits new issuance', { timeout: 15000 }, async t => {
  const f = await fixture(t)
  const s = f.session
  await f.run('ticket')
  const held = { ...s.ticket.value }
  f.loseNext('DELETE', `/v1/tickets/${held.id}`)
  await f.run('revoke')
  assert.equal(f.losses, 1)
  assert.match(s.error.value, /Geen geldig antwoord/)
  assert.deepEqual(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, '')
  assert.equal(s.outcome.value, null)
  assert.equal(f.db.prepare('SELECT revoked FROM tickets WHERE id = ?').get(held.id).revoked, 1)
  assert.equal(f.calls.length, 2, 'no automatic retry or reconciliation')

  await f.run('ticket')
  await f.run('commit')
  assert.equal(f.calls.length, 2, 'uncertainty blocks issuance and commit without network requests')
  assert.deepEqual(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true)
  await bounded(s.checkCurrentTicket(), 'revocation reconciliation')
  assert.equal(s.error.value, '')
  assert.equal(s.outcome.value.id, held.id)
  assert.equal(s.outcome.value.status, 'revoked')
  assert.equal(s.outcome.value.revoked, true)
  assert.equal(s.outcome.value.record, null)
  assert.equal(s.outcomeReceivedAt.value, now)
  assert.equal(s.ticket.value, null)
  assert.equal(s.revocationUncertain.value, false)
  assert.equal(s.canCommit.value, false)
  await f.run('ticket')
  assert.equal(s.error.value, '')
  assert.notEqual(s.ticket.value.id, held.id)
  assert.equal(s.canCommit.value, true)
  assert.equal(f.db.prepare('SELECT revoked, consumed FROM tickets WHERE id = ?').get(s.ticket.value.id).revoked, 0)
  await f.run('list')
  assert.equal(s.hasLoaded.value, true)
  assert.deepEqual(s.commands.value, [])
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM commands').get().count, 0)
  assert.equal(f.count('POST', '/v1/tickets'), 2)
  assert.equal(f.count('DELETE', `/v1/tickets/${held.id}`), 1)
  assert.equal(f.count('GET', `/v1/tickets/${held.id}`), 1)
  assert.equal(f.count('POST', '/v1/commands'), 0)
  assert.equal(f.calls.length, 5)
})
