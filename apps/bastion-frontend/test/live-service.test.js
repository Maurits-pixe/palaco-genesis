import test from 'node:test'
import assert from 'node:assert/strict'
import { once, getEventListeners } from 'node:events'
import { createServer } from 'node:net'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { effectScope, ref, watch } from 'vue'
import { io } from 'socket.io-client'
import * as productionApi from '../src/api.js'
import { createRealtime } from '../src/realtime.js'
import { useSession } from '../src/useSession.js'
import { createBastion } from '../../../services/bastion-core/service.js'
import { TRUSTED_MODULES, verifyModule, launchUrl } from '../../neo-launcher/src/verification.js'

const token = 'test-only-live-service-operator-secret'
const now = 1000
const commitCaution = 'Vastlegging niet bevestigd. Controleer de laatste inzending via het ticket-ID. Dien niet automatisch opnieuw in.'
const revokeCaution = 'Intrekking niet bevestigd. Vastleggen en nieuwe tickets blijven geblokkeerd. Controleer dit ticket of trek het expliciet opnieuw in.'
const ticketCaution = 'Ticketuitgifte niet bevestigd. Er kan al een serverticket bestaan. Zonder ontvangen ticket is lokaal vastleggen niet mogelijk. Geen automatische nieuwe aanvraag.'
const statusCaution = 'Ticketstatus niet bevestigd. Er is geen geldige nieuwe momentopname ontvangen. Deze fout bevestigt geen vastlegging of intrekking en herstelt geen toestemming. Controleer het ticket expliciet opnieuw; geen automatische herhaling.'
const localCommitBlocked = 'Niet ingezonden: de lokale ticketcontrole blokkeert vastleggen. Voor deze actie is geen commitverzoek verstuurd. Dit zegt niets over eerdere inzendingen.'

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

async function waitFor(read, predicate, label) {
  let stop
  try {
    await bounded(new Promise(resolve => {
      stop = watch(read, value => {
        if (predicate(value)) resolve()
      }, { immediate: true, flush: 'sync' })
    }), label)
  } finally {
    stop?.()
  }
}

async function nextCommit(socket, command) {
  let listener
  try {
    return await bounded(new Promise(resolve => {
      listener = entry => {
        if (entry.command === command) resolve(entry)
      }
      socket.on('command:committed', listener)
    }), `realtime commit: ${command}`)
  } finally {
    socket.off('command:committed', listener)
  }
}

function assertDisconnected(socket) {
  assert.equal(socket.connected, false)
  assert.equal(socket.active, false)
  assert.deepEqual(socket.auth, {})
  assert.deepEqual(socket.io.opts.auth, {})
  assert.deepEqual(Object.keys(socket._callbacks ?? {}), [])
  assert.equal(socket.io._readyState, 'closed')
}

async function fixture(t, { realtime = false, fault = () => {} } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'palaco-bastion-live-test-'))
  const probe = createServer()
  const scope = effectScope()
  const eventTarget = new EventTarget()
  const intervals = new Set()
  const calls = []
  const externalCommitCalls = []
  const sockets = []
  const listGates = []
  let app, db, session, dropNext, witness, nextListGate, tick
  let localNow = now
  let serverNow = now
  let losses = 0
  t.after(async () => {
    for (const gate of listGates) gate.release()
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
      for (const socket of sockets) assertDisconnected(socket)
    } finally {
      witness?.removeAllListeners()
      witness?.disconnect()
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
  app = createBastion({ token, port, dbPath }, { clock: () => serverNow, fault: stage => fault(stage) })
  await bounded(app.listen(), 'service startup')
  db = new DatabaseSync(dbPath)
  let origin = `http://127.0.0.1:${app.port}`
  const fetcher = async (path, options) => {
    assert.ok(options.signal instanceof AbortSignal)
    const call = { path, method: options.method }
    calls.push(call)
    const gate = options.method === 'GET' && path === '/v1/commands' ? nextListGate : undefined
    if (gate) nextListGate = undefined
    // A gated transport deliberately ignores cancellation, including while awaiting release.
    // The production API still receives the session signal and must reject a late response.
    const response = await fetch(origin + path, gate ? { ...options, signal: undefined } : options)
    call.status = response.status
    if (gate) {
      assert.equal(response.status, 200)
      const snapshot = await bounded(response.clone().json(), 'real journal snapshot body')
      gate.receive({ snapshot, signal: options.signal })
      await bounded(gate.wait, 'journal response release')
      assert.equal(response.bodyUsed, false, 'deliver the original, unconsumed HTTP response')
      gate.deliver()
    }
    if (`${options.method} ${path}` === dropNext) {
      dropNext = undefined
      assert.equal(response.status, options.method === 'POST' ? 201 : 200)
      if (options.method === 'GET' && path === '/v1/commands') {
        const listed = await bounded(response.clone().json(), 'real lost journal response body')
        const stored = db.prepare('SELECT id, command, committed_at FROM commands ORDER BY seq DESC LIMIT 100')
          .all().map(row => ({ ...row }))
        assert.deepEqual(listed, { commands: stored })
        assert.equal(response.bodyUsed, false, 'inspect only a clone before dropping the original response')
      } else if (options.method === 'GET' && /^\/v1\/tickets\/[a-zA-Z0-9_-]+$/.test(path)) {
        const id = path.split('/').at(-1)
        const snapshot = await bounded(response.clone().json(), 'real lost ticket status response body')
        assert.deepEqual(productionApi.validateTicketStatus(snapshot, id), snapshot)
        const stored = db.prepare('SELECT * FROM tickets WHERE id = ?').get(id)
        assert.ok(stored, 'the status must describe the requested persisted ticket')
        assert.equal(snapshot.id, stored.id)
        assert.equal(snapshot.command, stored.command)
        assert.equal(snapshot.not_before, stored.not_before)
        assert.equal(snapshot.expires_at, stored.expires_at)
        assert.equal(snapshot.revoked, stored.revoked === 1)
        const record = db.prepare('SELECT id, command, committed_at FROM commands WHERE ticket_id = ?').get(id)
        assert.deepEqual(snapshot.record, record ? { ...record } : null)
        assert.equal(response.bodyUsed, false, 'inspect only a clone before dropping the original response')
      } else if (options.method === 'POST' && path === '/v1/tickets') {
        // The mutation really committed before its successful response is lost.
        const issued = await bounded(response.clone().json(), 'real issued ticket response body')
        const stored = db.prepare('SELECT * FROM tickets WHERE id = ?').get(issued.id)
        assert.ok(stored, 'the exact response ticket must already be persisted')
        assert.equal(stored.command, JSON.parse(options.body).command)
        assert.equal(stored.not_before, issued.not_before)
        assert.equal(stored.expires_at, issued.expires_at)
        assert.equal(stored.revoked, 0)
        assert.equal(stored.consumed, 0)
        assert.equal(db.prepare('SELECT COUNT(*) AS count FROM commands WHERE ticket_id = ?').get(issued.id).count, 0)
        assert.equal(db.prepare('SELECT COUNT(*) AS count FROM audit WHERE ticket_id = ?').get(issued.id).count, 0)
        assert.equal(response.bodyUsed, false, 'inspect only a clone before dropping the original response')
      } else if (options.method === 'POST') {
        const { ticket_id: id } = JSON.parse(options.body)
        assert.equal(db.prepare('SELECT consumed FROM tickets WHERE id = ?').get(id).consumed, 1)
        assert.equal(db.prepare('SELECT COUNT(*) AS count FROM commands WHERE ticket_id = ?').get(id).count, 1)
      } else {
        const id = path.split('/').at(-1)
        assert.equal(db.prepare('SELECT revoked FROM tickets WHERE id = ?').get(id).revoked, 1)
        const { consumed } = db.prepare('SELECT consumed FROM tickets WHERE id = ?').get(id)
        assert.equal(db.prepare('SELECT COUNT(*) AS count FROM commands WHERE ticket_id = ?').get(id).count, consumed)
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
    ...(realtime ? {
      realtimeFactory: callbacks => createRealtime({
        ...callbacks,
        createSocket(options) {
          assert.deepEqual(options, {
            path: '/socket.io', auth: { token: session.token.value }, autoConnect: false,
            reconnection: false, withCredentials: false,
          })
          const socket = io(origin, options)
          sockets.push(socket)
          return socket
        },
      }),
    } : {}),
    eventTarget,
    scheduler: {
      now: () => typeof localNow === 'function' ? localNow() : localNow,
      setInterval(callback, milliseconds) {
        assert.equal(typeof callback, 'function')
        assert.equal(milliseconds, 100)
        tick = callback
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
  // Even the optional live transport requires an explicit manual connection.
  assert.equal(session.realtimeStatus.value, 'disconnected')
  session.token.value = token
  session.command.value = ' registreer é😀 wijziging '
  const externalFetch = (path, options) => fetch(origin + path, options)
  if (realtime) {
    // An independent real client provides an emission barrier while the session is disconnected.
    witness = io(origin, { auth: { token }, autoConnect: false, reconnection: false })
    const connected = bounded(once(witness, 'connect'), 'witness connection')
    witness.connect()
    await connected
  }
  return {
    session, db, calls, externalCommitCalls, sockets, witness, scope, eventTarget, intervals,
    externalFetch,
    get origin() { return origin },
    async restart() {
      assert.equal(sockets.length, 0, 'restart is only supported without session sockets')
      assert.equal(witness, undefined, 'restart is only supported without a witness')
      const previousPort = app.port
      await bounded(app.close(), 'service restart shutdown')
      app = undefined
      let port
      for (let attempt = 0; attempt < 10; attempt++) {
        const listening = once(probe, 'listening')
        probe.listen(0, '127.0.0.1')
        await bounded(listening, 'restart port allocation')
        port = probe.address().port
        await bounded(new Promise(resolve => probe.close(resolve)), 'restart port release')
        if (port !== previousPort) break
      }
      assert.notEqual(port, previousPort, 'restart needs a fresh endpoint, not pooled closed connections')
      app = createBastion({ token, port, dbPath }, { clock: () => serverNow, fault: stage => fault(stage) })
      await bounded(app.listen(), 'service restart startup')
      origin = `http://127.0.0.1:${app.port}`
    },
    setServerNow: value => { serverNow = value },
    setLocalNow: value => { localNow = value },
    tick: () => tick(),
    setFault: value => { fault = value },
    async commitExternal(command) {
      const ticket = await productionApi.issueTicket(command, 10000, token, externalFetch)
      return productionApi.commitCommand(ticket, command, token, externalFetch)
    },
    commitTicketExternal(ticket) {
      return productionApi.commitCommand(ticket, ticket.command, token, async (path, options) => {
        const call = { path, method: options.method, ticketId: JSON.parse(options.body).ticket_id }
        externalCommitCalls.push(call)
        const response = await externalFetch(path, options)
        call.status = response.status
        return response
      })
    },
    statusExternal: id => productionApi.getTicketStatus(id, token, externalFetch),
    revokeExternal: ticket => productionApi.revokeTicket(ticket, token, externalFetch),
    async connect() {
      const connected = waitFor(session.realtimeStatus, value => value === 'connected', 'session connection')
      session.realtime.connect(session.token.value)
      await connected
      return sockets.at(-1)
    },
    count: (method, path) => calls.filter(call => call.method === method && call.path === path).length,
    holdNextList() {
      assert.equal(nextListGate, undefined)
      let receive, release, deliver
      const received = new Promise(resolve => { receive = resolve })
      const wait = new Promise(resolve => { release = resolve })
      const delivered = new Promise(resolve => { deliver = resolve })
      const gate = { receive, release, deliver, wait }
      listGates.push(gate)
      nextListGate = gate
      return {
        release,
        received: () => bounded(received, 'journal snapshot received'),
        delivered: () => bounded(delivered, 'journal response delivered'),
      }
    },
    loseNext: (method, path) => { dropNext = `${method} ${path}` },
    get losses() { return losses },
    run: action => bounded(session.perform(action), action),
  }
}

test('live service: malformed tokens stay local; well-formed credentials require server authentication', { timeout: 20000 }, async t => {
  const f = await fixture(t, { realtime: true })
  const s = f.session
  const command = 'explicit authenticated ticket only'
  const lookupId = 'valid-lookup-id'
  const assertNoWrites = (tickets = 0) => {
    assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM tickets').get().count, tickets)
    for (const table of ['commands', 'audit', ...(tickets === 0 ? ['clock_state'] : [])]) {
      assert.deepEqual(f.db.prepare(`SELECT * FROM ${table}`).all(), [])
    }
  }
  const assertNoAuthority = () => {
    assert.equal(s.ticket.value, null)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.revocationUncertain.value, false)
    assert.equal(s.lastSubmissionId.value, '')
    assert.equal(s.outcome.value, null)
    assert.equal(s.outcomeReceivedAt.value, null)
    assert.deepEqual(s.commands.value, [])
    assert.equal(s.busy.value, '')
  }
  const assertReset = () => {
    assertNoAuthority()
    assert.equal(s.command.value, '')
    assert.equal(s.lookupId.value, '')
    assert.equal(s.ttlMs.value, 10000)
    assert.equal(s.hasLoaded.value, false)
    assert.equal(s.journalRefreshFailed.value, false)
    assert.equal(s.lastJournalRefreshAt.value, null)
    assert.equal(s.message.value, '')
    assert.equal(s.error.value, '')
    assert.equal(s.realtimeStatus.value, 'disconnected')
    assert.equal(f.sockets.length, 0)
  }

  for (const malformed of [' \t ', 'not-a-secret\r\nnot-a-secret']) {
    s.token.value = malformed
    assertReset()
    s.command.value = command
    s.lookupId.value = lookupId
    assert.equal(s.validLookupId.value, true)
    assert.equal(s.validToken.value, false)
    assert.equal(s.canRequestTicket.value, false)
    assert.equal(s.canCheckStatus.value, false)

    for (const action of ['ticket', 'list', 'status']) {
      await f.run(action)
      assert.equal(s.error.value, 'Vul een geldig toegangstoken in.')
      assertNoAuthority()
      assertNoWrites()
      assert.deepEqual(f.calls, [], `${action} must reject the token before HTTP`)
    }
    s.realtime.connect(s.token.value)
    assert.equal(s.realtimeStatus.value, 'error')
    f.tick()
    await Promise.resolve()
    assert.equal(s.command.value, command)
    assert.equal(s.lookupId.value, lookupId)
    assert.equal(s.realtimeStatus.value, 'error')
    assert.equal(f.sockets.length, 0, 'malformed tokens never create a session socket')
    assert.deepEqual(f.calls, [], 'validation failures never trigger automatic requests')
    assertNoAuthority()
    assertNoWrites()
  }

  s.token.value = 'wrong-but-well-formed-not-a-secret'
  assertReset()
  s.command.value = command
  s.lookupId.value = lookupId
  assert.equal(s.validToken.value, true)
  assert.equal(s.canRequestTicket.value, true)
  assert.equal(s.canCheckStatus.value, true)
  const rejectedCalls = [
    { path: '/v1/tickets', method: 'POST', status: 401 },
    { path: '/v1/commands', method: 'GET', status: 401 },
    { path: `/v1/tickets/${lookupId}`, method: 'GET', status: 401 },
  ]
  for (const [index, action] of ['ticket', 'list', 'status'].entries()) {
    await f.run(action)
    assert.equal(s.error.value, 'Toegang geweigerd. Controleer je token.')
    assertNoAuthority()
    assertNoWrites()
    assert.deepEqual(f.calls, rejectedCalls.slice(0, index + 1))
  }
  f.tick()
  await Promise.resolve()
  assert.deepEqual(f.calls, rejectedCalls, 'HTTP 401 never schedules retries')
  assert.equal(f.sockets.length, 0)
  assertNoAuthority()
  assertNoWrites()

  s.token.value = token
  assertReset()
  assert.equal(s.validToken.value, true)
  assert.equal(s.canRequestTicket.value, false, 'token replacement clears the draft')
  assert.equal(s.canCheckStatus.value, false, 'token replacement clears the lookup')
  f.tick()
  await Promise.resolve()
  assertReset()
  assert.deepEqual(f.calls, rejectedCalls, 'restoring credentials neither fetches nor issues a ticket')
  assertNoWrites()

  s.command.value = command
  assert.equal(s.canRequestTicket.value, true)
  await f.run('ticket')
  assert.equal(s.error.value, '')
  const issued = { ...s.ticket.value }
  assert.equal(issued.command, command)
  assert.equal(s.canCommit.value, true)
  await bounded(s.checkCurrentTicket(), 'explicit authenticated current ticket status')
  assert.equal(s.error.value, '')
  assert.equal(s.lookupId.value, issued.id)
  assert.equal(s.outcome.value.id, issued.id)
  assert.equal(s.outcome.value.status, 'active')
  assert.equal(s.outcome.value.record, null)
  assert.equal(s.outcomeReceivedAt.value, now)
  assert.deepEqual(s.ticket.value, issued)
  assert.equal(s.canCommit.value, true)
  assert.equal(s.lastSubmissionId.value, '')
  assert.deepEqual(s.commands.value, [])
  const expectedCalls = [
    ...rejectedCalls,
    { path: '/v1/tickets', method: 'POST', status: 201 },
    { path: `/v1/tickets/${issued.id}`, method: 'GET', status: 200 },
  ]
  f.tick()
  await Promise.resolve()
  assert.deepEqual(f.calls, expectedCalls, 'issuance and status never automatically commit or list')
  assert.equal(f.sockets.length, 0)
  assert.equal(s.canCommit.value, true)
  assertNoWrites(1)
  assert.deepEqual({ ...f.db.prepare('SELECT id, command, consumed, revoked FROM tickets').get() },
    { id: issued.id, command, consumed: 0, revoked: 0 })
})

for (const { label, command, length, error } of [
  { label: 'whitespace-only', command: ' \t\n\u00a0', length: 4, error: /Vul een commando/ },
  { label: 'ASCII 1025', command: 'a'.repeat(1025), length: 1025, error: /maximaal 1024 UTF-16/ },
  { label: 'emoji 513', command: '😀'.repeat(513), length: 1026, error: /maximaal 1024 UTF-16/ },
]) {
  test(`live service: ${label} is rejected before HTTP without changing the draft`, { timeout: 15000 }, async t => {
    const f = await fixture(t)
    const s = f.session
    assert.equal(command.length, length)
    s.command.value = command
    assert.equal(s.canRequestTicket.value, false)

    await f.run('ticket')
    assert.match(s.error.value, error)
    const assertUnchanged = () => {
      assert.equal(s.command.value, command)
      assert.equal(s.ticket.value, null)
      assert.equal(s.canRequestTicket.value, false)
      assert.equal(s.canCommit.value, false)
      assert.deepEqual(f.calls, [], 'production API validation must reject before HTTP')
      for (const table of ['tickets', 'commands', 'audit']) {
        assert.deepEqual(f.db.prepare(`SELECT * FROM ${table}`).all(), [])
      }
    }
    assertUnchanged()
    f.tick()
    await Promise.resolve()
    assertUnchanged()
  })
}

for (const { label, command } of [
  { label: 'ASCII 1024 with whitespace and markup', command: ` \t<note>${'a'.repeat(1007)}</note>\n ` },
  { label: 'emoji 512', command: '😀'.repeat(512) },
]) {
  test(`live service: ${label} round trips exactly once through ticket, commit and status`, { timeout: 15000 }, async t => {
    const f = await fixture(t)
    const s = f.session
    assert.equal(command.length, 1024)
    s.command.value = command
    assert.equal(s.canRequestTicket.value, true)
    f.tick()
    assert.deepEqual(f.calls, [], 'a valid draft does not automatically request a ticket')

    await f.run('ticket')
    assert.equal(s.error.value, '')
    const issued = { ...s.ticket.value }
    assert.equal(issued.command, command)
    assert.equal(s.command.value, command)
    assert.equal(s.canCommit.value, true)
    assert.deepEqual(f.db.prepare('SELECT id, command, consumed FROM tickets').all().map(row => ({ ...row })), [
      { id: issued.id, command, consumed: 0 },
    ])

    await f.run('commit')
    assert.equal(s.error.value, '')
    assert.equal(s.ticket.value, null)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.lastSubmissionId.value, issued.id)
    assert.equal(s.commands.value.length, 1)
    const record = { ...s.commands.value[0] }
    assert.deepEqual(record, { id: record.id, command, committed_at: now })
    const assertPersisted = () => {
      assert.equal(s.command.value, command)
      assert.deepEqual(s.commands.value, [record])
      assert.deepEqual(f.db.prepare('SELECT * FROM commands').all().map(row => ({ ...row })), [
        { seq: 1, ...record, ticket_id: issued.id },
      ])
      assert.deepEqual(f.db.prepare('SELECT id, command, consumed FROM tickets').all().map(row => ({ ...row })), [
        { id: issued.id, command, consumed: 1 },
      ])
      assert.deepEqual(f.db.prepare('SELECT * FROM audit').all().map(row => ({ ...row })), [
        { id: 1, ticket_id: issued.id, subject: 'local-admin', action: 'journal:append', checked_at: now },
      ])
    }
    assertPersisted()
    f.tick()
    assert.deepEqual(f.calls, [
      { path: '/v1/tickets', method: 'POST', status: 201 },
      { path: '/v1/commands', method: 'POST', status: 201 },
    ])

    await bounded(s.checkLastSubmission(), 'boundary command committed status')
    assert.equal(s.error.value, '')
    assert.deepEqual(s.outcome.value, {
      ...issued, checked_at: now, status: 'committed', revoked: false, record,
    })
    assert.equal(s.ticket.value, null)
    assert.equal(s.canCommit.value, false)
    f.tick()
    await Promise.resolve()
    assertPersisted()
    assert.deepEqual(f.calls, [
      { path: '/v1/tickets', method: 'POST', status: 201 },
      { path: '/v1/commands', method: 'POST', status: 201 },
      { path: `/v1/tickets/${issued.id}`, method: 'GET', status: 200 },
    ], 'one issuance, one commit and one explicit status request; no automatic retry')
  })
}

test('live service: lost issuance persists one active ticket but never grants local authority or retries', { timeout: 15000 }, async t => {
  const f = await fixture(t)
  const s = f.session
  const draft = s.command.value
  f.loseNext('POST', '/v1/tickets')
  await f.run('ticket')
  assert.equal(f.losses, 1)
  assert.match(s.error.value, /Geen geldig antwoord/)
  assert.equal(s.message.value, ticketCaution)
  assert.equal(s.command.value, draft)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.revocationUncertain.value, false)
  assert.equal(s.lastSubmissionId.value, '')
  assert.equal(s.lookupId.value, '')
  assert.equal(s.outcome.value, null)
  assert.equal(s.busy.value, '')
  assert.deepEqual(s.commands.value, [])
  assert.equal(f.calls.length, 1)

  // Only the test's database access reveals this ID; the client never received it.
  const tickets = f.db.prepare('SELECT * FROM tickets').all()
  assert.equal(tickets.length, 1)
  const lost = tickets[0]
  assert.equal(lost.command, draft)
  assert.equal(lost.revoked, 0)
  assert.equal(lost.consumed, 0)
  assert.ok(lost.not_before <= now && now < lost.expires_at)
  const assertUnchanged = () => {
    assert.deepEqual(f.db.prepare('SELECT * FROM tickets').all(), tickets)
    assert.deepEqual(f.db.prepare('SELECT * FROM commands').all(), [])
    assert.deepEqual(f.db.prepare('SELECT * FROM audit').all(), [])
  }
  assertUnchanged()
  f.tick()
  await f.run('commit')
  assert.equal(s.message.value, localCommitBlocked)
  assert.equal(f.calls.length, 1, 'no commit or automatic issuance request')
  assertUnchanged()

  await f.restart()
  assert.equal(f.calls.length, 1, 'orderly restart does not trigger client requests')
  assertUnchanged()
  s.lookupId.value = lost.id
  await f.run('status')
  assert.equal(s.outcome.value.id, lost.id)
  assert.equal(s.outcome.value.status, 'active')
  assert.equal(s.outcome.value.record, null)
  assert.equal(s.ticket.value, null, 'a status snapshot does not recreate a received ticket')
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, '')
  assert.equal(s.revocationUncertain.value, false)
  assert.equal(f.calls.length, 2)
  assert.deepEqual(f.calls.at(-1), { path: `/v1/tickets/${lost.id}`, method: 'GET', status: 200 })
  await f.run('commit')
  assert.equal(s.message.value, localCommitBlocked)
  assert.equal(f.calls.length, 2, 'explicit status still cannot authorize a commit')
  assert.equal(f.count('POST', '/v1/tickets'), 1)
  assert.equal(f.count('POST', '/v1/commands'), 0)
  assertUnchanged()

  await f.run('ticket')
  assert.equal(s.error.value, '')
  assert.notEqual(s.ticket.value.id, lost.id)
  assert.equal(s.canCommit.value, true)
  assert.equal(f.count('POST', '/v1/tickets'), 2, 'only a manual action requests another ticket')
  assert.equal(f.count('POST', '/v1/commands'), 0)
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM tickets').get().count, 2)
  assert.deepEqual(f.db.prepare('SELECT * FROM tickets WHERE id = ?').get(lost.id), lost)
  assert.deepEqual(f.db.prepare('SELECT * FROM commands').all(), [])
  assert.deepEqual(f.db.prepare('SELECT * FROM audit').all(), [])
})

test('live service: lost issuance is denied exactly at server expiry and status after restart never restores local authority', { timeout: 15000 }, async t => {
  const f = await fixture(t)
  const s = f.session
  const draft = s.command.value
  f.loseNext('POST', '/v1/tickets')
  await f.run('ticket')
  assert.equal(f.losses, 1)
  assert.match(s.error.value, /Geen geldig antwoord/)
  assert.equal(s.message.value, ticketCaution)
  assert.equal(s.command.value, draft)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, '')
  assert.equal(s.lookupId.value, '')
  assert.equal(s.outcome.value, null)
  assert.equal(s.revocationUncertain.value, false)
  assert.equal(s.busy.value, '')
  assert.deepEqual(s.commands.value, [])
  assert.deepEqual(f.calls, [{ path: '/v1/tickets', method: 'POST', status: 201 }])

  // Test-only database knowledge: the session never received this ticket or its ID.
  const tickets = f.db.prepare('SELECT * FROM tickets').all()
  assert.equal(tickets.length, 1)
  const lost = tickets[0]
  assert.equal(lost.command, draft)
  assert.equal(lost.revoked, 0)
  assert.equal(lost.consumed, 0)
  assert.ok(lost.not_before <= now && now < lost.expires_at)
  const assertUnchanged = () => {
    // The server clock watermark may advance; authority and journal/audit rows must not.
    assert.deepEqual(f.db.prepare('SELECT * FROM tickets').all(), tickets)
    assert.deepEqual(f.db.prepare('SELECT * FROM commands').all(), [])
    assert.deepEqual(f.db.prepare('SELECT * FROM audit').all(), [])
  }
  assertUnchanged()

  f.setServerNow(lost.expires_at)
  assert.equal(Date.now(), now)
  assert.equal(s.now.value, now)
  // Bypass the missing local ticket with test-only knowledge to exercise real server denial.
  const response = await bounded(f.externalFetch('/v1/commands', {
    method: 'POST',
    headers: { Authorization: ['Bearer', token].join(' '), 'Content-Type': 'application/json' },
    body: JSON.stringify({ ticket_id: lost.id, command: lost.command }),
  }), 'lost ticket commit at exact expiry')
  assert.equal(response.status, 403)
  assert.deepEqual(await bounded(response.json(), 'expired lost ticket response'), { error: 'Ticket denied' })
  assertUnchanged()
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, '')
  assert.equal(f.calls.length, 1, 'raw test request causes no session retry or new issuance')

  await f.restart()
  assert.equal(f.calls.length, 1, 'orderly restart causes no automatic requests')
  assertUnchanged()
  s.lookupId.value = lost.id // Explicit operator lookup using test-only database knowledge.
  await f.run('status')
  assert.equal(s.error.value, '')
  assert.equal(s.outcome.value.id, lost.id)
  assert.equal(s.outcome.value.command, lost.command)
  assert.equal(s.outcome.value.status, 'expired')
  assert.equal(s.outcome.value.checked_at, lost.expires_at, 'restart retains exact server expiry time')
  assert.equal(s.outcome.value.record, null)
  assert.equal(s.outcomeReceivedAt.value, now)
  assert.equal(s.now.value, now, 'the local clock remains stale')
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, '')
  assert.equal(s.revocationUncertain.value, false)
  assert.deepEqual(f.calls, [
    { path: '/v1/tickets', method: 'POST', status: 201 },
    { path: `/v1/tickets/${lost.id}`, method: 'GET', status: 200 },
  ])
  await f.run('commit')
  f.tick()
  assert.equal(s.message.value, localCommitBlocked)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, '')
  assert.equal(f.calls.length, 2, 'explicit commit and tick send no retry or new ticket request')
  assert.equal(f.count('POST', '/v1/tickets'), 1)
  assert.equal(f.count('POST', '/v1/commands'), 0, 'only the raw test request reached the command endpoint')
  assertUnchanged()
})

test('live service: clearing a draft leaves server authority active but requires a new explicit local ticket', { timeout: 15000 }, async t => {
  const f = await fixture(t, { realtime: true })
  const s = f.session
  const socket = await f.connect()
  await f.run('ticket')
  const held = { ...s.ticket.value }
  await bounded(s.checkCurrentTicket(), 'status before draft clear')
  const outcome = s.outcome.value
  const message = s.message.value
  const requests = f.calls.length
  const audit = f.db.prepare('SELECT * FROM audit').all()

  s.clearCommand()
  assert.equal(s.command.value, '')
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.outcome.value, outcome)
  assert.equal(s.outcomeReceivedAt.value, now)
  assert.equal(s.lookupId.value, held.id)
  assert.equal(s.message.value, message)
  assert.equal(s.token.value, token)
  assert.equal(s.ttlMs.value, 10000)
  assert.equal(s.realtimeStatus.value, 'connected')
  assert.equal(socket.connected, true)
  assert.equal(f.sockets.length, 1)
  assert.equal(f.calls.length, requests)
  assert.deepEqual(f.db.prepare('SELECT * FROM audit').all(), audit)
  assert.deepEqual({ ...f.db.prepare('SELECT consumed, revoked FROM tickets WHERE id = ?').get(held.id) },
    { consumed: 0, revoked: 0 })
  assert.equal((await f.statusExternal(held.id)).status, 'active')

  // A real emission is a deterministic barrier proving clearing did not disconnect.
  const received = nextCommit(socket, 'after draft clear')
  const external = await f.commitExternal('after draft clear')
  assert.deepEqual(await received, external)
  assert.deepEqual(s.commands.value, [external])
  assert.equal(f.calls.length, requests, 'clearing and realtime reception send no session requests')
  await f.run('commit')
  s.command.value = held.command
  await f.run('commit')
  assert.equal(s.canCommit.value, false)
  assert.equal(f.calls.length, requests, 'restoring text does not restore discarded local authority')
  await f.run('ticket')
  assert.notEqual(s.ticket.value.id, held.id)
  assert.equal(s.canCommit.value, true)
  const committed = nextCommit(socket, held.command)
  await f.run('commit')
  assert.equal((await committed).command, held.command)
  assert.equal(f.count('POST', '/v1/tickets'), 2)
  assert.equal(f.count('POST', '/v1/commands'), 1)
  assert.equal(f.count('DELETE', `/v1/tickets/${held.id}`), 0)
  assert.equal(f.calls.length, requests + 2)
  assert.equal((await f.statusExternal(held.id)).status, 'active')
})

test('live service: unknown status returns HTTP 404 without resolving retained uncertain revocation or mutating SQLite', { timeout: 15000 }, async t => {
  const f = await fixture(t)
  const s = f.session
  await f.run('ticket')
  const held = s.ticket.value
  const path = `/v1/tickets/${held.id}`
  await bounded(s.checkCurrentTicket(), 'initial explicit status')
  assert.equal(s.outcome.value.status, 'active')
  assert.equal(s.outcomeReceivedAt.value, now)
  f.loseNext('DELETE', path)
  await f.run('revoke')
  assert.equal(f.losses, 1)
  assert.equal(s.revocationUncertain.value, true)
  s.command.value = 'retained edited draft'
  const retained = () => ({
    command: s.command.value, ttlMs: s.ttlMs.value, commands: [...s.commands.value],
    search: s.search.value, hasLoaded: s.hasLoaded.value,
    journalRefreshFailed: s.journalRefreshFailed.value,
    lastJournalRefreshAt: s.lastJournalRefreshAt.value,
    lookupId: s.lookupId.value, lastSubmissionId: s.lastSubmissionId.value,
  })
  const database = () => Object.fromEntries(['tickets', 'commands', 'audit'].map(table =>
    [table, f.db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all()]))
  const persisted = database()
  const requests = f.calls.length
  const draft = retained()
  for (const id of ['', ' ' + held.id, held.id + ' ', 'é', '../tickets', 'x'.repeat(129), 'id\r\n']) {
    s.lookupId.value = id
    assert.equal(s.lookupId.value, id, 'editing preserves the exact ID without trimming')
    assert.equal(s.validLookupId.value, false)
    assert.equal(s.canCheckStatus.value, false)
    assert.equal(f.calls.length, requests, 'editing an invalid ID sends no request')
    const invalid = { ...draft, lookupId: id }
    assert.deepEqual(retained(), invalid)

    await f.run('status')
    assert.equal(s.error.value, 'Vul een geldig ticket-ID in.')
    assert.equal(s.message.value, statusCaution)
    assert.equal(s.busy.value, '')
    assert.equal(s.outcome.value, null)
    assert.equal(s.outcomeReceivedAt.value, null)
    assert.equal(s.ticket.value, held)
    assert.equal(s.revocationUncertain.value, true)
    assert.equal(s.canCommit.value, false)
    assert.deepEqual(retained(), invalid)
    assert.deepEqual(database(), persisted)
    assert.equal(f.calls.length, requests, 'invalid status is rejected locally without HTTP')
    f.tick()
    assert.equal(f.calls.length, requests, 'a clock tick never retries an invalid status')
    assert.equal(s.ticket.value, held)
    assert.equal(s.revocationUncertain.value, true)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.outcome.value, null)
    assert.equal(s.outcomeReceivedAt.value, null)
    assert.deepEqual(retained(), invalid)
    assert.deepEqual(database(), persisted)
  }

  s.lookupId.value = 'unknown-ticket'
  assert.equal(s.validLookupId.value, true)
  assert.equal(s.canCheckStatus.value, true, 'uncertain revocation does not block a valid status lookup')
  assert.equal(f.calls.length, requests, 'editing a valid ID sends no request')
  const before = { ...draft, lookupId: 'unknown-ticket' }
  assert.deepEqual(retained(), before)
  await f.run('status')
  assert.deepEqual(f.calls.at(-1), { path: '/v1/tickets/unknown-ticket', method: 'GET', status: 404 })
  assert.equal(s.error.value, 'Ticket niet gevonden.')
  assert.equal(s.message.value, statusCaution)
  assert.equal(s.busy.value, '')
  assert.equal(s.outcome.value, null)
  assert.equal(s.outcomeReceivedAt.value, null)
  assert.equal(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true)
  assert.equal(s.canCommit.value, false)
  assert.deepEqual(retained(), before)
  assert.deepEqual(database(), persisted)
  assert.equal(f.calls.length, requests + 1, 'no automatic retry or mutation')

  await bounded(s.checkCurrentTicket(), 'matching explicit status after not found')
  assert.deepEqual(f.calls.at(-1), { path, method: 'GET', status: 200 })
  assert.equal(s.outcome.value.id, held.id)
  assert.equal(s.outcome.value.status, 'revoked')
  assert.equal(s.outcomeReceivedAt.value, now)
  assert.equal(s.ticket.value, null)
  assert.equal(s.revocationUncertain.value, false)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.error.value, '')
  assert.equal(s.message.value, 'Ticketstatus opgehaald. Dit is een momentopname, geen nieuwe toestemming.')
  assert.equal(s.command.value, before.command)
  assert.deepEqual(database(), persisted)
  assert.equal(f.calls.length, requests + 2, 'only the matching explicit check follows the failed lookup')
})

test('live service: clearing HTTP 404 status feedback retains uncertain revocation through realtime until explicit matching status', { timeout: 15000 }, async t => {
  const f = await fixture(t, { realtime: true })
  const s = f.session
  const socket = await f.connect()
  await f.run('ticket')
  const held = s.ticket.value
  const path = `/v1/tickets/${held.id}`
  f.loseNext('DELETE', path)
  await f.run('revoke')
  assert.equal(f.losses, 1)
  assert.match(s.error.value, /Geen geldig antwoord/)
  assert.equal(s.message.value, revokeCaution)
  assert.equal(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true)
  assert.equal(s.canCommit.value, false)
  s.command.value = 'retained draft after uncertain revocation'
  s.lookupId.value = 'unknown-ticket'
  const retained = () => ({
    command: s.command.value, ttlMs: s.ttlMs.value,
    lookupId: s.lookupId.value, lastSubmissionId: s.lastSubmissionId.value,
    search: s.search.value, hasLoaded: s.hasLoaded.value,
    journalRefreshFailed: s.journalRefreshFailed.value,
    lastJournalRefreshAt: s.lastJournalRefreshAt.value,
  })
  const before = retained()
  const database = () => Object.fromEntries(['tickets', 'commands', 'audit'].map(table =>
    [table, f.db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all()]))
  const persisted = database()
  assert.equal(persisted.tickets.length, 1)
  assert.equal(persisted.tickets[0].revoked, 1)
  assert.equal(persisted.tickets[0].consumed, 0)
  assert.deepEqual(persisted.commands, [])
  await f.run('status')
  const failedLookupCalls = [
    { path: '/v1/tickets', method: 'POST', status: 201 },
    { path, method: 'DELETE', status: 200 },
    { path: '/v1/tickets/unknown-ticket', method: 'GET', status: 404 },
  ]
  assert.deepEqual(f.calls, failedLookupCalls)
  assert.equal(s.error.value, 'Ticket niet gevonden.')
  assert.equal(s.message.value, statusCaution)
  assert.equal(s.outcome.value, null)
  assert.equal(s.outcomeReceivedAt.value, null)
  assert.equal(s.canClearOutcome.value, true)
  assert.equal(s.busy.value, '')
  assert.equal(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true)
  assert.equal(s.canCommit.value, false)
  assert.deepEqual(database(), persisted)
  assert.deepEqual(retained(), before)
  const journal = s.commands.value

  s.clearOutcome()
  assert.equal(s.canClearOutcome.value, false)
  assert.equal(s.error.value, '')
  assert.equal(s.message.value, '')
  assert.equal(s.outcome.value, null)
  assert.equal(s.outcomeReceivedAt.value, null)
  assert.equal(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.commands.value, journal)
  assert.deepEqual(retained(), before)
  assert.deepEqual(database(), persisted)
  assert.deepEqual(f.calls, failedLookupCalls, 'clearing failed status sends no request')

  const command = 'external commit after clearing failed status'
  const witnessed = nextCommit(f.witness, command)
  const received = waitFor(s.commands, rows => rows.some(row => row.command === command), 'session record after status clear')
  const external = await f.commitExternal(command)
  assert.deepEqual(await witnessed, external)
  await received
  assert.deepEqual(s.commands.value, [external])
  assert.equal(socket.connected, true)
  assert.equal(s.realtimeStatus.value, 'connected')
  assert.equal(f.sockets.length, 1)
  assert.equal(s.canClearOutcome.value, false)
  assert.equal(s.outcome.value, null)
  assert.equal(s.outcomeReceivedAt.value, null)
  assert.equal(s.error.value, '')
  assert.equal(s.message.value, '')
  assert.equal(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true)
  assert.equal(s.canCommit.value, false)
  assert.deepEqual(retained(), before)
  assert.deepEqual(f.calls, failedLookupCalls, 'realtime does not reconcile or request authority')
  const afterExternal = database()
  assert.equal(afterExternal.tickets.length, 2)
  assert.deepEqual(afterExternal.tickets[0], persisted.tickets[0])
  assert.equal(afterExternal.commands.length, 1)
  assert.deepEqual({
    id: afterExternal.commands[0].id,
    command: afterExternal.commands[0].command,
    committed_at: afterExternal.commands[0].committed_at,
  }, external)

  await bounded(s.checkCurrentTicket(), 'explicit matching status after clearing HTTP 404')
  assert.deepEqual(s.outcome.value, {
    ...held, checked_at: now, status: 'revoked', revoked: true, record: null,
  })
  assert.equal(s.outcomeReceivedAt.value, now)
  assert.equal(s.canClearOutcome.value, true)
  assert.equal(s.ticket.value, null)
  assert.equal(s.revocationUncertain.value, false)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.error.value, '')
  assert.equal(s.message.value, 'Ticketstatus opgehaald. Dit is een momentopname, geen nieuwe toestemming.')
  assert.deepEqual(retained(), { ...before, lookupId: held.id })
  assert.deepEqual(database(), afterExternal)
  const reconciledJournal = s.commands.value

  s.clearOutcome()
  assert.equal(s.canClearOutcome.value, false)
  assert.equal(s.outcome.value, null)
  assert.equal(s.outcomeReceivedAt.value, null)
  assert.equal(s.error.value, '')
  assert.equal(s.message.value, '')
  assert.equal(s.ticket.value, null)
  assert.equal(s.revocationUncertain.value, false)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.commands.value, reconciledJournal)
  assert.deepEqual(s.commands.value, [external])
  assert.deepEqual(retained(), { ...before, lookupId: held.id })
  assert.equal(socket.connected, true)
  assert.equal(s.realtimeStatus.value, 'connected')
  assert.deepEqual(database(), afterExternal)
  assert.deepEqual(f.calls, [...failedLookupCalls, { path, method: 'GET', status: 200 }])
  assert.equal(f.calls.length, 4)
  assert.equal(f.count('POST', '/v1/tickets'), 1)
  assert.equal(f.count('DELETE', path), 1)
  assert.equal(f.count('GET', '/v1/tickets/unknown-ticket'), 1)
  assert.equal(f.count('GET', path), 1)
  assert.equal(f.count('POST', '/v1/commands'), 0)
  assert.equal(f.count('GET', '/v1/commands'), 0)
  assert.equal(f.losses, 1)
})

for (const resolution of ['status', 'revoke']) {
  test(`live service: draft clear retains uncertain revocation until explicit matching ${resolution}`, { timeout: 15000 }, async t => {
    const f = await fixture(t, { realtime: true })
    const s = f.session
    const socket = await f.connect()
    await f.run('ticket')
    const held = s.ticket.value
    const path = `/v1/tickets/${held.id}`
    f.loseNext('DELETE', path)
    await f.run('revoke')
    assert.equal(f.losses, 1)
    assert.match(s.error.value, /Geen geldig antwoord/)
    const error = s.error.value
    const requests = f.calls.length
    const audit = f.db.prepare('SELECT * FROM audit').all()

    s.clearCommand()
    assert.equal(s.command.value, '')
    assert.equal(s.ticket.value, held, 'retain original exact command and ticket identity for reconciliation')
    assert.equal(s.ticket.value.command, held.command)
    assert.equal(s.revocationUncertain.value, true)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.error.value, error)
    assert.equal(socket.connected, true)
    assert.equal(s.realtimeStatus.value, 'connected')
    assert.equal(f.sockets.length, 1)
    assert.equal(f.calls.length, requests)
    assert.deepEqual(f.db.prepare('SELECT * FROM audit').all(), audit)
    const received = nextCommit(socket, `barrier after uncertain draft clear: ${resolution}`)
    const external = await f.commitExternal(`barrier after uncertain draft clear: ${resolution}`)
    assert.deepEqual(await received, external)
    assert.deepEqual(s.commands.value, [external])
    assert.equal(f.calls.length, requests, 'no automatic requests or disconnect after draft clear')
    s.command.value = held.command
    await f.run('ticket')
    await f.run('commit')
    assert.equal(f.calls.length, requests, 'restoring text cannot bypass retained uncertainty')
    assert.equal(s.ticket.value, held)
    s.clearCommand()
    if (resolution === 'status') {
      await bounded(s.checkCurrentTicket(), 'explicit matching status after draft clear')
      assert.equal(s.outcome.value.id, held.id)
      assert.equal(s.outcome.value.command, held.command)
      assert.equal(s.outcome.value.status, 'revoked')
      assert.deepEqual(f.calls.at(-1), { path, method: 'GET', status: 200 })
    } else {
      await f.run('revoke')
      assert.deepEqual(f.calls.at(-1), { path, method: 'DELETE', status: 200 })
    }
    assert.equal(s.error.value, '')
    assert.equal(s.ticket.value, null)
    assert.equal(s.revocationUncertain.value, false)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.command.value, '')
    assert.equal(socket.connected, true)
    assert.equal(f.calls.length, requests + 1, 'only explicit matching reconciliation sends another request')
    assert.equal(f.count('POST', '/v1/tickets'), 1)
    assert.equal(f.count('POST', '/v1/commands'), 0)
    assert.equal(f.db.prepare('SELECT revoked FROM tickets WHERE id = ?').get(held.id).revoked, 1)
  })
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

test('live service: historical committed status stays isolated from a different current ticket and local clears', { timeout: 15000 }, async t => {
  const f = await fixture(t)
  const s = f.session
  const original = ' \t<note>café e\u0301 😀 & historie</note>\r\n  regel twee\n\t '
  s.command.value = original
  await f.run('ticket')
  const a = { ...s.ticket.value }
  await f.run('commit')
  assert.equal(s.error.value, '')
  assert.equal(s.lastSubmissionId.value, a.id)
  assert.equal(s.lookupId.value, a.id)
  const record = { ...s.commands.value[0] }
  assert.deepEqual(record, { id: record.id, command: original, committed_at: now })
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)

  await f.run('status')
  const historical = {
    ...a, checked_at: now, status: 'committed', revoked: false, record,
  }
  assert.deepEqual(s.outcome.value, historical)
  assert.equal(s.outcomeReceivedAt.value, now)
  assert.equal(s.outcomeMismatch.value, false)
  assert.equal(s.lastSubmissionId.value, a.id)

  s.command.value = ' \t<draft>B: andere opdracht 🧭</draft>\n '
  await f.run('ticket')
  assert.equal(s.error.value, '')
  const b = { ...s.ticket.value }
  assert.notEqual(b.id, a.id)
  assert.notEqual(b.command, original)
  assert.equal(s.canCommit.value, true)
  assert.deepEqual(s.outcome.value, historical)
  assert.equal(s.outcomeReceivedAt.value, now)
  assert.equal(s.outcomeMismatch.value, false, 'different ticket IDs are not an authority mismatch')
  assert.equal(s.lastSubmissionId.value, a.id, 'ticket issuance is not a submission')
  assert.equal(s.lookupId.value, a.id)

  const snapshot = () => Object.fromEntries(['tickets', 'commands', 'audit'].map(table =>
    [table, f.db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all()]))
  const persisted = snapshot()
  assert.equal(persisted.tickets.length, 2)
  assert.equal(persisted.commands.length, 1)
  assert.equal(persisted.audit.length, 1)
  assert.equal(persisted.tickets.find(ticket => ticket.id === a.id).consumed, 1)
  assert.equal(persisted.tickets.find(ticket => ticket.id === b.id).consumed, 0)
  assert.equal(persisted.tickets.find(ticket => ticket.id === b.id).revoked, 0)
  assert.equal(persisted.commands[0].command, original)
  assert.equal(persisted.commands[0].ticket_id, a.id)
  assert.equal(persisted.audit[0].ticket_id, a.id)
  const expectedCalls = [
    { path: '/v1/tickets', method: 'POST', status: 201 },
    { path: '/v1/commands', method: 'POST', status: 201 },
    { path: `/v1/tickets/${a.id}`, method: 'GET', status: 200 },
    { path: '/v1/tickets', method: 'POST', status: 201 },
  ]
  const assertUnchanged = (expectedError = '') => {
    assert.deepEqual(snapshot(), persisted, 'local operations and status reads preserve every persisted row')
    assert.deepEqual(f.calls, expectedCalls, 'only explicitly requested HTTP operations occur')
    assert.equal(s.lastSubmissionId.value, a.id)
    assert.equal(s.revocationUncertain.value, false)
    assert.equal(s.error.value, expectedError)
    assert.equal(s.busy.value, '')
  }
  assertUnchanged()

  const heldB = s.ticket.value
  assert.notEqual(record.id, a.id)
  assert.notEqual(record.id, b.id)
  s.lookupId.value = record.id
  assert.equal(s.validLookupId.value, true, 'record IDs are syntactically valid ticket lookup IDs')
  assert.equal(s.canCheckStatus.value, true)
  assert.equal(s.outcome.value, null)
  assert.equal(s.outcomeReceivedAt.value, null)
  assert.strictEqual(s.ticket.value, heldB)
  assert.deepEqual(s.ticket.value, b)
  assert.equal(s.canCommit.value, true)
  assert.deepEqual(s.commands.value, [record])
  assertUnchanged()

  await f.run('status')
  expectedCalls.push({ path: `/v1/tickets/${record.id}`, method: 'GET', status: 404 })
  assert.equal(s.message.value, statusCaution)
  assert.equal(s.outcome.value, null)
  assert.equal(s.outcomeReceivedAt.value, null)
  assert.equal(s.lookupId.value, record.id)
  assert.strictEqual(s.ticket.value, heldB)
  assert.deepEqual(s.ticket.value, b)
  assert.equal(s.canCommit.value, true)
  assert.equal(s.outcomeMismatch.value, false)
  assert.deepEqual(s.commands.value, [record])
  assertUnchanged('Ticket niet gevonden.')
  f.tick()
  await Promise.resolve()
  assertUnchanged('Ticket niet gevonden.')

  await bounded(s.checkLastSubmission(), 'historical submission after record-ID lookup')
  expectedCalls.push({ path: `/v1/tickets/${a.id}`, method: 'GET', status: 200 })
  assert.deepEqual(s.outcome.value, historical)
  assert.equal(s.outcomeReceivedAt.value, now)
  assert.equal(s.lookupId.value, a.id)
  assert.strictEqual(s.ticket.value, heldB)
  assert.deepEqual(s.ticket.value, b)
  assert.equal(s.canCommit.value, true)
  assert.equal(s.outcomeMismatch.value, false)
  assert.deepEqual(s.commands.value, [record], 'historical recovery must not duplicate journal entries')
  assertUnchanged()

  f.setLocalNow(now + 100)
  await f.run('status')
  expectedCalls.push({ path: `/v1/tickets/${a.id}`, method: 'GET', status: 200 })
  assert.deepEqual(s.outcome.value, historical)
  assert.equal(s.outcomeReceivedAt.value, now + 100)
  assert.deepEqual(s.ticket.value, b, 'rechecking historical A must not retire current B')
  assert.equal(s.canCommit.value, true)
  assert.equal(s.outcomeMismatch.value, false)
  assertUnchanged()
  const outcome = s.outcome.value
  const receipt = s.outcomeReceivedAt.value
  const assertHistorical = () => {
    assert.strictEqual(s.outcome.value, outcome)
    assert.deepEqual(s.outcome.value, historical)
    assert.equal(s.outcomeReceivedAt.value, receipt)
    assert.equal(s.lookupId.value, a.id)
    assert.equal(s.outcomeMismatch.value, false)
    assertUnchanged()
  }

  s.clearCommand()
  assert.equal(s.command.value, '')
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.deepEqual(s.commands.value, [record])
  assertHistorical()
  s.command.value = b.command
  assert.equal(s.ticket.value, null, 'restoring draft bytes does not restore cleared authority')
  assert.equal(s.canCommit.value, false)
  assertHistorical()

  s.clearJournal()
  assert.deepEqual(s.commands.value, [])
  assert.deepEqual(s.outcome.value.record, record, 'historical record is independent of the local journal')
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assertHistorical()

  s.clearOutcome()
  assert.equal(s.outcome.value, null)
  assert.equal(s.outcomeReceivedAt.value, null)
  assert.equal(s.lookupId.value, a.id)
  assert.equal(s.lastSubmissionId.value, a.id)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.deepEqual(s.commands.value, [])
  assertUnchanged()

  f.setLocalNow(now + 200)
  await bounded(s.checkLastSubmission(), 'historical submission after local clears')
  expectedCalls.push({ path: `/v1/tickets/${a.id}`, method: 'GET', status: 200 })
  assert.deepEqual(s.outcome.value, historical)
  assert.equal(s.outcomeReceivedAt.value, now + 200)
  assert.equal(s.lookupId.value, a.id)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.outcomeMismatch.value, false)
  assert.deepEqual(s.commands.value, [], 'status recovery must not repopulate the cleared journal')
  assertUnchanged()

  s.lookupId.value = b.id
  assert.equal(s.outcome.value, null)
  assert.equal(s.outcomeReceivedAt.value, null)
  assertUnchanged()
  await f.run('status')
  expectedCalls.push({ path: `/v1/tickets/${b.id}`, method: 'GET', status: 200 })
  assert.deepEqual(s.outcome.value, {
    ...b, checked_at: now, status: 'active', revoked: false, record: null,
  })
  assert.equal(s.outcomeReceivedAt.value, now + 200)
  assert.equal(s.lookupId.value, b.id)
  assert.equal(s.command.value, b.command)
  assert.equal(s.ticket.value, null, 'server-side active B is not restored local authority')
  assert.equal(s.canCommit.value, false)
  assert.equal(s.outcomeMismatch.value, false)
  assert.deepEqual(s.commands.value, [])
  assertUnchanged()
  assert.equal(f.calls.length, 9)
  assert.equal(f.count('POST', '/v1/tickets'), 2)
  assert.equal(f.count('POST', '/v1/commands'), 1)
  assert.equal(f.count('GET', `/v1/tickets/${a.id}`), 4)
  assert.equal(f.count('GET', `/v1/tickets/${b.id}`), 1)
  assert.equal(f.count('GET', '/v1/commands'), 0)
  assert.equal(f.count('DELETE', `/v1/tickets/${b.id}`), 0)
})

for (const { label, original, altered } of [
  {
    label: 'NFC versus NFD unicode',
    original: '<note>café 😀</note>\nregistreer wijziging',
    altered: ['<note>cafe\u0301 😀</note>\nregistreer wijziging'],
  },
  {
    label: 'CRLF versus LF',
    original: '<note>regel één 😀</note>\r\nregistreer wijziging',
    altered: ['<note>regel één 😀</note>\nregistreer wijziging'],
  },
  {
    label: 'leading and trailing whitespace',
    original: ' \t<note>wijziging 😀</note>\nregistreer wijziging\t ',
    altered: [
      '<note>wijziging 😀</note>\nregistreer wijziging\t ',
      ' \t<note>wijziging 😀</note>\nregistreer wijziging',
      '<note>wijziging 😀</note>\nregistreer wijziging',
    ],
  },
]) {
  test(`live service: exact ticket command binding survives restart for ${label}`, { timeout: 15000 }, async t => {
    const f = await fixture(t)
    const s = f.session
    const snapshot = () => ({
      tickets: f.db.prepare('SELECT * FROM tickets ORDER BY id').all().map(row => ({ ...row })),
      commands: f.db.prepare('SELECT * FROM commands ORDER BY seq').all().map(row => ({ ...row })),
      audit: f.db.prepare('SELECT * FROM audit ORDER BY id').all().map(row => ({ ...row })),
    })
    s.command.value = original
    await f.run('ticket')
    assert.equal(s.error.value, '')
    const issued = { ...s.ticket.value }
    assert.equal(issued.command, original)
    assert.equal(s.canCommit.value, true)
    const active = snapshot()
    assert.deepEqual(active, {
      tickets: [{
        id: issued.id, issuer: 'bastion-local', subject: 'local-admin',
        action: 'journal:append', resource: 'commands', command: original,
        not_before: now, expires_at: now + s.ttlMs.value, revoked: 0, consumed: 0,
      }],
      commands: [], audit: [],
    })

    for (const command of altered) {
      assert.notEqual(command, original)
      // Bypass commitCommand's local equality guard to exercise server authorization.
      const response = await bounded(f.externalFetch('/v1/commands', {
        method: 'POST',
        headers: { Authorization: ['Bearer', token].join(' '), 'Content-Type': 'application/json' },
        body: JSON.stringify({ ticket_id: issued.id, command }),
      }), 'altered command request')
      assert.equal(response.status, 403)
      assert.deepEqual(await bounded(response.json(), 'altered command response'), { error: 'Ticket denied' })
      assert.deepEqual(snapshot(), active, 'denial must not consume, revoke or mutate journal/audit authority')
      assert.deepEqual({ ...s.ticket.value }, issued)
      assert.equal(s.command.value, original)
      assert.equal(s.canCommit.value, true)
    }

    await f.restart()
    assert.deepEqual(snapshot(), active)
    await bounded(s.checkCurrentTicket(), 'exact active ticket status after restart')
    assert.equal(s.error.value, '')
    assert.deepEqual({ ...s.outcome.value }, {
      ...issued, checked_at: now, status: 'active', revoked: false, record: null,
    })
    assert.deepEqual({ ...s.ticket.value }, issued)
    assert.equal(s.command.value, original)
    assert.equal(s.canCommit.value, true)

    await f.run('commit')
    assert.equal(s.error.value, '')
    assert.equal(s.ticket.value, null)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.lastSubmissionId.value, issued.id)
    assert.equal(s.commands.value.length, 1)
    const record = { ...s.commands.value[0] }
    assert.deepEqual(record, { id: record.id, command: original, committed_at: now })
    const committed = snapshot()
    assert.deepEqual(committed.tickets, [{ ...active.tickets[0], consumed: 1 }])
    assert.deepEqual(committed.commands, [{ seq: 1, ...record, ticket_id: issued.id }])
    assert.deepEqual(committed.audit, [{
      id: 1, ticket_id: issued.id, subject: 'local-admin', action: 'journal:append', checked_at: now,
    }])
    await f.run('commit')
    assert.equal(f.count('POST', '/v1/tickets'), 1)
    assert.equal(f.count('POST', '/v1/commands'), 1, 'session submits original exactly once')
    assert.deepEqual(snapshot(), committed)

    for (const restart of [false, true]) {
      if (restart) await f.restart()
      await bounded(s.checkLastSubmission(), 'exact committed ticket status')
      assert.equal(s.error.value, '')
      assert.deepEqual({ ...s.outcome.value }, {
        ...issued, checked_at: now, status: 'committed', revoked: false, record,
      })
      await f.run('list')
      assert.equal(s.error.value, '')
      assert.equal(s.hasLoaded.value, true)
      assert.deepEqual(s.commands.value, [record])
      assert.equal(s.command.value, original)
      assert.equal(s.ticket.value, null, 'status and journal must not restore spent local authority')
      assert.equal(s.canCommit.value, false)
      assert.deepEqual(snapshot(), committed)
    }
  })
}

for (const clockFailure of ['invalid', 'throwing']) {
  test(`live service: ${clockFailure} local receipt clock retains a real ticket for status and revocation, not commit`, { timeout: 15000 }, async t => {
    const f = await fixture(t)
    const s = f.session
    f.setLocalNow(clockFailure === 'invalid' ? NaN : () => { throw new Error('local clock unavailable') })
    await f.run('ticket')
    assert.equal(s.error.value, '')
    const held = s.ticket.value
    assert.ok(held)
    assert.equal(held.not_before, now)
    assert.equal(held.expires_at, now + s.ttlMs.value)
    assert.equal(s.now.value, null)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.remaining.value, null)
    assert.equal(s.lastSubmissionId.value, '')
    const persisted = f.db.prepare('SELECT * FROM tickets').all()
    assert.equal(persisted.length, 1)
    assert.equal(persisted[0].id, held.id)
    assert.equal(persisted[0].command, held.command)
    assert.equal(persisted[0].consumed, 0)
    assert.equal(persisted[0].revoked, 0)
    assert.deepEqual(f.calls, [{ path: '/v1/tickets', method: 'POST', status: 201 }])

    await f.run('commit')
    assert.equal(s.ticket.value, held)
    assert.equal(s.message.value, localCommitBlocked)
    assert.equal(s.error.value, '')
    assert.equal(s.lastSubmissionId.value, '')
    assert.equal(f.count('POST', '/v1/commands'), 0)
    assert.equal(f.calls.length, 1)
    assert.deepEqual(f.db.prepare('SELECT * FROM tickets').all(), persisted)
    assert.deepEqual(f.db.prepare('SELECT * FROM commands').all(), [])
    assert.deepEqual(f.db.prepare('SELECT * FROM audit').all(), [])

    const path = `/v1/tickets/${held.id}`
    await bounded(s.checkCurrentTicket(), 'active status despite failed local clock')
    assert.equal(s.error.value, '')
    assert.equal(s.outcome.value.id, held.id)
    assert.equal(s.outcome.value.command, held.command)
    assert.equal(s.outcome.value.status, 'active')
    assert.equal(s.outcome.value.checked_at, now)
    assert.equal(s.outcome.value.revoked, false)
    assert.equal(s.outcome.value.record, null)
    assert.equal(s.outcomeReceivedAt.value, null)
    assert.equal(s.ticket.value, held)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.remaining.value, null)
    await f.run('commit')
    assert.equal(s.lastSubmissionId.value, '')
    assert.deepEqual(f.db.prepare('SELECT * FROM tickets').all(), persisted)
    assert.deepEqual(f.db.prepare('SELECT * FROM commands').all(), [])
    assert.deepEqual(f.db.prepare('SELECT * FROM audit').all(), [])
    assert.deepEqual(f.calls, [
      { path: '/v1/tickets', method: 'POST', status: 201 },
      { path, method: 'GET', status: 200 },
    ])

    await f.run('revoke')
    assert.equal(s.error.value, '')
    assert.equal(s.ticket.value, null)
    assert.equal(s.revocationUncertain.value, false)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.lastSubmissionId.value, '')
    assert.deepEqual({ ...f.db.prepare('SELECT consumed, revoked FROM tickets WHERE id = ?').get(held.id) },
      { consumed: 0, revoked: 1 })
    assert.deepEqual(f.db.prepare('SELECT * FROM commands').all(), [])
    assert.deepEqual(f.db.prepare('SELECT ticket_id, action FROM audit').all().map(row => ({ ...row })),
      [{ ticket_id: held.id, action: 'ticket:revoke' }])
    assert.deepEqual(f.calls, [
      { path: '/v1/tickets', method: 'POST', status: 201 },
      { path, method: 'GET', status: 200 },
      { path, method: 'DELETE', status: 200 },
    ])
  })
}

for (const response of ['received', 'lost']) {
  test(`live service: explicit revoke at exact expiry persists revoked status with response ${response}`, { timeout: 15000 }, async t => {
    const f = await fixture(t)
    const s = f.session
    const lost = response === 'lost'
    const snapshot = () => Object.fromEntries(['tickets', 'commands', 'audit'].map(table =>
      [table, f.db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all()]))
    await f.run('ticket')
    assert.equal(s.error.value, '')
    const held = s.ticket.value
    assert.ok(held)
    assert.equal(s.canCommit.value, true)
    const path = `/v1/tickets/${held.id}`
    const issued = [{ path: '/v1/tickets', method: 'POST', status: 201 }]
    const before = snapshot()
    f.setServerNow(held.expires_at)
    f.setLocalNow(held.expires_at)
    f.tick()
    assert.equal(s.now.value, held.expires_at)
    assert.equal(s.remaining.value, 0)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.ticket.value, held)
    assert.equal(s.outcome.value, null)
    assert.deepEqual(f.calls, issued, 'expiry ticks must not fetch status and retire the held ticket')
    assert.deepEqual(snapshot(), before)

    if (lost) f.loseNext('DELETE', path)
    await f.run('revoke')
    assert.equal(f.losses, Number(lost))
    assert.equal(s.ticket.value, lost ? held : null)
    assert.equal(s.revocationUncertain.value, lost)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.outcome.value, null)
    if (lost) {
      assert.match(s.error.value, /Geen geldig antwoord/)
      assert.equal(s.message.value, revokeCaution)
    } else {
      assert.equal(s.error.value, '')
    }
    const revoked = snapshot()
    assert.equal(revoked.tickets.length, 1)
    assert.equal(revoked.tickets[0].id, held.id)
    assert.equal(revoked.tickets[0].revoked, 1)
    assert.equal(revoked.tickets[0].consumed, 0)
    assert.deepEqual(revoked.commands, [])
    assert.equal(revoked.audit.length, 1)
    assert.equal(revoked.audit[0].ticket_id, held.id)
    assert.equal(revoked.audit[0].action, 'ticket:revoke')
    assert.equal(revoked.audit[0].checked_at, held.expires_at)
    const mutations = [...issued, { path, method: 'DELETE', status: 200 }]
    assert.deepEqual(f.calls, mutations)
    for (const localNow of [held.expires_at, held.expires_at + 100]) {
      f.setLocalNow(localNow)
      f.tick()
      assert.equal(s.ticket.value, lost ? held : null)
      assert.equal(s.revocationUncertain.value, lost)
      assert.equal(s.canCommit.value, false)
      if (lost) {
        await f.run('ticket')
        await f.run('commit')
        assert.equal(s.ticket.value, held)
        assert.equal(s.revocationUncertain.value, true)
      }
      assert.deepEqual(f.calls, mutations, 'ticks and uncertain authority checks never retry or issue')
      assert.deepEqual(snapshot(), revoked)
    }

    if (lost) {
      await bounded(s.checkCurrentTicket(), 'explicit revoked status at server expiry')
    } else {
      s.lookupId.value = held.id
      assert.deepEqual(f.calls, mutations, 'entering the same ticket ID does not automatically fetch')
      await f.run('status')
    }
    assert.equal(s.error.value, '')
    assert.deepEqual(s.outcome.value, {
      ...held, checked_at: held.expires_at, status: 'revoked', revoked: true, record: null,
    })
    assert.equal(s.ticket.value, null)
    assert.equal(s.revocationUncertain.value, false)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.lastSubmissionId.value, '')
    assert.deepEqual(s.commands.value, [])
    f.setLocalNow(held.expires_at + 200)
    f.tick()
    await f.run('commit')
    assert.equal(s.ticket.value, null)
    assert.equal(s.revocationUncertain.value, false)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.outcome.value.status, 'revoked')
    assert.equal(s.outcome.value.checked_at, held.expires_at)
    assert.deepEqual(snapshot(), revoked, 'ticks and the explicit GET never duplicate mutation or audit')
    assert.deepEqual(f.calls, [...mutations, { path, method: 'GET', status: 200 }])
  })
}

test('live service: local expiry ticks preserve the active snapshot until an explicit expired status', { timeout: 15000 }, async t => {
  const f = await fixture(t)
  const s = f.session
  await f.run('ticket')
  const held = s.ticket.value
  const path = `/v1/tickets/${held.id}`
  await bounded(s.checkCurrentTicket(), 'initial active status before expiry')
  assert.equal(s.error.value, '')
  const active = s.outcome.value
  const checkedAt = active.checked_at
  const receipt = s.outcomeReceivedAt.value
  assert.equal(active.status, 'active')
  assert.equal(checkedAt, now)
  assert.equal(receipt, now)
  assert.equal(s.canCommit.value, true)
  const persisted = () => Object.fromEntries(['tickets', 'commands', 'audit'].map(table =>
    [table, f.db.prepare(`SELECT * FROM ${table}`).all()]))
  const before = persisted()
  const initialCalls = [
    { path: '/v1/tickets', method: 'POST', status: 201 },
    { path, method: 'GET', status: 200 },
  ]
  assert.deepEqual(f.calls, initialCalls)

  f.setServerNow(held.expires_at)
  for (const localNow of [held.expires_at, held.expires_at + 100]) {
    f.setLocalNow(localNow)
    f.tick()
    assert.equal(s.now.value, localNow)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.remaining.value, 0)
    assert.equal(s.ticket.value, held)
    assert.equal(s.outcome.value, active)
    assert.equal(s.outcome.value.status, 'active')
    assert.equal(s.outcome.value.checked_at, checkedAt)
    assert.equal(s.outcomeReceivedAt.value, receipt)
    assert.deepEqual(f.calls, initialCalls, 'ticks never request status or mutate remotely')
    assert.deepEqual(persisted(), before)
  }

  await bounded(s.checkCurrentTicket(), 'explicit expired status at fixed server expiry')
  assert.equal(s.error.value, '')
  const expired = s.outcome.value
  const expiredReceipt = s.outcomeReceivedAt.value
  assert.notEqual(expired, active)
  assert.equal(expired.id, held.id)
  assert.equal(expired.status, 'expired')
  assert.equal(expired.checked_at, held.expires_at)
  assert.equal(expiredReceipt, held.expires_at + 100)
  assert.notEqual(expiredReceipt, receipt)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.revocationUncertain.value, false)
  assert.equal(s.lastSubmissionId.value, '')
  assert.deepEqual(s.commands.value, [])
  assert.deepEqual(persisted(), before)
  const finalCalls = [...initialCalls, { path, method: 'GET', status: 200 }]
  assert.deepEqual(f.calls, finalCalls)

  f.setLocalNow(held.expires_at + 200)
  f.tick()
  assert.equal(s.outcome.value, expired)
  assert.equal(s.outcome.value.status, 'expired')
  assert.equal(s.outcome.value.checked_at, held.expires_at)
  assert.equal(s.outcomeReceivedAt.value, expiredReceipt)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.deepEqual(s.commands.value, [])
  assert.deepEqual(persisted(), before)
  assert.deepEqual(f.calls, finalCalls)
})

for (const terminal of ['committed', 'revoked']) {
  test(`live service: local ticks retain an active snapshot until explicit status discovers external ${terminal}`, { timeout: 15000 }, async t => {
    const f = await fixture(t)
    const s = f.session
    await f.run('ticket')
    const held = s.ticket.value
    const path = `/v1/tickets/${held.id}`
    await bounded(s.checkCurrentTicket(), 'initial active status before remote operation')
    const active = s.outcome.value
    const checkedAt = active.checked_at
    const receipt = s.outcomeReceivedAt.value
    assert.equal(active.id, held.id)
    assert.equal(active.status, 'active')
    assert.equal(active.record, null)
    assert.equal(checkedAt, now)
    assert.equal(receipt, now)
    const initialCalls = [
      { path: '/v1/tickets', method: 'POST', status: 201 },
      { path, method: 'GET', status: 200 },
    ]
    assert.deepEqual(f.calls, initialCalls)
    const revokeExternal = t.mock.method(f, 'revokeExternal')
    const externalCalls = []
    const externalFetch = async (path, options) => {
      const call = { path, method: options.method, ticketId: JSON.parse(options.body).ticket_id }
      externalCalls.push(call)
      const response = await f.externalFetch(path, options)
      call.status = response.status
      return response
    }
    const record = terminal === 'committed'
      ? await bounded(productionApi.commitCommand(held, held.command, token, externalFetch), 'external same-ticket commit')
      : (await bounded(f.revokeExternal(held), 'external same-ticket revocation'), null)
    const persisted = () => Object.fromEntries(['tickets', 'commands', 'audit'].map(table =>
      [table, f.db.prepare(`SELECT * FROM ${table}`).all()]))
    const remote = persisted()
    assert.equal(remote.tickets.length, 1)
    assert.equal(remote.tickets[0].id, held.id)
    assert.equal(remote.tickets[0].command, held.command)
    assert.equal(remote.tickets[0].consumed, terminal === 'committed' ? 1 : 0)
    assert.equal(remote.tickets[0].revoked, terminal === 'revoked' ? 1 : 0)
    assert.equal(remote.commands.length, record ? 1 : 0)
    if (record) {
      assert.equal(record.command, held.command)
      assert.equal(record.committed_at, now)
      const { id, command, committed_at, ticket_id } = remote.commands[0]
      assert.equal(ticket_id, held.id)
      assert.deepEqual({ id, command, committed_at }, record)
    }
    assert.equal(remote.audit.length, 1)
    assert.equal(remote.audit[0].ticket_id, held.id)
    assert.equal(remote.audit[0].action, record ? remote.tickets[0].action : 'ticket:revoke')
    assert.equal(remote.audit[0].checked_at, now)
    const expectedExternal = record
      ? [{ path: '/v1/commands', method: 'POST', ticketId: held.id, status: 201 }] : []
    assert.deepEqual(externalCalls, expectedExternal)
    assert.equal(revokeExternal.mock.callCount(), record ? 0 : 1)
    if (!record) assert.equal(revokeExternal.mock.calls[0].arguments[0], held)

    for (const localNow of [now + 100, now + 200]) {
      assert.ok(localNow >= held.not_before && localNow < held.expires_at)
      f.setLocalNow(localNow)
      f.tick()
      assert.equal(s.now.value, localNow)
      assert.equal(s.ticket.value, held)
      assert.equal(s.canCommit.value, true, 'local preflight is not server authority')
      assert.equal(s.outcome.value, active)
      assert.equal(active.status, 'active')
      assert.equal(active.checked_at, checkedAt)
      assert.equal(s.outcomeReceivedAt.value, receipt)
      assert.equal(s.lastSubmissionId.value, '')
      assert.equal(s.revocationUncertain.value, false)
      assert.deepEqual(s.commands.value, [])
      assert.deepEqual(f.calls, initialCalls, 'no automatic status or journal requests')
      assert.deepEqual(externalCalls, expectedExternal)
      assert.deepEqual(persisted(), remote)
    }

    await bounded(s.checkCurrentTicket(), 'explicit status discovers remote terminal state')
    const outcome = s.outcome.value
    assert.equal(s.error.value, '')
    assert.notEqual(outcome, active)
    assert.equal(outcome.id, held.id)
    assert.equal(outcome.command, held.command)
    assert.equal(outcome.not_before, held.not_before)
    assert.equal(outcome.expires_at, held.expires_at)
    assert.equal(outcome.status, terminal)
    assert.equal(outcome.revoked, terminal === 'revoked')
    assert.equal(outcome.checked_at, now, 'server clock stayed constant')
    assert.deepEqual(outcome.record, record)
    assert.equal(s.outcomeReceivedAt.value, now + 200)
    assert.equal(s.ticket.value, null)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.lastSubmissionId.value, '', 'no local submission occurred')
    assert.equal(s.revocationUncertain.value, false)
    assert.deepEqual(s.commands.value, [], 'status is not a journal refresh')
    assert.deepEqual(persisted(), remote, 'GET preserves the remote mutation exactly')
    const finalCalls = [...initialCalls, { path, method: 'GET', status: 200 }]
    assert.deepEqual(f.calls, finalCalls)
    f.setLocalNow(now + 300)
    f.tick()
    assert.equal(s.outcome.value, outcome)
    assert.equal(outcome.checked_at, now)
    assert.equal(s.outcomeReceivedAt.value, now + 200)
    assert.equal(s.ticket.value, null)
    assert.equal(s.canCommit.value, false)
    assert.deepEqual(persisted(), remote)
    assert.deepEqual(f.calls, finalCalls)
    assert.deepEqual(externalCalls, expectedExternal)
    assert.equal(revokeExternal.mock.callCount(), record ? 0 : 1)
    assert.deepEqual(f.sockets, [])
    assert.equal(f.witness, undefined)
  })
}

for (const terminal of ['committed', 'revoked']) {
  test(`live service: stale active snapshot permits one real commit denial after external ${terminal}`, { timeout: 15000 }, async t => {
    const f = await fixture(t)
    const s = f.session
    await f.run('ticket')
    const held = s.ticket.value
    const path = `/v1/tickets/${held.id}`
    await bounded(s.checkCurrentTicket(), 'active snapshot before external terminal operation')
    const active = s.outcome.value
    const receipt = s.outcomeReceivedAt.value
    assert.equal(active.status, 'active')
    assert.equal(active.record, null)
    assert.equal(receipt, now)
    const revokeExternal = t.mock.method(f, 'revokeExternal')
    const record = terminal === 'committed'
      ? await bounded(f.commitTicketExternal(held), 'external same-ticket production commit')
      : (await bounded(f.revokeExternal(held), 'external same-ticket production revocation'), null)
    const persisted = () => Object.fromEntries(['tickets', 'commands', 'audit'].map(table =>
      [table, f.db.prepare(`SELECT * FROM ${table}`).all()]))
    const remote = persisted()
    assert.equal(remote.tickets.length, 1)
    assert.equal(remote.tickets[0].id, held.id)
    assert.equal(remote.tickets[0].consumed, record ? 1 : 0)
    assert.equal(remote.tickets[0].revoked, record ? 0 : 1)
    assert.equal(remote.commands.length, record ? 1 : 0)
    if (record) {
      const { id, command, committed_at, ticket_id } = remote.commands[0]
      assert.equal(ticket_id, held.id)
      assert.deepEqual({ id, command, committed_at }, record)
    }
    assert.equal(remote.audit.length, 1)
    assert.equal(remote.audit[0].ticket_id, held.id)
    const initialCalls = [
      { path: '/v1/tickets', method: 'POST', status: 201 },
      { path, method: 'GET', status: 200 },
    ]
    assert.deepEqual(f.calls, initialCalls)
    assert.equal(s.ticket.value, held)
    assert.equal(s.canCommit.value, true, 'stale local preflight is not server authority')
    assert.equal(s.outcome.value, active)
    assert.equal(s.outcomeReceivedAt.value, receipt)
    await f.run('commit')
    const deniedCalls = [...initialCalls, { path: '/v1/commands', method: 'POST', status: 403 }]
    assert.deepEqual(f.calls, deniedCalls, 'real denial sends no automatic retry or lookup')
    assert.match(s.error.value, /Geen toestemming/)
    assert.equal(s.message.value, commitCaution)
    assert.equal(s.ticket.value, null)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.lastSubmissionId.value, held.id)
    assert.equal(s.lookupId.value, held.id)
    assert.equal(s.outcome.value, null)
    assert.equal(s.outcomeReceivedAt.value, null)
    assert.equal(s.revocationUncertain.value, false)
    assert.deepEqual(s.commands.value, [])
    assert.deepEqual(persisted(), remote, 'denied commit preserves all remote writes')
    await f.run('commit')
    assert.deepEqual(f.calls, deniedCalls, 'missing local ticket blocks HTTP entirely')
    assert.equal(s.message.value, localCommitBlocked)
    assert.equal(s.ticket.value, null)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.lastSubmissionId.value, held.id)
    assert.equal(s.lookupId.value, held.id)
    assert.equal(s.outcome.value, null)
    assert.equal(s.outcomeReceivedAt.value, null)
    assert.deepEqual(s.commands.value, [])
    assert.deepEqual(persisted(), remote)
    await bounded(s.checkLastSubmission(), 'explicit status resolves the denied submission')
    const outcome = s.outcome.value
    assert.equal(s.error.value, '')
    assert.match(s.message.value, /Ticketstatus opgehaald/)
    assert.equal(outcome.id, held.id)
    assert.equal(outcome.command, held.command)
    assert.equal(outcome.not_before, held.not_before)
    assert.equal(outcome.expires_at, held.expires_at)
    assert.equal(outcome.status, terminal)
    assert.equal(outcome.revoked, terminal === 'revoked')
    assert.equal(outcome.checked_at, now)
    assert.deepEqual(outcome.record, record)
    assert.equal(s.outcomeReceivedAt.value, now)
    assert.equal(s.ticket.value, null)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.lastSubmissionId.value, held.id)
    assert.equal(s.lookupId.value, held.id)
    assert.equal(s.revocationUncertain.value, false)
    assert.deepEqual(s.commands.value, [], 'status never inserts the remote record into the journal')
    assert.deepEqual(persisted(), remote)
    const finalCalls = [...deniedCalls, { path, method: 'GET', status: 200 }]
    assert.deepEqual(f.calls, finalCalls)
    f.setLocalNow(now + 100)
    f.tick()
    assert.equal(s.outcome.value, outcome)
    assert.equal(s.outcomeReceivedAt.value, now)
    assert.equal(s.ticket.value, null)
    assert.equal(s.canCommit.value, false)
    assert.deepEqual(s.commands.value, [])
    assert.deepEqual(f.calls, finalCalls, 'clock ticks cause no requests')
    assert.deepEqual(persisted(), remote)
    assert.deepEqual(f.externalCommitCalls, record
      ? [{ path: '/v1/commands', method: 'POST', ticketId: held.id, status: 201 }] : [])
    assert.equal(revokeExternal.mock.callCount(), record ? 0 : 1)
    if (!record) assert.equal(revokeExternal.mock.calls[0].arguments[0], held)
    assert.deepEqual(f.sockets, [])
    assert.equal(f.witness, undefined)
  })
}

for (const sample of ['expiry', 'invalid', 'throwing']) {
  test(`live service: fresh commit clock rejects ${sample} without a tick or any persisted mutation`, { timeout: 15000 }, async t => {
    const f = await fixture(t)
    const s = f.session
    await f.run('ticket')
    await bounded(s.checkCurrentTicket(), 'status before commit preflight')
    const held = s.ticket.value
    const outcome = s.outcome.value
    const receipt = s.outcomeReceivedAt.value
    s.lastSubmissionId.value = 'retained-id'
    const persisted = () => Object.fromEntries(['tickets', 'commands', 'audit', 'clock_state'].map(table =>
      [table, f.db.prepare(`SELECT * FROM ${table}`).all()]))
    const before = persisted()
    const requests = f.calls.length
    f.setLocalNow(sample === 'expiry' ? held.expires_at : sample === 'invalid' ? NaN
      : () => { throw new Error('commit clock unavailable') })
    assert.equal(s.now.value, now)
    assert.equal(s.canCommit.value, true, 'cached countdown has not observed the clock change')

    await f.run('commit')
    assert.equal(s.now.value, sample === 'expiry' ? held.expires_at : null)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.ticket.value, held)
    assert.equal(s.lastSubmissionId.value, 'retained-id')
    assert.equal(s.lookupId.value, held.id)
    assert.equal(s.outcome.value, outcome)
    assert.equal(s.outcomeReceivedAt.value, receipt)
    assert.equal(s.busy.value, '')
    assert.equal(s.error.value, '')
    assert.equal(s.message.value, localCommitBlocked)
    assert.equal(s.revocationUncertain.value, false)
    assert.equal(f.calls.length, requests)
    assert.equal(f.count('POST', '/v1/commands'), 0)
    assert.deepEqual(persisted(), before, 'no ticket, journal, audit or watermark mutation')

    if (sample !== 'expiry') {
      f.setLocalNow(now + 100)
      assert.equal(s.now.value, null, 'recovery has not had a tick')
      assert.equal(s.canCommit.value, false)
      assert.equal(f.calls.length, requests, 'clock recovery is not an automatic submission')
      await f.run('commit')
      assert.equal(s.now.value, now + 100)
      assert.equal(s.error.value, '')
      assert.equal(s.message.value, 'Commando vastgelegd in het logboek; er is niets uitgevoerd.')
      assert.equal(s.ticket.value, null)
      assert.equal(s.lastSubmissionId.value, held.id)
      assert.equal(s.outcome.value, null)
      assert.equal(f.count('POST', '/v1/commands'), 1)
      assert.equal(f.db.prepare('SELECT consumed FROM tickets WHERE id = ?').get(held.id).consumed, 1)
      assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM commands WHERE ticket_id = ?').get(held.id).count, 1)
      const audit = f.db.prepare('SELECT ticket_id, action FROM audit').all().map(row => ({ ...row }))
      assert.deepEqual(audit, [{ ticket_id: held.id, action: 'journal:append' }])
      const after = persisted()
      await f.run('commit')
      f.tick()
      assert.equal(f.calls.length, requests + 1, 'explicit recovery submits exactly once without retry')
      assert.deepEqual(persisted(), after)
    }
  })
}

test('live service: a throwing countdown tick fails closed, then fresh preflight permits only one explicit commit without a recovery tick', { timeout: 15000 }, async t => {
  const f = await fixture(t)
  const s = f.session
  await f.run('ticket')
  assert.equal(s.error.value, '')
  const held = s.ticket.value
  const persisted = f.db.prepare('SELECT * FROM tickets').all()
  assert.equal(s.canCommit.value, true)
  assert.equal(s.remaining.value, 10)

  f.setLocalNow(() => { throw new Error('local tick clock unavailable') })
  assert.doesNotThrow(() => f.tick())
  assert.equal(s.now.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.remaining.value, null)
  assert.equal(s.ticket.value, held)
  await f.run('commit')
  assert.equal(s.lastSubmissionId.value, '')
  assert.equal(f.count('POST', '/v1/commands'), 0)
  assert.deepEqual(f.db.prepare('SELECT * FROM tickets').all(), persisted)
  assert.deepEqual(f.db.prepare('SELECT * FROM commands').all(), [])
  assert.deepEqual(f.db.prepare('SELECT * FROM audit').all(), [])
  assert.deepEqual(f.calls, [{ path: '/v1/tickets', method: 'POST', status: 201 }])

  f.setLocalNow(now + 100)
  assert.equal(s.now.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.remaining.value, null)
  assert.equal(s.ticket.value, held)
  assert.equal(s.lastSubmissionId.value, '')
  assert.deepEqual(f.db.prepare('SELECT * FROM tickets').all(), persisted)
  assert.deepEqual(f.db.prepare('SELECT * FROM commands').all(), [])
  assert.deepEqual(f.db.prepare('SELECT * FROM audit').all(), [])
  assert.deepEqual(f.calls, [{ path: '/v1/tickets', method: 'POST', status: 201 }],
    'neither clock failure nor recovery sends an automatic request')

  await f.run('commit')
  assert.equal(s.now.value, now + 100)
  assert.equal(s.error.value, '')
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, held.id)
  assert.equal(s.lookupId.value, held.id)
  assert.equal(s.commands.value.length, 1)
  const record = { ...s.commands.value[0] }
  assert.deepEqual(record, { id: record.id, command: held.command, committed_at: now })
  assert.deepEqual({ ...f.db.prepare('SELECT id, command, committed_at FROM commands WHERE ticket_id = ?').get(held.id) }, record)
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM commands').get().count, 1)
  assert.deepEqual({ ...f.db.prepare('SELECT consumed, revoked FROM tickets WHERE id = ?').get(held.id) },
    { consumed: 1, revoked: 0 })
  const audit = f.db.prepare('SELECT * FROM audit').all()
  assert.equal(audit.length, 1)
  assert.equal(audit[0].ticket_id, held.id)
  assert.equal(audit[0].action, 'journal:append')
  await f.run('commit')
  f.tick()
  assert.deepEqual(f.calls, [
    { path: '/v1/tickets', method: 'POST', status: 201 },
    { path: '/v1/commands', method: 'POST', status: 201 },
  ], 'a consumed local ticket cannot be submitted again')

  f.setLocalNow(() => { throw new Error('local receipt clock unavailable') })
  await bounded(s.checkLastSubmission(), 'committed status despite failed receipt clock')
  assert.equal(s.error.value, '')
  assert.equal(s.outcome.value.id, held.id)
  assert.equal(s.outcome.value.status, 'committed')
  assert.equal(s.outcome.value.checked_at, now)
  assert.deepEqual(s.outcome.value.record, record)
  assert.equal(s.outcomeReceivedAt.value, null)
  await f.run('list')
  assert.equal(s.error.value, '')
  assert.equal(s.hasLoaded.value, true)
  assert.equal(s.journalRefreshFailed.value, false)
  assert.equal(s.lastJournalRefreshAt.value, null)
  assert.deepEqual(s.commands.value, [record])
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, held.id)
  assert.deepEqual(f.db.prepare('SELECT * FROM audit').all(), audit)
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM commands').get().count, 1)
  assert.deepEqual(f.calls, [
    { path: '/v1/tickets', method: 'POST', status: 201 },
    { path: '/v1/commands', method: 'POST', status: 201 },
    { path: `/v1/tickets/${held.id}`, method: 'GET', status: 200 },
    { path: '/v1/commands', method: 'GET', status: 200 },
  ])
})

for (const uncertain of [false, true]) {
  test(`live service: TTL edits retire only normal authority without restoration, uncertainty=${uncertain}`, { timeout: 15000 }, async t => {
    const f = await fixture(t)
    const s = f.session
    await f.run('ticket')
    assert.equal(s.error.value, '')
    const held = s.ticket.value
    const originalTtl = s.ttlMs.value
    const issuedWindow = structuredClone({ ...held })
    const path = `/v1/tickets/${held.id}`
    await bounded(s.checkCurrentTicket(), 'initial active status before TTL edits')
    assert.equal(s.error.value, '')
    const active = s.outcome.value
    const activeSnapshot = structuredClone({ ...active })
    const receipt = s.outcomeReceivedAt.value
    assert.deepEqual(active, { ...held, checked_at: now, status: 'active', revoked: false, record: null })
    assert.equal(receipt, now)
    assert.equal(s.canCommit.value, true)
    const expectedCalls = [
      { path: '/v1/tickets', method: 'POST', status: 201 },
      { path, method: 'GET', status: 200 },
    ]
    if (uncertain) {
      f.loseNext('DELETE', path)
      await f.run('revoke')
      assert.match(s.error.value, /Geen geldig antwoord/)
      assert.equal(s.message.value, revokeCaution)
      expectedCalls.push({ path, method: 'DELETE', status: 200 })
    }
    assert.equal(f.losses, Number(uncertain))
    assert.equal(s.ticket.value, held)
    assert.equal(s.revocationUncertain.value, uncertain)
    const persisted = () => Object.fromEntries(['tickets', 'commands', 'audit'].map(table =>
      [table, f.db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all()]))
    const baseline = persisted()
    assert.equal(baseline.tickets.length, 1)
    for (const [key, value] of Object.entries({ ...issuedWindow, revoked: Number(uncertain), consumed: 0 })) {
      assert.equal(baseline.tickets[0][key], value)
    }
    assert.equal(held.not_before, now)
    assert.equal(held.expires_at, now + originalTtl)
    assert.deepEqual(baseline.commands, [])
    assert.equal(baseline.audit.length, Number(uncertain))
    if (uncertain) {
      assert.equal(baseline.audit[0].ticket_id, held.id)
      assert.equal(baseline.audit[0].action, 'ticket:revoke')
      assert.equal(baseline.audit[0].checked_at, now)
    }
    const journal = s.commands.value
    const command = s.command.value
    const lastSubmissionId = s.lastSubmissionId.value
    const feedback = { message: s.message.value, error: s.error.value }
    const assertPreserved = () => {
      assert.equal(s.ticket.value, uncertain ? held : null)
      assert.equal(s.revocationUncertain.value, uncertain)
      assert.equal(s.canCommit.value, false, 'restoring the original TTL never restores commit authority')
      if (uncertain) assert.equal(s.canRequestTicket.value, false)
      assert.equal(s.outcome.value, active)
      assert.deepEqual(s.outcome.value, activeSnapshot)
      assert.equal(s.outcomeReceivedAt.value, receipt)
      assert.equal(s.lastSubmissionId.value, lastSubmissionId)
      assert.equal(s.command.value, command)
      assert.equal(s.commands.value, journal)
      assert.deepEqual(s.commands.value, [])
      assert.deepEqual(held, issuedWindow, 'TTL edits never alter the exact issued window')
      assert.deepEqual(persisted(), baseline)
      assert.deepEqual(f.calls, expectedCalls, 'edits, ticks and local rejection never send requests')
      assert.equal(f.sockets.length, 0)
      assert.equal(s.realtimeStatus.value, 'disconnected')
    }
    for (const value of [originalTtl + 1, '', originalTtl]) {
      s.ttlMs.value = value
      assert.equal(s.ttlMs.value, value)
      assertPreserved()
      f.setLocalNow(now + 100)
      f.tick()
      assert.equal(s.now.value, now + 100)
      assertPreserved()
      assert.deepEqual({ message: s.message.value, error: s.error.value }, feedback)
    }
    await f.run('commit')
    assert.equal(s.message.value, localCommitBlocked)
    assert.equal(s.error.value, '')
    assert.equal(s.busy.value, '')
    assertPreserved()
    if (uncertain) {
      await bounded(s.checkCurrentTicket(), 'explicit revoked status after TTL edits')
    } else {
      s.lookupId.value = held.id
      assertPreserved()
      await f.run('status')
    }
    assert.equal(s.error.value, '')
    assert.deepEqual(s.outcome.value, {
      ...held, checked_at: now, status: uncertain ? 'revoked' : 'active', revoked: uncertain, record: null,
    })
    assert.equal(s.outcomeReceivedAt.value, now + 100)
    assert.equal(s.ticket.value, null, 'even a fresh active GET never restores the retired ticket')
    assert.equal(s.revocationUncertain.value, false)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.lastSubmissionId.value, lastSubmissionId)
    assert.equal(s.command.value, command)
    assert.equal(s.commands.value, journal)
    assert.deepEqual(s.commands.value, [])
    assert.deepEqual(persisted(), baseline, 'explicit status neither inserts journal rows nor mutates SQLite')
    assert.deepEqual(f.calls, [...expectedCalls, { path, method: 'GET', status: 200 }])
    assert.equal(f.sockets.length, 0)
    assert.equal(f.losses, Number(uncertain))
  })
}

for (const ttl of ['', 0, 60001, 1.5, NaN, Infinity]) {
  test(`live service: invalid TTL ${JSON.stringify(String(ttl))} rejects explicit issuance locally without retry`, { timeout: 15000 }, async t => {
    const f = await fixture(t)
    const s = f.session
    const draft = s.command.value
    s.ttlMs.value = ttl
    assert.equal(s.validTtl.value, false)
    assert.equal(s.canRequestTicket.value, false)

    await f.run('ticket')
    assert.match(s.error.value, /gehele geldigheidsduur van 1 t\/m 60000 ms/)
    assert.equal(s.message.value, ticketCaution)
    assert.equal(s.busy.value, '')
    assert.equal(s.command.value, draft)
    assert.equal(s.ticket.value, null)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.lastSubmissionId.value, '')
    assert.equal(s.lookupId.value, '')
    assert.equal(s.outcome.value, null)
    f.tick()
    await Promise.resolve()
    assert.equal(s.validTtl.value, false)
    assert.equal(s.canRequestTicket.value, false)
    assert.deepEqual(f.calls, [], 'validation and clock ticks send no HTTP request or automatic retry')
    assert.deepEqual(s.commands.value, [])
    for (const table of ['tickets', 'commands', 'audit']) {
      assert.deepEqual(f.db.prepare(`SELECT * FROM ${table}`).all(), [])
    }
  })
}

for (const ttl of ['1', '60000']) {
  test(`live service: restored numeric-string TTL ${ttl} issues exactly but stale local time cannot authorize commit at server expiry`, { timeout: 15000 }, async t => {
    const f = await fixture(t)
    const s = f.session
    const draft = s.command.value
    s.ttlMs.value = ''
    assert.equal(s.validTtl.value, false)
    assert.equal(s.canRequestTicket.value, false)
    s.ttlMs.value = ttl
    assert.equal(s.validTtl.value, true)
    assert.equal(s.canRequestTicket.value, true)
    assert.deepEqual(f.calls, [], 'restoring eligibility does not automatically request a ticket')
    await f.run('ticket')
    assert.equal(s.error.value, '')
    const held = { ...s.ticket.value }
    assert.equal(held.command, draft)
    assert.equal(held.not_before, now)
    assert.equal(held.expires_at, now + Number(ttl))
    assert.equal(held.expires_at - held.not_before, Number(ttl))
    assert.equal(s.validTtl.value, true)
    assert.equal(s.canRequestTicket.value, true)
    assert.equal(s.canCommit.value, true)
    assert.deepEqual(f.calls, [{ path: '/v1/tickets', method: 'POST', status: 201 }])
    const tickets = f.db.prepare('SELECT * FROM tickets').all()
    assert.equal(tickets.length, 1)
    assert.equal(tickets[0].id, held.id)
    assert.equal(tickets[0].command, draft)
    assert.equal(tickets[0].not_before, held.not_before)
    assert.equal(tickets[0].expires_at, held.expires_at)
    assert.equal(tickets[0].consumed, 0)
    assert.equal(tickets[0].revoked, 0)
    const assertUnchanged = () => {
      assert.deepEqual(f.db.prepare('SELECT * FROM tickets').all(), tickets)
      assert.deepEqual(f.db.prepare('SELECT * FROM commands').all(), [])
      assert.deepEqual(f.db.prepare('SELECT * FROM audit').all(), [])
      assert.deepEqual(s.commands.value, [])
    }
    assertUnchanged()

    // Only server time advances: local usability is preflight, not authority.
    f.setServerNow(held.expires_at)
    assert.equal(Date.now(), now)
    f.tick()
    assert.equal(s.now.value, now)
    assert.deepEqual(s.ticket.value, held)
    assert.equal(s.canCommit.value, true)
    assert.equal(productionApi.ticketUsable(held, s.command.value), true)
    await f.run('commit')
    assert.deepEqual(f.calls.at(-1), { path: '/v1/commands', method: 'POST', status: 403 })
    assert.match(s.error.value, /Geen toestemming/)
    assert.equal(s.message.value, commitCaution)
    assert.equal(s.ticket.value, null)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.lastSubmissionId.value, held.id)
    assert.equal(s.lookupId.value, held.id)
    assert.equal(s.outcome.value, null)
    assertUnchanged()
    assert.equal(f.calls.length, 2, 'denial triggers neither retry nor automatic status lookup')

    await f.run('commit')
    assert.equal(f.calls.length, 2, 'consumed local authority cannot send another request')
    assert.equal(s.lastSubmissionId.value, held.id)
    await bounded(s.checkLastSubmission(), 'expired submission status')
    assert.equal(s.error.value, '')
    assert.match(s.message.value, /Ticketstatus opgehaald/)
    assert.equal(s.outcome.value.id, held.id)
    assert.equal(s.outcome.value.command, held.command)
    assert.equal(s.outcome.value.not_before, held.not_before)
    assert.equal(s.outcome.value.expires_at, held.expires_at)
    assert.equal(s.outcome.value.status, 'expired')
    assert.equal(s.outcome.value.checked_at, held.expires_at)
    assert.equal(s.outcome.value.revoked, false)
    assert.equal(s.outcome.value.record, null)
    assert.equal(s.outcomeReceivedAt.value, now)
    assert.equal(s.ticket.value, null)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.lastSubmissionId.value, held.id)
    assert.equal(s.lookupId.value, held.id)
    assert.equal(s.outcomeMismatch.value, false)
    assert.equal(s.now.value, now)
    f.tick()
    await f.run('commit')
    assert.equal(s.message.value, localCommitBlocked)
    assert.equal(s.ticket.value, null)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.lastSubmissionId.value, held.id)
    assert.equal(s.lookupId.value, held.id)
    assert.equal(s.outcome.value.status, 'expired')
    assertUnchanged()
    assert.equal(f.count('POST', '/v1/tickets'), 1)
    assert.equal(f.count('POST', '/v1/commands'), 1)
    assert.equal(f.count('GET', `/v1/tickets/${held.id}`), 1)
    assert.deepEqual(f.calls, [
      { path: '/v1/tickets', method: 'POST', status: 201 },
      { path: '/v1/commands', method: 'POST', status: 403 },
      { path: `/v1/tickets/${held.id}`, method: 'GET', status: 200 },
    ])
  })
}

test('live service: external production revocation leaves stale local preflight usable until the real commit is denied', { timeout: 15000 }, async t => {
  const f = await fixture(t)
  const s = f.session
  await f.run('ticket')
  assert.equal(s.error.value, '')
  const held = { ...s.ticket.value }
  assert.equal(s.canCommit.value, true)
  await bounded(f.revokeExternal(held), 'external ticket revocation')
  assert.deepEqual({ ...f.db.prepare('SELECT consumed, revoked FROM tickets WHERE id = ?').get(held.id) },
    { consumed: 0, revoked: 1 })
  const audit = f.db.prepare('SELECT * FROM audit').all()
  assert.equal(audit.length, 1)
  assert.equal(audit[0].action, 'ticket:revoke')
  assert.deepEqual(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, false)
  assert.equal(s.canCommit.value, true)
  assert.equal(productionApi.ticketUsable(held, s.command.value), true)
  assert.equal(f.calls.length, 1, 'external revocation is not a session operation')

  await f.run('commit')
  assert.deepEqual(f.calls.at(-1), { path: '/v1/commands', method: 'POST', status: 403 })
  assert.match(s.error.value, /Geen toestemming/)
  assert.equal(s.message.value, commitCaution)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, held.id)
  assert.equal(s.lookupId.value, held.id)
  assert.equal(s.outcome.value, null)
  assert.deepEqual(s.commands.value, [])
  assert.deepEqual({ ...f.db.prepare('SELECT consumed, revoked FROM tickets WHERE id = ?').get(held.id) },
    { consumed: 0, revoked: 1 })
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM commands').get().count, 0)
  assert.deepEqual(f.db.prepare('SELECT * FROM audit').all(), audit)
  assert.equal(f.calls.length, 2, 'denial triggers neither retry nor automatic status lookup')

  await f.run('commit')
  assert.equal(f.calls.length, 2, 'consumed local authority cannot send another request')
  assert.equal(s.lastSubmissionId.value, held.id)
  await bounded(s.checkLastSubmission(), 'externally revoked submission status')
  assert.equal(s.error.value, '')
  assert.match(s.message.value, /Ticketstatus opgehaald/)
  assert.equal(s.outcome.value.id, held.id)
  assert.equal(s.outcome.value.status, 'revoked')
  assert.equal(s.outcome.value.checked_at, now)
  assert.equal(s.outcome.value.revoked, true)
  assert.equal(s.outcome.value.record, null)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.revocationUncertain.value, false)
  assert.equal(s.lastSubmissionId.value, held.id)
  assert.deepEqual(s.commands.value, [])
  assert.deepEqual({ ...f.db.prepare('SELECT consumed, revoked FROM tickets WHERE id = ?').get(held.id) },
    { consumed: 0, revoked: 1 })
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM commands').get().count, 0)
  assert.deepEqual(f.db.prepare('SELECT * FROM audit').all(), audit)
  assert.equal(f.count('POST', '/v1/tickets'), 1)
  assert.equal(f.count('POST', '/v1/commands'), 1)
  assert.equal(f.count('GET', `/v1/tickets/${held.id}`), 1)
  assert.equal(f.calls.length, 3)
})

test('live service: a real commit 503 rolls back mutation without restoring local authority or retrying', { timeout: 15000 }, async t => {
  const f = await fixture(t)
  const s = f.session
  await f.run('ticket')
  assert.equal(s.error.value, '')
  const held = { ...s.ticket.value }
  const stages = []
  f.setFault(stage => {
    stages.push(stage)
    if (stage === 'before-commit') throw new Error('injected transaction failure')
  })
  await f.run('commit')
  assert.deepEqual(stages, ['after-begin', 'before-commit', 'before-watermark-commit'])
  assert.deepEqual(f.calls.at(-1), { path: '/v1/commands', method: 'POST', status: 503 })
  assert.match(s.error.value, /De service kan dit verzoek niet verwerken/)
  assert.equal(s.message.value, commitCaution)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, held.id)
  assert.equal(s.lookupId.value, held.id)
  assert.equal(s.outcome.value, null)
  assert.deepEqual(s.commands.value, [])
  assert.deepEqual({ ...f.db.prepare('SELECT consumed, revoked FROM tickets WHERE id = ?').get(held.id) },
    { consumed: 0, revoked: 0 })
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM commands').get().count, 0)
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM audit').get().count, 0)
  assert.equal(f.db.prepare('SELECT last_time FROM clock_state WHERE id = 1').get().last_time, now)
  assert.equal(f.calls.length, 2, '503 triggers neither retry nor automatic status lookup')

  await f.run('commit')
  assert.equal(f.calls.length, 2, 'lost local authority cannot send another POST')
  assert.equal(s.lastSubmissionId.value, held.id)
  f.setFault(() => {})
  await bounded(s.checkLastSubmission(), 'rolled back submission status')
  assert.deepEqual(f.calls.at(-1), { path: `/v1/tickets/${held.id}`, method: 'GET', status: 200 })
  assert.equal(s.error.value, '')
  assert.match(s.message.value, /Ticketstatus opgehaald/)
  assert.equal(s.outcome.value.id, held.id)
  assert.equal(s.outcome.value.status, 'active')
  assert.equal(s.outcome.value.checked_at, now)
  assert.equal(s.outcome.value.revoked, false)
  assert.equal(s.outcome.value.record, null)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, held.id)
  await f.run('commit')
  assert.equal(f.calls.length, 3, 'an active status snapshot does not reauthorize submission')
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM commands').get().count, 0)
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM audit').get().count, 0)

  await f.run('ticket')
  assert.equal(s.error.value, '')
  const fresh = { ...s.ticket.value }
  assert.notEqual(fresh.id, held.id)
  assert.equal(s.canCommit.value, true)
  assert.equal(f.calls.length, 4, 'new issuance does not automatically commit')
  await f.run('commit')
  assert.deepEqual(f.calls.at(-1), { path: '/v1/commands', method: 'POST', status: 201 })
  assert.equal(s.error.value, '')
  assert.equal(s.ticket.value, null)
  assert.equal(s.lastSubmissionId.value, fresh.id)
  assert.equal(s.commands.value.length, 1)
  assert.deepEqual({ ...f.db.prepare('SELECT id, command, committed_at FROM commands WHERE ticket_id = ?').get(fresh.id) },
    { ...s.commands.value[0] })
  assert.deepEqual({ ...f.db.prepare('SELECT consumed, revoked FROM tickets WHERE id = ?').get(fresh.id) },
    { consumed: 1, revoked: 0 })
  assert.deepEqual({ ...f.db.prepare('SELECT consumed, revoked FROM tickets WHERE id = ?').get(held.id) },
    { consumed: 0, revoked: 0 })
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM commands').get().count, 1)
  const audit = f.db.prepare('SELECT ticket_id, action FROM audit').all()
  assert.equal(audit.length, 1)
  assert.equal(audit[0].ticket_id, fresh.id)
  assert.equal(audit[0].action, 'journal:append')
  await f.run('commit')
  assert.equal(f.count('POST', '/v1/tickets'), 2)
  assert.equal(f.count('POST', '/v1/commands'), 2)
  assert.equal(f.count('GET', `/v1/tickets/${held.id}`), 1)
  assert.equal(f.calls.length, 5, 'manual recovery commits exactly once without automatic calls')
})

test('live service: persisted watermark rejects a backwards clock after restart without restoring local authority', { timeout: 15000 }, async t => {
  const f = await fixture(t)
  const s = f.session
  const snapshot = () => Object.fromEntries(['tickets', 'commands', 'audit', 'clock_state'].map(table =>
    [table, f.db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all()]))
  await f.run('ticket')
  assert.equal(s.error.value, '')
  const held = { ...s.ticket.value }
  const path = `/v1/tickets/${held.id}`
  assert.equal(held.not_before, now)
  assert.ok(held.expires_at > 1100)
  assert.equal(s.canCommit.value, true)

  f.setServerNow(1100)
  await bounded(s.checkCurrentTicket(), 'advance durable watermark with active status')
  assert.deepEqual(f.calls.at(-1), { path, method: 'GET', status: 200 })
  assert.equal(s.error.value, '')
  assert.equal(s.outcome.value.id, held.id)
  assert.equal(s.outcome.value.status, 'active')
  assert.equal(s.outcome.value.checked_at, 1100)
  assert.equal(s.outcome.value.record, null)
  assert.deepEqual(s.ticket.value, held)
  const persisted = snapshot()
  assert.equal(persisted.tickets.length, 1)
  assert.equal(persisted.tickets[0].id, held.id)
  assert.equal(persisted.tickets[0].consumed, 0)
  assert.equal(persisted.tickets[0].revoked, 0)
  assert.deepEqual(persisted.commands, [])
  assert.deepEqual(persisted.audit, [])
  assert.equal(persisted.clock_state[0].last_time, 1100)

  f.setServerNow(now)
  await bounded(f.restart(), 'restart with backwards server clock')
  assert.deepEqual(snapshot(), persisted, 'the same SQLite journal retains its watermark across restart')
  assert.equal(f.calls.length, 2, 'restart sends no session requests')
  assert.equal(Date.now(), now)
  assert.equal(s.now.value, now)
  assert.deepEqual(s.ticket.value, held)
  assert.equal(s.canCommit.value, true)
  assert.equal(productionApi.ticketUsable(held, s.command.value), true)
  await f.run('commit')
  assert.deepEqual(f.calls.at(-1), { path: '/v1/commands', method: 'POST', status: 503 })
  assert.match(s.error.value, /De service kan dit verzoek niet verwerken/)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, held.id)
  assert.equal(s.lookupId.value, held.id)
  assert.equal(s.outcome.value, null)
  assert.equal(s.outcomeReceivedAt.value, null)
  assert.equal(s.revocationUncertain.value, false)
  assert.deepEqual(s.commands.value, [])
  assert.deepEqual(snapshot(), persisted, 'backwards-clock denial changes no ticket, command, audit or clock')
  assert.equal(f.calls.length, 3, '503 triggers neither retry nor automatic status lookup')
  await f.run('commit')
  assert.equal(f.calls.length, 3, 'consumed local authority cannot submit again')

  await bounded(s.checkLastSubmission(), 'backwards-clock submission status')
  assert.deepEqual(f.calls.at(-1), { path, method: 'GET', status: 503 })
  assert.match(s.error.value, /De service kan dit verzoek niet verwerken/)
  assert.equal(s.outcome.value, null)
  assert.equal(s.outcomeReceivedAt.value, null)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, held.id)
  assert.equal(s.revocationUncertain.value, false)
  assert.deepEqual(s.commands.value, [])
  assert.deepEqual(snapshot(), persisted, 'failed explicit lookup preserves the durable watermark and empty journal')
  assert.equal(f.calls.length, 4, 'failed lookup triggers no automatic requests')

  // Clock recovery, not clearing an unhealthy-storage latch, makes explicit requests safe again.
  f.setServerNow(1100)
  await bounded(s.checkLastSubmission(), 'safe-clock active submission status')
  assert.deepEqual(f.calls.at(-1), { path, method: 'GET', status: 200 })
  assert.equal(s.error.value, '')
  assert.equal(s.outcome.value.id, held.id)
  assert.equal(s.outcome.value.status, 'active')
  assert.equal(s.outcome.value.checked_at, 1100)
  assert.equal(s.outcome.value.revoked, false)
  assert.equal(s.outcome.value.record, null)
  assert.equal(s.outcomeReceivedAt.value, now)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, held.id)
  assert.deepEqual(s.commands.value, [])
  assert.deepEqual(snapshot(), persisted)
  await f.run('commit')
  assert.equal(f.calls.length, 5, 'an active status snapshot cannot restore authority or permit recommit')

  await f.run('ticket')
  assert.equal(s.error.value, '')
  const fresh = { ...s.ticket.value }
  assert.notEqual(fresh.id, held.id)
  assert.equal(fresh.not_before, 1100)
  assert.equal(f.calls.length, 6, 'new manual issuance does not automatically commit')
  // Advance local preflight only for the new ticket's later not-before boundary.
  t.mock.method(Date, 'now', () => 1100)
  f.setLocalNow(1100)
  f.tick()
  assert.equal(s.canCommit.value, true)
  await f.run('commit')
  assert.deepEqual(f.calls.at(-1), { path: '/v1/commands', method: 'POST', status: 201 })
  assert.equal(s.error.value, '')
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, fresh.id)
  assert.equal(s.commands.value.length, 1)
  const record = { ...s.commands.value[0] }
  assert.equal(record.command, fresh.command)
  assert.equal(record.committed_at, 1100)
  assert.deepEqual({ ...f.db.prepare('SELECT id, command, committed_at FROM commands WHERE ticket_id = ?').get(fresh.id) }, record)
  assert.deepEqual({ ...f.db.prepare('SELECT consumed, revoked FROM tickets WHERE id = ?').get(fresh.id) },
    { consumed: 1, revoked: 0 })
  assert.deepEqual(f.db.prepare('SELECT * FROM tickets WHERE id = ?').get(held.id), persisted.tickets[0])
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM tickets').get().count, 2)
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM commands').get().count, 1)
  const audit = f.db.prepare('SELECT ticket_id, action FROM audit').all()
  assert.equal(audit.length, 1)
  assert.equal(audit[0].ticket_id, fresh.id)
  assert.equal(audit[0].action, 'journal:append')
  assert.equal(f.db.prepare('SELECT last_time FROM clock_state WHERE id = 1').get().last_time, 1100)
  await f.run('commit')
  assert.equal(f.count('POST', '/v1/tickets'), 2)
  assert.equal(f.count('POST', '/v1/commands'), 2)
  assert.equal(f.count('GET', path), 3)
  assert.deepEqual(f.calls, [
    { path: '/v1/tickets', method: 'POST', status: 201 },
    { path, method: 'GET', status: 200 },
    { path: '/v1/commands', method: 'POST', status: 503 },
    { path, method: 'GET', status: 503 },
    { path, method: 'GET', status: 200 },
    { path: '/v1/tickets', method: 'POST', status: 201 },
    { path: '/v1/commands', method: 'POST', status: 201 },
  ], 'manual recovery commits once with no automatic requests or retries')
})

test('live service: failed watermark durability latches revocation and NEO verification fail-closed', { timeout: 15000 }, async t => {
  const f = await fixture(t)
  const s = f.session
  await f.run('ticket')
  assert.equal(s.error.value, '')
  const held = { ...s.ticket.value }
  const path = `/v1/tickets/${held.id}`
  const snapshot = () => Object.fromEntries(['tickets', 'commands', 'audit', 'clock_state'].map(table =>
    [table, f.db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all()]))
  const healthy = snapshot()
  assert.equal(healthy.tickets.length, 1)
  assert.equal(healthy.tickets[0].id, held.id)
  assert.equal(healthy.tickets[0].consumed, 0)
  assert.equal(healthy.tickets[0].revoked, 0)
  assert.deepEqual(healthy.commands, [])
  assert.deepEqual(healthy.audit, [])
  assert.equal(s.canCommit.value, true)

  const stages = []
  f.setFault(stage => {
    stages.push(stage)
    if (stage === 'before-commit' || stage === 'before-watermark-commit') {
      throw new Error('injected transaction and watermark durability failure')
    }
  })
  await f.run('revoke')
  const injectedStages = ['after-begin', 'before-commit', 'before-watermark-commit']
  assert.deepEqual(stages, injectedStages)
  assert.deepEqual(f.calls, [
    { path: '/v1/tickets', method: 'POST', status: 201 },
    { path, method: 'DELETE', status: 503 },
  ])
  assert.match(s.error.value, /De service kan dit verzoek niet verwerken/)
  assert.deepEqual(snapshot(), healthy, 'both mutation and watermark transactions rolled back')
  assert.deepEqual(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.outcome.value, null)
  assert.equal(s.lastSubmissionId.value, '')
  assert.deepEqual(s.commands.value, [])
  await f.run('ticket')
  await f.run('commit')
  assert.equal(f.calls.length, 2, 'uncertainty sends no issuance, commit, retry or status requests')

  // Remove the throwing injection, but record any unexpected re-entry past the storage latch.
  f.setFault(stage => { stages.push(stage) })
  await bounded(s.checkCurrentTicket(), 'latched ticket status')
  assert.deepEqual(f.calls.at(-1), { path, method: 'GET', status: 503 })
  assert.match(s.error.value, /De service kan dit verzoek niet verwerken/)
  assert.equal(s.outcome.value, null)
  assert.deepEqual(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true)
  assert.equal(s.canCommit.value, false)
  await f.run('revoke')
  assert.deepEqual(f.calls.at(-1), { path, method: 'DELETE', status: 503 })
  assert.match(s.error.value, /De service kan dit verzoek niet verwerken/)
  assert.deepEqual(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true)
  assert.equal(s.canCommit.value, false)
  assert.equal(productionApi.ticketUsable(held, s.command.value), true, 'old local preflight is not authority')
  await f.run('ticket')
  await f.run('commit')
  assert.equal(f.calls.length, 4, 'failed explicit checks do not restore authority or schedule requests')

  const externalCalls = []
  const transport = async (path, options) => {
    const response = await bounded(f.externalFetch(path, options), 'real public or stale-authority request')
    const payload = await bounded(response.clone().json(), 'real response inspection')
    externalCalls.push({ path, method: options.method ?? 'GET', status: response.status, payload })
    return response
  }
  await assert.rejects(bounded(productionApi.commitCommand(held, held.command, token, transport),
    'old authority commit'), /De service kan dit verzoek niet verwerken/)
  await assert.rejects(bounded(productionApi.issueTicket(held.command, s.ttlMs.value, token, transport),
    'latched issuance'), /De service kan dit verzoek niet verwerken/)
  const health = await transport('/health', { signal: AbortSignal.timeout(5000) })
  assert.equal(health.status, 503)
  assert.deepEqual(await bounded(health.json(), 'public unavailable health'), { status: 'unavailable' })

  const module = TRUSTED_MODULES.find(candidate => candidate.id === 'bastion')
  const routes = new Map([
    [module.manifestPath, '/.well-known/palaco-app.json'],
    [module.healthPath, '/health'],
  ])
  const neoCalls = []
  const neoFetch = async (path, options) => {
    assert.ok(routes.has(path), 'only actual configured BASTION verification paths are mapped')
    assert.equal(options.credentials, 'omit')
    assert.deepEqual(options.headers, { Accept: 'application/json' })
    assert.ok(options.signal instanceof AbortSignal)
    if (path === module.healthPath) assert.equal(neoCalls[0].response.bodyUsed, true)
    const response = await transport(routes.get(path), options)
    neoCalls.push({ path, response })
    return response
  }
  let evidence
  await assert.rejects(bounded(verifyModule(module, neoFetch, 3000).then(result => { evidence = result }),
    'NEO latched service verification'), /Verificatie mislukt/)
  assert.equal(evidence, undefined)
  assert.equal(launchUrl(module, evidence, now), null)
  assert.deepEqual(neoCalls.map(({ path, response }) => [path, response.status]), [
    [module.manifestPath, 200], [module.healthPath, 503],
  ])
  assert.deepEqual(externalCalls.map(({ path, method, status }) => ({ path, method, status })), [
    { path: '/v1/commands', method: 'POST', status: 503 },
    { path: '/v1/tickets', method: 'POST', status: 503 },
    { path: '/health', method: 'GET', status: 503 },
    { path: '/.well-known/palaco-app.json', method: 'GET', status: 200 },
    { path: '/health', method: 'GET', status: 503 },
  ])
  assert.deepEqual(externalCalls[3].payload, { id: 'bastion', name: 'BASTION', protocol: 'palaco-app/v1' })
  assert.deepEqual(externalCalls[4].payload, { status: 'unavailable' })
  assert.deepEqual(stages, injectedStages, 'the latch rejects operations before invoking the now nonthrowing hook')
  assert.deepEqual(snapshot(), healthy, 'healthy persisted ticket, clock and empty journal/audit remain unchanged')
  assert.deepEqual(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.outcome.value, null)
  assert.equal(s.lastSubmissionId.value, '')
  assert.deepEqual(s.commands.value, [])
  assert.equal(f.calls.length, 4, 'health and NEO checks trigger no session reconciliation')
})

test('live service: a real revocation 503 preserves uncertainty through active status until explicit retry', { timeout: 15000 }, async t => {
  const f = await fixture(t)
  const s = f.session
  await f.run('ticket')
  assert.equal(s.error.value, '')
  const held = { ...s.ticket.value }
  const path = `/v1/tickets/${held.id}`
  const stages = []
  f.setFault(stage => {
    stages.push(stage)
    if (stage === 'before-commit') throw new Error('injected transaction failure')
  })
  await f.run('revoke')
  assert.deepEqual(stages, ['after-begin', 'before-commit', 'before-watermark-commit'])
  assert.deepEqual(f.calls.at(-1), { path, method: 'DELETE', status: 503 })
  assert.match(s.error.value, /De service kan dit verzoek niet verwerken/)
  assert.equal(s.message.value, revokeCaution, 'rollback is still unconfirmed to the client')
  assert.deepEqual(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, '')
  assert.equal(s.outcome.value, null)
  assert.deepEqual(s.commands.value, [])
  assert.deepEqual({ ...f.db.prepare('SELECT consumed, revoked FROM tickets WHERE id = ?').get(held.id) },
    { consumed: 0, revoked: 0 })
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM commands').get().count, 0)
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM audit').get().count, 0)
  assert.equal(f.db.prepare('SELECT last_time FROM clock_state WHERE id = 1').get().last_time, now)
  assert.equal(f.calls.length, 2, '503 triggers neither retry nor automatic reconciliation')
  assert.equal(f.count('DELETE', path), 1)
  assert.equal(f.count('POST', '/v1/commands'), 0)

  await f.run('ticket')
  await f.run('commit')
  assert.equal(f.calls.length, 2, 'uncertainty blocks issuance and commit without requests')
  f.setFault(() => {})
  await bounded(s.checkCurrentTicket(), 'rolled back revocation status')
  assert.deepEqual(f.calls.at(-1), { path, method: 'GET', status: 200 })
  assert.equal(s.error.value, '')
  assert.equal(s.outcome.value.id, held.id)
  assert.equal(s.outcome.value.status, 'active')
  assert.match(s.message.value, /geen nieuwe toestemming/)
  assert.equal(s.outcome.value.checked_at, now)
  assert.equal(s.outcome.value.revoked, false)
  assert.equal(s.outcome.value.record, null)
  assert.deepEqual(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true)
  assert.equal(s.canCommit.value, false)
  await f.run('ticket')
  await f.run('commit')
  assert.equal(f.calls.length, 3, 'active status does not resolve uncertainty or retry revocation')
  assert.deepEqual({ ...f.db.prepare('SELECT consumed, revoked FROM tickets WHERE id = ?').get(held.id) },
    { consumed: 0, revoked: 0 })
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM audit').get().count, 0)

  await f.run('revoke')
  assert.deepEqual(f.calls.at(-1), { path, method: 'DELETE', status: 200 })
  assert.equal(s.error.value, '')
  assert.equal(s.ticket.value, null)
  assert.equal(s.revocationUncertain.value, false)
  assert.equal(s.canCommit.value, false)
  assert.deepEqual({ ...f.db.prepare('SELECT consumed, revoked FROM tickets WHERE id = ?').get(held.id) },
    { consumed: 0, revoked: 1 })
  const audit = f.db.prepare('SELECT ticket_id, action FROM audit').all()
  assert.equal(audit.length, 1)
  assert.equal(audit[0].ticket_id, held.id)
  assert.equal(audit[0].action, 'ticket:revoke')
  assert.equal(f.calls.length, 4, 'only the explicit retry revokes')
  await f.run('ticket')
  assert.equal(s.error.value, '')
  assert.notEqual(s.ticket.value.id, held.id)
  assert.equal(s.canCommit.value, true)
  assert.deepEqual({ ...f.db.prepare('SELECT consumed, revoked FROM tickets WHERE id = ?').get(s.ticket.value.id) },
    { consumed: 0, revoked: 0 })
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM commands').get().count, 0)
  assert.deepEqual(f.db.prepare('SELECT ticket_id, action FROM audit').all(), audit)
  assert.deepEqual(s.commands.value, [])
  assert.equal(f.count('POST', '/v1/tickets'), 2)
  assert.equal(f.count('DELETE', path), 2)
  assert.equal(f.count('GET', path), 1)
  assert.equal(f.count('POST', '/v1/commands'), 0)
  assert.equal(f.calls.length, 5)
})

test('live service: external commit before lost successful revoke preserves the record while matching committed status clears uncertainty', { timeout: 15000 }, async t => {
  const f = await fixture(t)
  const s = f.session
  await f.run('ticket')
  const held = s.ticket.value
  const path = `/v1/tickets/${held.id}`
  assert.equal(s.canCommit.value, true)

  // Await the real commit before revoking: this tests ordering, not simultaneous racing.
  const record = await bounded(f.commitTicketExternal(held), 'external commit of session ticket')
  assert.deepEqual({ ...f.db.prepare('SELECT consumed, revoked FROM tickets WHERE id = ?').get(held.id) },
    { consumed: 1, revoked: 0 })
  await f.run('list')
  assert.deepEqual(s.commands.value, [record])
  f.loseNext('DELETE', path)
  await f.run('revoke')
  assert.equal(f.losses, 1)
  assert.match(s.error.value, /Geen geldig antwoord/)
  assert.equal(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true)
  assert.equal(s.canCommit.value, false)
  assert.deepEqual(s.commands.value, [record])
  assert.deepEqual({ ...f.db.prepare('SELECT consumed, revoked FROM tickets WHERE id = ?').get(held.id) },
    { consumed: 1, revoked: 1 })
  const audit = f.db.prepare('SELECT * FROM audit ORDER BY rowid').all()
  assert.deepEqual(audit.map(({ ticket_id, action }) => ({ ticket_id, action })), [
    { ticket_id: held.id, action: 'journal:append' },
    { ticket_id: held.id, action: 'ticket:revoke' },
  ])
  await f.run('ticket')
  await f.run('commit')
  assert.equal(f.calls.length, 3, 'uncertainty causes neither issuance, commit, retry nor automatic status')
  await bounded(s.checkCurrentTicket(), 'committed and revoked matching status')
  assert.equal(s.error.value, '')
  assert.deepEqual({ ...s.outcome.value }, {
    id: held.id, command: held.command, not_before: held.not_before, expires_at: held.expires_at,
    checked_at: now, status: 'committed', revoked: true, record,
  })
  assert.equal(s.outcomeReceivedAt.value, now)
  assert.equal(s.ticket.value, null)
  assert.equal(s.revocationUncertain.value, false)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, '', 'the external commit is not a local submission')
  assert.deepEqual(s.commands.value, [record], 'status must not erase the existing journal')
  await f.run('list')
  await f.run('commit')
  assert.deepEqual(s.commands.value, [record])
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM tickets').get().count, 1)
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM commands').get().count, 1)
  assert.deepEqual({ ...f.db.prepare('SELECT id, command, committed_at FROM commands WHERE ticket_id = ?').get(held.id) }, record)
  assert.deepEqual(f.db.prepare('SELECT * FROM audit ORDER BY rowid').all(), audit)
  assert.deepEqual(f.externalCommitCalls, [
    { path: '/v1/commands', method: 'POST', ticketId: held.id, status: 201 },
  ])
  assert.deepEqual(f.calls, [
    { path: '/v1/tickets', method: 'POST', status: 201 },
    { path: '/v1/commands', method: 'GET', status: 200 },
    { path, method: 'DELETE', status: 200 },
    { path, method: 'GET', status: 200 },
    { path: '/v1/commands', method: 'GET', status: 200 },
  ])
})

for (const terminal of ['revoked', 'committed']) {
  test(`live service: lost ${terminal} status preserves uncertain revocation until an explicit matching retry`, { timeout: 15000 }, async t => {
    const f = await fixture(t)
    const s = f.session
    await f.run('ticket')
    assert.equal(s.error.value, '')
    const held = s.ticket.value
    const path = `/v1/tickets/${held.id}`
    assert.equal(s.canCommit.value, true)
    const record = terminal === 'committed'
      ? await bounded(f.commitTicketExternal(held), 'external same-ticket commit before revocation')
      : null
    f.loseNext('DELETE', path)
    await f.run('revoke')
    assert.equal(f.losses, 1)
    assert.match(s.error.value, /Geen geldig antwoord/)
    assert.equal(s.message.value, revokeCaution)
    assert.equal(s.ticket.value, held)
    assert.equal(s.revocationUncertain.value, true)
    assert.equal(s.canCommit.value, false)

    // Reads may advance the clock watermark, but must preserve every authority and journal row.
    const snapshot = () => Object.fromEntries(['tickets', 'commands', 'audit'].map(table =>
      [table, f.db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all()]))
    const persisted = snapshot()
    assert.equal(persisted.tickets.length, 1)
    const { id, command, not_before, expires_at, revoked, consumed } = persisted.tickets[0]
    assert.deepEqual({ id, command, not_before, expires_at, revoked, consumed }, {
      ...held, revoked: 1, consumed: record ? 1 : 0,
    })
    assert.deepEqual(persisted.commands.map(({ id, command, committed_at }) =>
      ({ id, command, committed_at })), record ? [record] : [])
    assert.deepEqual(persisted.audit.map(({ ticket_id, action }) => ({ ticket_id, action })), [
      ...(record ? [{ ticket_id: held.id, action: 'journal:append' }] : []),
      { ticket_id: held.id, action: 'ticket:revoke' },
    ])

    f.loseNext('GET', path)
    await bounded(s.checkCurrentTicket(), 'lost terminal status during uncertain revocation')
    assert.equal(f.losses, 2)
    assert.match(s.error.value, /Geen geldig antwoord/)
    assert.equal(s.message.value, statusCaution)
    assert.equal(s.outcome.value, null)
    assert.equal(s.outcomeReceivedAt.value, null)
    assert.equal(s.lookupId.value, held.id)
    assert.equal(s.ticket.value, held)
    assert.equal(s.revocationUncertain.value, true)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.lastSubmissionId.value, '')
    assert.equal(s.busy.value, '')
    assert.deepEqual(s.commands.value, [])
    assert.deepEqual(snapshot(), persisted, 'the lost successful status read changes no persisted rows')
    assert.deepEqual(f.calls, [
      { path: '/v1/tickets', method: 'POST', status: 201 },
      { path, method: 'DELETE', status: 200 },
      { path, method: 'GET', status: 200 },
    ])

    const assertBlocked = async () => {
      f.tick()
      await f.run('ticket')
      await f.run('commit')
      assert.equal(s.message.value, localCommitBlocked)
      assert.equal(s.ticket.value, held)
      assert.equal(s.revocationUncertain.value, true)
      assert.equal(s.canCommit.value, false)
      assert.equal(s.outcome.value, null)
      assert.equal(s.outcomeReceivedAt.value, null)
      assert.equal(f.calls.length, 3, 'uncertainty blocks explicit issuance and commit without any HTTP retry')
      assert.deepEqual(snapshot(), persisted)
    }
    await assertBlocked()
    await f.restart()
    assert.equal(f.calls.length, 3, 'orderly restart sends no automatic requests')
    await assertBlocked()

    await bounded(s.checkCurrentTicket(), 'explicit matching terminal status retry')
    assert.equal(s.error.value, '')
    assert.deepEqual(s.outcome.value, {
      ...held, checked_at: now, status: terminal, revoked: true, record,
    })
    assert.equal(s.outcomeReceivedAt.value, now)
    assert.equal(s.ticket.value, null)
    assert.equal(s.revocationUncertain.value, false)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.lastSubmissionId.value, '', 'the external commit is never a local submission')
    assert.deepEqual(s.commands.value, [], 'status must not import historical journal records')
    assert.equal(s.hasLoaded.value, false)
    assert.deepEqual(snapshot(), persisted, 'the successful status retry preserves the terminal record and audit')
    await f.run('commit')
    assert.equal(s.message.value, localCommitBlocked)
    assert.equal(s.canCommit.value, false)
    assert.deepEqual(f.calls, [
      { path: '/v1/tickets', method: 'POST', status: 201 },
      { path, method: 'DELETE', status: 200 },
      { path, method: 'GET', status: 200 },
      { path, method: 'GET', status: 200 },
    ])
    assert.equal(f.count('POST', '/v1/tickets'), 1)
    assert.equal(f.count('POST', '/v1/commands'), 0)
    assert.equal(f.count('DELETE', path), 1)
    assert.equal(f.count('GET', path), 2)
    assert.equal(f.count('GET', '/v1/commands'), 0)
    assert.deepEqual(f.externalCommitCalls, record
      ? [{ path: '/v1/commands', method: 'POST', ticketId: held.id, status: 201 }]
      : [])
    assert.equal(f.losses, 2)
    assert.deepEqual(snapshot(), persisted)
  })
}

test('live service: lost successful revoke before external commit denies the same ticket without resolving local uncertainty automatically', { timeout: 15000 }, async t => {
  const f = await fixture(t)
  const s = f.session
  await f.run('ticket')
  const held = s.ticket.value
  const path = `/v1/tickets/${held.id}`
  f.loseNext('DELETE', path)
  await f.run('revoke')
  assert.equal(f.losses, 1)
  assert.match(s.error.value, /Geen geldig antwoord/)
  assert.equal(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true)
  assert.equal(s.canCommit.value, false)
  const tickets = f.db.prepare('SELECT * FROM tickets').all()
  assert.equal(tickets.length, 1)
  assert.equal(tickets[0].id, held.id)
  assert.equal(tickets[0].consumed, 0)
  assert.equal(tickets[0].revoked, 1)
  const audit = f.db.prepare('SELECT * FROM audit ORDER BY rowid').all()
  assert.deepEqual(audit.map(({ ticket_id, action }) => ({ ticket_id, action })), [
    { ticket_id: held.id, action: 'ticket:revoke' },
  ])

  await assert.rejects(bounded(f.commitTicketExternal(held), 'external commit after session revocation'), /Geen toestemming/)
  assert.deepEqual(f.externalCommitCalls, [
    { path: '/v1/commands', method: 'POST', ticketId: held.id, status: 403 },
  ])
  assert.equal(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true, 'external denial cannot reconcile session authority')
  assert.equal(s.outcome.value, null)
  assert.deepEqual(s.commands.value, [])
  await f.run('ticket')
  await f.run('commit')
  assert.equal(f.calls.length, 2, 'no automatic retry, reconciliation or replacement ticket')
  await bounded(s.checkCurrentTicket(), 'explicit revoked status after denied external commit')
  assert.equal(s.error.value, '')
  assert.deepEqual({ ...s.outcome.value }, {
    id: held.id, command: held.command, not_before: held.not_before, expires_at: held.expires_at,
    checked_at: now, status: 'revoked', revoked: true, record: null,
  })
  assert.equal(s.outcomeReceivedAt.value, now)
  assert.equal(s.ticket.value, null)
  assert.equal(s.revocationUncertain.value, false)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, '')
  await f.run('list')
  await f.run('commit')
  assert.deepEqual(s.commands.value, [])
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.deepEqual(f.db.prepare('SELECT * FROM tickets').all(), tickets)
  assert.deepEqual(f.db.prepare('SELECT * FROM commands').all(), [])
  assert.deepEqual(f.db.prepare('SELECT * FROM audit ORDER BY rowid').all(), audit)
  assert.equal(f.externalCommitCalls.length, 1, 'the denied external commit is never retried')
  assert.deepEqual(f.calls, [
    { path: '/v1/tickets', method: 'POST', status: 201 },
    { path, method: 'DELETE', status: 200 },
    { path, method: 'GET', status: 200 },
    { path: '/v1/commands', method: 'GET', status: 200 },
  ])
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
  assert.equal(s.message.value, commitCaution)
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
  assert.equal(s.message.value, localCommitBlocked)
  assert.equal(s.error.value, '')
  assert.equal(f.count('POST', '/v1/commands'), 1)
  assert.deepEqual({ ...f.db.prepare('SELECT id, command, committed_at FROM commands WHERE ticket_id = ?').get(id) }, persisted)
  assert.equal(s.lastSubmissionId.value, id)
  await bounded(s.checkLastSubmission(), 'lost commit reconciliation')
  assert.equal(s.error.value, '')
  assert.match(s.message.value, /Ticketstatus opgehaald/)
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

for (const action of ['commit', 'revoke']) {
  test(`live service: operator manually recovers a lost ${action} outcome after clearSession`, { timeout: 15000 }, async t => {
    const f = await fixture(t)
    const s = f.session
    const committing = action === 'commit'
    const snapshot = () => Object.fromEntries(['tickets', 'commands', 'audit', 'clock_state'].map(table =>
      [table, f.db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all()]))
    await f.run('ticket')
    assert.equal(s.error.value, '')
    const held = { ...s.ticket.value }
    const operatorCopiedId = s.ticket.value.id // Operator copies the received ID before clearing local state.
    const path = `/v1/tickets/${operatorCopiedId}`
    assert.equal(s.canCommit.value, true)
    const operation = { path: committing ? '/v1/commands' : path, method: committing ? 'POST' : 'DELETE', status: committing ? 201 : 200 }
    f.loseNext(operation.method, operation.path)
    await f.run(action)
    assert.equal(f.losses, 1)
    assert.match(s.error.value, /Geen geldig antwoord/)
    assert.equal(s.message.value, committing ? commitCaution : revokeCaution)
    assert.deepEqual(s.ticket.value, committing ? null : held)
    assert.equal(s.lastSubmissionId.value, committing ? operatorCopiedId : '')
    assert.equal(s.revocationUncertain.value, !committing)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.outcome.value, null)
    assert.equal(s.outcomeReceivedAt.value, null)
    assert.deepEqual(s.commands.value, [])
    const persisted = snapshot()
    assert.equal(persisted.tickets.length, 1)
    assert.equal(persisted.tickets[0].id, operatorCopiedId)
    assert.equal(persisted.tickets[0].command, held.command)
    assert.equal(persisted.tickets[0].consumed, Number(committing))
    assert.equal(persisted.tickets[0].revoked, Number(!committing))
    assert.equal(persisted.commands.length, Number(committing))
    const record = committing ? {
      id: persisted.commands[0].id, command: held.command, committed_at: now,
    } : null
    if (committing) {
      assert.equal(persisted.commands[0].ticket_id, operatorCopiedId)
      assert.equal(persisted.commands[0].command, record.command)
      assert.equal(persisted.commands[0].committed_at, record.committed_at)
    }
    assert.equal(persisted.audit.length, 1)
    assert.equal(persisted.audit[0].ticket_id, operatorCopiedId)
    assert.equal(persisted.audit[0].action, committing ? 'journal:append' : 'ticket:revoke')
    const mutationCalls = [{ path: '/v1/tickets', method: 'POST', status: 201 }, operation]
    assert.deepEqual(f.calls, mutationCalls)
    const assertCleared = () => {
      assert.equal(s.command.value, '')
      assert.equal(s.ticket.value, null)
      assert.equal(s.lookupId.value, '')
      assert.equal(s.lastSubmissionId.value, '')
      assert.equal(s.outcome.value, null)
      assert.equal(s.outcomeReceivedAt.value, null)
      assert.equal(s.revocationUncertain.value, false)
      assert.equal(s.canCommit.value, false)
      assert.equal(s.canCheckStatus.value, false)
      assert.deepEqual(s.commands.value, [])
      assert.equal(s.hasLoaded.value, false)
      assert.equal(s.lastJournalRefreshAt.value, null)
    }
    s.clearSession()
    assert.equal(s.token.value, '')
    assert.equal(s.validToken.value, false)
    assertCleared()
    assert.deepEqual(f.calls, mutationCalls, 'local clearing does not revoke or fetch')
    assert.deepEqual(snapshot(), persisted)
    s.token.value = token
    assert.equal(s.validToken.value, true)
    assertCleared()
    assert.deepEqual(f.calls, mutationCalls, 'restoring credentials does not restore IDs or fetch')
    assert.deepEqual(snapshot(), persisted)
    await s.checkLastSubmission()
    assertCleared()
    assert.deepEqual(f.calls, mutationCalls, 'the cleared last-submission shortcut is a no-op')
    s.lookupId.value = operatorCopiedId
    assert.equal(s.canCheckStatus.value, true)
    assert.equal(s.outcome.value, null)
    assert.equal(s.outcomeReceivedAt.value, null)
    assert.deepEqual(f.calls, mutationCalls, 'manually entering the copied ID does not fetch')
    assert.deepEqual(snapshot(), persisted)
    await f.run('status')
    assert.equal(s.error.value, '')
    assert.deepEqual(s.outcome.value, {
      id: operatorCopiedId, command: held.command, not_before: held.not_before,
      expires_at: held.expires_at, checked_at: now,
      status: committing ? 'committed' : 'revoked', revoked: !committing, record,
    })
    assert.equal(s.outcomeReceivedAt.value, now)
    assert.equal(s.ticket.value, null)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.revocationUncertain.value, false)
    assert.equal(s.lastSubmissionId.value, '')
    assert.deepEqual(s.commands.value, [])
    assert.equal(s.hasLoaded.value, false)
    f.tick()
    await Promise.resolve()
    assert.deepEqual(f.calls, [...mutationCalls, { path, method: 'GET', status: 200 }],
      'one issue, one lost operation and one manual lookup; no retries, new issues or extra revokes')
    assert.deepEqual(snapshot(), persisted, 'manual recovery and clock ticks leave all persisted rows unchanged')
    assert.equal(f.losses, 1)
  })
}

test('live service: explicit lookup finds a lost successful commit after service close and recreation on the same database', { timeout: 15000 }, async t => {
  const f = await fixture(t)
  const s = f.session
  await f.run('ticket')
  assert.equal(s.error.value, '')
  const held = { ...s.ticket.value }
  f.loseNext('POST', '/v1/commands')
  await f.run('commit')
  assert.equal(f.losses, 1)
  assert.match(s.error.value, /Geen geldig antwoord/)
  assert.equal(s.message.value, commitCaution)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, held.id)
  assert.equal(s.lookupId.value, held.id)
  assert.equal(s.outcome.value, null)
  assert.deepEqual(s.commands.value, [])
  assert.equal(f.calls.length, 2, 'lost success triggers neither retry nor status lookup')
  const persisted = { ...f.db.prepare('SELECT id, command, committed_at FROM commands WHERE ticket_id = ?').get(held.id) }
  assert.deepEqual(persisted, { id: persisted.id, command: held.command, committed_at: now })
  const tickets = f.db.prepare('SELECT * FROM tickets').all()
  assert.equal(tickets.length, 1)
  assert.equal(tickets[0].id, held.id)
  assert.equal(tickets[0].consumed, 1)
  assert.equal(tickets[0].revoked, 0)
  const audit = f.db.prepare('SELECT * FROM audit').all()
  assert.equal(audit.length, 1)
  assert.equal(audit[0].ticket_id, held.id)
  assert.equal(audit[0].action, 'journal:append')
  const assertPersisted = () => {
    assert.deepEqual(f.db.prepare('SELECT * FROM tickets').all(), tickets)
    assert.deepEqual(f.db.prepare('SELECT id, command, committed_at FROM commands').all().map(row => ({ ...row })), [persisted])
    assert.deepEqual(f.db.prepare('SELECT * FROM audit').all(), audit)
  }
  assertPersisted()

  const previousOrigin = f.origin
  await f.restart()
  assert.notEqual(f.origin, previousOrigin)
  assert.equal(f.session, s)
  assert.equal(f.scope.active, true)
  assert.equal(f.intervals.size, 1)
  assert.equal(getEventListeners(f.eventTarget, 'pagehide').length, 1)
  assert.equal(s.token.value, token)
  assert.equal(s.command.value, held.command)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, held.id)
  assert.equal(s.lookupId.value, held.id)
  assert.equal(s.outcome.value, null)
  assert.deepEqual(s.commands.value, [])
  assert.equal(s.realtimeStatus.value, 'disconnected')
  assert.equal(f.sockets.length, 0)
  assert.equal(f.witness, undefined)
  assert.equal(f.calls.length, 2, 'service recreation does not automatically request anything')
  assert.equal(s.message.value, commitCaution)
  assertPersisted()

  await bounded(s.checkLastSubmission(), 'lost commit status after service recreation')
  assert.equal(s.error.value, '')
  assert.match(s.message.value, /Ticketstatus opgehaald/)
  assert.equal(s.outcome.value.id, held.id)
  assert.equal(s.outcome.value.status, 'committed')
  assert.equal(s.outcome.value.checked_at, now)
  assert.equal(s.outcome.value.revoked, false)
  assert.deepEqual(s.outcome.value.record, persisted)
  assert.equal(s.outcomeReceivedAt.value, now)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, held.id)
  assert.deepEqual(s.commands.value, [])
  assert.equal(f.calls.length, 3, 'explicit status does not fetch the journal')
  await f.run('list')
  assert.equal(s.error.value, '')
  assert.equal(s.hasLoaded.value, true)
  assert.deepEqual(s.commands.value, [persisted])
  await f.run('commit')
  assert.equal(f.calls.length, 4, 'a second commit cannot send another POST after reconciliation')
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, held.id)
  assert.equal(f.count('POST', '/v1/tickets'), 1)
  assert.equal(f.count('POST', '/v1/commands'), 1)
  assert.equal(f.count('GET', `/v1/tickets/${held.id}`), 1)
  assert.equal(f.count('GET', '/v1/commands'), 1)
  assert.equal(f.losses, 1)
  assertPersisted()
})

test('live service: lost successful revocation survives service recreation until explicit status clears uncertainty', { timeout: 15000 }, async t => {
  const f = await fixture(t)
  const s = f.session
  const snapshot = () => Object.fromEntries(['tickets', 'audit', 'commands', 'clock_state'].map(table =>
    [table, f.db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all()]))
  await f.run('ticket')
  assert.equal(s.error.value, '')
  const held = { ...s.ticket.value }
  const path = `/v1/tickets/${held.id}`
  assert.equal(s.canCommit.value, true)
  f.loseNext('DELETE', path)
  await f.run('revoke')
  assert.equal(f.losses, 1)
  assert.match(s.error.value, /Geen geldig antwoord/)
  assert.deepEqual(f.calls, [
    { path: '/v1/tickets', method: 'POST', status: 201 },
    { path, method: 'DELETE', status: 200 },
  ])
  assert.deepEqual(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, '')
  assert.equal(s.outcome.value, null)
  const persisted = snapshot()
  assert.equal(persisted.tickets.length, 1)
  assert.equal(persisted.tickets[0].id, held.id)
  assert.equal(persisted.tickets[0].revoked, 1)
  assert.equal(persisted.tickets[0].consumed, 0)
  assert.deepEqual(persisted.commands, [])
  assert.equal(persisted.audit.length, 1)
  assert.equal(persisted.audit[0].ticket_id, held.id)
  assert.equal(persisted.audit[0].action, 'ticket:revoke')
  assert.equal(persisted.clock_state.length, 1)
  assert.equal(persisted.clock_state[0].last_time, now)

  await f.run('ticket')
  await f.run('commit')
  assert.equal(f.calls.length, 2, 'uncertainty blocks issuance and commit without retry or lookup')
  assert.deepEqual(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true)
  assert.deepEqual(snapshot(), persisted)

  const previousOrigin = f.origin
  await bounded(f.restart(), 'restart after lost successful revocation')
  assert.notEqual(f.origin, previousOrigin)
  assert.equal(f.session, s)
  assert.equal(f.scope.active, true)
  assert.equal(f.intervals.size, 1)
  assert.equal(getEventListeners(f.eventTarget, 'pagehide').length, 1)
  assert.equal(s.token.value, token)
  assert.equal(s.command.value, held.command)
  assert.deepEqual(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, '')
  assert.equal(s.outcome.value, null)
  assert.deepEqual(s.commands.value, [])
  assert.equal(s.realtimeStatus.value, 'disconnected')
  assert.equal(f.sockets.length, 0)
  assert.equal(f.witness, undefined)
  assert.equal(f.calls.length, 2, 'service recreation sends no automatic requests')
  assert.deepEqual(snapshot(), persisted, 'the same SQLite database retains the full revocation snapshot')

  await f.run('ticket')
  await f.run('commit')
  assert.equal(f.calls.length, 2, 'held uncertainty still blocks issuance and commit after restart')
  assert.deepEqual(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true)
  assert.equal(s.canCommit.value, false)
  assert.deepEqual(snapshot(), persisted)

  const externalCalls = []
  await assert.rejects(bounded(productionApi.commitCommand(held, held.command, token, async (path, options) => {
    const response = await f.externalFetch(path, options)
    externalCalls.push({ path, method: options.method, status: response.status })
    return response
  }), 'external revoked ticket commit after restart'), /Geen toestemming/)
  assert.deepEqual(externalCalls, [{ path: '/v1/commands', method: 'POST', status: 403 }])
  assert.equal(f.calls.length, 2, 'the direct enforcement probe is not a session request')
  assert.deepEqual(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true)
  assert.deepEqual(snapshot(), persisted, 'denied old authority changes no ticket, audit, command or fixed clock')

  await bounded(s.checkCurrentTicket(), 'revoked ticket status after service recreation')
  assert.deepEqual(f.calls.at(-1), { path, method: 'GET', status: 200 })
  assert.equal(s.error.value, '')
  assert.equal(s.outcome.value.id, held.id)
  assert.equal(s.outcome.value.status, 'revoked')
  assert.equal(s.outcome.value.checked_at, now)
  assert.equal(s.outcome.value.revoked, true)
  assert.equal(s.outcome.value.record, null)
  assert.equal(s.outcomeReceivedAt.value, now)
  assert.equal(s.ticket.value, null)
  assert.equal(s.revocationUncertain.value, false)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, '')
  assert.deepEqual(s.commands.value, [])
  assert.deepEqual(snapshot(), persisted, 'explicit status neither repeats revocation nor changes the durable snapshot')
  await f.run('commit')
  assert.equal(f.calls.length, 3, 'terminal status does not restore the old authority or automatically commit')

  await f.run('ticket')
  assert.equal(s.error.value, '')
  const fresh = { ...s.ticket.value }
  assert.notEqual(fresh.id, held.id)
  assert.equal(s.revocationUncertain.value, false)
  assert.equal(s.canCommit.value, true)
  assert.equal(s.lastSubmissionId.value, '')
  assert.deepEqual(s.commands.value, [])
  const afterIssuance = snapshot()
  assert.equal(afterIssuance.tickets.length, 2)
  assert.deepEqual(afterIssuance.tickets.find(row => row.id === held.id), persisted.tickets[0])
  assert.equal(afterIssuance.tickets.find(row => row.id === fresh.id).revoked, 0)
  assert.equal(afterIssuance.tickets.find(row => row.id === fresh.id).consumed, 0)
  assert.deepEqual(afterIssuance.audit, persisted.audit)
  assert.deepEqual(afterIssuance.commands, persisted.commands)
  assert.deepEqual(afterIssuance.clock_state, persisted.clock_state)
  assert.deepEqual(f.calls, [
    { path: '/v1/tickets', method: 'POST', status: 201 },
    { path, method: 'DELETE', status: 200 },
    { path, method: 'GET', status: 200 },
    { path: '/v1/tickets', method: 'POST', status: 201 },
  ])
  assert.equal(f.count('POST', '/v1/tickets'), 2)
  assert.equal(f.count('DELETE', path), 1)
  assert.equal(f.count('GET', path), 1)
  assert.equal(f.count('POST', '/v1/commands'), 0)
  assert.equal(f.count('GET', '/v1/commands'), 0)
  assert.equal(f.calls.length, 4, 'only fresh manual issuance grants authority, without automatic commit')
  assert.equal(externalCalls.length, 1)
  assert.equal(f.losses, 1)
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
  assert.equal(s.message.value, revokeCaution, 'lost success has the same caution as a rollback')
  assert.deepEqual(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, '')
  assert.equal(s.outcome.value, null)
  assert.equal(f.db.prepare('SELECT revoked FROM tickets WHERE id = ?').get(held.id).revoked, 1)
  assert.equal(f.calls.length, 2, 'no automatic retry or reconciliation')
  assert.equal(f.count('DELETE', `/v1/tickets/${held.id}`), 1)
  assert.equal(f.count('POST', '/v1/commands'), 0)

  await f.run('ticket')
  await f.run('commit')
  assert.equal(f.calls.length, 2, 'uncertainty blocks issuance and commit without network requests')
  assert.deepEqual(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true)
  await bounded(s.checkCurrentTicket(), 'revocation reconciliation')
  assert.equal(s.error.value, '')
  assert.equal(s.outcome.value.id, held.id)
  assert.equal(s.outcome.value.status, 'revoked')
  assert.match(s.message.value, /geen nieuwe toestemming/)
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

test('live realtime: newest 100 records stay bounded without deleting older submissions or restoring authority', { timeout: 30000 }, async t => {
  const f = await fixture(t, { realtime: true })
  const s = f.session
  await f.connect()
  s.command.value = 'uniquely oldest session submission é😀'
  await f.run('ticket')
  const issued = { ...s.ticket.value }
  const originalEvent = nextCommit(f.witness, issued.command)
  await f.run('commit')
  assert.equal(s.error.value, '')
  const original = await originalEvent
  assert.deepEqual(s.commands.value, [original])
  assert.equal(s.lastSubmissionId.value, issued.id)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)

  const snapshot = () => Object.fromEntries(['tickets', 'commands', 'audit'].map(table =>
    [table, f.db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all().map(row => ({ ...row }))]))
  const firstStored = snapshot()
  assert.equal(firstStored.tickets[0].consumed, 1)
  const recentFromDb = () => f.db.prepare(
    'SELECT id, command, committed_at FROM commands ORDER BY seq DESC LIMIT 100',
  ).all().map(row => ({ ...row }))
  const assertStored = count => {
    const stored = snapshot()
    assert.equal(stored.commands.length, count)
    assert.equal(stored.audit.length, count)
    assert.equal(stored.tickets.length, count)
    assert.ok(stored.tickets.every(row => row.consumed === 1 && row.revoked === 0))
    assert.ok(stored.audit.every(row => row.action === 'journal:append'))
    assert.equal(f.db.prepare(`
      SELECT COUNT(*) AS count FROM commands c
      JOIN tickets t ON t.id = c.ticket_id
      JOIN audit a ON a.ticket_id = t.id
      WHERE t.consumed = 1 AND a.action = 'journal:append'
    `).get().count, count)
    for (const table of ['tickets', 'commands', 'audit']) {
      assert.deepEqual(stored[table][0], firstStored[table][0],
        `local eviction must retain the original ${table} row`)
    }
    return stored
  }

  const external = []
  for (let index = 1; index <= 100; index++) {
    const command = `bounded external record ${index}`
    const witnessed = index === 100 ? nextCommit(f.witness, command) : null
    const record = await bounded(f.commitExternal(command), `external commit ${index}`)
    external.push(record)
    if (witnessed) assert.deepEqual(await witnessed, record)
  }
  await waitFor(s.commands, records =>
    records.length === 100 && records[0].id === external.at(-1).id &&
    records.at(-1).id === external[0].id, 'newest 100 realtime records')
  const recent = recentFromDb()
  assert.deepEqual(recent, [...external].reverse(), 'sequence, not equal timestamps, orders the records')
  assert.deepEqual(s.commands.value, recent)
  assert.equal(s.commands.value.some(row => row.id === original.id), false)
  const stored101 = assertStored(101)
  assert.equal(f.count('GET', '/v1/commands'), 0, 'connected events alone maintain the bounded history')

  await f.run('list')
  assert.equal(s.error.value, '')
  assert.equal(s.hasLoaded.value, true)
  assert.equal(f.count('GET', '/v1/commands'), 1)
  assert.deepEqual(s.commands.value, recent, 'an explicit real HTTP list returns the same newest 100')
  const callsBeforeSearch = f.calls.length
  s.search.value = issued.command
  assert.deepEqual(s.filteredCommands.value, [], 'local search cannot find an evicted server record')
  assert.equal(f.calls.length, callsBeforeSearch, 'search does not fetch older history')

  await bounded(s.checkLastSubmission(), 'evicted original submission status')
  assert.equal(s.error.value, '')
  assert.deepEqual(s.outcome.value, {
    ...issued, checked_at: now, status: 'committed', revoked: false, record: original,
  })
  assert.equal(s.lookupId.value, issued.id)
  assert.equal(s.lastSubmissionId.value, issued.id)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.revocationUncertain.value, false)
  assert.deepEqual(s.commands.value, recent, 'status does not insert an older record into recent history')
  assert.deepEqual(s.filteredCommands.value, [])
  assert.deepEqual(snapshot(), stored101, 'listing, search and status do not mutate persisted history')
  const beforeClearSearch = {
    commands: s.commands.value, outcome: s.outcome.value,
    outcomeSnapshot: JSON.parse(JSON.stringify(s.outcome.value)), outcomeReceipt: s.outcomeReceivedAt.value,
    journalReceipt: s.lastJournalRefreshAt.value, lastSubmission: s.lastSubmissionId.value,
    lookup: s.lookupId.value, sockets: [...f.sockets], realtime: s.realtimeStatus.value,
    requests: f.calls.length, lists: f.count('GET', '/v1/commands'),
  }
  s.search.value = ''
  assert.equal(s.commands.value, beforeClearSearch.commands)
  assert.deepEqual(s.filteredCommands.value, recent, 'clearing search reveals the same ordered 100 records')
  assert.equal(s.filteredCommands.value.length, 100)
  assert.equal(s.filteredCommands.value.some(row => row.id === original.id), false)
  assert.equal(s.outcome.value, beforeClearSearch.outcome)
  assert.deepEqual(s.outcome.value, beforeClearSearch.outcomeSnapshot)
  assert.equal(s.outcomeReceivedAt.value, beforeClearSearch.outcomeReceipt)
  assert.equal(s.lastJournalRefreshAt.value, beforeClearSearch.journalReceipt)
  assert.equal(s.lastSubmissionId.value, beforeClearSearch.lastSubmission)
  assert.equal(s.lookupId.value, beforeClearSearch.lookup)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.revocationUncertain.value, false)
  assert.equal(f.calls.length, beforeClearSearch.requests)
  assert.equal(f.count('GET', '/v1/commands'), beforeClearSearch.lists)
  assert.deepEqual(snapshot(), stored101, 'clearing search does not mutate persisted history')
  assert.deepEqual(f.sockets, beforeClearSearch.sockets)
  assert.equal(s.realtimeStatus.value, beforeClearSearch.realtime)
  assert.equal(s.realtimeStatus.value, 'connected')
  assert.ok(f.sockets.every(socket => socket.connected))
  s.clearOutcome()
  assert.equal(s.outcome.value, null)
  assert.equal(s.outcomeReceivedAt.value, null)
  assert.deepEqual(s.commands.value, recent, 'clearing outcome preserves all 100 recent records')
  assert.equal(s.lastSubmissionId.value, issued.id)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)

  assert.equal(s.realtimeStatus.value, 'connected')
  const finalCommand = 'bounded final live record 102'
  const finalEvent = nextCommit(f.witness, finalCommand)
  const final = await bounded(f.commitExternal(finalCommand), 'external commit 102')
  assert.deepEqual(await finalEvent, final)
  await waitFor(s.commands, records =>
    records.length === 100 && records[0].id === final.id &&
    records.at(-1).id === recent.at(-2).id, 'bounded realtime insertion after explicit list')
  assert.deepEqual(s.commands.value, [final, ...recent.slice(0, -1)])
  assert.deepEqual(s.commands.value, recentFromDb())
  assert.equal(s.commands.value.some(row => row.id === recent.at(-1).id), false,
    'exactly the oldest visible record is evicted by the next live insert')
  assertStored(102)
  assert.equal(s.lastJournalRefreshAt.value, beforeClearSearch.journalReceipt)
  assert.equal(s.lastSubmissionId.value, issued.id)
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(f.count('POST', '/v1/tickets'), 1)
  assert.equal(f.count('POST', '/v1/commands'), 1)
  assert.equal(f.count('GET', `/v1/tickets/${issued.id}`), 1)
  assert.equal(f.count('GET', '/v1/commands'), 1, 'the final live insert needs no additional list')
  assert.equal(f.calls.length, 4, 'only explicit session actions issue HTTP requests')
})

test('live realtime: a reentrant socket factory retires its stale real socket and preserves only the replacement', { timeout: 20000 }, async t => {
  const sockets = []
  let adapter
  // Register before the fixture so these separately owned clients close before the service.
  t.after(() => {
    try {
      adapter?.disconnect()
    } finally {
      for (const socket of sockets) {
        socket.removeAllListeners()
        socket.disconnect()
      }
    }
  })
  const f = await fixture(t, { realtime: true })
  const statuses = ref([])
  const entries = ref([])
  const connections = []
  adapter = createRealtime({
    onStatus: status => statuses.value.push(status),
    onReset() {},
    onEntry: entry => entries.value.push(entry),
    createSocket(options) {
      const socket = io(f.origin, options)
      sockets.push(socket)
      socket.on('connect', () => connections.push(socket))
      if (sockets.length === 1) adapter.connect(token)
      return socket
    },
  })

  adapter.connect(token)
  assert.equal(sockets.length, 2)
  const [stale, replacement] = sockets
  assertDisconnected(stale)
  await waitFor(() => statuses.value.at(-1), value => value === 'connected', 'replacement connection')
  assert.deepEqual(connections, [replacement], 'the stale socket never opens')
  assert.deepEqual(statuses.value, ['disconnected', 'connecting', 'disconnected', 'connecting', 'connected'])
  assert.equal(replacement.connected, true)
  assert.equal(replacement.active, true)
  assert.deepEqual(f.calls, [])
  for (const table of ['tickets', 'commands', 'audit']) {
    assert.equal(f.db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get().count, 0,
      'connecting and replacing clients never issues tickets or commands')
  }

  const received = waitFor(() => entries.value.length, count => count === 1, 'replacement normalized entry')
  const witnessed = nextCommit(f.witness, 'replacement é😀 record')
  const record = await f.commitExternal('replacement é😀 record')
  assert.deepEqual(await witnessed, record)
  await received
  assert.deepEqual(entries.value, [record], 'only the replacement delivers the real normalized record once')
  assertDisconnected(stale)
  assert.deepEqual(connections, [replacement])

  adapter.disconnect()
  assertDisconnected(replacement)
  const statusesAfterDisconnect = [...statuses.value]
  assert.equal(statusesAfterDisconnect.at(-1), 'disconnected')
  const missedEvent = nextCommit(f.witness, 'replacement disconnected barrier')
  const missed = await f.commitExternal('replacement disconnected barrier')
  assert.deepEqual(await missedEvent, missed)
  assert.deepEqual(entries.value, [record], 'a witnessed later commit cannot reach the disconnected adapter')
  assert.deepEqual(statuses.value, statusesAfterDisconnect)
  assert.equal(sockets.length, 2, 'disconnect never creates an automatic replacement')
  assert.deepEqual(connections, [replacement])
  assertDisconnected(stale)
  assertDisconnected(replacement)
  assert.deepEqual(f.db.prepare('SELECT id, command, committed_at FROM commands ORDER BY seq').all().map(row => ({ ...row })), [record, missed])
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM tickets WHERE consumed = 1').get().count, 2)
  for (const table of ['tickets', 'commands', 'audit']) {
    assert.equal(f.db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get().count, 2)
  }
  assert.deepEqual(f.calls, [], 'only the explicit external commits issue HTTP requests')
  assert.deepEqual(f.sockets, [], 'the fixture session never connects')
})

test('live realtime: disconnecting in the connecting callback creates no socket until a deliberate manual connection', { timeout: 20000 }, async t => {
  const sockets = []
  let adapter
  t.after(() => {
    try {
      adapter?.disconnect()
    } finally {
      for (const socket of sockets) {
        socket.removeAllListeners()
        socket.disconnect()
      }
    }
  })
  const f = await fixture(t, { realtime: true })
  const statuses = ref([])
  const entries = ref([])
  const connections = []
  let cancelConnecting = true
  adapter = createRealtime({
    onStatus(status) {
      statuses.value.push(status)
      if (status === 'connecting' && cancelConnecting) adapter.disconnect()
    },
    onReset() {},
    onEntry: entry => entries.value.push(entry),
    createSocket(options) {
      const socket = io(f.origin, options)
      sockets.push(socket)
      socket.on('connect', () => connections.push(socket))
      return socket
    },
  })

  adapter.connect(token)
  assert.deepEqual(statuses.value, ['disconnected', 'connecting', 'disconnected'])
  assert.equal(sockets.length, 0, 'the connecting callback cancels before the real socket factory')
  for (const table of ['tickets', 'commands', 'audit']) {
    assert.equal(f.db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get().count, 0)
  }
  const missedEvent = nextCommit(f.witness, 'cancelled connection barrier')
  const missed = await f.commitExternal('cancelled connection barrier')
  assert.deepEqual(await missedEvent, missed)
  assert.equal(sockets.length, 0, 'a real emission barrier does not trigger an automatic attempt')
  assert.deepEqual(entries.value, [])
  assert.deepEqual(connections, [])
  assert.deepEqual(statuses.value, ['disconnected', 'connecting', 'disconnected'])
  assert.deepEqual(f.calls, [])

  cancelConnecting = false
  adapter.connect(token)
  await waitFor(() => statuses.value.at(-1), value => value === 'connected', 'deliberate manual connection')
  assert.equal(sockets.length, 1)
  const [socket] = sockets
  assert.deepEqual(connections, [socket])
  assert.equal(socket.connected, true)
  assert.equal(socket.active, true)
  assert.deepEqual(entries.value, [], 'manual connection does not replay the missed record')
  const received = waitFor(() => entries.value.length, count => count === 1, 'manual connection normalized entry')
  const witnessed = nextCommit(f.witness, 'manual connection é😀 record')
  const record = await f.commitExternal('manual connection é😀 record')
  assert.deepEqual(await witnessed, record)
  await received
  assert.deepEqual(entries.value, [record])

  adapter.disconnect()
  assertDisconnected(socket)
  assert.deepEqual(statuses.value, ['disconnected', 'connecting', 'disconnected', 'disconnected', 'connecting', 'connected', 'disconnected'])
  assert.equal(sockets.length, 1)
  assert.deepEqual(connections, [socket])
  assert.deepEqual(f.db.prepare('SELECT id, command, committed_at FROM commands ORDER BY seq').all().map(row => ({ ...row })), [missed, record])
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM tickets WHERE consumed = 1').get().count, 2)
  for (const table of ['tickets', 'commands', 'audit']) {
    assert.equal(f.db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get().count, 2)
  }
  assert.deepEqual(f.calls, [], 'connect and disconnect themselves send no journal or authority requests')
  assert.deepEqual(f.sockets, [])
})

test('live realtime: clearing the journal disconnects without losing authority or status; reconnect never replays missed commits', { timeout: 20000 }, async t => {
  const f = await fixture(t, { realtime: true })
  const s = f.session
  const socket = await f.connect()
  const firstEvent = nextCommit(socket, 'external before clear')
  const first = await f.commitExternal('external before clear')
  assert.deepEqual(await firstEvent, first)
  assert.deepEqual(s.commands.value, [first])
  assert.equal(f.calls.length, 0, 'the session receives a real event without issuing HTTP requests')

  await f.run('ticket')
  const submittedId = s.ticket.value.id
  const ownEvent = nextCommit(socket, s.command.value)
  await f.run('commit')
  const own = await ownEvent
  assert.deepEqual(s.commands.value, [own, first], 'HTTP confirmation and its real event are deduplicated')
  await bounded(s.checkLastSubmission(), 'submission status before clear')
  assert.equal(s.outcome.value.status, 'committed')
  await f.run('list')
  assert.equal(s.lastJournalRefreshAt.value, now)
  s.search.value = 'external'
  assert.deepEqual(s.filteredCommands.value, [first])
  await f.run('ticket')
  const held = { ...s.ticket.value }
  f.loseNext('DELETE', `/v1/tickets/${held.id}`)
  await f.run('revoke')
  assert.equal(f.losses, 1)
  assert.equal(s.revocationUncertain.value, true)
  const outcome = { ...s.outcome.value }
  const feedback = { message: s.message.value, error: s.error.value }
  const requests = f.calls.length

  s.clearJournal()
  assertDisconnected(socket)
  assert.equal(s.realtimeStatus.value, 'disconnected')
  assert.deepEqual(s.commands.value, [])
  assert.deepEqual(s.filteredCommands.value, [])
  assert.equal(s.search.value, '')
  assert.equal(s.hasLoaded.value, false)
  assert.equal(s.journalRefreshFailed.value, false)
  assert.equal(s.lastJournalRefreshAt.value, null)
  assert.equal(s.token.value, token)
  assert.deepEqual(s.ticket.value, held)
  assert.equal(s.command.value, held.command)
  assert.equal(s.revocationUncertain.value, true)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lookupId.value, submittedId)
  assert.equal(s.lastSubmissionId.value, submittedId)
  assert.deepEqual(s.outcome.value, outcome)
  assert.equal(s.outcomeReceivedAt.value, now)
  assert.deepEqual({ message: s.message.value, error: s.error.value }, feedback)

  const missedEvent = nextCommit(f.witness, 'disconnected HTTP sentinel')
  const missed = await f.commitExternal('disconnected HTTP sentinel')
  assert.deepEqual(await missedEvent, missed)
  assert.deepEqual(s.commands.value, [], 'a successfully emitted disconnected commit cannot refill the journal')
  assert.equal(f.calls.length, requests)
  const reconnected = await f.connect()
  assert.notEqual(reconnected, socket)
  assert.deepEqual(s.commands.value, [])
  const freshEvent = nextCommit(reconnected, 'external after reconnect')
  const fresh = await f.commitExternal('external after reconnect')
  assert.deepEqual(await freshEvent, fresh)
  assert.deepEqual(s.commands.value, [fresh], 'new events arrive, but neither old nor disconnected records replay')
  assert.equal(s.hasLoaded.value, false)
  assert.equal(s.lastJournalRefreshAt.value, null)
  assert.equal(f.calls.length, requests, 'reconnection does not automatically refresh or mutate')

  await f.run('list')
  const persisted = f.db.prepare('SELECT id, command, committed_at FROM commands ORDER BY seq DESC').all().map(row => ({ ...row }))
  assert.deepEqual(persisted, [fresh, missed, own, first])
  assert.deepEqual(s.commands.value, persisted)
  assert.equal(new Set(s.commands.value.map(row => row.id)).size, 4)
  assert.equal(s.hasLoaded.value, true)
  assert.equal(s.lastJournalRefreshAt.value, now)
  assert.deepEqual(s.ticket.value, held)
  assert.equal(s.revocationUncertain.value, true)
  assert.deepEqual(s.outcome.value, outcome)
  assert.equal(s.outcomeReceivedAt.value, now)
  assert.equal(f.count('POST', '/v1/commands'), 1)
  assert.equal(f.count('DELETE', `/v1/tickets/${held.id}`), 1)
  assert.equal(f.count('GET', '/v1/commands'), 2)
  assert.equal(f.calls.length, requests + 1)
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM tickets WHERE consumed = 1').get().count, 4)
})

test('live realtime: replacing the token resets only local authority; explicit authentication and listing recover shared server records', { timeout: 20000 }, async t => {
  const f = await fixture(t, { realtime: true })
  const s = f.session
  const socket = await f.connect()
  await f.run('ticket')
  const submittedId = s.ticket.value.id
  const committedEvent = nextCommit(socket, s.command.value)
  await f.run('commit')
  const committed = await committedEvent
  await bounded(s.checkLastSubmission(), 'submission receipt before token replacement')
  await f.run('list')
  s.search.value = 'registreer'
  s.command.value = 'held across local token replacement'
  s.ttlMs.value = 20000
  await f.run('ticket')
  const held = { ...s.ticket.value }
  assert.deepEqual(s.commands.value, [committed])
  assert.deepEqual(s.filteredCommands.value, [committed])
  assert.equal(s.hasLoaded.value, true)
  assert.equal(s.lastJournalRefreshAt.value, now)
  assert.equal(s.outcome.value.id, submittedId)
  assert.equal(s.outcome.value.status, 'committed')
  assert.deepEqual(s.outcome.value.record, committed)
  assert.equal(s.outcomeReceivedAt.value, now)
  assert.equal(s.lookupId.value, submittedId)
  assert.equal(s.lastSubmissionId.value, submittedId)
  assert.equal(s.canCommit.value, true)
  assert.notEqual(s.message.value, '')
  assert.equal((await f.statusExternal(held.id)).status, 'active')
  const requests = f.calls.length
  const invalidToken = 'invalid-nonempty-operator-token'

  s.token.value = invalidToken
  assert.equal(s.token.value, invalidToken)
  assertDisconnected(socket)
  assert.equal(s.realtimeStatus.value, 'disconnected')
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.revocationUncertain.value, false)
  assert.equal(s.command.value, '')
  assert.equal(s.ttlMs.value, 10000)
  assert.equal(s.search.value, '')
  assert.deepEqual(s.commands.value, [])
  assert.deepEqual(s.filteredCommands.value, [])
  assert.equal(s.hasLoaded.value, false)
  assert.equal(s.journalRefreshFailed.value, false)
  assert.equal(s.lastJournalRefreshAt.value, null)
  assert.equal(s.lookupId.value, '')
  assert.equal(s.lastSubmissionId.value, '')
  assert.equal(s.outcome.value, null)
  assert.equal(s.outcomeReceivedAt.value, null)
  assert.equal(s.outcomeMismatch.value, false)
  assert.equal(s.message.value, '')
  assert.equal(s.error.value, '')
  assert.equal(s.busy.value, '')
  assert.equal(f.calls.length, requests, 'token replacement sends no request, including revocation')
  assert.equal(f.sockets.length, 1, 'a typed token never starts a connection')
  assert.equal((await f.statusExternal(held.id)).status, 'active')
  assert.deepEqual({ ...f.db.prepare('SELECT consumed, revoked FROM tickets WHERE id = ?').get(held.id) }, { consumed: 0, revoked: 0 })
  assert.equal(f.count('DELETE', `/v1/tickets/${held.id}`), 0)

  const rejected = waitFor(s.realtimeStatus, value => value === 'error', 'invalid token connection rejection')
  s.realtime.connect(s.token.value)
  await rejected
  const invalidSocket = f.sockets.at(-1)
  assert.notEqual(invalidSocket, socket)
  assert.equal(f.sockets.length, 2)
  assertDisconnected(invalidSocket)
  await f.run('list')
  assert.notEqual(s.error.value, '')
  assert.equal(s.journalRefreshFailed.value, true)
  assert.equal(s.hasLoaded.value, false)
  const feedback = { message: s.message.value, error: s.error.value }
  const barrierEvent = nextCommit(f.witness, 'shared operator commit while token is invalid')
  const barrier = await f.commitExternal('shared operator commit while token is invalid')
  assert.deepEqual(await barrierEvent, barrier)
  assert.deepEqual(s.commands.value, [], 'an independently witnessed real commit cannot update the rejected session')
  assert.deepEqual({ message: s.message.value, error: s.error.value }, feedback)
  assert.equal(s.realtimeStatus.value, 'error')
  assertDisconnected(socket)
  assertDisconnected(invalidSocket)
  assert.equal(f.sockets.length, 2, 'authentication failure never reconnects')
  assert.equal(f.calls.length, requests + 1)

  s.token.value = token
  assert.equal(f.calls.length, requests + 1, 'restoring the shared operator token does not fetch')
  assert.equal(f.sockets.length, 2, 'restoring the token does not connect')
  assert.equal(s.realtimeStatus.value, 'disconnected')
  assert.equal(s.error.value, '')
  assert.equal(s.journalRefreshFailed.value, false)
  assert.deepEqual(s.commands.value, [])
  const restoredSocket = await f.connect()
  assert.notEqual(restoredSocket, invalidSocket)
  assert.deepEqual(s.commands.value, [], 'connection alone does not replay shared records')
  assert.equal(f.calls.length, requests + 1)
  await f.run('list')
  assert.deepEqual(s.commands.value, [barrier, committed])
  assert.equal(s.hasLoaded.value, true)
  assert.equal(s.lastJournalRefreshAt.value, now)
  assert.equal(s.error.value, '')
  assert.equal(s.busy.value, '')
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.lastSubmissionId.value, '')
  assert.equal(s.lookupId.value, '')
  assert.equal(s.outcome.value, null)
  assert.equal(s.outcomeReceivedAt.value, null)
  assert.equal((await f.statusExternal(held.id)).status, 'active', 'local credential changes do not revoke the shared operator ticket')
  assert.equal(f.calls.length, requests + 2)
})

test('live realtime: a lost successful refresh retains its receipt and failure until another explicit list', { timeout: 20000 }, async t => {
  const f = await fixture(t, { realtime: true })
  const s = f.session
  const socket = await f.connect()
  const baselineWitness = nextCommit(f.witness, 'refresh baseline')
  const baselineEvent = nextCommit(socket, 'refresh baseline')
  const baseline = await f.commitExternal('refresh baseline')
  assert.deepEqual(await baselineWitness, baseline)
  assert.deepEqual(await baselineEvent, baseline)
  await waitFor(s.commands, rows => rows.some(row => row.id === baseline.id), 'baseline session record')
  assert.equal(f.calls.length, 0)

  await f.run('ticket')
  const held = s.ticket.value
  f.loseNext('DELETE', `/v1/tickets/${held.id}`)
  await f.run('revoke')
  assert.equal(f.losses, 1)
  assert.equal(s.revocationUncertain.value, true)
  const authority = () => ({
    ticket: { ...s.ticket.value }, canCommit: s.canCommit.value,
    revocationUncertain: s.revocationUncertain.value,
    lastSubmissionId: s.lastSubmissionId.value, lookupId: s.lookupId.value,
    outcome: s.outcome.value, outcomeReceivedAt: s.outcomeReceivedAt.value,
    command: s.command.value, ttlMs: s.ttlMs.value,
  })
  const retainedAuthority = authority()
  assert.equal(retainedAuthority.ticket.id, held.id)
  assert.equal(retainedAuthority.canCommit, false)
  // Reads may advance the server watermark, but must not mutate authority or journal/audit rows.
  const database = () => Object.fromEntries(['tickets', 'commands', 'audit'].map(table =>
    [table, f.db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all().map(row => ({ ...row }))]))
  const beforeLists = database()
  await f.run('list')
  assert.deepEqual(s.commands.value, [baseline])
  assert.equal(s.hasLoaded.value, true)
  assert.equal(s.lastJournalRefreshAt.value, now)
  assert.equal(s.journalRefreshFailed.value, false)
  assert.equal(s.error.value, '')
  assert.deepEqual(database(), beforeLists)
  assert.deepEqual(authority(), retainedAuthority)
  assert.equal(s.ticket.value, held)
  assert.equal(f.calls.length, 3)

  f.setLocalNow(now + 100)
  f.tick()
  const previous = s.commands.value
  f.loseNext('GET', '/v1/commands')
  await f.run('list')
  assert.equal(f.losses, 2)
  assert.equal(s.commands.value, previous)
  assert.deepEqual(s.commands.value, [baseline])
  assert.equal(s.hasLoaded.value, true)
  assert.equal(s.lastJournalRefreshAt.value, now)
  assert.equal(s.journalRefreshFailed.value, true)
  assert.match(s.error.value, /Geen geldig antwoord/)
  const failedError = s.error.value
  assert.equal(s.busy.value, '')
  assert.deepEqual(database(), beforeLists)
  assert.deepEqual(authority(), retainedAuthority)
  assert.equal(s.ticket.value, held)
  assert.equal(f.calls.length, 4)

  const witnessed = nextCommit(f.witness, 'after lost refresh')
  const received = nextCommit(socket, 'after lost refresh')
  const external = await f.commitExternal('after lost refresh')
  assert.deepEqual(await witnessed, external)
  assert.deepEqual(await received, external)
  await waitFor(s.commands, rows => rows.some(row => row.id === external.id), 'record after failed refresh')
  assert.deepEqual(s.commands.value, [external, baseline])
  assert.equal(s.hasLoaded.value, true)
  assert.equal(s.journalRefreshFailed.value, true)
  assert.equal(s.lastJournalRefreshAt.value, now)
  assert.equal(s.error.value, failedError)
  assert.deepEqual(authority(), retainedAuthority)
  assert.equal(s.ticket.value, held)
  assert.equal(s.realtimeStatus.value, 'connected')
  assert.equal(f.calls.length, 4, 'realtime reception sends no HTTP request or automatic list retry')
  assert.equal(f.count('GET', '/v1/commands'), 2)

  const beforeRecovery = database()
  f.setLocalNow(now + 200)
  f.tick()
  await f.run('list')
  assert.equal(s.hasLoaded.value, true)
  assert.equal(s.journalRefreshFailed.value, false)
  assert.equal(s.lastJournalRefreshAt.value, now + 200)
  assert.equal(s.error.value, '')
  const newest = f.db.prepare('SELECT id, command, committed_at FROM commands ORDER BY seq DESC LIMIT 100')
    .all().map(row => ({ ...row }))
  assert.deepEqual(newest, [external, baseline])
  assert.deepEqual(s.commands.value, newest)
  assert.equal(new Set(s.commands.value.map(row => row.id)).size, s.commands.value.length)
  assert.deepEqual(database(), beforeRecovery)
  assert.deepEqual(authority(), retainedAuthority)
  assert.equal(s.ticket.value, held)
  assert.equal(f.losses, 2)
  assert.equal(f.count('GET', '/v1/commands'), 3)
  assert.deepEqual(f.calls, [
    { path: '/v1/tickets', method: 'POST', status: 201 },
    { path: `/v1/tickets/${held.id}`, method: 'DELETE', status: 200 },
    { path: '/v1/commands', method: 'GET', status: 200 },
    { path: '/v1/commands', method: 'GET', status: 200 },
    { path: '/v1/commands', method: 'GET', status: 200 },
  ])
})

test('live realtime: token replacement isolates a held real list from a newer explicit request', { timeout: 20000 }, async t => {
  const f = await fixture(t, { realtime: true })
  const s = f.session
  const socket = await f.connect()
  const firstEvent = nextCommit(socket, 'snapshot before token replacement')
  const first = await f.commitExternal('snapshot before token replacement')
  assert.deepEqual(await firstEvent, first)
  const oldGate = f.holdNextList()
  const oldListing = f.run('list')
  const operations = [oldListing]
  let newGate
  t.after(async () => {
    oldGate.release()
    newGate?.release()
    await Promise.all(operations)
  })
  const old = await oldGate.received()
  assert.deepEqual(old.snapshot.commands, [first])
  assert.equal(old.signal.aborted, false)
  assert.equal(s.busy.value, 'list')
  const bufferedEvent = nextCommit(socket, 'buffered before token replacement')
  const buffered = await f.commitExternal('buffered before token replacement')
  assert.deepEqual(await bufferedEvent, buffered)
  assert.deepEqual(s.commands.value, [buffered, first])
  s.search.value = 'buffered'

  s.token.value = 'another-invalid-nonempty-token'
  assert.equal(old.signal.aborted, true)
  assertDisconnected(socket)
  assert.equal(s.realtimeStatus.value, 'disconnected')
  assert.deepEqual(s.commands.value, [])
  assert.deepEqual(s.filteredCommands.value, [])
  assert.equal(s.search.value, '')
  assert.equal(s.busy.value, '')
  assert.equal(s.hasLoaded.value, false)
  assert.equal(s.lastJournalRefreshAt.value, null)
  assert.equal(s.message.value, '')
  assert.equal(s.error.value, '')
  assert.equal(f.calls.length, 1)
  assert.equal(f.sockets.length, 1)

  const newerEvent = nextCommit(f.witness, 'shared record after token replacement')
  const newer = await f.commitExternal('shared record after token replacement')
  assert.deepEqual(await newerEvent, newer)
  assert.deepEqual(s.commands.value, [])
  s.token.value = token
  assert.equal(f.calls.length, 1)
  assert.equal(f.sockets.length, 1)
  newGate = f.holdNextList()
  const newListing = f.run('list')
  operations.push(newListing)
  const current = await newGate.received()
  assert.deepEqual(current.snapshot.commands, [newer, buffered, first])
  assert.equal(current.signal.aborted, false)
  s.search.value = 'shared'
  s.command.value = 'new local draft'
  oldGate.release()
  await oldGate.delivered()
  await oldListing

  assert.equal(current.signal.aborted, false)
  assert.equal(s.busy.value, 'list', 'the aborted generation cannot finish the newer request')
  assert.deepEqual(s.commands.value, [], 'neither the old snapshot nor its buffered real event can repopulate')
  assert.deepEqual(s.filteredCommands.value, [])
  assert.equal(s.token.value, token)
  assert.equal(s.command.value, 'new local draft')
  assert.equal(s.search.value, 'shared')
  assert.equal(s.hasLoaded.value, false)
  assert.equal(s.lastJournalRefreshAt.value, null)
  assert.equal(s.journalRefreshFailed.value, false)
  assert.equal(s.message.value, '')
  assert.equal(s.error.value, '')
  assert.equal(s.realtimeStatus.value, 'disconnected')
  assertDisconnected(socket)
  assert.equal(f.sockets.length, 1)
  assert.equal(f.calls.length, 2)

  newGate.release()
  await newGate.delivered()
  await newListing
  assert.deepEqual(s.commands.value, [newer, buffered, first], 'the new real snapshot alone determines shared journal order')
  assert.deepEqual(s.filteredCommands.value, [newer])
  assert.equal(new Set(s.commands.value.map(row => row.id)).size, 3)
  assert.equal(s.hasLoaded.value, true)
  assert.equal(s.lastJournalRefreshAt.value, now)
  assert.equal(s.journalRefreshFailed.value, false)
  assert.equal(s.message.value, 'Logboek bijgewerkt.')
  assert.equal(s.error.value, '')
  assert.equal(s.busy.value, '')
  assert.equal(s.ticket.value, null)
  assert.equal(s.canCommit.value, false)
  assert.equal(s.realtimeStatus.value, 'disconnected')
  assert.equal(f.count('GET', '/v1/commands'), 2)
  assert.equal(f.calls.length, 2)
})

test('live realtime: an event after the real list snapshot survives delayed delivery exactly once', { timeout: 20000 }, async t => {
  const f = await fixture(t, { realtime: true })
  const s = f.session
  const firstEvent = nextCommit(f.witness, 'oldest snapshot record')
  const first = await f.commitExternal('oldest snapshot record')
  assert.deepEqual(await firstEvent, first)
  const socket = await f.connect()
  const sharedEvent = nextCommit(socket, 'event also present in snapshot')
  const shared = await f.commitExternal('event also present in snapshot')
  assert.deepEqual(await sharedEvent, shared)
  assert.deepEqual(s.commands.value, [shared])

  const gate = f.holdNextList()
  const listing = f.run('list')
  t.after(async () => {
    gate.release()
    await listing
  })
  const { snapshot, signal } = await gate.received()
  assert.deepEqual(snapshot.commands, [shared, first])
  assert.equal(signal.aborted, false)
  assert.equal(s.busy.value, 'list')
  assert.equal(s.hasLoaded.value, false)

  const lateEvent = nextCommit(socket, 'event after snapshot')
  const late = await f.commitExternal('event after snapshot')
  assert.deepEqual(await lateEvent, late)
  assert.equal(snapshot.commands.some(row => row.id === late.id), false)
  assert.deepEqual(s.commands.value, [late, shared])
  assert.equal(s.busy.value, 'list')
  gate.release()
  await gate.delivered()
  await listing

  assert.deepEqual(s.commands.value, [late, shared, first])
  assert.deepEqual(s.commands.value.slice(1), snapshot.commands, 'snapshot order is retained')
  assert.equal(new Set(s.commands.value.map(row => row.id)).size, 3)
  assert.equal(s.busy.value, '')
  assert.equal(s.hasLoaded.value, true)
  assert.equal(s.lastJournalRefreshAt.value, now)
  assert.equal(s.journalRefreshFailed.value, false)
  assert.equal(s.error.value, '')
  assert.equal(f.count('GET', '/v1/commands'), 1)
})

test('live realtime: clearing a held list isolates its late response and buffered events from a subsequent list', { timeout: 20000 }, async t => {
  const f = await fixture(t, { realtime: true })
  const s = f.session
  const socket = await f.connect()
  const firstEvent = nextCommit(socket, 'initial persisted record')
  const first = await f.commitExternal('initial persisted record')
  assert.deepEqual(await firstEvent, first)
  const oldGate = f.holdNextList()
  const oldListing = f.run('list')
  const operations = [oldListing]
  let newGate
  t.after(async () => {
    oldGate.release()
    newGate?.release()
    await Promise.all(operations)
  })
  const old = await oldGate.received()
  assert.deepEqual(old.snapshot.commands, [first])
  const bufferedEvent = nextCommit(socket, 'buffered in cleared generation')
  const buffered = await f.commitExternal('buffered in cleared generation')
  assert.deepEqual(await bufferedEvent, buffered)
  assert.deepEqual(s.commands.value, [buffered, first])
  s.search.value = 'buffered'

  s.clearJournal()
  assert.equal(old.signal.aborted, true)
  assertDisconnected(socket)
  assert.equal(s.realtimeStatus.value, 'disconnected')
  assert.deepEqual(s.commands.value, [])
  assert.deepEqual(s.filteredCommands.value, [])
  assert.equal(s.search.value, '')
  assert.equal(s.busy.value, '')
  assert.equal(s.hasLoaded.value, false)
  assert.equal(s.lastJournalRefreshAt.value, null)
  assert.equal(s.journalRefreshFailed.value, false)
  assert.equal(s.token.value, token)

  const newerEvent = nextCommit(f.witness, 'persisted while disconnected')
  const newer = await f.commitExternal('persisted while disconnected')
  assert.deepEqual(await newerEvent, newer)
  assert.deepEqual(s.commands.value, [])
  newGate = f.holdNextList()
  const newListing = f.run('list')
  operations.push(newListing)
  const current = await newGate.received()
  assert.deepEqual(current.snapshot.commands, [newer, buffered, first])
  s.search.value = 'persisted'
  oldGate.release()
  await oldGate.delivered()
  await oldListing

  assert.equal(current.signal.aborted, false)
  assert.equal(s.busy.value, 'list', 'the old completion cannot finish the new request')
  assert.deepEqual(s.commands.value, [])
  assert.deepEqual(s.filteredCommands.value, [])
  assert.equal(s.search.value, 'persisted')
  assert.equal(s.hasLoaded.value, false)
  assert.equal(s.lastJournalRefreshAt.value, null)
  assert.equal(s.journalRefreshFailed.value, false)
  assert.equal(s.message.value, '')
  assert.equal(s.error.value, '')
  assert.equal(s.realtimeStatus.value, 'disconnected')

  newGate.release()
  await newGate.delivered()
  await newListing
  const persisted = f.db.prepare('SELECT id, command, committed_at FROM commands ORDER BY seq DESC').all().map(row => ({ ...row }))
  assert.deepEqual(persisted, [newer, buffered, first])
  assert.deepEqual(s.commands.value, persisted, 'a cleared realtime buffer must not promote its record above the newer snapshot record')
  assert.deepEqual(s.filteredCommands.value, [newer, first])
  assert.equal(new Set(s.commands.value.map(row => row.id)).size, 3)
  assert.equal(s.busy.value, '')
  assert.equal(s.hasLoaded.value, true)
  assert.equal(s.lastJournalRefreshAt.value, now)
  assert.equal(s.journalRefreshFailed.value, false)
  assert.equal(s.error.value, '')
  assert.equal(f.count('GET', '/v1/commands'), 2)
  assert.equal(f.sockets.length, 1, 'manual listing does not reconnect realtime')
})

test('live realtime: pagehide fully clears a connected session without revoking server authority; manual reconnect and scope disposal work', { timeout: 20000 }, async t => {
  const f = await fixture(t, { realtime: true })
  const s = f.session
  const socket = await f.connect()
  const firstEvent = nextCommit(socket, 'external before pagehide')
  const first = await f.commitExternal('external before pagehide')
  assert.deepEqual(await firstEvent, first)
  assert.deepEqual(s.commands.value, [first])
  await f.run('ticket')
  const ownEvent = nextCommit(socket, s.command.value)
  await f.run('commit')
  const own = await ownEvent
  assert.notEqual(s.lastSubmissionId.value, '')
  s.ttlMs.value = 6000
  s.command.value = 'held through pagehide'
  await f.run('ticket')
  const held = { ...s.ticket.value }
  await bounded(s.checkCurrentTicket(), 'active ticket before pagehide')
  assert.equal(s.outcome.value.status, 'active')
  assert.equal(s.outcomeReceivedAt.value, now)
  await f.run('list')
  assert.deepEqual(s.commands.value, [own, first])
  assert.equal(s.lastJournalRefreshAt.value, now)
  s.search.value = 'external'
  const requests = f.calls.length

  function assertCleared() {
    assert.equal(s.token.value, '')
    assert.equal(s.command.value, '')
    assert.equal(s.ttlMs.value, 10000)
    assert.equal(s.ticket.value, null)
    assert.equal(s.revocationUncertain.value, false)
    assert.equal(s.canCommit.value, false)
    assert.equal(s.lookupId.value, '')
    assert.equal(s.lastSubmissionId.value, '')
    assert.equal(s.outcome.value, null)
    assert.equal(s.outcomeReceivedAt.value, null)
    assert.equal(s.outcomeMismatch.value, false)
    assert.equal(s.search.value, '')
    assert.deepEqual(s.commands.value, [])
    assert.deepEqual(s.filteredCommands.value, [])
    assert.equal(s.hasLoaded.value, false)
    assert.equal(s.journalRefreshFailed.value, false)
    assert.equal(s.lastJournalRefreshAt.value, null)
    assert.equal(s.busy.value, '')
    assert.equal(s.message.value, '')
    assert.equal(s.error.value, '')
    assert.equal(s.realtimeStatus.value, 'disconnected')
  }

  f.eventTarget.dispatchEvent(new Event('pagehide'))
  assertCleared()
  assertDisconnected(socket)
  assert.equal(f.calls.length, requests, 'pagehide sends no revocation or other HTTP request')
  const hiddenEvent = nextCommit(f.witness, 'external after pagehide')
  const hidden = await f.commitExternal('external after pagehide')
  assert.deepEqual(await hiddenEvent, hidden)
  assertCleared()
  const status = await bounded(f.statusExternal(held.id), 'server ticket after pagehide')
  assert.equal(status.status, 'active')
  assert.equal(status.revoked, false)
  assert.equal(status.record, null)
  assert.deepEqual({ ...f.db.prepare('SELECT revoked, consumed FROM tickets WHERE id = ?').get(held.id) }, { revoked: 0, consumed: 0 })
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM commands').get().count, 3)
  assert.equal(f.calls.length, requests)

  s.token.value = token
  assert.equal(s.realtimeStatus.value, 'disconnected')
  assert.equal(f.sockets.length, 1, 'restoring the token does not automatically reconnect')
  const reconnected = await f.connect()
  const freshEvent = nextCommit(reconnected, 'external after manual recovery')
  const fresh = await f.commitExternal('external after manual recovery')
  assert.deepEqual(await freshEvent, fresh)
  assert.deepEqual(s.commands.value, [fresh])
  await f.run('list')
  assert.deepEqual(s.commands.value, [fresh, hidden, own, first])
  assert.equal(s.ticket.value, null, 'reconnecting never restores cleared local authority')
  assert.equal(f.count('POST', '/v1/commands'), 1)
  assert.equal(f.calls.some(call => call.method === 'DELETE'), false)

  f.scope.stop()
  assertCleared()
  assertDisconnected(reconnected)
  assert.equal(f.intervals.size, 0)
  assert.equal(getEventListeners(f.eventTarget, 'pagehide').length, 0)
  const disposedEvent = nextCommit(f.witness, 'external after disposal')
  const disposed = await f.commitExternal('external after disposal')
  assert.deepEqual(await disposedEvent, disposed)
  assertCleared()
  s.realtime.connect(token)
  await f.run('list')
  assert.equal(f.sockets.length, 2, 'a disposed scope cannot reconnect')
  assert.equal(f.calls.length, requests + 1, 'a disposed scope cannot send requests')
  assert.deepEqual(
    f.db.prepare('SELECT id, command, committed_at FROM commands ORDER BY seq DESC').all().map(row => ({ ...row })),
    [disposed, fresh, hidden, own, first],
  )
  assert.equal((await f.statusExternal(held.id)).status, 'active')
})
