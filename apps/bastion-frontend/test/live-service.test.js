import test from 'node:test'
import assert from 'node:assert/strict'
import { once, getEventListeners } from 'node:events'
import { createServer } from 'node:net'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { effectScope, watch } from 'vue'
import { io } from 'socket.io-client'
import * as productionApi from '../src/api.js'
import { createRealtime } from '../src/realtime.js'
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

async function fixture(t, { realtime = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'palaco-bastion-live-test-'))
  const probe = createServer()
  const scope = effectScope()
  const eventTarget = new EventTarget()
  const intervals = new Set()
  const calls = []
  const sockets = []
  const listGates = []
  let app, db, session, dropNext, witness, nextListGate
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
  app = createBastion({ token, port, dbPath }, { clock: () => now })
  await bounded(app.listen(), 'service startup')
  db = new DatabaseSync(dbPath)
  const origin = `http://127.0.0.1:${app.port}`
  const fetcher = async (path, options) => {
    assert.ok(options.signal instanceof AbortSignal)
    calls.push({ path, method: options.method })
    const gate = options.method === 'GET' && path === '/v1/commands' ? nextListGate : undefined
    if (gate) nextListGate = undefined
    // A gated transport deliberately ignores cancellation, including while awaiting release.
    // The production API still receives the session signal and must reject a late response.
    const response = await fetch(origin + path, gate ? { ...options, signal: undefined } : options)
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
    ...(realtime ? {
      realtimeFactory: callbacks => createRealtime({
        ...callbacks,
        createSocket(options) {
          assert.deepEqual(options, {
            path: '/socket.io', auth: { token }, autoConnect: false,
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
    session, db, calls, sockets, witness, scope, eventTarget, intervals,
    async commitExternal(command) {
      const ticket = await productionApi.issueTicket(command, 10000, token, externalFetch)
      return productionApi.commitCommand(ticket, command, token, externalFetch)
    },
    statusExternal: id => productionApi.getTicketStatus(id, token, externalFetch),
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
