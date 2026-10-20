import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { effectScope, isRef } from 'vue'
import { useSession } from '../src/useSession.js'
import { createRealtime } from '../src/realtime.js'
import { listCommands } from '../src/api.js'

const held = () => ({ id: 'ticket-1', command: 'journal only', not_before: 1000, expires_at: 1100 })
const record = (id = 'record-1') => ({ id, command: 'journal only', committed_at: 1050 })
const snapshot = (changes = {}) => ({
  ...held(), checked_at: 1050, status: 'active', revoked: false, record: null, ...changes,
})
const actions = { ticket: 'issueTicket', commit: 'commitCommand', revoke: 'revokeTicket', status: 'getTicketStatus', list: 'listCommands' }
const results = { ticket: held(), commit: record(), revoke: undefined, status: snapshot(), list: [record()] }
const deferred = () => {
  let resolve, reject
  const promise = new Promise((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}

function fixture(t, eventTarget = new EventTarget(), apiOverrides = {}) {
  const scope = effectScope()
  const calls = []
  const sockets = []
  const realtimeCallbacks = []
  const clock = { time: 1050, reads: 0, tick: null, cleared: [], interval: null }
  const api = { ...Object.fromEntries(Object.entries(actions).map(([action, name]) => [name, (...args) => {
    const call = { action, args, signal: args.at(-1), ...deferred() }
    calls.push(call)
    return call.promise
  }])), ...apiOverrides }
  const state = scope.run(() => useSession({
    api,
    eventTarget,
    scheduler: {
      now: () => { clock.reads++; return clock.time },
      setInterval(callback, interval) { clock.tick = callback; clock.interval = interval; return 42 },
      clearInterval(id) { clock.cleared.push(id) },
    },
    realtimeFactory: callbacks => {
      realtimeCallbacks.push(callbacks)
      return createRealtime({
        ...callbacks,
        createSocket(options) {
          const socket = {
            auth: options.auth, io: { opts: { ...options } }, handlers: {},
            connects: 0, disconnects: 0, removed: false,
            on(name, callback) { this.handlers[name] = callback },
            connect() { this.connects++ },
            disconnect() { this.disconnects++ },
            removeAllListeners() { this.removed = true },
          }
          sockets.push(socket)
          return socket
        }
      })
    },
  }))
  t.after(() => scope.stop())
  state.token.value = 'test-session-token'
  return { state, scope, calls, sockets, clock, eventTarget, realtimeCallbacks }
}

function prepare(state, action) {
  state.command.value = 'journal only'
  state.ttlMs.value = 50
  state.ticket.value = held()
  state.lookupId.value = held().id
  state.outcome.value = snapshot()
  state.outcomeReceivedAt.value = 1000
  state.lastSubmissionId.value = 'retained-id'
  state.commands.value = [record()]
  state.search.value = 'journal'
  state.hasLoaded.value = true
  state.journalRefreshFailed.value = true
  state.lastJournalRefreshAt.value = 1000
  state.message.value = 'previous message'
  state.error.value = 'previous error'
  if (action === 'revoke') state.revocationUncertain.value = true
}

function assertEmpty(state, token = '') {
  for (const key of ['command', 'search', 'busy', 'message', 'error', 'lookupId', 'lastSubmissionId']) {
    assert.equal(state[key].value, '', key)
  }
  assert.equal(state.token.value, token)
  assert.equal(state.ticket.value, null)
  assert.equal(state.revocationUncertain.value, false)
  assert.deepEqual(state.commands.value, [])
  assert.deepEqual(state.filteredCommands.value, [])
  assert.equal(state.hasLoaded.value, false)
  assert.equal(state.journalRefreshFailed.value, false)
  assert.equal(state.lastJournalRefreshAt.value, null)
  assert.equal(state.outcome.value, null)
  assert.equal(state.outcomeReceivedAt.value, null)
  assert.equal(state.outcomeMismatch.value, false)
  assert.equal(state.realtimeStatus.value, 'disconnected')
  assert.equal(state.canCommit.value, false)
  assert.equal(state.remaining.value, 0)
  assert.equal(state.ttlMs.value, 10000)
}

function assertDisconnected(socket) {
  assert.deepEqual(socket.auth, {})
  assert.deepEqual(socket.io.opts.auth, {})
  assert.equal(socket.disconnects, 1)
  assert.equal(socket.removed, true)
}

function pageTransition(type, persisted) {
  const event = new Event(type)
  Object.defineProperty(event, 'persisted', { value: persisted })
  return event
}

function retainedOutcomeState(state) {
  return structuredClone(Object.fromEntries(Object.entries(state)
    .filter(([key, value]) => isRef(value) && !['outcome', 'outcomeReceivedAt', 'outcomeMismatch', 'message', 'error', 'busy'].includes(key))
    .map(([key, value]) => [key, JSON.parse(JSON.stringify(value.value))])))
}

for (const uncertain of [false, true]) {
  test(`malformed injected ticket windows or clocks cannot count down or submit, uncertainty=${uncertain}`, async t => {
    const { state, calls, clock } = fixture(t)
    prepare(state, 'commit')
    state.revocationUncertain.value = uncertain
    const invalid = [
      Infinity, -Infinity, NaN, Number.MAX_SAFE_INTEGER + 1, 1000.5, -1,
      8_640_000_000_000_001, null, undefined, true, {}, [], '', 'invalid',
      '1969-12-31T23:59:59.999Z', '+275760-09-13T00:00:00.001Z',
    ]
    const tickets = []
    for (const field of ['not_before', 'expires_at']) {
      tickets.push(...invalid.map(value => ({ ...held(), [field]: value })))
      const missing = held()
      delete missing[field]
      tickets.push(missing)
    }
    tickets.push(
      { ...held(), not_before: 1100 },
      { ...held(), not_before: 1101 },
      { ...held(), expires_at: 61_001 },
    )
    async function assertGuarded() {
      const currentTicket = state.ticket.value
      assert.equal(state.canCommit.value, false)
      assert.equal(state.remaining.value, null)
      assert.equal(state.revocationUncertain.value, uncertain)
      await state.perform('commit')
      assert.equal(state.ticket.value, currentTicket)
      assert.equal(state.lastSubmissionId.value, 'retained-id')
      assert.equal(state.revocationUncertain.value, uncertain)
      assert.equal(calls.length, 0)
      assert.equal(state.busy.value, '')
    }
    for (const ticket of tickets) {
      state.ticket.value = ticket
      await assertGuarded()
    }
    state.ticket.value = held()
    assert.equal(state.canCommit.value, !uncertain)
    assert.equal(state.remaining.value, 1)
    for (const time of [...invalid, '1050', new Date(1050).toISOString()]) {
      clock.time = time
      clock.tick()
      await assertGuarded()
    }
    state.ticket.value = null
    assert.equal(state.remaining.value, 0)
    assert.equal(state.canCommit.value, false)
    assert.equal(state.revocationUncertain.value, uncertain)
    state.clearSession()
    assertEmpty(state)
  })
}

test('session countdown preserves valid numeric and ISO windows through pending, active and expired times', t => {
  const { state, calls, clock } = fixture(t)
  prepare(state, 'commit')
  for (const iso of [false, true]) {
    state.ticket.value = {
      ...held(),
      not_before: iso ? new Date(1000).toISOString() : 1000,
      expires_at: iso ? new Date(3000).toISOString() : 3000,
    }
    for (const [time, remaining, canCommit] of [
      [0, 3, false], [999, 3, false], [1000, 2, true], [1001, 2, true],
      [2000, 1, true], [2999, 1, true], [3000, 0, false], [3001, 0, false],
    ]) {
      clock.time = time
      clock.tick()
      assert.equal(state.remaining.value, remaining)
      assert.equal(state.canCommit.value, canCommit)
    }
    state.revocationUncertain.value = true
    clock.time = 1050
    clock.tick()
    assert.equal(state.remaining.value, 2)
    assert.equal(state.canCommit.value, false)
    state.revocationUncertain.value = false
    state.command.value = 'different'
    assert.equal(state.remaining.value, 0)
    state.command.value = held().command
  }
  assert.equal(calls.length, 0)
  state.clearSession()
  assertEmpty(state)
})

test('countdown UI separates unavailable, positive and expired time and disclaims server authority', () => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const result = app.match(/<div v-if="ticket" class="result">([\s\S]*?)<\/div>/)[1]
  assert.match(result, /<p v-if="remaining === null">Resterende tijd niet beschikbaar\. Controleer de lokale klok en ticketgegevens\.<\/p>\s*<p v-else-if="remaining > 0">Nog circa \{\{ remaining \}\} seconden\.<\/p>\s*<p v-else>Verlopen\. Vraag een nieuw ticket aan\.<\/p>/)
  assert.match(result, /<p v-if="remaining > 0 && !canCommit && !revocationUncertain">Niet geldig voor de huidige invoer of begintijd\.<\/p>/)
  assert.match(result, /De aftelling gebruikt de lokale klok; alleen de server beslist over geldigheid\./)
})

for (const uncertain of [false, true]) {
  test(`same-ID mismatches are derived warnings only, uncertainty=${uncertain}`, async t => {
    const { state, calls, sockets, clock } = fixture(t)
    prepare(state, 'status')
    state.revocationUncertain.value = uncertain
    state.realtime.connect(state.token.value)
    sockets[0].handlers.connect()
    const currentTicket = state.ticket.value
    for (const changes of [
      { command: 'different' }, { not_before: 1001 }, { expires_at: 1101 },
    ]) {
      const operation = state.checkCurrentTicket()
      const request = calls.at(-1)
      assert.equal(state.outcomeMismatch.value, false)
      request.resolve(snapshot({ ...changes, status: 'revoked', revoked: true }))
      await operation
      assert.equal(state.outcomeMismatch.value, true)
      assert.equal(state.ticket.value, currentTicket)
      assert.equal(state.revocationUncertain.value, uncertain)
      assert.equal(state.canCommit.value, !uncertain)
      assert.equal(state.outcomeMismatch.value, true)
    }
    clock.time = 5000
    clock.tick()
    assert.equal(state.outcomeMismatch.value, true)
    assert.equal(state.canCommit.value, false)
    sockets[0].handlers['command:committed'](record('live'))
    assert.equal(state.outcomeMismatch.value, true)
    assert.equal(state.commands.value[0].id, 'live')
    assert.equal(state.realtimeStatus.value, 'connected')
    assert.equal(calls.length, 3)
    assert.ok(calls.every(call => call.action === 'status' && !call.signal.aborted))
    assert.equal(sockets.length, 1)
    assert.equal(sockets[0].connects, 1)
    assert.equal(sockets[0].disconnects, 0)
  })
}

test('warning validates displayed outcome and ignores other IDs, absent authority and equivalent ISO windows', t => {
  const { state, calls, sockets } = fixture(t)
  prepare(state, 'status')
  const valid = snapshot({ command: 'different' })
  assert.equal(state.outcomeMismatch.value, false)
  for (const invalid of [
    null, {}, [], { ...valid, extra: true }, { ...valid, status: 'committed' },
    { ...valid, not_before: '1970-01-01T00:00:01.000Z' },
    { ...valid, expires_at: 8_640_000_000_000_001 },
  ]) {
    state.outcome.value = invalid
    assert.equal(state.outcomeMismatch.value, false)
  }
  state.outcome.value = valid
  assert.equal(state.outcomeMismatch.value, true)
  state.outcome.value = snapshot({ id: 'intentionally-other-ticket', command: 'different' })
  assert.equal(state.outcomeMismatch.value, false)
  state.outcome.value = valid
  state.ticket.value = null
  assert.equal(state.outcomeMismatch.value, false)
  state.outcome.value = snapshot()
  state.ticket.value = {
    ...held(), not_before: new Date(1000).toISOString(), expires_at: new Date(1100).toISOString(),
  }
  assert.equal(state.outcomeMismatch.value, false)
  for (const field of ['not_before', 'expires_at']) {
    const missing = held()
    delete missing[field]
    state.ticket.value = missing
    assert.equal(state.outcomeMismatch.value, true)
    for (const boundary of [null, undefined, '', 'invalid', {}, [], true, NaN, Infinity]) {
      state.ticket.value = { ...held(), [field]: boundary }
      assert.equal(state.outcomeMismatch.value, true)
    }
  }
  assert.equal(calls.length, 0)
  assert.equal(sockets.length, 0)
})

for (const reset of ['lookup', 'command', 'ttl', 'clearOutcome', 'clearSession', 'token', 'pagehide', 'dispose']) {
  test(`${reset} removes a displayed mismatch warning without requests`, t => {
    const { state, calls, sockets, eventTarget, scope } = fixture(t)
    prepare(state, 'status')
    state.outcome.value = snapshot({ command: 'different' })
    assert.equal(state.outcomeMismatch.value, true)
    if (reset === 'lookup') state.lookupId.value = 'other-ticket'
    else if (reset === 'command') state.command.value = 'edited'
    else if (reset === 'ttl') state.ttlMs.value = 60
    else if (reset === 'token') state.token.value = 'new-test-token'
    else if (reset === 'pagehide') eventTarget.dispatchEvent(pageTransition('pagehide', true))
    else if (reset === 'dispose') scope.stop()
    else state[reset]()
    assert.equal(state.outcomeMismatch.value, false)
    if (['clearSession', 'token', 'pagehide', 'dispose'].includes(reset)) {
      assertEmpty(state, reset === 'token' ? 'new-test-token' : '')
    }
    assert.equal(calls.length, 0)
    assert.equal(sockets.length, 0)
  })
}

test('fresh issuance recomputes warning against the held ticket, not the lookup field or stale warning state', async t => {
  const { state, calls, sockets } = fixture(t)
  prepare(state, 'status')
  assert.equal(state.outcomeMismatch.value, false)
  let issuing = state.perform('ticket')
  assert.equal(state.outcomeMismatch.value, false)
  calls[0].resolve({ ...held(), expires_at: 1101 })
  await issuing
  assert.equal(state.outcomeMismatch.value, true)
  issuing = state.perform('ticket')
  assert.equal(state.outcomeMismatch.value, false)
  calls[1].resolve(held())
  await issuing
  assert.equal(state.outcomeMismatch.value, false)
  assert.equal(state.canCommit.value, true)
  issuing = state.perform('ticket')
  calls[2].resolve({ ...held(), id: 'fresh-ticket' })
  await issuing
  assert.equal(state.outcomeMismatch.value, false)
  assert.equal(state.outcome.value.id, 'ticket-1')
  assert.equal(calls.length, 3)
  assert.ok(calls.every(call => call.action === 'ticket'))
  assert.equal(sockets.length, 0)
})

test('mismatch UI is an alert inside the source-bound result without claiming all actions are blocked', () => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const result = app.match(/<div v-if="outcome" class="result">([\s\S]*?)<\/div>/)[1]
  assert.match(result, /Ticket: <code>\{\{ outcome.id \}\}<\/code>/)
  assert.match(result, /<p v-if="outcomeMismatch" role="alert" class="error">Statusgegevens wijken af van het lokaal bewaarde ticket\. Deze uitkomst wijzigt het lokale ticket of de onzekerheidsblokkering niet\.<\/p>/)
  assert.match(result, /\{\{ outcome.command \}\}/)
  assert.doesNotMatch(result, /zijn geblokkeerd/)
})

test('clearing an idle outcome retains the entire session, live connection and uncertainty, and is idempotent', async t => {
  const { state, calls, sockets, clock } = fixture(t)
  state.realtime.connect(state.token.value)
  sockets[0].handlers.connect()
  prepare(state, 'revoke')
  const operation = state.perform('status')
  calls[0].resolve(snapshot())
  await operation
  const before = retainedOutcomeState(state)
  assert.notEqual(state.message.value, '')
  state.clearOutcome()
  state.clearOutcome()
  assert.equal(state.outcome.value, null)
  assert.equal(state.message.value, '')
  assert.equal(state.error.value, '')
  assert.equal(state.busy.value, '')
  assert.deepEqual(retainedOutcomeState(state), before)
  assert.equal(state.revocationUncertain.value, true)
  assert.equal(state.canCommit.value, false)
  assert.equal(calls.length, 1)
  assert.equal(calls[0].signal.aborted, false)
  assert.equal(sockets.length, 1)
  assert.equal(sockets[0].disconnects, 0)
  assert.deepEqual(clock.cleared, [])
  sockets[0].handlers['command:committed'](record('still-connected'))
  assert.equal(state.commands.value[0].id, 'still-connected')
})

test('clearing a completed terminal reconciliation only hides it, never restores authority', async t => {
  const { state, calls } = fixture(t)
  prepare(state, 'revoke')
  const operation = state.perform('status')
  calls[0].resolve(snapshot({ status: 'committed', record: record('historical') }))
  await operation
  assert.equal(state.ticket.value, null)
  assert.equal(state.revocationUncertain.value, false)
  assert.equal(state.outcomeMismatch.value, false)
  const before = retainedOutcomeState(state)
  state.clearOutcome()
  assert.deepEqual(retainedOutcomeState(state), before)
  assert.equal(state.outcome.value, null)
  assert.equal(state.canCommit.value, false)
  assert.deepEqual(state.commands.value, [record()])
})

test('clearing failed status feedback retains IDs, ticket and blocked revocation without retry', async t => {
  const { state, calls } = fixture(t)
  prepare(state, 'revoke')
  const operation = state.perform('status')
  calls[0].reject(new Error('status failure'))
  await operation
  assert.equal(state.error.value, 'status failure')
  const before = retainedOutcomeState(state)
  state.clearOutcome()
  state.clearOutcome()
  assert.equal(state.error.value, '')
  assert.equal(state.message.value, '')
  assert.deepEqual(retainedOutcomeState(state), before)
  assert.equal(calls.length, 1)
})

for (const action of ['ticket', 'commit', 'revoke', 'list']) {
  for (const settlement of ['resolve', 'reject']) {
    test(`idle outcome clear preserves ${action} ${settlement} feedback and all other state`, async t => {
      const { state, calls } = fixture(t)
      prepare(state, action)
      const operation = state.perform(action)
      if (settlement === 'resolve') calls[0].resolve(results[action])
      else calls[0].reject(new Error(`${action} failure`))
      await operation
      state.outcome.value = snapshot()
      const before = retainedOutcomeState(state)
      const feedback = [state.message.value, state.error.value]
      assert.ok(feedback.some(Boolean))
      state.clearOutcome()
      state.clearOutcome()
      assert.equal(state.outcome.value, null)
      assert.deepEqual([state.message.value, state.error.value], feedback)
      assert.deepEqual(retainedOutcomeState(state), before)
      assert.equal(calls.length, 1)
    })

    test(`outcome clear is a complete no-op during busy ${action}, later ${settlement} still settles normally`, async t => {
      const { state, calls } = fixture(t)
      prepare(state, action)
      const operation = state.perform(action)
      state.outcome.value = snapshot()
      state.message.value = 'keep busy feedback'
      state.error.value = 'keep busy error'
      const before = retainedOutcomeState(state)
      state.clearOutcome()
      assert.equal(state.busy.value, action)
      assert.deepEqual(state.outcome.value, snapshot())
      assert.equal(state.message.value, 'keep busy feedback')
      assert.equal(state.error.value, 'keep busy error')
      assert.deepEqual(retainedOutcomeState(state), before)
      assert.equal(calls[0].signal.aborted, false)
      assert.equal(calls.length, 1)
      if (settlement === 'resolve') calls[0].resolve(results[action])
      else calls[0].reject(new Error(`${action} failure`))
      await operation
      assert.equal(state.busy.value, '')
      if (settlement === 'reject') assert.equal(state.error.value, `${action} failure`)
      else if (action === 'ticket') assert.deepEqual(state.ticket.value, held())
      else if (action === 'commit') assert.equal(state.ticket.value, null)
      else if (action === 'revoke') assert.equal(state.revocationUncertain.value, false)
      else assert.equal(state.journalRefreshFailed.value, false)
    })
  }
}

for (const settlement of ['resolve', 'reject']) {
  test(`clearing pending status preserves uncertain authority against late terminal ${settlement}`, async t => {
    const { state, calls, sockets } = fixture(t)
    state.realtime.connect(state.token.value)
    sockets[0].handlers.connect()
    prepare(state, 'revoke')
    const operation = state.perform('status')
    const before = retainedOutcomeState(state)
    let atAbort
    calls[0].signal.addEventListener('abort', () => {
      atAbort = { busy: state.busy.value, outcome: state.outcome.value }
    })
    state.clearOutcome()
    assert.deepEqual(atAbort, { busy: '', outcome: null })
    assert.equal(calls[0].signal.aborted, true)
    assert.equal(state.busy.value, '')
    state.clearOutcome()
    if (settlement === 'resolve') calls[0].resolve(snapshot({ status: 'committed', record: record() }))
    else calls[0].reject(new Error('late status failure'))
    await operation
    assert.deepEqual(retainedOutcomeState(state), before)
    assert.deepEqual(state.ticket.value, held())
    assert.equal(state.revocationUncertain.value, true)
    assert.equal(state.canCommit.value, false)
    assert.equal(state.outcome.value, null)
    assert.equal(state.message.value, '')
    assert.equal(state.error.value, '')
    assert.equal(calls.length, 1)
    assert.equal(sockets[0].disconnects, 0)
    sockets[0].handlers['command:committed'](record('after-clear'))
    assert.equal(state.commands.value[0].id, 'after-clear')
  })

  for (const action of Object.keys(actions)) {
    for (const newerCompleted of [false, true]) {
      test(`cleared status late ${settlement} cannot affect newer ${action}, completed=${newerCompleted}`, async t => {
        const { state, calls } = fixture(t)
        prepare(state, 'status')
        const old = state.perform('status')
        state.clearOutcome()
        assert.equal(calls[0].signal.aborted, true)
        if (action === 'status' || action === 'revoke') state.revocationUncertain.value = true
        state.lookupId.value = action === 'status' ? 'different-ticket' : held().id
        const newer = state.perform(action)
        assert.equal(calls.length, 2)
        const nextResult = action === 'status' ? snapshot({ id: 'different-ticket' }) : results[action]
        if (newerCompleted) {
          calls[1].resolve(nextResult)
          await newer
        }
        const before = retainedOutcomeState(state)
        const other = [state.busy.value, state.message.value, state.error.value, state.outcome.value]
        if (settlement === 'resolve') calls[0].resolve(snapshot({ status: 'committed', record: record('stale') }))
        else calls[0].reject(new Error('stale error must not replace feedback'))
        await old
        assert.deepEqual(retainedOutcomeState(state), before)
        assert.deepEqual([state.busy.value, state.message.value, state.error.value, state.outcome.value], other)
        assert.equal(calls[1].signal.aborted, false)
        if (!newerCompleted) {
          assert.equal(state.busy.value, action)
          calls[1].resolve(nextResult)
          await newer
          assert.equal(state.busy.value, '')
          assert.equal(state.error.value, '')
        }
        if (action === 'status') {
          assert.deepEqual(state.outcome.value, nextResult)
          assert.deepEqual(state.ticket.value, held())
          assert.equal(state.revocationUncertain.value, true)
        }
        assert.equal(calls.length, 2)
      })
    }
  }
}

test('status abort callbacks can start a newer request without its identity or feedback being cleared', async t => {
  const { state, calls } = fixture(t)
  prepare(state, 'status')
  const old = state.perform('status')
  let newer
  calls[0].signal.addEventListener('abort', () => {
    newer = state.perform('list')
    state.message.value = 'new list feedback'
  })
  state.clearOutcome()
  assert.equal(state.busy.value, 'list')
  assert.equal(calls.length, 2)
  calls[0].reject(new Error('abort'))
  await old
  assert.equal(state.busy.value, 'list')
  assert.equal(state.message.value, 'new list feedback')
  assert.equal(state.error.value, '')
  calls[1].resolve([record('fresh')])
  await newer
  assert.deepEqual(state.commands.value, [record('fresh')])
})

test('outcome clear is inert after disposal, including manually changed refs', async t => {
  const { state, scope, calls } = fixture(t)
  prepare(state, 'status')
  const operation = state.perform('status')
  scope.stop()
  assertEmpty(state)
  prepare(state, 'revoke')
  state.busy.value = 'status'
  const before = retainedOutcomeState(state)
  state.clearOutcome()
  assert.deepEqual(retainedOutcomeState(state), before)
  assert.deepEqual(state.outcome.value, snapshot())
  assert.equal(state.busy.value, 'status')
  assert.equal(state.message.value, 'previous message')
  assert.equal(state.error.value, 'previous error')
  calls[0].resolve(snapshot({ status: 'committed', record: record() }))
  await operation
  assert.deepEqual(retainedOutcomeState(state), before)
  assert.deepEqual(state.outcome.value, snapshot())
  assert.equal(state.busy.value, 'status')
})

for (const reset of ['clearSession', 'token', 'pagehide']) {
  test(`outcome clear does not weaken subsequent full-session reset via ${reset}`, async t => {
    const { state, eventTarget, sockets, calls } = fixture(t)
    state.realtime.connect(state.token.value)
    prepare(state, 'revoke')
    const operation = state.perform('status')
    state.clearOutcome()
    if (reset === 'clearSession') state.clearSession()
    else if (reset === 'token') state.token.value = 'replacement-token'
    else eventTarget.dispatchEvent(pageTransition('pagehide', true))
    assertEmpty(state, reset === 'token' ? 'replacement-token' : '')
    assertDisconnected(sockets[0])
    calls[0].resolve(snapshot({ status: 'committed', record: record() }))
    await operation
    assertEmpty(state, reset === 'token' ? 'replacement-token' : '')
  })
}

for (const status of ['active', 'committed']) {
  test(`editing a loaded ${status} lookup clears only its local read context; same exact ID is inert`, async t => {
    const { state, calls, sockets } = fixture(t)
    state.realtime.connect(state.token.value)
    sockets[0].handlers.connect()
    prepare(state, 'revoke')
    const operation = state.perform('status')
    calls[0].resolve(snapshot({ status, record: status === 'committed' ? record('historical') : null }))
    await operation
    const before = retainedOutcomeState(state)
    const feedback = state.message.value
    const result = state.outcome.value
    state.lookupId.value = held().id
    assert.equal(state.outcome.value, result)
    assert.equal(state.message.value, feedback)
    assert.deepEqual(retainedOutcomeState(state), before)

    // Whitespace is an exact ID edit, not a normalized equivalent.
    state.lookupId.value = ` ${held().id} `
    before.lookupId = ` ${held().id} `
    assert.equal(state.lookupId.value, ` ${held().id} `)
    assert.equal(state.outcome.value, null)
    assert.equal(state.message.value, '')
    assert.equal(state.error.value, '')
    assert.deepEqual(retainedOutcomeState(state), before)
    assert.equal(state.revocationUncertain.value, status === 'active')
    assert.equal(state.canCommit.value, false)
    assert.equal(calls.length, 1)
    assert.equal(calls[0].signal.aborted, false)
    assert.equal(sockets[0].disconnects, 0)
    sockets[0].handlers['command:committed'](record('after-edit'))
    assert.equal(state.commands.value[0].id, 'after-edit')
  })
}

test('editing after status failure clears its feedback without retrying or changing authority', async t => {
  const { state, calls } = fixture(t)
  prepare(state, 'revoke')
  const operation = state.perform('status')
  calls[0].reject(new Error('status failure'))
  await operation
  const before = retainedOutcomeState(state)
  state.lookupId.value = held().id
  assert.equal(state.error.value, 'status failure')
  state.lookupId.value = 'another-id'
  before.lookupId = 'another-id'
  assert.equal(state.outcome.value, null)
  assert.equal(state.error.value, '')
  assert.equal(state.message.value, '')
  assert.deepEqual(retainedOutcomeState(state), before)
  assert.equal(calls.length, 1)
})

for (const settlement of ['resolve', 'reject']) {
  test(`lookup edit aborts pending status before late terminal ${settlement}, preserving uncertainty`, async t => {
    const { state, calls } = fixture(t)
    prepare(state, 'revoke')
    const operation = state.perform('status')
    state.lookupId.value = held().id
    assert.equal(calls[0].signal.aborted, false)
    assert.equal(state.busy.value, 'status')
    let atAbort
    calls[0].signal.addEventListener('abort', () => {
      atAbort = [state.busy.value, state.outcome.value, state.message.value, state.error.value]
    })
    const before = retainedOutcomeState(state)
    state.lookupId.value = ''
    before.lookupId = ''
    assert.deepEqual(atAbort, ['', null, '', ''])
    assert.equal(calls[0].signal.aborted, true)
    if (settlement === 'resolve') calls[0].resolve(snapshot({ status: 'committed', record: record('stale') }))
    else calls[0].reject(new Error('stale status error'))
    await operation
    assert.deepEqual(retainedOutcomeState(state), before)
    assert.equal(state.outcome.value, null)
    assert.equal(state.error.value, '')
    assert.equal(state.message.value, '')
    assert.equal(state.revocationUncertain.value, true)
    assert.deepEqual(state.ticket.value, held())
    assert.equal(state.canCommit.value, false)
    assert.equal(calls.length, 1)
  })

  for (const action of ['status', 'ticket', 'commit']) {
    for (const newerCompleted of [false, true]) {
      test(`edited lookup late ${settlement} cannot affect next ${action}, completed=${newerCompleted}`, async t => {
        const { state, calls } = fixture(t)
        prepare(state, 'status')
        const old = state.perform('status')
        state.lookupId.value = 'different-ticket'
        assert.equal(calls[0].signal.aborted, true)
        assert.equal(calls.length, 1)
        if (action === 'status') state.revocationUncertain.value = true
        const newer = state.perform(action)
        assert.equal(calls.length, 2)
        const result = action === 'status' ? snapshot({ id: 'different-ticket' }) : results[action]
        if (newerCompleted) {
          calls[1].resolve(result)
          await newer
        }
        const before = retainedOutcomeState(state)
        const readContext = [state.busy.value, state.message.value, state.error.value, state.outcome.value]
        if (settlement === 'resolve') calls[0].resolve(snapshot({ status: 'committed', record: record('stale') }))
        else calls[0].reject(new Error('stale status error'))
        await old
        assert.deepEqual(retainedOutcomeState(state), before)
        assert.deepEqual([state.busy.value, state.message.value, state.error.value, state.outcome.value], readContext)
        assert.equal(calls[1].signal.aborted, false)
        if (!newerCompleted) {
          assert.equal(state.busy.value, action)
          calls[1].resolve(result)
          await newer
        }
        assert.equal(state.busy.value, '')
        assert.equal(state.error.value, '')
        if (action === 'commit') {
          assert.equal(state.lookupId.value, held().id)
          assert.equal(state.lastSubmissionId.value, held().id)
          assert.equal(state.ticket.value, null)
          assert.match(state.message.value, /Commando vastgelegd/)
          assert.deepEqual(state.commands.value, [record()])
        } else if (action === 'status') {
          assert.deepEqual(state.outcome.value, result)
          assert.equal(state.revocationUncertain.value, true)
        } else assert.deepEqual(state.ticket.value, held())
        assert.equal(calls.length, 2)
      })
    }
  }
}

test('lookup abort callbacks can start a fresh request without losing its identity or feedback', async t => {
  const { state, calls } = fixture(t)
  prepare(state, 'status')
  const old = state.perform('status')
  let newer
  calls[0].signal.addEventListener('abort', () => {
    newer = state.perform('status')
    state.message.value = 'fresh status feedback'
  })
  state.lookupId.value = 'fresh-id'
  assert.equal(calls.length, 2)
  assert.equal(calls[1].args[0], 'fresh-id')
  calls[0].resolve(snapshot({ status: 'committed', record: record('stale') }))
  await old
  assert.equal(state.busy.value, 'status')
  assert.equal(state.message.value, 'fresh status feedback')
  assert.equal(calls[1].signal.aborted, false)
  calls[1].resolve(snapshot({ id: 'fresh-id' }))
  await newer
  assert.equal(state.outcome.value.id, 'fresh-id')
})

for (const action of ['ticket', 'commit', 'revoke', 'list']) {
  test(`lookup edit respects busy ${action} guard and preserves non-status feedback afterward`, async t => {
    const { state, calls } = fixture(t)
    prepare(state, action)
    state.lookupId.value = 'different-before-action'
    state.outcome.value = snapshot()
    const operation = state.perform(action)
    state.outcome.value = snapshot()
    state.message.value = 'busy feedback'
    state.error.value = 'busy error'
    state.lookupId.value = 'different-during-action'
    assert.equal(state.busy.value, action)
    assert.deepEqual(state.outcome.value, snapshot())
    assert.equal(state.message.value, 'busy feedback')
    assert.equal(state.error.value, 'busy error')
    assert.equal(calls[0].signal.aborted, false)
    calls[0].resolve(results[action])
    await operation
    const feedback = [state.message.value, state.error.value]
    state.lookupId.value = 'different-after-action'
    assert.equal(state.outcome.value, null)
    assert.deepEqual([state.message.value, state.error.value], feedback)
    state.lookupId.value = 'no-read-context'
    assert.deepEqual([state.message.value, state.error.value], feedback)
    assert.equal(calls.length, 1)
  })
}

for (const shortcut of ['checkCurrentTicket', 'checkLastSubmission']) {
  test(`${shortcut} replaces loaded read context with exactly one explicit request`, async t => {
    const { state, calls } = fixture(t)
    prepare(state, 'status')
    state.lookupId.value = 'unrelated-id'
    const old = state.perform('status')
    calls[0].resolve(snapshot({ id: 'unrelated-id' }))
    await old
    const operation = state[shortcut]()
    assert.equal(calls.length, 2)
    assert.equal(calls[1].action, 'status')
    assert.equal(calls[1].args[0], shortcut === 'checkCurrentTicket' ? held().id : 'retained-id')
    assert.equal(state.outcome.value, null)
    assert.equal(state.busy.value, 'status')
    assert.equal(calls[1].signal.aborted, false)
    calls[1].resolve(snapshot({ id: calls[1].args[0] }))
    await operation
    assert.equal(state.outcome.value.id, calls[1].args[0])
    assert.equal(calls.length, 2)
  })
}

for (const settlement of ['resolve', 'reject']) {
  test(`commit lookup assignment preserves its request and ${settlement} feedback after a loaded read`, async t => {
    const { state, calls } = fixture(t)
    prepare(state, 'status')
    state.lookupId.value = 'historical-ticket'
    const checking = state.perform('status')
    calls[0].resolve(snapshot({ id: 'historical-ticket' }))
    await checking
    const committing = state.perform('commit')
    assert.equal(calls.length, 2)
    assert.equal(state.lookupId.value, held().id)
    assert.equal(state.lastSubmissionId.value, held().id)
    assert.equal(state.busy.value, 'commit')
    assert.equal(calls[1].signal.aborted, false)
    assert.equal(state.outcome.value, null)
    if (settlement === 'resolve') calls[1].resolve(record())
    else calls[1].reject(new Error('commit response lost'))
    await committing
    const feedback = [state.message.value, state.error.value]
    assert.ok(feedback.some(Boolean))
    state.lookupId.value = 'another-manual-id'
    assert.deepEqual([state.message.value, state.error.value], feedback)
    assert.equal(state.ticket.value, null)
    assert.equal(calls.length, 2)
  })
}

test('lookup editing after scope cleanup cannot clear manually seeded read context', t => {
  const { state, scope, calls } = fixture(t)
  scope.stop()
  assertEmpty(state)
  prepare(state, 'revoke')
  state.busy.value = 'status'
  const before = retainedOutcomeState(state)
  state.lookupId.value = 'after-disposal'
  before.lookupId = 'after-disposal'
  assert.deepEqual(retainedOutcomeState(state), before)
  assert.deepEqual(state.outcome.value, snapshot())
  assert.equal(state.busy.value, 'status')
  assert.equal(state.message.value, 'previous message')
  assert.equal(state.error.value, 'previous error')
  assert.equal(calls.length, 0)
})

test('lookup help describes exact IDs, local-only clearing and explicit requests with accessible association', () => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  assert.match(app, /<input id="lookup-id"[^>]*aria-describedby="lookup-id-help"/)
  assert.match(app, /id="lookup-id-help"[^>]*>Een ander ID wist alleen de lokale status/)
  assert.match(app, /Geen herstel van toestemming of intrekking op de server; geen automatisch verzoek\./)
  assert.match(app, /Gebruik het exacte ID, zonder omringende spaties\./)
  assert.match(app, /Ticket: <code>\{\{ outcome.id \}\}<\/code>/)
})

test('outcome clear UI is an explicit local-only button with status-only busy eligibility and honest help', () => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  assert.match(app, /clearSession, clearOutcome,\s*\} = useSession\(\)/)
  const button = app.match(/<button[^>]*@click="clearOutcome"[^>]*>Wis ticketuitkomst<\/button>/)?.[0]
  assert.ok(button)
  assert.match(button, /type="button"/)
  assert.match(button, /:disabled="\(!!busy && busy !== 'status'\) \|\| \(!outcome && busy !== 'status'\)"/)
  assert.match(button, /aria-describedby="clear-outcome-help"/)
  assert.match(app, /id="clear-outcome-help"[^>]*>Wist alleen lokaal/)
  assert.match(app, /Ticket-ID's blijven behouden\. Geen intrekking, terugdraaien of herstel van toestemming\./)
  assert.match(app, /Controleer de status opnieuw met een expliciete actie; geen automatische verzoeken\./)
  assert.ok(app.indexOf('@click="clearOutcome"') > app.indexOf('<div v-if="outcome"'))
  assert.ok(app.indexOf('@click="clearOutcome"') < app.indexOf('aria-labelledby="journal-title"'))
})

for (const persisted of [false, true]) {
  test(`pagehide persisted=${persisted} clears loaded state; pageshow requires explicit token and actions`, async t => {
    const { state, eventTarget, calls, sockets, clock } = fixture(t)
    state.realtime.connect(state.token.value)
    prepare(state, 'revoke')
    eventTarget.dispatchEvent(pageTransition('pagehide', persisted))
    assertEmpty(state)
    assertDisconnected(sockets[0])
    assert.deepEqual(clock.cleared, [])
    eventTarget.dispatchEvent(pageTransition('pageshow', persisted))
    assertEmpty(state)
    assert.equal(calls.length, 0)
    assert.equal(sockets.length, 1)
    state.token.value = 'restored-session-token'
    assert.equal(calls.length, 0)
    assert.equal(sockets.length, 1)
    state.realtime.connect(state.token.value)
    assert.deepEqual(sockets[1].auth, { token: 'restored-session-token' })
    for (const action of Object.keys(actions)) {
      prepare(state, action)
      const operation = state.perform(action)
      assert.equal(calls.at(-1).action, action)
      assert.ok(calls.at(-1).args.includes('restored-session-token'))
      calls.at(-1).resolve(results[action])
      await operation
      assert.equal(state.error.value, '')
      assert.equal(state.busy.value, '')
    }
    // The empty-token path must also clear local state, without disposing the session.
    state.token.value = ''
    prepare(state, 'revoke')
    eventTarget.dispatchEvent(pageTransition('pagehide', persisted))
    assertEmpty(state)
  })

  for (const action of Object.keys(actions)) {
    for (const settlement of ['resolve', 'reject']) {
      for (const reauthenticate of [false, true]) {
        test(`pagehide persisted=${persisted}: ${action} stale ${settlement}, reauthenticate=${reauthenticate}`, async t => {
          const { state, eventTarget, calls, sockets, realtimeCallbacks } = fixture(t)
          state.realtime.connect(state.token.value)
          const socket = sockets[0]
          prepare(state, action)
          const old = state.perform(action)
          eventTarget.dispatchEvent(pageTransition('pagehide', persisted))
          assertEmpty(state)
          assert.equal(calls[0].signal.aborted, true)
          assertDisconnected(socket)
          eventTarget.dispatchEvent(pageTransition('pageshow', persisted))
          assert.equal(calls.length, 1)
          assert.equal(sockets.length, 1)
          let replacement
          if (reauthenticate) {
            state.token.value = 'replacement-token'
            state.command.value = 'new session'
            state.realtime.connect(state.token.value)
            sockets[1].handlers.connect()
            sockets[1].handlers['command:committed'](record('new-session-record'))
            replacement = state.perform('ticket')
          }
          socket.handlers['command:committed'](record('late'))
          socket.handlers.connect()
          socket.handlers.disconnect()
          socket.handlers.connect_error()
          realtimeCallbacks[0].onEntry(record('late-direct-callback'))
          realtimeCallbacks[0].onStatus('error')
          realtimeCallbacks[0].onReset()
          if (settlement === 'resolve') calls[0].resolve(results[action])
          else calls[0].reject(new Error('stale private failure'))
          await old
          if (!reauthenticate) {
            assertEmpty(state)
            return
          }
          assert.equal(state.token.value, 'replacement-token')
          assert.equal(state.command.value, 'new session')
          assert.equal(state.busy.value, 'ticket')
          assert.equal(state.realtimeStatus.value, 'connected')
          assert.deepEqual(state.commands.value, [record('new-session-record')])
          assert.equal(state.ticket.value, null)
          assert.equal(state.outcome.value, null)
          assert.equal(state.lastSubmissionId.value, '')
          assert.equal(state.lookupId.value, '')
          assert.equal(state.revocationUncertain.value, false)
          assert.equal(state.search.value, '')
          assert.equal(state.hasLoaded.value, false)
          assert.equal(state.journalRefreshFailed.value, false)
          assert.equal(state.lastJournalRefreshAt.value, null)
          assert.equal(state.error.value, '')
          assert.equal(state.message.value, '')
          assert.equal(calls[1].signal.aborted, false)
          calls[1].resolve({ ...held(), id: 'new-ticket', command: 'new session' })
          await replacement
          assert.equal(state.ticket.value.id, 'new-ticket')
          assert.equal(state.busy.value, '')
        })
      }
    }
  }
}

test('scope disposal removes the exact pagehide listener before aborting; later events leave refs alone', async t => {
  class TrackedTarget extends EventTarget {
    added = []
    removed = []
    addEventListener(...args) { this.added.push(args); super.addEventListener(...args) }
    removeEventListener(...args) { this.removed.push(args); super.removeEventListener(...args) }
  }
  const eventTarget = new TrackedTarget()
  const { state, scope, calls } = fixture(t, eventTarget)
  assert.equal(eventTarget.added.length, 1)
  assert.equal(eventTarget.added[0][0], 'pagehide')
  prepare(state, 'ticket')
  const operation = state.perform('ticket')
  calls[0].signal.addEventListener('abort', () => {
    assert.deepEqual(eventTarget.removed, eventTarget.added)
  })
  scope.stop()
  assert.deepEqual(eventTarget.removed, eventTarget.added)
  assertEmpty(state)
  state.command.value = 'after disposal'
  state.token.value = 'after-disposal-token'
  for (const persisted of [false, true]) {
    eventTarget.dispatchEvent(pageTransition('pagehide', persisted))
    assert.equal(state.command.value, 'after disposal')
    assert.equal(state.token.value, 'after-disposal-token')
  }
  calls[0].resolve(held())
  await operation
  assert.equal(state.command.value, 'after disposal')
})

test('visibilitychange does not clear, disconnect or abort an active session', async t => {
  const { state, eventTarget, calls, sockets } = fixture(t)
  state.realtime.connect(state.token.value)
  prepare(state, 'list')
  const operation = state.perform('list')
  eventTarget.dispatchEvent(new Event('visibilitychange'))
  assert.equal(state.token.value, 'test-session-token')
  assert.equal(state.search.value, 'journal')
  assert.equal(state.lastJournalRefreshAt.value, 1000)
  assert.equal(state.busy.value, 'list')
  assert.equal(calls[0].signal.aborted, false)
  assert.equal(sockets[0].disconnects, 0)
  calls[0].resolve([record()])
  await operation
  assert.equal(state.hasLoaded.value, true)
})

test('default browser event target is safe without window during SSR', t => {
  assert.equal(globalThis.window, undefined)
  const scope = effectScope()
  t.after(() => scope.stop())
  const state = scope.run(() => useSession({
    scheduler: { now: () => 1050, setInterval: () => 42, clearInterval() {} },
  }))
  prepare(state, 'ticket')
  state.clearSession()
  assertEmpty(state)
})

test('session help describes browser lifecycle limits and explicit restoration without security guarantees', () => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  assert.match(app, /pagehide \(ook bij terug\/vooruit-cache\)/)
  assert.match(app, /Voer na terugkeer het token opnieuw in/)
  assert.match(app, /geen automatische verzoeken of herverbinding/)
  assert.match(app, /browser levert pagehide niet gegarandeerd/)
  assert.match(app, /geen veilige geheugenwissing/)
  assert.match(app, /geen intrekking van servertickets of terugdraaien/)
})

for (const action of Object.keys(actions)) {
  for (const settlement of ['resolve', 'reject']) {
    for (const reset of ['clear', 'token']) {
      test(`${action}: ${reset} aborts immediately; stale ${settlement}/finally cannot change a newer busy session`, async t => {
        const { state, calls, sockets } = fixture(t)
        state.realtime.connect(state.token.value)
        const socket = sockets[0]
        prepare(state, action)
        const old = state.perform(action)
        assert.equal(calls.length, 1)
        assert.equal(calls[0].action, action)
        assert.equal(calls[0].signal.aborted, false)
        assert.equal(state.busy.value, action)
        if (reset === 'clear') state.clearSession()
        else state.token.value = 'replacement-token'
        assert.equal(calls[0].signal.aborted, true)
        assertEmpty(state, reset === 'clear' ? '' : 'replacement-token')
        assertDisconnected(socket)
        socket.handlers['command:committed'](record('late'))
        socket.handlers.connect()
        socket.handlers.connect_error()
        assertEmpty(state, reset === 'clear' ? '' : 'replacement-token')

        state.token.value = 'new-session-token'
        state.command.value = 'new session'
        const replacement = state.perform('ticket')
        assert.equal(calls.length, 2)
        assert.notEqual(calls[0].signal, calls[1].signal)
        if (settlement === 'resolve') calls[0].resolve(results[action])
        else calls[0].reject(new Error('stale private failure'))
        await old
        assert.equal(state.busy.value, 'ticket')
        assert.equal(state.command.value, 'new session')
        assert.equal(state.token.value, 'new-session-token')
        assert.equal(state.ticket.value, null)
        assert.deepEqual(state.commands.value, [])
        assert.equal(state.outcome.value, null)
        assert.equal(state.lastSubmissionId.value, '')
        assert.equal(state.lookupId.value, '')
        assert.equal(state.revocationUncertain.value, false)
        assert.equal(state.error.value, '')
        assert.equal(state.message.value, '')
        assert.equal(state.journalRefreshFailed.value, false)
        assert.equal(state.lastJournalRefreshAt.value, null)
        assert.equal(calls[1].signal.aborted, false)
        calls[1].resolve({ ...held(), id: 'new-ticket', command: 'new session' })
        await replacement
        assert.equal(state.ticket.value.id, 'new-ticket')
        assert.equal(state.busy.value, '')
        assert.match(state.message.value, /Ticket ontvangen/)
      })
    }

    test(`${action}: scope disposal aborts and clears clock/socket; late ${settlement} and callbacks stay inert`, async t => {
      const { state, scope, calls, sockets, clock } = fixture(t)
      state.realtime.connect(state.token.value)
      const socket = sockets[0]
      prepare(state, action)
      const operation = state.perform(action)
      assert.equal(clock.interval, 100)
      clock.time = 1060
      clock.tick()
      assert.equal(state.now.value, 1060)
      scope.stop()
      assertEmpty(state)
      assert.equal(calls[0].signal.aborted, true)
      assert.deepEqual(clock.cleared, [42])
      assertDisconnected(socket)
      clock.time = 2000
      clock.tick()
      assert.equal(state.now.value, 1060)
      socket.handlers['command:committed'](record('late'))
      socket.handlers.connect()
      socket.handlers.disconnect()
      socket.handlers.connect_error()
      if (settlement === 'resolve') calls[0].resolve(results[action])
      else calls[0].reject(new Error('late private failure'))
      await operation
      assertEmpty(state)
      await state.perform('list')
      state.realtime.connect('not-allowed-after-disposal')
      assert.equal(calls.length, 1)
      assert.equal(sockets.length, 1)
    })

    test(`${action}: clearing with an empty token also rejects late ${settlement} without a replacement`, async t => {
      const { state, calls } = fixture(t)
      state.token.value = ''
      prepare(state, action)
      const operation = state.perform(action)
      state.clearSession()
      assertEmpty(state)
      assert.equal(calls[0].signal.aborted, true)
      if (settlement === 'resolve') calls[0].resolve(results[action])
      else calls[0].reject(new Error('stale failure'))
      await operation
      assertEmpty(state)
    })
  }
}

test('ticket gate, separate submission, uncertain outcome, and retained ID use the production flow', async t => {
  const { state, calls, clock } = fixture(t)
  state.command.value = 'journal only'
  const issuing = state.perform('ticket')
  assert.equal(state.ticket.value, null)
  assert.equal(calls[0].args[1], 10000)
  await state.perform('list')
  assert.equal(calls.length, 1)
  calls[0].resolve(held())
  await issuing
  assert.equal(state.canCommit.value, true)
  assert.equal(state.remaining.value, 1)
  clock.time = 1100
  clock.tick()
  assert.equal(state.canCommit.value, false)
  await state.perform('commit')
  assert.equal(calls.length, 1)
  clock.time = 1050
  clock.tick()
  const committing = state.perform('commit')
  assert.equal(state.ticket.value, null)
  assert.equal(state.canCommit.value, false)
  assert.equal(state.lastSubmissionId.value, 'ticket-1')
  assert.equal(state.lookupId.value, 'ticket-1')
  assert.deepEqual(calls[1].args[0], held())
  calls[1].reject(new Error('response lost'))
  await committing
  assert.equal(state.error.value, 'response lost')
  assert.equal(state.busy.value, '')
  await state.perform('commit')
  assert.equal(calls.length, 2)
  state.command.value = 'different'
  const issuingAgain = state.perform('ticket')
  calls[2].resolve({ ...held(), command: 'different' })
  await issuingAgain
  assert.equal(state.lastSubmissionId.value, 'ticket-1')
  state.clearSession()
  assertEmpty(state)
})

test('normal successful commit consumes the ticket and merges its journal record', async t => {
  const { state, calls } = fixture(t)
  prepare(state, 'commit')
  state.commands.value = [record('previous')]
  const operation = state.perform('commit')
  assert.equal(state.ticket.value, null)
  calls[0].resolve(record())
  await operation
  assert.deepEqual(state.commands.value, [record(), record('previous')])
  assert.equal(state.lastSubmissionId.value, 'ticket-1')
  assert.equal(state.busy.value, '')
  assert.match(state.message.value, /niets uitgevoerd/)
  assert.equal(state.error.value, '')
})

test('uncertain revocation fails closed through edits and active lookup; manual retry can confirm', async t => {
  const { state, calls } = fixture(t)
  prepare(state, 'revoke')
  const revoking = state.perform('revoke')
  calls[0].reject(new Error('confirmation lost'))
  await revoking
  assert.equal(state.revocationUncertain.value, true)
  assert.deepEqual(state.ticket.value, held())
  assert.equal(state.canCommit.value, false)
  state.command.value = 'changed'
  state.ttlMs.value = 10
  assert.deepEqual(state.ticket.value, held())
  await state.perform('ticket')
  await state.perform('commit')
  assert.equal(calls.length, 1)
  const checking = state.perform('status')
  calls[1].resolve(snapshot())
  await checking
  assert.equal(state.revocationUncertain.value, true)
  assert.deepEqual(state.ticket.value, held())
  const retry = state.perform('revoke')
  assert.deepEqual(calls[2].args[0], held())
  calls[2].resolve()
  await retry
  assert.equal(state.ticket.value, null)
  assert.equal(state.revocationUncertain.value, false)
  assert.equal(state.busy.value, '')
  assert.match(state.message.value, /server ingetrokken/)
  assert.deepEqual(state.commands.value, [record()])
})

test('status never restores authority or journal history and only retires the same terminal ticket', async t => {
  const { state, calls } = fixture(t)
  prepare(state, 'status')
  state.revocationUncertain.value = true
  for (const value of [
    snapshot({ checked_at: 999, status: 'pending' }),
    snapshot(),
    snapshot({ id: 'other', status: 'revoked', revoked: true }),
  ]) {
    const operation = state.perform('status')
    calls.at(-1).resolve(value)
    await operation
    assert.deepEqual(state.ticket.value, held())
    assert.equal(state.revocationUncertain.value, true)
  }
  const committed = snapshot({ status: 'committed', record: record('historical') })
  const operation = state.perform('status')
  calls.at(-1).resolve(committed)
  await operation
  assert.equal(state.ticket.value, null)
  assert.equal(state.revocationUncertain.value, false)
  assert.deepEqual(state.commands.value, [record()])
  assert.deepEqual(state.outcome.value, committed)
  const active = state.perform('status')
  calls.at(-1).resolve(snapshot())
  await active
  assert.equal(state.ticket.value, null)
  assert.equal(state.lastSubmissionId.value, 'retained-id')
})

test('production status flow displays mismatched terminal windows without retiring held authority', async t => {
  const { state, calls } = fixture(t)
  prepare(state, 'revoke')
  const ticket = state.ticket.value
  const commands = state.commands.value
  for (const status of ['revoked', 'expired', 'committed']) {
    for (const [not_before, expires_at] of [[1001, 1100], [1000, 1101], [1100, 1200]]) {
      const value = snapshot({
        not_before, expires_at, checked_at: expires_at, status,
        revoked: status === 'revoked',
        record: status === 'committed' ? { ...record('historical'), committed_at: not_before } : null,
      })
      const operation = state.perform('status')
      calls.at(-1).resolve(value)
      await operation
      assert.deepEqual(state.outcome.value, value)
      assert.equal(state.ticket.value, ticket)
      assert.equal(state.revocationUncertain.value, true)
      assert.equal(state.canCommit.value, false)
      assert.equal(state.commands.value, commands)
      assert.equal(state.error.value, '')
      assert.match(state.message.value, /geen nieuwe toestemming/)
    }
  }
  assert.equal(calls.length, 9)
})

test('current-ticket shortcut does not change lookup or call the API while busy', async t => {
  const { state, calls } = fixture(t)
  prepare(state, 'revoke')
  state.lookupId.value = 'unrelated-ticket'
  const revoking = state.perform('revoke')
  await state.checkCurrentTicket()
  assert.equal(state.lookupId.value, 'unrelated-ticket')
  assert.equal(state.busy.value, 'revoke')
  assert.equal(calls.length, 1)
  calls[0].reject(new Error('confirmation lost'))
  await revoking
})

for (const guard of ['no ticket', 'empty token', 'blank token', 'disposed']) {
  test(`current-ticket shortcut: ${guard} does not change lookup or call the API`, async t => {
    const { state, calls, scope } = fixture(t)
    if (guard === 'disposed') scope.stop()
    if (guard === 'empty token') state.token.value = ''
    if (guard === 'blank token') state.token.value = ' \t\n '
    prepare(state, 'revoke')
    if (guard === 'no ticket') state.ticket.value = null
    state.lookupId.value = 'unrelated-ticket'
    await state.checkCurrentTicket()
    assert.equal(state.lookupId.value, 'unrelated-ticket')
    assert.equal(state.busy.value, '')
    assert.equal(state.message.value, 'previous message')
    assert.equal(state.error.value, 'previous error')
    assert.deepEqual(calls, [])
  })
}

for (const value of [
  snapshot(),
  snapshot({ checked_at: 999, status: 'pending' }),
  snapshot({ status: 'revoked', revoked: true }),
  snapshot({ checked_at: 1100, status: 'expired' }),
  snapshot({ status: 'committed', record: record('historical') }),
  snapshot({ id: 'other-ticket', status: 'revoked', revoked: true }),
  snapshot({ command: 'different', status: 'revoked', revoked: true }),
  snapshot({ status: 'committed' }),
]) {
  test(`current-ticket shortcut reconciles ${value.status} (${value.id}, ${value.command}, record: ${!!value.record}) without mutations`, async t => {
    const { state, calls, clock } = fixture(t)
    prepare(state, 'revoke')
    state.lookupId.value = 'unrelated-ticket'
    const nonterminal = ['active', 'pending'].includes(value.status)
    clock.time = nonterminal ? 1050 : 1200
    clock.tick()
    assert.equal(state.remaining.value, nonterminal ? 1 : 0)
    const checking = state.checkCurrentTicket()
    assert.equal(state.lookupId.value, held().id)
    assert.equal(state.busy.value, 'status')
    assert.equal(state.outcome.value, null)
    assert.equal(calls.length, 1)
    assert.equal(calls[0].action, 'status')
    assert.equal(calls[0].args[0], held().id)
    assert.equal(calls[0].args[1], state.token.value)
    assert.equal(calls[0].signal.aborted, false)
    calls[0].resolve(value)
    await checking
    const retires = value.id === held().id && value.command === held().command &&
      ['revoked', 'expired', 'committed'].includes(value.status) &&
      (value.status !== 'committed' || value.record !== null)
    assert.deepEqual(state.ticket.value, retires ? null : held())
    assert.equal(state.revocationUncertain.value, !retires)
    assert.equal(state.canCommit.value, false)
    assert.deepEqual(state.commands.value, [record()])
    assert.deepEqual(state.outcome.value, value)
    assert.equal(state.lastSubmissionId.value, 'retained-id')
    assert.equal(state.busy.value, '')
    assert.equal(state.error.value, '')
    assert.equal(calls.length, 1)
    assert.match(state.message.value, /geen nieuwe toestemming/)
  })
}

test('failed current-ticket shortcut leaves held ticket blocked without retry or mutation', async t => {
  const { state, calls } = fixture(t)
  prepare(state, 'revoke')
  const checking = state.checkCurrentTicket()
  calls[0].reject(new Error('status unavailable'))
  await checking
  assert.deepEqual(state.ticket.value, held())
  assert.equal(state.revocationUncertain.value, true)
  assert.equal(state.canCommit.value, false)
  assert.equal(state.outcome.value, null)
  assert.equal(state.error.value, 'status unavailable')
  assert.equal(state.busy.value, '')
  await state.perform('commit')
  await state.perform('ticket')
  assert.equal(calls.length, 1)
  assert.equal(calls[0].action, 'status')
  assert.deepEqual(state.commands.value, [record()])
})

for (const reset of ['clear', 'token', 'dispose']) {
  for (const settlement of ['resolve', 'reject']) {
    test(`current-ticket shortcut: ${reset} aborts and ignores stale ${settlement}`, async t => {
      const { state, calls, scope } = fixture(t)
      prepare(state, 'revoke')
      const checking = state.checkCurrentTicket()
      if (reset === 'clear') state.clearSession()
      else if (reset === 'token') state.token.value = 'replacement-token'
      else scope.stop()
      const token = reset === 'token' ? 'replacement-token' : ''
      assertEmpty(state, token)
      assert.equal(calls[0].signal.aborted, true)
      let replacement
      if (reset !== 'dispose') {
        state.token.value = 'new-session-token'
        prepare(state, 'revoke')
        state.ticket.value = { ...held(), id: 'new-ticket' }
        replacement = state.checkCurrentTicket()
      }
      if (settlement === 'resolve') calls[0].resolve(snapshot({ status: 'revoked', revoked: true }))
      else calls[0].reject(new Error('stale failure'))
      await checking
      if (replacement) {
        assert.equal(state.busy.value, 'status')
        assert.equal(state.lookupId.value, 'new-ticket')
        assert.equal(state.ticket.value.id, 'new-ticket')
        assert.equal(state.revocationUncertain.value, true)
        assert.equal(state.error.value, '')
        assert.equal(state.outcome.value, null)
        assert.equal(calls[1].signal.aborted, false)
        calls[1].resolve(snapshot({ id: 'new-ticket' }))
        await replacement
        assert.equal(state.busy.value, '')
        assert.equal(state.ticket.value.id, 'new-ticket')
      } else assertEmpty(state)
      assert.ok(calls.every(call => call.action === 'status'))
      assert.equal(calls.length, replacement ? 2 : 1)
    })
  }
}

test('current-ticket button delegates to the composable without gating on expiry or uncertainty; manual lookup remains', () => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  assert.match(app, /checkCurrentTicket, clearSession,[\s\S]*} = useSession\(\)/)
  assert.match(app, /Ticket intrekken<\/button>\s*<button class="secondary" :disabled="!!busy \|\| !ticket \|\| !token.trim\(\)" @click="checkCurrentTicket">Controleer huidig ticket<\/button>/)
  assert.match(app, /<form @submit.prevent="perform\('status'\)">/)
  assert.match(app, /<input id="lookup-id" v-model="lookupId"/)
})

for (const commitResult of ['lost', 'successful']) {
  test(`last-submission shortcut checks the retained ID after a ${commitResult} commit response without a held ticket`, async t => {
    const { state, calls } = fixture(t)
    prepare(state, 'commit')
    const submitting = state.perform('commit')
    assert.equal(state.ticket.value, null)
    assert.equal(state.lastSubmissionId.value, 'ticket-1')
    if (commitResult === 'lost') calls[0].reject(new Error('commit response lost'))
    else calls[0].resolve(record())
    await submitting
    assert.equal(calls.length, 1)
    state.lookupId.value = 'unrelated-manual-id'
    const checking = state.checkLastSubmission()
    assert.equal(state.lookupId.value, 'ticket-1')
    assert.equal(state.busy.value, 'status')
    assert.equal(calls.length, 2)
    assert.equal(calls[1].action, 'status')
    assert.deepEqual(calls[1].args.slice(0, -1), ['ticket-1', 'test-session-token', undefined])
    assert.ok(calls[1].signal instanceof AbortSignal)
    const committed = snapshot({ status: 'committed', record: record('historical-record') })
    calls[1].resolve(committed)
    await checking
    assert.deepEqual(state.outcome.value, committed)
    assert.equal(state.ticket.value, null)
    assert.equal(state.canCommit.value, false)
    assert.equal(state.lastSubmissionId.value, 'ticket-1')
    assert.deepEqual(state.commands.value, [record()])
    assert.equal(state.error.value, '')
    assert.equal(calls.length, 2)
  })
}

for (const guard of ['busy', 'missing ID', 'empty token', 'blank token', 'disposed']) {
  test(`last-submission shortcut: ${guard} leaves lookup unchanged and makes no request`, async t => {
    const { state, calls, scope } = fixture(t)
    if (guard === 'disposed') scope.stop()
    if (guard === 'empty token') state.token.value = ''
    if (guard === 'blank token') state.token.value = ' \t\n '
    // Populate after disposal/token resets so each guard is exercised independently.
    prepare(state, 'status')
    if (guard === 'missing ID') state.lastSubmissionId.value = ''
    let inFlight
    if (guard === 'busy') inFlight = state.perform('list')
    state.lookupId.value = 'manual-id-to-preserve'
    // Seed after the edit to isolate shortcut guards from lookup invalidation.
    state.outcome.value = snapshot()
    const before = calls.length
    await state.checkLastSubmission()
    assert.equal(state.lookupId.value, 'manual-id-to-preserve')
    assert.equal(calls.length, before)
    assert.deepEqual(state.outcome.value, snapshot())
    assert.deepEqual(state.ticket.value, held())
    if (inFlight) {
      assert.equal(state.busy.value, 'list')
      calls[0].resolve([])
      await inFlight
    }
  })
}

test('failed last-submission check retains its ID and does not retry or mutate the journal', async t => {
  const { state, calls } = fixture(t)
  prepare(state, 'status')
  state.ticket.value = null
  const checking = state.checkLastSubmission()
  calls[0].reject(new Error('status unavailable'))
  await checking
  await Promise.resolve()
  assert.equal(state.lastSubmissionId.value, 'retained-id')
  assert.equal(state.lookupId.value, 'retained-id')
  assert.equal(state.ticket.value, null)
  assert.equal(state.outcome.value, null)
  assert.equal(state.error.value, 'status unavailable')
  assert.equal(state.busy.value, '')
  assert.deepEqual(state.commands.value, [record()])
  assert.equal(calls.length, 1)
  assert.equal(calls[0].action, 'status')
})

for (const status of ['pending', 'active', 'committed', 'expired', 'revoked']) {
  test(`last-submission ${status} status preserves a different held ticket and revocation uncertainty`, async t => {
    const { state, calls } = fixture(t)
    prepare(state, 'revoke')
    state.lastSubmissionId.value = 'previous-ticket'
    const checking = state.checkLastSubmission()
    assert.equal(calls[0].args[0], 'previous-ticket')
    const value = snapshot({
      id: 'previous-ticket', status,
      checked_at: status === 'pending' ? 999 : status === 'expired' ? 1100 : 1050,
      revoked: status === 'revoked',
      record: status === 'committed' ? record('historical-record') : null,
    })
    calls[0].resolve(value)
    await checking
    assert.deepEqual(state.outcome.value, value)
    assert.deepEqual(state.ticket.value, held())
    assert.equal(state.revocationUncertain.value, true)
    assert.equal(state.canCommit.value, false)
    assert.equal(state.lastSubmissionId.value, 'previous-ticket')
    assert.deepEqual(state.commands.value, [record()])
    assert.equal(calls.length, 1)
    assert.equal(calls[0].action, 'status')
  })
}

for (const status of ['pending', 'active', 'committed']) {
  test(`last-submission ${status} snapshot never restores consumed authority or adds historical journal records`, async t => {
    const { state, calls } = fixture(t)
    prepare(state, 'status')
    state.ticket.value = null
    const checking = state.checkLastSubmission()
    const value = snapshot({
      id: 'retained-id', status, checked_at: status === 'pending' ? 999 : 1050,
      record: status === 'committed' ? record('historical-record') : null,
    })
    calls[0].resolve(value)
    await checking
    assert.deepEqual(state.outcome.value, value)
    assert.equal(state.ticket.value, null)
    assert.equal(state.canCommit.value, false)
    assert.deepEqual(state.commands.value, [record()])
    assert.equal(calls.length, 1)
  })
}

for (const reset of ['clear', 'token', 'dispose']) {
  for (const settlement of ['resolve', 'reject']) {
    test(`last-submission shortcut: ${reset} aborts and ignores stale ${settlement}`, async t => {
      const { state, calls, scope } = fixture(t)
      prepare(state, 'status')
      state.ticket.value = null
      const checking = state.checkLastSubmission()
      if (reset === 'clear') state.clearSession()
      else if (reset === 'token') state.token.value = 'replacement-token'
      else scope.stop()
      assertEmpty(state, reset === 'token' ? 'replacement-token' : '')
      assert.equal(calls[0].signal.aborted, true)
      let replacement
      if (reset !== 'dispose') {
        state.token.value = 'new-session-token'
        state.lastSubmissionId.value = 'new-submission'
        replacement = state.checkLastSubmission()
      }
      if (settlement === 'resolve') calls[0].resolve(snapshot({ id: 'retained-id', status: 'committed', record: record() }))
      else calls[0].reject(new Error('stale failure'))
      await checking
      if (replacement) {
        assert.equal(state.busy.value, 'status')
        assert.equal(state.lookupId.value, 'new-submission')
        assert.equal(state.lastSubmissionId.value, 'new-submission')
        assert.equal(state.outcome.value, null)
        assert.equal(state.error.value, '')
        assert.equal(state.message.value, '')
        assert.deepEqual(state.commands.value, [])
        assert.equal(calls[1].signal.aborted, false)
        calls[1].resolve(snapshot({ id: 'new-submission' }))
        await replacement
        assert.equal(state.outcome.value.id, 'new-submission')
        assert.equal(state.busy.value, '')
      } else assertEmpty(state)
      assert.ok(calls.every(call => call.action === 'status'))
      assert.equal(calls.length, replacement ? 2 : 1)
    })
  }
}

test('last-submission button is an explicit manual read beside the readonly retained ID', () => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  assert.match(app, /checkLastSubmission,[\s\S]*} = useSession\(\)/)
  assert.match(app, /<div v-if="lastSubmissionId">\s*<label[^>]*>[^<]*<\/label>\s*<input id="last-submission" :value="lastSubmissionId" readonly @focus="\$event.target.select\(\)" \/>\s*<button type="button" class="secondary" :disabled="!!busy \|\| !token.trim\(\)" @click="checkLastSubmission">Controleer laatste inzending<\/button>\s*<\/div>/)
  assert.match(app, /@click="checkCurrentTicket">Controleer huidig ticket<\/button>/)
  assert.match(app, /<form @submit.prevent="perform\('status'\)">/)
  assert.doesNotMatch(app, /clipboard|localStorage|sessionStorage/)
})

test('command or TTL changes retire local authority; mismatched and premature tickets cannot commit', async t => {
  const { state, calls, clock } = fixture(t)
  prepare(state, 'commit')
  state.command.value = 'different'
  assert.equal(state.ticket.value, null)
  state.ticket.value = held()
  await state.perform('commit')
  assert.equal(calls.length, 0)
  state.command.value = held().command
  state.ticket.value = held()
  state.ttlMs.value++
  assert.equal(state.ticket.value, null)
  state.ticket.value = held()
  clock.time = 999
  clock.tick()
  await state.perform('commit')
  assert.equal(calls.length, 0)
})

test('list merges realtime events arriving during the request; manual disconnect resets journal', async t => {
  const { state, calls, sockets } = fixture(t)
  state.realtime.connect(state.token.value)
  const socket = sockets[0]
  socket.handlers.connect()
  assert.equal(state.realtimeStatus.value, 'connected')
  const loading = state.perform('list')
  socket.handlers['command:committed'](record('during-1'))
  socket.handlers['command:committed'](record('during-2'))
  calls[0].resolve([record('during-1'), record('loaded')])
  await loading
  assert.deepEqual(state.commands.value.map(value => value.id), ['during-2', 'during-1', 'loaded'])
  assert.equal(state.hasLoaded.value, true)
  assert.equal(state.busy.value, '')
  state.realtime.disconnect()
  assert.deepEqual(state.commands.value, [])
  assert.equal(state.hasLoaded.value, false)
  assertDisconnected(socket)
  socket.handlers['command:committed'](record('late'))
  assert.deepEqual(state.commands.value, [])
})

test('all current request failures release busy without retries', async t => {
  for (const action of Object.keys(actions)) {
    const { state, calls } = fixture(t)
    prepare(state, action)
    const operation = state.perform(action)
    calls[0].reject(new Error('service failed'))
    await operation
    assert.equal(state.busy.value, '')
    assert.equal(state.error.value, 'service failed')
    assert.equal(calls.length, 1)
  }
})

test('App uses the production composable and always enables clear with the local-only warning', () => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  assert.match(app, /} = useSession\(\)/)
  const button = app.match(/<button[^>]*@click="clearSession"[^>]*>/)?.[0]
  assert.ok(button)
  assert.doesNotMatch(button, /disabled/)
  assert.match(app, /alleen lokaal/)
  assert.match(app, /geen intrekking van servertickets of terugdraaien/)
  assert.match(app, /al verzonden wijziging kan nog worden voltooid/)
  assert.match(app, /kopieer het ticket-ID vóór het wissen/)
  assert.match(app, /Dien nooit automatisch opnieuw in/)
})

test('local search uses trimmed case-insensitive literal command text OR record ID without mutations or requests', async t => {
  const { state, calls, sockets } = fixture(t)
  const loaded = Object.freeze([
    Object.freeze({ ...record('record-A'), command: 'ÉCHO ΚαΛΗΜΈΡΑ 🙂 [a.*]+? (x) $^|\\' }),
    Object.freeze({ ...record('MiXeD-ID-42'), command: 'different text' }),
    Object.freeze({ ...record('record-C'), command: 'echo another' }),
  ])
  state.commands.value = loaded
  const original = state.commands.value
  for (const [query, ids] of [
    [' écHo ', ['record-A']],
    ['καλημέρα', ['record-A']],
    ['🙂', ['record-A']],
    ['[a.*]+?', ['record-A']],
    ['(x) $^|\\', ['record-A']],
    ['.*', ['record-A']],
    ['[', ['record-A']],
    ['  mixed-id-4 \n', ['MiXeD-ID-42']],
    ['record-', ['record-A', 'record-C']],
    ['echo', ['record-C']],
    ['absent', []],
    ['', ['record-A', 'MiXeD-ID-42', 'record-C']],
    [' \t\n ', ['record-A', 'MiXeD-ID-42', 'record-C']],
  ]) {
    state.search.value = query
    assert.deepEqual(state.filteredCommands.value.map(entry => entry.id), ids, query)
    assert.strictEqual(state.commands.value, original)
    assert.deepEqual(state.commands.value, loaded)
    assert.equal(state.search.value, query)
  }
  await Promise.resolve()
  assert.deepEqual(calls, [])
  assert.deepEqual(sockets, [])
})

test('search reacts to list/realtime merges and eviction while retaining the query and loaded ordering', async t => {
  const { state, calls, sockets } = fixture(t)
  state.search.value = '  MATCH  '
  state.realtime.connect(state.token.value)
  const socket = sockets[0]
  const loading = state.perform('list')
  socket.handlers['command:committed']({ ...record('during'), command: 'match during refresh' })
  assert.deepEqual(state.filteredCommands.value.map(entry => entry.id), ['during'])
  const loaded = Array.from({ length: 100 }, (_, i) => ({
    ...record(`loaded-${i}`), command: i % 2 ? 'other' : 'match',
  }))
  calls[0].resolve(loaded)
  await loading
  assert.equal(state.commands.value.length, 100)
  assert.deepEqual(state.commands.value.map(entry => entry.id), ['during', ...loaded.slice(0, 99).map(entry => entry.id)])
  assert.deepEqual(state.filteredCommands.value.map(entry => entry.id),
    ['during', ...loaded.slice(0, 99).filter(entry => entry.command === 'match').map(entry => entry.id)])
  socket.handlers['command:committed']({ ...record('new'), command: 'MATCH new' })
  assert.equal(state.commands.value.length, 100)
  assert.equal(state.commands.value.some(entry => entry.id === 'loaded-98'), false)
  assert.equal(state.filteredCommands.value[0].id, 'new')
  socket.handlers['command:committed']({ ...record('new'), command: 'no longer relevant' })
  assert.equal(state.filteredCommands.value.some(entry => entry.id === 'new'), false)
  assert.equal(state.search.value, '  MATCH  ')
  const refreshing = state.perform('list')
  assert.ok(state.filteredCommands.value.length > 0)
  assert.equal(state.commands.value.length, 100)
  calls[1].resolve([{ ...record('replacement'), command: 'match replacement' }])
  await refreshing
  assert.deepEqual(state.filteredCommands.value.map(entry => entry.id), ['replacement'])
  assert.equal(state.search.value, '  MATCH  ')
  assert.equal(calls.length, 2)
  assert.equal(sockets.length, 1)
})

test('search never includes historical ticket status or changes that separate panel', async t => {
  const { state, calls } = fixture(t)
  state.commands.value = [record()]
  state.search.value = 'historical'
  state.lookupId.value = 'ticket-1'
  const checking = state.perform('status')
  const historical = snapshot({ status: 'committed', command: 'historical', record: { ...record('historical-record'), command: 'historical' } })
  calls[0].resolve(historical)
  await checking
  assert.deepEqual(state.filteredCommands.value, [])
  assert.deepEqual(state.commands.value, [record()])
  state.search.value = 'ticket-1'
  assert.deepEqual(state.filteredCommands.value, [])
  state.search.value = ''
  assert.deepEqual(state.filteredCommands.value, [record()])
  assert.deepEqual(state.outcome.value, historical)
  assert.equal(state.lookupId.value, 'ticket-1')
  assert.equal(calls.length, 1)
})

test('journal UI wires local search, accessible controls, counts, distinct empty states and escaped records', () => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  assert.match(app, /commands, search, filteredCommands[\s\S]*} = useSession\(\)/)
  assert.match(app, /<label for="journal-search">Zoek in geladen logboek<\/label>/)
  const input = app.match(/<input id="journal-search"[^>]*>/)?.[0]
  assert.ok(input)
  for (const attribute of ['v-model="search"', 'type="search"', 'autocomplete="off"', 'spellcheck="false"', 'maxlength="1024"', 'aria-describedby="journal-search-help"']) {
    assert.ok(input.includes(attribute), attribute)
  }
  assert.match(app, /<button type="button"[^>]*@click="search = ''">Wis zoekopdracht<\/button>/)
  assert.match(app, /<p role="status" aria-live="polite">{{ filteredCommands.length }} van {{ commands.length }} geladen records<\/p>/)
  assert.match(app, /v-if="!commands.length"[^>]*>{{ journalRefreshFailed \? 'Geen records beschikbaar na mislukte verversing.' : hasLoaded \? 'Het logboek is leeg.' : 'Nog geen records geladen.' }}/)
  assert.match(app, /v-else-if="!filteredCommands.length"[^>]*>Geen geladen records gevonden/)
  assert.match(app, /v-for="entry in filteredCommands" :key="entry.id"><pre>{{ entry.command }}<\/pre>/)
  assert.doesNotMatch(app, /v-html|localStorage|sessionStorage|URLSearchParams/)
  assert.match(app, /maximaal 100 lokaal geladen records/)
  assert.match(app, /Niet in de hele database of ticket-ID's/)
  assert.match(app, /alleen in sessiegeheugen/)
})

test('snapshot receipt time uses successful response time, survives failure and search, and advances on empty retry', async t => {
  const { state, calls, clock } = fixture(t)
  assert.equal(state.lastJournalRefreshAt.value, null)
  const loading = state.perform('list')
  assert.equal(state.lastJournalRefreshAt.value, null)
  clock.time = 1060
  calls[0].resolve([record()])
  await loading
  assert.equal(state.lastJournalRefreshAt.value, 1060)
  state.search.value = 'missing'
  assert.deepEqual(state.filteredCommands.value, [])
  assert.equal(state.lastJournalRefreshAt.value, 1060)

  clock.time = 1070
  const refreshing = state.perform('list')
  assert.equal(state.lastJournalRefreshAt.value, 1060)
  clock.time = 1080
  calls[1].reject(new Error('unavailable'))
  await refreshing
  assert.equal(state.lastJournalRefreshAt.value, 1060)
  const retry = state.perform('list')
  assert.equal(state.lastJournalRefreshAt.value, 1060)
  clock.time = 1090
  calls[2].resolve([])
  await retry
  assert.equal(state.lastJournalRefreshAt.value, 1090)
  assert.equal(state.hasLoaded.value, true)
  assert.deepEqual(state.commands.value, [])
  assert.equal(state.search.value, 'missing')
})

test('realtime arrivals, clock ticks and successful ticket, commit, status and revoke do not refresh snapshot receipt time', async t => {
  const { state, calls, sockets, clock } = fixture(t)
  state.realtime.connect(state.token.value)
  sockets[0].handlers.connect()
  sockets[0].handlers['command:committed'](record('before-snapshot'))
  assert.equal(state.lastJournalRefreshAt.value, null)
  const loading = state.perform('list')
  calls[0].resolve([record()])
  await loading
  const receivedAt = state.lastJournalRefreshAt.value
  clock.time = 1060
  clock.tick()
  sockets[0].handlers['command:committed'](record('after-snapshot'))
  assert.equal(state.lastJournalRefreshAt.value, receivedAt)
  state.command.value = held().command
  state.lookupId.value = held().id
  for (const action of ['ticket', 'commit', 'status', 'ticket', 'revoke']) {
    const operation = state.perform(action)
    assert.equal(calls.at(-1).action, action)
    calls.at(-1).resolve(results[action])
    await operation
    assert.equal(state.lastJournalRefreshAt.value, receivedAt, action)
  }
})

test('snapshot receipt accepts epoch zero and Date limits but rejects invalid local clock values', async t => {
  const { state, calls, clock } = fixture(t)
  for (const value of [0, 8640000000000000, NaN, Infinity, -Infinity, -1, 0.5,
    8640000000000001, Number.MAX_SAFE_INTEGER + 1, '1050', null, undefined]) {
    const loading = state.perform('list')
    clock.time = value
    calls.at(-1).resolve([])
    await loading
    const expected = value === 0 || value === 8640000000000000 ? value : null
    assert.equal(state.lastJournalRefreshAt.value, expected, String(value))
    assert.equal(state.hasLoaded.value, true)
    assert.equal(state.error.value, '')
    if (expected !== null) assert.doesNotThrow(() => new Date(expected).toISOString())
  }
})

test('refresh retains loaded rows and search on failure; unrelated successes cannot clear its warning', async t => {
  const { state, calls } = fixture(t)
  prepare(state, 'list')
  const rows = state.commands.value
  const refreshing = state.perform('list')
  assert.strictEqual(state.commands.value, rows)
  assert.equal(state.hasLoaded.value, true)
  assert.equal(state.journalRefreshFailed.value, false)
  assert.deepEqual(state.filteredCommands.value, [record()])
  calls[0].reject(new Error('refresh unavailable'))
  await refreshing
  assert.strictEqual(state.commands.value, rows)
  assert.equal(state.hasLoaded.value, true)
  assert.equal(state.journalRefreshFailed.value, true)
  assert.equal(state.search.value, 'journal')
  assert.equal(calls.length, 1)
  for (const action of ['status', 'ticket']) {
    const operation = state.perform(action)
    assert.equal(state.journalRefreshFailed.value, true)
    calls.at(-1).resolve(results[action])
    await operation
    assert.equal(state.error.value, '')
    assert.equal(state.journalRefreshFailed.value, true)
    assert.strictEqual(state.commands.value, rows)
  }
  const retry = state.perform('list')
  assert.equal(state.journalRefreshFailed.value, false)
  assert.strictEqual(state.commands.value, rows)
  calls.at(-1).resolve([])
  await retry
  assert.deepEqual(state.commands.value, [])
  assert.equal(state.hasLoaded.value, true)
  assert.equal(state.journalRefreshFailed.value, false)
  assert.equal(state.search.value, 'journal')
})

test('invalid realtime dates silently preserve records and receipt while valid date boundaries flow through', async t => {
  const { state, calls, sockets, clock } = fixture(t)
  state.realtime.connect(state.token.value)
  sockets[0].handlers.connect()
  const loading = state.perform('list')
  calls[0].resolve([record()])
  await loading
  const rows = state.commands.value
  const receipt = state.lastJournalRefreshAt.value
  const reads = clock.reads
  const message = state.message.value
  const emit = sockets[0].handlers['command:committed']
  clock.time = 5000
  for (const committed_at of [
    -1, -0.5, 0.5, Number.MAX_SAFE_INTEGER + 1, Number.MAX_SAFE_INTEGER,
    8_640_000_000_000_001, -8_640_000_000_000_001, Infinity, -Infinity, NaN,
    '1969-12-31T23:59:59.999Z', '+275760-09-13T00:00:00.001Z',
  ]) {
    for (const id of [record().id, 'invalid-new-entry']) {
      emit({ ...record(id), command: 'invalid replacement', committed_at })
      assert.strictEqual(state.commands.value, rows)
      assert.deepEqual(state.commands.value, [record()])
      assert.equal(state.lastJournalRefreshAt.value, receipt)
      assert.equal(state.hasLoaded.value, true)
      assert.equal(state.journalRefreshFailed.value, false)
      assert.equal(state.error.value, '')
      assert.equal(state.message.value, message)
      assert.equal(state.realtimeStatus.value, 'connected')
      assert.equal(clock.reads, reads)
    }
  }
  for (const [index, committed_at] of [
    0, 8_640_000_000_000_000, '1970-01-01T00:00:00.000Z',
    '2026-01-01T00:00:00.000Z', '+275760-09-13T00:00:00.000Z',
  ].entries()) {
    const incoming = { ...record(`valid-${index}`), committed_at }
    emit({ ...incoming, ignored: true })
    assert.deepEqual(state.commands.value[0], incoming)
    assert.equal(state.lastJournalRefreshAt.value, receipt)
  }
  assert.equal(calls.length, 1)
  assert.equal(sockets.length, 1)
  assert.equal(sockets[0].connects, 1)
  assert.equal(sockets[0].disconnects, 0)
})

test('real list helper rejects invalid date snapshots atomically and retains the previous session snapshot', async t => {
  let commands = [record('loaded')]
  let fetches = 0
  const { state, calls, sockets, clock } = fixture(t, undefined, {
    listCommands: (token, _fetcher, signal) => listCommands(token, async () => {
      fetches++
      return Response.json({ commands })
    }, signal),
  })
  state.realtime.connect(state.token.value)
  sockets[0].handlers.connect()
  prepare(state, 'list')
  await state.perform('list')
  const rows = state.commands.value
  const receipt = state.lastJournalRefreshAt.value
  const ticket = state.ticket.value
  const outcome = state.outcome.value
  const reads = clock.reads
  clock.time = 5000
  const invalidDates = [
    -1, 0.5, Number.MAX_SAFE_INTEGER + 1, 8_640_000_000_000_001,
    '1969-12-31T23:59:59.999Z',
  ]
  for (const committed_at of invalidDates) {
    commands = [record('replacement'), { ...record('invalid'), committed_at }]
    await state.perform('list')
    assert.strictEqual(state.commands.value, rows)
    assert.deepEqual(state.filteredCommands.value, [record('loaded')])
    assert.equal(state.search.value, 'journal')
    assert.equal(state.lastJournalRefreshAt.value, receipt)
    assert.equal(state.hasLoaded.value, true)
    assert.equal(state.journalRefreshFailed.value, true)
    assert.equal(state.error.value, 'Onverwacht logboekantwoord van de service.')
    assert.equal(state.message.value, '')
    assert.equal(state.busy.value, '')
    assert.equal(state.ticket.value, ticket)
    assert.equal(state.outcome.value, outcome)
    assert.equal(state.outcomeReceivedAt.value, 1000)
    assert.equal(state.lastSubmissionId.value, 'retained-id')
    assert.equal(state.realtimeStatus.value, 'connected')
    assert.equal(clock.reads, reads)
  }
  assert.equal(fetches, 1 + invalidDates.length)
  assert.equal(calls.length, 0)
  assert.equal(sockets.length, 1)
  assert.equal(sockets[0].connects, 1)
  assert.equal(sockets[0].disconnects, 0)
})

for (const conflicting of [false, true]) {
  for (const authority of ['absent', 'held', 'uncertain']) {
    test(`actual list helper rejects duplicate snapshots without changing loaded session state, conflicting=${conflicting}, authority=${authority}`, async t => {
      const responses = [
        [record('loaded')],
        [record('private-duplicate'), {
          ...record('private-duplicate'),
          ...(conflicting ? { command: 'private conflicting command', committed_at: 1051 } : {}),
        }],
        [record('replacement')],
      ]
      let fetches = 0
      const { state, calls, sockets, clock } = fixture(t, undefined, {
        listCommands: (token, _fetcher, signal) => listCommands(token, async (url, options) => {
          assert.equal(url, '/v1/commands')
          assert.equal(options.method, 'GET')
          return Response.json({ commands: responses[fetches++] })
        }, signal),
      })
      state.realtime.connect(state.token.value)
      sockets[0].handlers.connect()
      prepare(state, 'list')
      if (authority === 'absent') state.ticket.value = null
      state.revocationUncertain.value = authority === 'uncertain'
      await state.perform('list')
      const rows = state.commands.value
      const receipt = state.lastJournalRefreshAt.value
      const ticket = state.ticket.value
      const outcome = state.outcome.value
      assert.deepEqual(rows, [record('loaded')])
      assert.equal(state.canCommit.value, authority === 'held')

      clock.time = 1060
      await state.perform('list')
      assert.equal(state.commands.value, rows)
      assert.deepEqual(state.filteredCommands.value, [record('loaded')])
      assert.equal(state.search.value, 'journal')
      assert.equal(state.lastJournalRefreshAt.value, receipt)
      assert.equal(state.hasLoaded.value, true)
      assert.equal(state.journalRefreshFailed.value, true)
      assert.equal(state.error.value, 'Onverwacht logboekantwoord van de service.')
      assert.equal(state.busy.value, '')
      assert.equal(state.ticket.value, ticket)
      assert.equal(state.revocationUncertain.value, authority === 'uncertain')
      assert.equal(state.canCommit.value, authority === 'held')
      assert.equal(state.outcome.value, outcome)
      assert.equal(state.outcomeReceivedAt.value, 1000)
      assert.equal(state.lastSubmissionId.value, 'retained-id')
      assert.equal(state.realtimeStatus.value, 'connected')
      assert.equal(sockets.length, 1)
      assert.equal(sockets[0].connects, 1)
      assert.equal(sockets[0].disconnects, 0)
      assert.equal(calls.length, 0)
      assert.equal(fetches, 2)

      clock.time = 1070
      await state.perform('list')
      assert.deepEqual(state.commands.value, [record('replacement')])
      assert.deepEqual(state.filteredCommands.value, [record('replacement')])
      assert.equal(state.search.value, 'journal')
      assert.equal(state.lastJournalRefreshAt.value, 1070)
      assert.equal(state.journalRefreshFailed.value, false)
      assert.equal(state.error.value, '')
      assert.equal(state.ticket.value, ticket)
      assert.equal(state.revocationUncertain.value, authority === 'uncertain')
      assert.equal(state.canCommit.value, authority === 'held')
      assert.equal(state.outcome.value, outcome)
      assert.equal(state.outcomeReceivedAt.value, 1000)
      assert.equal(state.lastSubmissionId.value, 'retained-id')
      assert.equal(state.realtimeStatus.value, 'connected')
      assert.equal(sockets.length, 1)
      assert.equal(sockets[0].connects, 1)
      assert.equal(sockets[0].disconnects, 0)
      assert.equal(calls.length, 0)
      assert.equal(fetches, 3)
    })
  }
}

for (const newer of ['pending', 'complete']) {
  test(`actual duplicate rejection from an old session cannot affect a ${newer} newer refresh`, async t => {
    const rejected = deferred()
    const deliverFailure = deferred()
    const newerResponse = deferred()
    let fetches = 0
    const { state, calls, sockets } = fixture(t, undefined, {
      listCommands: async (token, _fetcher, signal) => {
        try {
          return await listCommands(token, async () => {
            fetches++
            return fetches === 1
              ? Response.json({ commands: [record('duplicate'), record('duplicate')] })
              : newerResponse.promise
          }, signal)
        } catch (error) {
          rejected.resolve(error)
          await deliverFailure.promise
          throw error
        }
      },
    })
    const stale = state.perform('list')
    assert.equal((await rejected.promise).message, 'Onverwacht logboekantwoord van de service.')
    state.token.value = 'new-test-session-token'
    prepare(state, 'list')
    const fresh = state.perform('list')
    if (newer === 'complete') {
      newerResponse.resolve(Response.json({ commands: [record('new-session')] }))
      await fresh
    }
    const currentState = () => JSON.parse(JSON.stringify(Object.fromEntries(Object.entries(state)
      .filter(([, value]) => isRef(value)).map(([key, value]) => [key, value.value]))))
    const before = currentState()
    deliverFailure.resolve()
    await stale
    assert.deepEqual(currentState(), before)
    if (newer === 'pending') {
      assert.equal(state.busy.value, 'list')
      newerResponse.resolve(Response.json({ commands: [record('new-session')] }))
      await fresh
    }
    assert.deepEqual(state.commands.value, [record('new-session')])
    assert.equal(state.journalRefreshFailed.value, false)
    assert.equal(state.error.value, '')
    assert.equal(state.busy.value, '')
    assert.equal(fetches, 2)
    assert.equal(calls.length, 0)
    assert.equal(sockets.length, 0)
  })
}

test('initial list failure is not a successfully loaded empty journal', async t => {
  const { state, calls } = fixture(t)
  const loading = state.perform('list')
  calls[0].reject(new Error('initial load unavailable'))
  await loading
  assert.deepEqual(state.commands.value, [])
  assert.equal(state.hasLoaded.value, false)
  assert.equal(state.lastJournalRefreshAt.value, null)
  assert.equal(state.journalRefreshFailed.value, true)
  assert.equal(state.error.value, 'initial load unavailable')
  assert.equal(state.busy.value, '')
  assert.equal(calls.length, 1)
})

for (const loaded of [[], [record('snapshot')]]) {
  test(`successful snapshot of ${loaded.length} rows replaces old rows, never reintroducing retained history`, async t => {
    const { state, calls } = fixture(t)
    prepare(state, 'list')
    const loading = state.perform('list')
    assert.deepEqual(state.commands.value, [record()])
    calls[0].resolve(loaded)
    await loading
    assert.deepEqual(state.commands.value, loaded)
    assert.equal(state.hasLoaded.value, true)
    assert.equal(state.journalRefreshFailed.value, false)
    assert.equal(state.lastJournalRefreshAt.value, 1050)
    assert.equal(state.search.value, 'journal')
  })
}

for (const settlement of ['resolve', 'reject']) {
  test(`realtime during refresh ${settlement} stays validated, deduplicated, newest-first and capped at 100`, async t => {
    const { state, calls, sockets } = fixture(t)
    state.realtime.connect(state.token.value)
    const socket = sockets[0]
    prepare(state, 'list')
    const loading = state.perform('list')
    assert.deepEqual(state.commands.value, [record()])
    for (let i = 0; i < 150; i++) {
      socket.handlers['command:committed']({ ...record(`event-${i}`), command: `match ${i}` })
    }
    socket.handlers['command:committed']({ ...record('event-100'), command: 'replacement' })
    for (let i = 0; i < 110; i++) {
      socket.handlers['command:committed']({ ...record(`invalid-${i}`), committed_at: 'not a timestamp' })
    }
    const expectedIds = ['event-100', ...Array.from({ length: 100 }, (_, i) => `event-${149 - i}`).filter(id => id !== 'event-100')]
    assert.equal(state.commands.value.length, 100)
    assert.deepEqual(state.commands.value.map(entry => entry.id), expectedIds)
    state.search.value = 'MATCH'
    assert.equal(state.filteredCommands.value.length, 99)
    if (settlement === 'resolve') {
      calls[0].resolve([record('event-100'), record('snapshot'), record('record-1')])
    } else calls[0].reject(new Error('refresh failed'))
    await loading
    assert.equal(state.commands.value.length, 100)
    assert.deepEqual(state.commands.value.map(entry => entry.id), expectedIds)
    assert.equal(state.commands.value[0].command, 'replacement')
    assert.equal(state.filteredCommands.value.length, 99)
    assert.equal(state.search.value, 'MATCH')
    assert.equal(state.hasLoaded.value, true)
    assert.equal(state.journalRefreshFailed.value, settlement === 'reject')
    assert.equal(calls.length, 1)
  })
}

test('failed initial list keeps realtime arrivals without claiming a loaded snapshot', async t => {
  const { state, calls, sockets } = fixture(t)
  state.realtime.connect(state.token.value)
  const loading = state.perform('list')
  sockets[0].handlers['command:committed'](record('during'))
  calls[0].reject(new Error('unavailable'))
  await loading
  assert.deepEqual(state.commands.value, [record('during')])
  assert.equal(state.hasLoaded.value, false)
  assert.equal(state.journalRefreshFailed.value, true)
})

for (const reset of ['manual disconnect', 'socket disconnect', 'socket error', 'reconnect']) {
  for (const settlement of ['resolve', 'reject']) {
    test(`${reset} isolates pending list ${settlement} from pre-reset snapshot and buffered events`, async t => {
      const { state, calls, sockets } = fixture(t)
      state.realtime.connect(state.token.value)
      const socket = sockets[0]
      prepare(state, 'list')
      const loading = state.perform('list')
      socket.handlers['command:committed'](record('before-reset'))
      if (reset === 'manual disconnect') state.realtime.disconnect()
      else if (reset === 'socket disconnect') socket.handlers.disconnect()
      else if (reset === 'socket error') socket.handlers.connect_error()
      else state.realtime.connect(state.token.value)
      assert.deepEqual(state.commands.value, [])
      assert.equal(state.hasLoaded.value, false)
      assert.equal(state.journalRefreshFailed.value, false)
      assert.equal(state.lastJournalRefreshAt.value, null)
      socket.handlers['command:committed'](record('stale-socket'))
      assert.deepEqual(state.commands.value, [])
      if (reset === 'reconnect') {
        sockets[1].handlers['command:committed'](record('after-reset'))
      }
      if (settlement === 'resolve') calls[0].resolve([record('old-snapshot')])
      else calls[0].reject(new Error('pre-reset failure'))
      await loading
      assert.deepEqual(state.commands.value, reset === 'reconnect' ? [record('after-reset')] : [])
      assert.equal(state.hasLoaded.value, false)
      assert.equal(state.journalRefreshFailed.value, false)
      assert.equal(state.error.value, '')
      assert.equal(state.lastJournalRefreshAt.value, null)
      assert.equal(state.message.value, '')
      assert.equal(state.busy.value, '')
      assert.equal(state.search.value, 'journal')
      const fresh = state.perform('list')
      calls[1].resolve([record('fresh-snapshot')])
      await fresh
      assert.deepEqual(state.commands.value, [record('fresh-snapshot')])
      assert.equal(state.hasLoaded.value, true)
      assert.equal(state.lastJournalRefreshAt.value, 1050)
    })
  }
}

test('journal warning clears on session and realtime resets', async t => {
  for (const reset of ['clear', 'token', 'dispose', 'disconnect', 'reconnect', 'socket reset']) {
    const { state, calls, scope, sockets } = fixture(t)
    state.realtime.connect(state.token.value)
    const loading = state.perform('list')
    calls[0].reject(new Error('failed'))
    await loading
    assert.equal(state.journalRefreshFailed.value, true)
    if (reset === 'clear') state.clearSession()
    else if (reset === 'token') state.token.value = 'replacement-token'
    else if (reset === 'dispose') scope.stop()
    else if (reset === 'disconnect') state.realtime.disconnect()
    else if (reset === 'reconnect') state.realtime.connect(state.token.value)
    else sockets[0].handlers.disconnect()
    assert.equal(state.journalRefreshFailed.value, false, reset)
    assert.deepEqual(state.commands.value, [], reset)
    assert.equal(state.hasLoaded.value, false, reset)
  }
})

test('journal UI announces refresh progress and failure independently of generic action messages', () => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  assert.match(app, /v-if="busy === 'list'" role="status" aria-live="polite">Logboek vernieuwen… Bestaande records blijven zichtbaar\./)
  assert.match(app, /v-if="journalRefreshFailed" role="alert"[^>]*>Logboek vernieuwen mislukt\. Getoonde gegevens kunnen verouderd zijn\./)
  assert.match(app, /Er worden geen automatische nieuwe pogingen gedaan\./)
})

test('journal receipt UI uses an accessible local-clock label and semantic ISO time, including epoch zero', () => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  assert.match(app, /lastJournalRefreshAt,[\s\S]*} = useSession\(\)/)
  assert.match(app, /role="status" aria-live="polite" aria-describedby="journal-receipt-help"/)
  assert.match(app, /v-if="lastJournalRefreshAt !== null">Laatste geslaagde verversing ontvangen:/)
  assert.match(app, /<time :datetime="receiptIso\(lastJournalRefreshAt\)">{{ date\(lastJournalRefreshAt\) }}<\/time>/)
  assert.match(app, /return value !== null \? new Date\(value\).toISOString\(\) : undefined/)
  assert.match(app, /v-else>Geen ontvangsttijdstip beschikbaar\./)
  assert.match(app, /Volgens de lokale klok; geen server- of audittijd en geen garantie/)
  assert.match(app, /Realtime-events vernieuwen dit ontvangsttijdstip van de snapshot niet\./)
})

test('outcome receipt samples successful current status once, accepting epoch zero and rejecting invalid clocks', async t => {
  const { state, calls, clock } = fixture(t)
  assert.equal(state.outcomeReceivedAt.value, null)
  state.lookupId.value = held().id
  const maxDate = 8_640_000_000_000_000
  for (const value of [
    0, 1075, maxDate, -1, 0.5, NaN, Infinity, -Infinity, maxDate + 1,
    Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER + 1, null, undefined, '', '1050', true, {}, [],
  ]) {
    const reads = clock.reads
    const operation = state.perform('status')
    assert.equal(state.outcome.value, null)
    assert.equal(state.outcomeReceivedAt.value, null)
    assert.equal(clock.reads, reads)
    clock.time = value
    calls.at(-1).resolve(snapshot())
    await operation
    const expected = Number.isSafeInteger(value) && value >= 0 && value <= maxDate ? value : null
    assert.equal(state.outcomeReceivedAt.value, expected, String(value))
    assert.deepEqual(state.outcome.value, snapshot())
    assert.equal(clock.reads, reads + 1)
  }
})

test('status retry clears the previous receipt immediately and failure leaves no receipt', async t => {
  const { state, calls, clock } = fixture(t)
  state.lookupId.value = held().id
  let operation = state.perform('status')
  calls[0].resolve(snapshot())
  await operation
  assert.equal(state.outcomeReceivedAt.value, 1050)
  operation = state.perform('status')
  assert.equal(state.outcome.value, null)
  assert.equal(state.outcomeReceivedAt.value, null)
  const reads = clock.reads
  calls[1].reject(new Error('failed status retry'))
  await operation
  assert.equal(state.error.value, 'failed status retry')
  assert.equal(state.outcome.value, null)
  assert.equal(state.outcomeReceivedAt.value, null)
  assert.equal(clock.reads, reads)
  operation = state.perform('status')
  clock.time = 1090
  calls[2].resolve(snapshot())
  await operation
  assert.equal(state.outcomeReceivedAt.value, 1090)
})

for (const reset of ['clearOutcome', 'lookup', 'commit', 'clearSession', 'token', 'pagehide', 'dispose']) {
  test(`${reset} clears an actually received outcome and its local receipt`, async t => {
    const { state, calls, scope, eventTarget } = fixture(t)
    prepare(state, 'status')
    const operation = state.perform('status')
    calls[0].resolve(snapshot())
    await operation
    assert.equal(state.outcomeReceivedAt.value, 1050)
    let committing
    if (reset === 'lookup') state.lookupId.value = 'other-ticket'
    else if (reset === 'token') state.token.value = 'replacement-token'
    else if (reset === 'pagehide') eventTarget.dispatchEvent(pageTransition('pagehide', true))
    else if (reset === 'dispose') scope.stop()
    else if (reset === 'commit') committing = state.perform('commit')
    else state[reset]()
    assert.equal(state.outcome.value, null)
    assert.equal(state.outcomeReceivedAt.value, null)
    if (committing) {
      calls[1].resolve(record())
      await committing
      assert.equal(state.outcomeReceivedAt.value, null)
    }
  })
}

for (const reset of ['clearOutcome', 'lookup', 'clearSession', 'token', 'pagehide', 'dispose']) {
  for (const settlement of ['resolve', 'reject']) {
    test(`${reset}: stale status ${settlement}/finally cannot stamp or clear a newer receipt`, async t => {
      const { state, calls, clock, eventTarget, scope } = fixture(t)
      state.lookupId.value = held().id
      const old = state.perform('status')
      if (reset === 'lookup') state.lookupId.value = 'other-ticket'
      else if (reset === 'token') state.token.value = 'replacement-token'
      else if (reset === 'pagehide') eventTarget.dispatchEvent(pageTransition('pagehide', true))
      else if (reset === 'dispose') scope.stop()
      else state[reset]()
      assert.equal(calls[0].signal.aborted, true)
      assert.equal(state.outcomeReceivedAt.value, null)
      if (reset !== 'dispose') state.token.value = 'new-session-token'
      state.lookupId.value = 'new-ticket'
      const newer = state.perform('status')
      const reads = clock.reads
      if (settlement === 'resolve') calls[0].resolve(snapshot())
      else calls[0].reject(new Error('stale status failure'))
      await old
      assert.equal(state.outcomeReceivedAt.value, null)
      assert.equal(clock.reads, reads)
      if (reset === 'dispose') {
        assert.equal(calls.length, 1)
        return
      }
      assert.equal(state.busy.value, 'status')
      clock.time = 1080
      calls[1].resolve(snapshot({ id: 'new-ticket' }))
      await newer
      assert.equal(state.outcomeReceivedAt.value, 1080)
      // A second stale completion after the new result must also be inert.
      const late = state.perform('status')
      state.clearOutcome()
      const latest = state.perform('status')
      calls[3].resolve(snapshot({ id: 'new-ticket' }))
      await latest
      clock.time = 1090
      const before = clock.reads
      if (settlement === 'resolve') calls[2].resolve(snapshot())
      else calls[2].reject(new Error('late status failure'))
      await late
      assert.equal(state.outcomeReceivedAt.value, 1080)
      assert.equal(state.outcome.value.id, 'new-ticket')
      assert.equal(state.busy.value, '')
      assert.equal(state.error.value, '')
      assert.equal(clock.reads, before)
    })
  }
}

test('non-status actions, input edits, realtime lifecycle/events and ticks preserve a visible outcome receipt', async t => {
  const { state, calls, clock, sockets } = fixture(t)
  prepare(state, 'status')
  let operation = state.perform('status')
  calls[0].resolve(snapshot())
  await operation
  const displayed = state.outcome.value
  for (const action of ['ticket', 'list', 'revoke']) {
    clock.time = 1070
    operation = state.perform(action)
    calls.at(-1).resolve(results[action])
    await operation
    assert.equal(state.outcome.value, displayed)
    assert.equal(state.outcomeReceivedAt.value, 1050, action)
  }
  state.command.value = 'edited'
  state.ttlMs.value = 60
  state.realtime.connect(state.token.value)
  sockets[0].handlers.connect()
  sockets[0].handlers['command:committed'](record('live'))
  sockets[0].handlers.disconnect()
  state.realtime.connect(state.token.value)
  state.realtime.disconnect()
  clock.time = 5000
  clock.tick()
  assert.equal(state.outcome.value, displayed)
  assert.equal(state.outcomeReceivedAt.value, 1050)
  assert.equal(calls.length, 4)
})

test('receipt clocks do not gate matching terminal authority or change mismatched/active authority', async t => {
  for (const localTime of [0, 8_640_000_000_000_000, NaN]) {
    for (const uncertain of [false, true]) {
      for (const kind of ['matching terminal', 'mismatched terminal', 'active']) {
        const { state, calls, clock } = fixture(t)
        prepare(state, 'status')
        state.revocationUncertain.value = uncertain
        const currentTicket = state.ticket.value
        const journal = state.commands.value
        const operation = state.perform('status')
        clock.time = localTime
        const value = kind === 'active' ? snapshot() : snapshot({
          status: 'revoked', revoked: true,
          ...(kind === 'mismatched terminal' ? { expires_at: 1101 } : {}),
        })
        calls[0].resolve(value)
        await operation
        assert.deepEqual(state.outcome.value, value)
        assert.equal(state.outcomeReceivedAt.value, Number.isNaN(localTime) ? null : localTime)
        assert.equal(state.ticket.value, kind === 'matching terminal' ? null : currentTicket)
        assert.equal(state.revocationUncertain.value, kind === 'matching terminal' ? false : uncertain)
        assert.equal(state.commands.value, journal)
        assert.equal(state.outcomeMismatch.value, kind === 'mismatched terminal')
        assert.equal(state.canCommit.value, kind !== 'matching terminal' && !uncertain)
      }
    }
  }
})

test('outcome UI separates server check time from local receipt with semantic time and honest help', () => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  assert.match(app, /outcomeReceivedAt,[\s\S]*} = useSession\(\)/)
  const result = app.match(/<div v-if="outcome" class="result">([\s\S]*?)<\/div>/)[1]
  assert.match(result, /Gecontroleerd door server: \{\{ date\(outcome.checked_at\) \}\}/)
  assert.match(result, /aria-describedby="outcome-receipt-help">Uitkomst lokaal ontvangen:/)
  assert.match(result, /<time v-if="outcomeReceivedAt !== null" :datetime="receiptIso\(outcomeReceivedAt\)">{{ date\(outcomeReceivedAt\) }}<\/time>/)
  assert.match(result, /v-else>Geen ontvangsttijdstip beschikbaar\./)
  assert.match(result, /id="outcome-receipt-help"[^>]*>Volgens de lokale klok; geen server- of audittijd en geen garantie dat de uitkomst actueel is\./)
  assert.match(result, /Controleer de status handmatig opnieuw voor een nieuwe momentopname\./)
})
