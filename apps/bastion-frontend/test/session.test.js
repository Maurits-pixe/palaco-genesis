import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { effectScope } from 'vue'
import { useSession } from '../src/useSession.js'
import { createRealtime } from '../src/realtime.js'

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

function fixture(t) {
  const scope = effectScope()
  const calls = []
  const sockets = []
  const clock = { time: 1050, tick: null, cleared: [], interval: null }
  const api = Object.fromEntries(Object.entries(actions).map(([action, name]) => [name, (...args) => {
    const call = { action, args, signal: args.at(-1), ...deferred() }
    calls.push(call)
    return call.promise
  }]))
  const state = scope.run(() => useSession({
    api,
    scheduler: {
      now: () => clock.time,
      setInterval(callback, interval) { clock.tick = callback; clock.interval = interval; return 42 },
      clearInterval(id) { clock.cleared.push(id) },
    },
    realtimeFactory: callbacks => createRealtime({
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
      },
    }),
  }))
  t.after(() => scope.stop())
  state.token.value = 'test-session-token'
  return { state, scope, calls, sockets, clock }
}

function prepare(state, action) {
  state.command.value = 'journal only'
  state.ttlMs.value = 50
  state.ticket.value = held()
  state.lookupId.value = held().id
  state.outcome.value = snapshot()
  state.lastSubmissionId.value = 'retained-id'
  state.commands.value = [record()]
  state.search.value = 'journal'
  state.hasLoaded.value = true
  state.journalRefreshFailed.value = true
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
  assert.equal(state.outcome.value, null)
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

test('initial list failure is not a successfully loaded empty journal', async t => {
  const { state, calls } = fixture(t)
  const loading = state.perform('list')
  calls[0].reject(new Error('initial load unavailable'))
  await loading
  assert.deepEqual(state.commands.value, [])
  assert.equal(state.hasLoaded.value, false)
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
      assert.equal(state.message.value, '')
      assert.equal(state.busy.value, '')
      assert.equal(state.search.value, 'journal')
      const fresh = state.perform('list')
      calls[1].resolve([record('fresh-snapshot')])
      await fresh
      assert.deepEqual(state.commands.value, [record('fresh-snapshot')])
      assert.equal(state.hasLoaded.value, true)
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
