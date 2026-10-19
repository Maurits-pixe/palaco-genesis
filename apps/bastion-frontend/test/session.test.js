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
  state.hasLoaded.value = true
  state.message.value = 'previous message'
  state.error.value = 'previous error'
  if (action === 'revoke') state.revocationUncertain.value = true
}

function assertEmpty(state, token = '') {
  for (const key of ['command', 'busy', 'message', 'error', 'lookupId', 'lastSubmissionId']) {
    assert.equal(state[key].value, '', key)
  }
  assert.equal(state.token.value, token)
  assert.equal(state.ticket.value, null)
  assert.equal(state.revocationUncertain.value, false)
  assert.deepEqual(state.commands.value, [])
  assert.equal(state.hasLoaded.value, false)
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
