import test from 'node:test'
import assert from 'node:assert/strict'
import { createRealtime } from '../src/realtime.js'

function fixture(hooks = {}) {
  const sockets = []
  const states = []
  const entries = []
  let resets = 0
  const realtime = createRealtime({
    onEntry: (entry) => entries.push(entry),
    onStatus: (state) => { states.push(state); hooks.onStatus?.(state) },
    onReset: () => { resets++; entries.length = 0; hooks.onReset?.() },
    createSocket(options) {
      const handlers = {}
      const socket = {
        options, handlers, auth: options.auth, io: { opts: { ...options } },
        connects: 0, disconnects: 0,
        on(event, fn) { handlers[event] = fn; return socket },
        removeAllListeners() { socket.removed = true },
        connect() { socket.connects++; hooks.connect?.(socket) },
        disconnect() { socket.disconnects++; hooks.disconnect?.(socket) },
      }
      sockets.push(socket)
      hooks.createSocket?.(socket)
      return socket
    },
  })
  return { realtime, sockets, states, entries, resetCount: () => resets }
}

const record = { id: 'id', command: 'registreer', committed_at: new Date().toISOString() }

test('realtime is opt-in, same-origin and authenticates only through handshake auth', () => {
  const f = fixture()
  assert.equal(f.sockets.length, 0)
  f.realtime.connect('user-entered-test-token')
  const socket = f.sockets[0]
  assert.deepEqual(socket.options.auth, { token: 'user-entered-test-token' })
  assert.equal(socket.options.path, '/socket.io')
  assert.equal(socket.options.autoConnect, false)
  assert.equal(socket.options.reconnection, false)
  assert.equal(socket.options.withCredentials, false)
  assert.equal(socket.options.query, undefined)
  assert.equal(socket.connects, 1)
  assert.equal(f.states.at(-1), 'connecting')
  socket.handlers.connect()
  assert.equal(f.states.at(-1), 'connected')
})

test('events are validated before merge callback; untrusted fields are discarded', () => {
  const f = fixture()
  f.realtime.connect('user-entered-test-token')
  const socket = f.sockets[0]
  socket.handlers['command:committed']({ ...record, ignored: 'discard' })
  assert.deepEqual(f.entries, [record])
  for (const value of [null, {}, { ...record, id: '../bad' }, { ...record, command: 'x'.repeat(1025) }]) {
    socket.handlers['command:committed'](value)
  }
  assert.equal(f.entries.length, 1)
  const unicode = { ...record, id: 'unicode', command: '😀'.repeat(512) }
  socket.handlers['command:committed'](unicode)
  assert.deepEqual(f.entries[1], unicode)
})

test('realtime accepts 600 multibyte é characters and rejects over 1024 JavaScript units', () => {
  const f = fixture()
  f.realtime.connect('user-entered-test-token')
  const emit = f.sockets[0].handlers['command:committed']
  const multibyte = { ...record, command: 'é'.repeat(600) }
  emit(multibyte)
  assert.deepEqual(f.entries, [multibyte])
  emit({ ...record, command: 'é'.repeat(1025) })
  emit({ ...record, command: '😀'.repeat(513) })
  assert.deepEqual(f.entries, [multibyte])
})

test('token replacement clears cached entries and old credentials, ignoring late events', () => {
  const f = fixture()
  f.realtime.connect('first-user-token')
  const first = f.sockets[0]
  first.handlers['command:committed'](record)
  f.realtime.connect('second-user-token')
  assert.equal(f.entries.length, 0)
  assert.equal(first.removed, true)
  assert.deepEqual(first.auth, {})
  assert.deepEqual(first.io.opts.auth, {})
  assert.equal(first.disconnects, 1)
  assert.deepEqual(f.sockets[1].auth, { token: 'second-user-token' })
  first.handlers['command:committed'](record)
  first.handlers.connect()
  first.handlers.disconnect()
  assert.equal(f.entries.length, 0)
  assert.equal(f.states.at(-1), 'connecting')
})

test('manual disconnect and session reset clear data and all socket credentials', () => {
  const f = fixture()
  f.realtime.connect('user-entered-test-token')
  const socket = f.sockets[0]
  socket.handlers['command:committed'](record)
  f.realtime.disconnect()
  assert.equal(f.entries.length, 0)
  assert.deepEqual(socket.auth, {})
  assert.deepEqual(socket.io.opts.auth, {})
  assert.equal(f.states.at(-1), 'disconnected')
  assert.equal(f.resetCount(), 2)
})

test('server disconnect stops socket without reconnecting and reports disconnected', () => {
  const f = fixture()
  f.realtime.connect('user-entered-test-token')
  const socket = f.sockets[0]
  socket.handlers.connect()
  socket.handlers.disconnect('transport close with private detail')
  assert.equal(socket.connects, 1)
  assert.equal(socket.disconnects, 1)
  assert.deepEqual(socket.auth, {})
  assert.equal(f.states.at(-1), 'disconnected')
})

test('connection errors are generic, clear credentials and never reflect error/token details', () => {
  const f = fixture()
  f.realtime.connect('user-entered-test-token')
  const socket = f.sockets[0]
  socket.handlers.connect_error(new Error('private token details'))
  assert.equal(f.states.at(-1), 'error')
  assert.deepEqual(socket.auth, {})
  assert.deepEqual(socket.io.opts.auth, {})
  assert.equal(f.entries.length, 0)
  assert.ok(f.states.every((state) => !state.includes('private')))
})

test('invalid tokens never create sockets', () => {
  const f = fixture()
  for (const token of ['', ' ', 'bad\r\nheader']) f.realtime.connect(token)
  assert.equal(f.sockets.length, 0)
  assert.equal(f.states.at(-1), 'error')
})

function assertDetached(socket) {
  assert.equal(socket.removed, true)
  assert.deepEqual(socket.auth, {})
  assert.deepEqual(socket.io.opts.auth, {})
  assert.equal(socket.disconnects, 1)
}

function assertWinner(f, socket) {
  assert.equal(socket.connects, 1)
  assert.equal(socket.disconnects, 0)
  assert.deepEqual(socket.auth, { token: 'replacement-token' })
  assert.equal(f.states.at(-1), 'connected')
  assert.deepEqual(f.entries, [record])
}

for (const phase of ['reset', 'disconnected', 'connecting', 'factory']) {
  for (const action of ['disconnect', 'replace']) {
    test(`${action} during ${phase} cancels the older connect`, () => {
      let armed = true
      let f
      function reenter() {
        if (!armed) return
        armed = false
        if (action === 'disconnect') {
          f.realtime.disconnect()
        } else {
          f.realtime.connect('replacement-token')
          const winner = f.sockets.at(-1)
          winner.handlers.connect()
          winner.handlers['command:committed'](record)
        }
      }
      f = fixture({
        onReset: () => { if (phase === 'reset') reenter() },
        onStatus: (state) => { if (state === phase) reenter() },
        createSocket: () => { if (phase === 'factory') reenter() },
      })
      f.realtime.connect('older-token')
      if (phase === 'factory') {
        assertDetached(f.sockets[0])
        assert.equal(f.sockets[0].connects, 0)
      }
      assert.equal(f.sockets.length, (phase === 'factory' ? 1 : 0) + (action === 'replace' ? 1 : 0))
      if (action === 'replace') {
        assertWinner(f, f.sockets.at(-1))
      } else {
        assert.equal(f.states.at(-1), 'disconnected')
        assert.deepEqual(f.entries, [])
      }
    })
  }
}

for (const operation of ['connect', 'disconnect']) {
  test(`socket cleanup reentry preserves a replacement during ${operation}`, () => {
    const f = fixture()
    f.realtime.connect('older-token')
    const old = f.sockets[0]
    old.disconnect = () => {
      old.disconnects++
      f.realtime.connect('replacement-token')
      const winner = f.sockets.at(-1)
      winner.handlers.connect()
      winner.handlers['command:committed'](record)
    }
    if (operation === 'connect') f.realtime.connect('superseded-token')
    else f.realtime.disconnect()
    assert.equal(f.sockets.length, 2)
    assertDetached(old)
    const winner = f.sockets[1]
    assertWinner(f, winner)
    const states = [...f.states]
    const resets = f.resetCount()
    old.handlers.connect()
    old.handlers['command:committed']({ ...record, id: 'stale' })
    old.handlers.disconnect()
    old.handlers.connect_error(new Error('stale private details'))
    assert.deepEqual(f.states, states)
    assert.equal(f.resetCount(), resets)
    assertWinner(f, winner)
  })
}

for (const phase of ['factory', 'connect', 'stale cleanup']) {
  test(`replacement survives an older ${phase} throwing`, () => {
    let armed = true
    let f
    function replaceThenThrow(socket) {
      if (!armed) return
      armed = false
      f.realtime.connect('replacement-token')
      const winner = f.sockets.at(-1)
      winner.handlers.connect()
      winner.handlers['command:committed'](record)
      if (phase === 'stale cleanup') {
        socket.disconnect = () => { socket.disconnects++; throw new Error('private cleanup details') }
      } else {
        throw new Error('private connection details')
      }
    }
    f = fixture({
      createSocket: (socket) => { if (phase !== 'connect') replaceThenThrow(socket) },
      connect: (socket) => { if (phase === 'connect') replaceThenThrow(socket) },
    })
    f.realtime.connect('older-token')
    assert.equal(f.sockets.length, 2)
    assertWinner(f, f.sockets[1])
    if (phase === 'stale cleanup') assertDetached(f.sockets[0])
    assert.ok(f.states.every((state) => !state.includes('private')))
  })
}

for (const phase of ['factory', 'connect']) {
  test(`${phase} failures without reentry still clear data and report a generic error`, () => {
    const fail = () => { throw new Error('private connection details') }
    const f = fixture({ [phase === 'factory' ? 'createSocket' : 'connect']: fail })
    f.realtime.connect('user-entered-test-token')
    assert.equal(f.states.at(-1), 'error')
    assert.deepEqual(f.entries, [])
    if (phase === 'connect') assertDetached(f.sockets[0])
  })
}
