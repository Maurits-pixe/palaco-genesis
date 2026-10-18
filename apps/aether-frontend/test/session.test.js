import test from 'node:test'
import assert from 'node:assert/strict'
import { effectScope } from 'vue'
import { useRecordSession } from '../src/session.js'

function deferred() {
  let resolve, reject
  const promise = new Promise((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}

function setup(t) {
  const calls = []
  const send = (input, token, fetcher, signal) => {
    const pending = deferred()
    calls.push({ input, token, fetcher, signal, ...pending })
    return pending.promise
  }
  const scope = effectScope()
  const session = scope.run(() => useRecordSession({ create: send, read: send }))
  t.after(() => scope.stop())
  session.token.value = 'test-only-input'
  session.plaintext.value = 'private text'
  session.recordId.value = 'record-1'
  return { session, calls, scope }
}

function state(session) {
  return Object.fromEntries(['token', 'plaintext', 'recordId', 'result', 'busy', 'message', 'error']
    .map(key => [key, session[key].value]))
}

const empty = { token: '', plaintext: '', recordId: '', result: null, busy: '', message: '', error: '' }

for (const action of ['read', 'create']) {
  test(`clearing a pending ${action} wipes immediately and ignores late success`, async (t) => {
    const { session, calls } = setup(t)
    const pending = session.perform(action)
    session.message.value = 'old message'
    session.error.value = 'old error'
    session.result.value = { plaintext: 'old result' }
    session.clearSession()
    assert.deepEqual(state(session), empty)
    assert.equal(calls[0].signal.aborted, true)
    calls[0].resolve({ id: 'late', plaintext: 'late private text' })
    await pending
    assert.deepEqual(state(session), empty)
  })
}

test('token change invalidates a pending request synchronously', async (t) => {
  const { session, calls } = setup(t)
  const pending = session.perform('read')
  session.token.value = 'replacement-input'
  assert.deepEqual(state(session), { ...empty, token: 'replacement-input' })
  assert.equal(calls[0].signal.aborted, true)
  calls[0].reject(new Error('old failure'))
  await pending
  assert.deepEqual(state(session), { ...empty, token: 'replacement-input' })
})

for (const outcome of ['success', 'failure']) {
  test(`stale ${outcome} and finally cannot affect a new busy request`, async (t) => {
    const { session, calls } = setup(t)
    const old = session.perform('create')
    session.clearSession()
    session.token.value = 'new-input'
    session.recordId.value = 'new-id'
    const current = session.perform('read')
    const waiting = state(session)
    assert.equal(waiting.busy, 'read')
    if (outcome === 'success') calls[0].resolve({ id: 'old-id' })
    else calls[0].reject(new Error('old error'))
    await old
    assert.deepEqual(state(session), waiting)
    assert.equal(calls[1].signal.aborted, false)
    calls[1].resolve({ id: 'new-id', plaintext: 'new text' })
    await current
    assert.deepEqual(session.result.value, { id: 'new-id', plaintext: 'new text' })
    assert.equal(session.message.value, 'Record opgehaald.')
    assert.equal(session.busy.value, '')
    assert.equal(session.error.value, '')
  })
}

for (const cleanup of ['scope', 'dispose']) {
  test(`${cleanup} cleanup aborts, wipes, and prevents later work`, async (t) => {
    const { session, calls, scope } = setup(t)
    const pending = session.perform('read')
    if (cleanup === 'scope') scope.stop()
    else session.dispose()
    assert.equal(calls[0].signal.aborted, true)
    assert.deepEqual(state(session), empty)
    calls[0].resolve({ id: 'record-1', plaintext: 'late' })
    await pending
    await session.perform('create')
    assert.equal(calls.length, 1)
    assert.deepEqual(state(session), empty)
    session.dispose()
  })
}

test('current create success, read success, errors, and busy guard remain valid', async (t) => {
  const { session, calls } = setup(t)
  const created = session.perform('create')
  await session.perform('read')
  assert.equal(calls.length, 1)
  assert.equal(calls[0].input, 'private text')
  assert.equal(calls[0].token, 'test-only-input')
  assert.equal(calls[0].fetcher, undefined)
  calls[0].resolve({ id: 'created-id' })
  await created
  assert.equal(session.recordId.value, 'created-id')
  assert.equal(session.plaintext.value, '')
  assert.match(session.message.value, /Record opgeslagen/)
  assert.equal(session.busy.value, '')
  session.recordId.value = '  created-id  '
  const read = session.perform('read')
  assert.equal(calls[1].input, 'created-id')
  calls[1].resolve({ id: 'created-id', plaintext: '<b>text</b>' })
  await read
  assert.equal(session.result.value.plaintext, '<b>text</b>')
  const failed = session.perform('read')
  assert.equal(session.result.value, null)
  assert.equal(session.message.value, '')
  calls[2].reject(new Error('current error'))
  await failed
  assert.equal(session.error.value, 'current error')
  assert.equal(session.busy.value, '')
})
