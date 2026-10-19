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
  const send = (action) => (input, token, fetcher, signal) => {
    const pending = deferred()
    calls.push({ action, input, token, fetcher, signal, ...pending })
    return pending.promise
  }
  const scope = effectScope()
  const session = scope.run(() => useRecordSession({ create: send('create'), read: send('read') }))
  t.after(() => scope.stop())
  session.token.value = 'test-only-input'
  session.plaintext.value = 'private text'
  session.recordId.value = 'record-1'
  return { session, calls, scope }
}

function state(session) {
  return Object.fromEntries(['token', 'plaintext', 'recordId', 'lastCreatedId', 'result', 'busy', 'message', 'error']
    .map(key => [key, session[key].value]))
}

const empty = { token: '', plaintext: '', recordId: '', lastCreatedId: '', result: null, busy: '', message: '', error: '' }

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

test('only a successful create replaces the confirmed ID, independently of manual reads', async (t) => {
  const { session, calls } = setup(t)
  const created = session.perform('create')
  assert.equal(session.lastCreatedId.value, '')
  calls[0].resolve({ id: 'confirmed-1' })
  await created
  assert.equal(session.lastCreatedId.value, 'confirmed-1')

  session.recordId.value = 'other-record'
  assert.equal(session.lastCreatedId.value, 'confirmed-1')
  for (const outcome of ['success', 'failure']) {
    const pending = session.perform('read')
    const call = calls.at(-1)
    assert.equal(call.input, 'other-record')
    if (outcome === 'success') call.resolve({ id: 'other-record', plaintext: 'other text' })
    else call.reject(new Error('missing record'))
    await pending
    assert.equal(session.lastCreatedId.value, 'confirmed-1')
  }

  const failed = session.perform('create')
  assert.equal(session.lastCreatedId.value, 'confirmed-1')
  calls.at(-1).reject(new Error('uncertain write'))
  await failed
  assert.equal(session.lastCreatedId.value, 'confirmed-1')
  const later = session.perform('create')
  assert.equal(session.lastCreatedId.value, 'confirmed-1')
  calls.at(-1).resolve({ id: 'confirmed-2' })
  await later
  assert.equal(session.lastCreatedId.value, 'confirmed-2')
  assert.equal(session.recordId.value, 'confirmed-2')
})

test('the shortcut reads the confirmed ID manually without creating or retrying on failure', async (t) => {
  const { session, calls } = setup(t)
  const created = session.perform('create')
  calls[0].resolve({ id: 'confirmed' })
  await created
  for (const outcome of ['success', 'failure']) {
    session.recordId.value = 'edited-id'
    const pending = session.readLastCreated()
    assert.equal(session.recordId.value, 'confirmed')
    assert.equal(calls.at(-1).action, 'read')
    assert.equal(calls.at(-1).input, 'confirmed')
    if (outcome === 'success') calls.at(-1).resolve({ id: 'confirmed', plaintext: '<b>plain text</b>' })
    else calls.at(-1).reject(new Error('read failed'))
    await pending
    assert.equal(session.lastCreatedId.value, 'confirmed')
    if (outcome === 'success') assert.equal(session.result.value.plaintext, '<b>plain text</b>')
    else assert.equal(session.error.value, 'read failed')
  }
  assert.deepEqual(calls.map(call => call.action), ['create', 'read', 'read'])
})

for (const guard of ['busy', 'blank token', 'no ID', 'disposed']) {
  test(`shortcut ${guard} guard leaves all fields unchanged and performs no request`, async (t) => {
    const { session, calls } = setup(t)
    if (guard !== 'no ID') {
      const created = session.perform('create')
      calls[0].resolve({ id: 'confirmed' })
      await created
    }
    let pending
    if (guard === 'busy') pending = session.perform('create')
    if (guard === 'blank token') session.token.value = '   '
    if (guard === 'disposed') session.dispose()
    // Exercise each guard independently, even if invalidation normally also erases the ID.
    if (guard === 'blank token' || guard === 'disposed') session.lastCreatedId.value = 'confirmed'
    session.recordId.value = 'do-not-change'
    const before = state(session)
    const count = calls.length
    await session.readLastCreated()
    assert.deepEqual(state(session), before)
    assert.equal(calls.length, count)
    if (pending) {
      calls.at(-1).reject(new Error('create failed'))
      await pending
    }
  })
}

for (const cleanup of ['clear', 'token', 'dispose', 'scope']) {
  for (const outcome of ['success', 'failure']) {
    test(`${cleanup} erases the confirmed ID and ignores stale create ${outcome}`, async (t) => {
      const { session, calls, scope } = setup(t)
      const created = session.perform('create')
      calls[0].resolve({ id: 'confirmed' })
      await created
      const stale = session.perform('create')
      if (cleanup === 'clear') session.clearSession()
      else if (cleanup === 'token') session.token.value = 'replacement'
      else if (cleanup === 'dispose') session.dispose()
      else scope.stop()
      assert.equal(session.lastCreatedId.value, '')
      assert.equal(calls[1].signal.aborted, true)

      let current
      if (cleanup === 'clear' || cleanup === 'token') {
        session.token.value = 'replacement'
        current = session.perform('create')
      }
      const before = state(session)
      if (outcome === 'success') calls[1].resolve({ id: 'stale-id' })
      else calls[1].reject(new Error('stale error'))
      await stale
      assert.deepEqual(state(session), before)
      if (current) {
        assert.equal(session.busy.value, 'create')
        calls[2].resolve({ id: 'current-id' })
        await current
        assert.equal(session.lastCreatedId.value, 'current-id')
      } else {
        await session.readLastCreated()
        assert.equal(calls.length, 2)
        assert.deepEqual(state(session), empty)
      }
    })
  }
}
