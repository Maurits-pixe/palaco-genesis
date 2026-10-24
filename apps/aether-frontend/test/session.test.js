import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { effectScope } from 'vue'
import { useRecordSession } from '../src/session.js'

function deferred() {
  let resolve, reject
  const promise = new Promise((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}

function setup(t, eventTarget = new EventTarget()) {
  const calls = []
  const send = (action) => (input, token, fetcher, signal) => {
    const pending = deferred()
    calls.push({ action, input, token, fetcher, signal, ...pending })
    return pending.promise
  }
  const scope = effectScope()
  const session = scope.run(() => useRecordSession({ create: send('create'), read: send('read'), eventTarget }))
  t.after(() => scope.stop())
  session.token.value = 'test-only-input'
  session.plaintext.value = 'private text'
  session.recordId.value = 'record-1'
  return { session, calls, scope, eventTarget }
}

function state(session) {
  return Object.fromEntries(['token', 'plaintext', 'recordId', 'lastCreatedId', 'result', 'busy', 'message', 'error']
    .map(key => [key, session[key].value]))
}

const empty = { token: '', plaintext: '', recordId: '', lastCreatedId: '', result: null, busy: '', message: '', error: '' }

function pageTransition(type, persisted) {
  const event = new Event(type)
  Object.defineProperty(event, 'persisted', { value: persisted })
  return event
}

for (const persisted of [false, true]) {
  test(`pagehide persisted=${persisted} clears loaded state without automatically restoring it`, async (t) => {
    const { session, calls, eventTarget } = setup(t)
    session.lastCreatedId.value = 'confirmed'
    const pending = session.perform('read')
    calls[0].resolve({ id: 'record-1', plaintext: 'loaded text' })
    await pending
    session.error.value = 'old feedback'
    eventTarget.dispatchEvent(pageTransition('pagehide', persisted))
    assert.deepEqual(state(session), empty)
    eventTarget.dispatchEvent(pageTransition('pageshow', persisted))
    assert.deepEqual(state(session), empty)
    assert.equal(calls.length, 1)
    session.token.value = 'fresh-token'
    session.recordId.value = 'fresh-id'
    const current = session.perform('read')
    assert.equal(calls[1].token, 'fresh-token')
    calls[1].resolve({ id: 'fresh-id', plaintext: 'fresh text' })
    await current
    assert.equal(session.result.value.plaintext, 'fresh text')
  })

  for (const action of ['read', 'create']) {
    for (const outcome of ['success', 'failure']) {
      for (const next of ['idle', 'read', 'create']) {
        test(`pagehide persisted=${persisted} aborts ${action}, ignores stale ${outcome} while ${next}`, async (t) => {
          const { session, calls, eventTarget } = setup(t)
          session.lastCreatedId.value = 'confirmed'
          const stale = session.perform(action)
          session.result.value = { plaintext: 'old content' }
          session.message.value = 'old feedback'
          session.error.value = 'old error'
          eventTarget.dispatchEvent(pageTransition('pagehide', persisted))
          assert.deepEqual(state(session), empty)
          assert.equal(calls[0].signal.aborted, true)
          eventTarget.dispatchEvent(pageTransition('pageshow', persisted))
          assert.deepEqual(state(session), empty)
          assert.equal(calls.length, 1)

          let current
          if (next !== 'idle') {
            session.token.value = 'fresh-token'
            session.recordId.value = 'fresh-id'
            session.plaintext.value = 'fresh text'
            current = session.perform(next)
            assert.equal(calls[1].token, 'fresh-token')
            assert.equal(calls[1].input, next === 'read' ? 'fresh-id' : 'fresh text')
          }
          const before = state(session)
          if (outcome === 'success') calls[0].resolve({ id: 'stale-id', plaintext: 'stale text' })
          else calls[0].reject(new Error('stale error'))
          await stale
          assert.deepEqual(state(session), before)
          assert.equal(calls.length, next === 'idle' ? 1 : 2)
          if (current) {
            assert.equal(calls[1].signal.aborted, false)
            calls[1].resolve({ id: 'fresh-id', plaintext: 'fresh text' })
            await current
            assert.equal(session.busy.value, '')
            assert.equal(session.error.value, '')
            if (next === 'read') assert.equal(session.result.value.plaintext, 'fresh text')
            else assert.equal(session.lastCreatedId.value, 'fresh-id')
          }
        })
      }
    }
  }
}

for (const cleanup of ['dispose', 'scope']) {
  test(`${cleanup} removes the exact pagehide listener before aborting and leaves disposed refs alone`, async (t) => {
    const added = []
    const removed = []
    class LifecycleTarget extends EventTarget {
      addEventListener(...args) {
        added.push(args)
        super.addEventListener(...args)
      }
      removeEventListener(...args) {
        removed.push(args)
        super.removeEventListener(...args)
      }
    }
    const { session, calls, scope, eventTarget } = setup(t, new LifecycleTarget())
    const pending = session.perform('read')
    assert.equal(added.length, 1)
    assert.equal(added[0][0], 'pagehide')
    calls[0].signal.addEventListener('abort', () => {
      assert.equal(removed.length, 1)
      assert.deepEqual(removed[0], added[0])
    }, { once: true })
    if (cleanup === 'scope') scope.stop()
    else session.dispose()
    assert.equal(removed.length, 1)
    assert.deepEqual(removed[0], added[0])
    assert.equal(calls[0].signal.aborted, true)
    assert.deepEqual(state(session), empty)
    for (const key of Object.keys(empty)) {
      session[key].value = key === 'result' ? { plaintext: 'sentinel' } : 'sentinel'
    }
    const before = state(session)
    for (const persisted of [false, true]) {
      eventTarget.dispatchEvent(pageTransition('pagehide', persisted))
      assert.deepEqual(state(session), before)
    }
    calls[0].resolve({ id: 'stale-id', plaintext: 'stale text' })
    await pending
    assert.deepEqual(state(session), before)
  })
}

test('ordinary hide and visibility changes leave loaded state intact', async (t) => {
  const { session, calls, eventTarget } = setup(t)
  const pending = session.perform('read')
  calls[0].resolve({ id: 'record-1', plaintext: 'loaded text' })
  await pending
  const before = state(session)
  eventTarget.dispatchEvent(new Event('hide'))
  eventTarget.dispatchEvent(new Event('visibilitychange'))
  assert.deepEqual(state(session), before)
  assert.equal(calls.length, 1)
})

test('default lifecycle dependency is safe without a browser window', () => {
  assert.equal(globalThis.window, undefined)
  const session = useRecordSession()
  session.token.value = 'node-input'
  session.dispose()
  assert.deepEqual(state(session), empty)
})

test('changing the loaded result ID clears only read state synchronously without refetching', async (t) => {
  const { session, calls } = setup(t)
  session.lastCreatedId.value = 'confirmed'
  const pending = session.perform('read')
  calls[0].resolve({ id: 'record-1', plaintext: 'loaded text' })
  await pending
  const before = state(session)
  session.recordId.value = '  record-2  '
  assert.deepEqual(state(session), {
    ...before, recordId: '  record-2  ', result: null, message: '', error: '',
  })
  assert.equal(calls.length, 1)
  assert.equal(calls[0].signal.aborted, false)
})

test('normalized whitespace edits preserve both pending reads and loaded results', async (t) => {
  const { session, calls } = setup(t)
  const pending = session.perform('read')
  const before = state(session)
  session.recordId.value = ' \trecord-1\n '
  assert.deepEqual(state(session), { ...before, recordId: ' \trecord-1\n ' })
  assert.equal(calls[0].signal.aborted, false)
  calls[0].resolve({ id: 'record-1', plaintext: 'loaded text' })
  await pending
  const loaded = state(session)
  session.recordId.value = 'record-1'
  assert.deepEqual(state(session), { ...loaded, recordId: 'record-1' })
  assert.equal(calls.length, 1)
})

test('ID edits clear read errors but preserve idle create feedback', async (t) => {
  const { session, calls } = setup(t)
  for (const action of ['read', 'create']) {
    const pending = session.perform(action)
    calls.at(-1).reject(new Error(`${action} failed`))
    await pending
    const before = state(session)
    session.recordId.value = `${action}-other`
    assert.deepEqual(state(session), {
      ...before, recordId: `${action}-other`, error: action === 'read' ? '' : 'create failed',
    })
  }
  const created = session.perform('create')
  session.recordId.value = 'edited-during-create'
  assert.equal(session.busy.value, 'create')
  assert.equal(calls[2].signal.aborted, false)
  calls[2].resolve({ id: 'confirmed' })
  await created
  assert.equal(session.recordId.value, 'confirmed')
  assert.equal(session.lastCreatedId.value, 'confirmed')
  assert.match(session.message.value, /Record opgeslagen/)
  assert.equal(calls[2].signal.aborted, false)
  const before = state(session)
  session.recordId.value = 'edited-after-create'
  assert.deepEqual(state(session), { ...before, recordId: 'edited-after-create' })
  assert.equal(calls.length, 3)
})

for (const outcome of ['success', 'failure']) {
  for (const next of ['idle', 'read', 'create']) {
    test(`ID change aborts pending read and ignores late ${outcome} while ${next}`, async (t) => {
      const { session, calls } = setup(t)
      session.lastCreatedId.value = 'confirmed'
      const stale = session.perform('read')
      const before = state(session)
      let atAbort
      calls[0].signal.addEventListener('abort', () => { atAbort = state(session) }, { once: true })
      session.recordId.value = '  next-id  '
      const cleared = { ...before, recordId: '  next-id  ', busy: '', result: null, message: '', error: '' }
      assert.deepEqual(state(session), cleared)
      assert.deepEqual(atAbort, cleared)
      assert.equal(calls[0].signal.aborted, true)
      assert.equal(calls.length, 1)
      const current = next === 'idle' ? undefined : session.perform(next)
      const waiting = state(session)
      if (outcome === 'success') calls[0].resolve({ id: 'record-1', plaintext: 'stale text' })
      else calls[0].reject(new Error('stale error'))
      await stale
      assert.deepEqual(state(session), waiting)
      if (current) {
        assert.equal(calls[1].signal.aborted, false)
        assert.equal(calls[1].input, next === 'read' ? 'next-id' : before.plaintext)
        calls[1].resolve({ id: 'next-id', plaintext: 'current text' })
        await current
        assert.equal(session.busy.value, '')
        assert.equal(session.error.value, '')
        if (next === 'read') assert.deepEqual(session.result.value, { id: 'next-id', plaintext: 'current text' })
        else {
          assert.equal(session.lastCreatedId.value, 'next-id')
          assert.match(session.message.value, /Record opgeslagen/)
        }
      }
    })
  }
}

test('ID change invalidates identity before abort callbacks start a new request', async (t) => {
  const { session, calls } = setup(t)
  const stale = session.perform('read')
  let current
  calls[0].signal.addEventListener('abort', () => {
    current = session.perform('read')
    calls[0].reject(new Error('aborted'))
  }, { once: true })
  session.recordId.value = 'next-id'
  await stale
  assert.equal(session.busy.value, 'read')
  assert.equal(calls[1].input, 'next-id')
  assert.equal(calls[1].signal.aborted, false)
  calls[1].resolve({ id: 'next-id', plaintext: 'current text' })
  await current
  assert.equal(session.result.value.id, 'next-id')
})

for (const cleanup of ['clear', 'token', 'scope']) {
  test(`${cleanup} still wipes a loaded result after normalized ID edits`, async (t) => {
    const { session, calls, scope } = setup(t)
    session.lastCreatedId.value = 'confirmed'
    const pending = session.perform('read')
    calls[0].resolve({ id: 'record-1', plaintext: 'loaded text' })
    await pending
    session.recordId.value = ' record-1 '
    if (cleanup === 'clear') session.clearSession()
    else if (cleanup === 'token') session.token.value = 'replacement'
    else scope.stop()
    assert.deepEqual(state(session), { ...empty, token: cleanup === 'token' ? 'replacement' : '' })
  })
}

test('scope disposal stops both watchers and future requests', async (t) => {
  const { session, calls, scope } = setup(t)
  const pending = session.perform('read')
  scope.stop()
  assert.equal(calls[0].signal.aborted, true)
  assert.deepEqual(state(session), empty)
  session.result.value = { id: 'sentinel', plaintext: 'unchanged' }
  session.message.value = 'unchanged'
  session.error.value = 'unchanged'
  session.token.value = 'after-disposal'
  session.recordId.value = 'after-disposal'
  const before = state(session)
  calls[0].resolve({ id: 'stale', plaintext: 'stale' })
  await pending
  await session.perform('read')
  assert.deepEqual(state(session), before)
  assert.equal(calls.length, 1)
})

test('clearing a loaded read retains credentials, both IDs and unsaved input; refetch and full clear work', async (t) => {
  const { session, calls } = setup(t)
  const created = session.perform('create')
  calls[0].resolve({ id: 'confirmed' })
  await created
  session.recordId.value = '  edited-id  '
  session.plaintext.value = '  unsaved private text  '
  const loaded = session.perform('read')
  calls[1].resolve({ id: 'edited-id', plaintext: 'loaded text' })
  await loaded
  const before = state(session)
  session.clearReadResult()
  const cleared = { ...before, result: null, message: '', error: '' }
  assert.deepEqual(state(session), cleared)
  session.clearReadResult()
  assert.deepEqual(state(session), cleared)
  assert.equal(calls.length, 2)
  assert.equal(calls[1].signal.aborted, false)

  const refetch = session.perform('read')
  assert.equal(calls[2].input, 'edited-id')
  assert.equal(calls[2].token, before.token)
  calls[2].resolve({ id: 'edited-id', plaintext: 'fresh text' })
  await refetch
  assert.equal(session.result.value.plaintext, 'fresh text')
  assert.equal(session.plaintext.value, before.plaintext)
  session.clearSession()
  assert.deepEqual(state(session), empty)
})

test('idle clear removes read errors, is idempotent and sends no requests', async (t) => {
  const { session, calls } = setup(t)
  const pending = session.perform('read')
  calls[0].reject(new Error('read failed'))
  await pending
  assert.equal(session.error.value, 'read failed')
  const before = state(session)
  for (let count = 0; count < 3; count++) {
    session.clearReadResult()
    assert.deepEqual(state(session), { ...before, message: '', error: '' })
    assert.equal(calls.length, 1)
  }
})

for (const outcome of ['success', 'failure']) {
  for (const next of ['idle', 'read', 'create']) {
    test(`read-result clear aborts pending read and ignores late ${outcome} while ${next}`, async (t) => {
      const { session, calls } = setup(t)
      session.lastCreatedId.value = 'confirmed'
      const stale = session.perform('read')
      session.message.value = 'old read message'
      session.error.value = 'old read error'
      session.result.value = { plaintext: 'old read content' }
      const before = state(session)
      let atAbort
      calls[0].signal.addEventListener('abort', () => { atAbort = state(session) }, { once: true })
      session.clearReadResult()
      const cleared = { ...before, busy: '', result: null, message: '', error: '' }
      assert.deepEqual(atAbort, cleared)
      assert.deepEqual(state(session), cleared)
      assert.equal(calls[0].signal.aborted, true)
      assert.equal(calls.length, 1)

      const current = next === 'idle' ? undefined : session.perform(next)
      const waiting = state(session)
      if (outcome === 'success') calls[0].resolve({ id: 'stale-id', plaintext: 'stale content' })
      else calls[0].reject(new Error('stale failure'))
      await stale
      assert.deepEqual(state(session), waiting)
      if (current) {
        assert.equal(session.busy.value, next)
        assert.equal(calls[1].signal.aborted, false)
        calls[1].resolve({ id: 'current-id', plaintext: 'current text' })
        await current
        assert.equal(session.busy.value, '')
        if (next === 'read') assert.equal(session.result.value.plaintext, 'current text')
        else {
          assert.equal(session.lastCreatedId.value, 'current-id')
          assert.equal(session.plaintext.value, '')
        }
      }
    })
  }
}

test('read-result clear invalidates the old identity before synchronous abort callbacks start a new request', async (t) => {
  const { session, calls } = setup(t)
  const stale = session.perform('read')
  let current
  calls[0].signal.addEventListener('abort', () => {
    current = session.perform('create')
    calls[0].reject(new Error('aborted read'))
  }, { once: true })
  session.clearReadResult()
  await stale
  assert.equal(session.busy.value, 'create')
  assert.equal(calls[1].signal.aborted, false)
  calls[1].resolve({ id: 'created-after-abort' })
  await current
  assert.equal(session.lastCreatedId.value, 'created-after-abort')
})

for (const guard of ['create', 'disposed']) {
  test(`read-result clear is a complete no-op during ${guard}`, async (t) => {
    const { session, calls } = setup(t)
    const pending = session.perform('create')
    if (guard === 'disposed') session.dispose()
    session.result.value = { plaintext: 'unchanged content' }
    session.message.value = 'unchanged message'
    session.error.value = 'unchanged error'
    session.lastCreatedId.value = 'unchanged-id'
    const before = state(session)
    const aborted = calls[0].signal.aborted
    let aborts = 0
    calls[0].signal.addEventListener('abort', () => { aborts++ })
    session.clearReadResult()
    assert.deepEqual(state(session), before)
    assert.equal(calls.length, 1)
    assert.equal(calls[0].signal.aborted, aborted)
    assert.equal(aborts, 0)
    calls[0].resolve({ id: 'created-id' })
    await pending
    if (guard === 'disposed') assert.deepEqual(state(session), before)
    else {
      assert.equal(session.lastCreatedId.value, 'created-id')
      assert.equal(session.plaintext.value, '')
      assert.match(session.message.value, /Record opgeslagen/)
    }
  })
}

test('read-result clear UI is local, explicitly typed, and enabled only for a result or pending read', async () => {
  const source = await readFile(new URL('../src/App.vue', import.meta.url), 'utf8')
  assert.match(source, /const \{[^}]*clearReadResult[^}]*\} = useRecordSession\(\)/)
  assert.match(source, /<button type="button"[^>]*:disabled="busy === 'create' \|\| \(!result && busy !== 'read'\)"[^>]*aria-describedby="clear-read-help"[^>]*@click="clearReadResult">Wis gelezen inhoud<\/button>/)
  assert.match(source, /id="clear-read-help"[^>]*>Wist alleen het lokale leesresultaat/)
  assert.match(source, /Verwijdert niets uit de database en garandeert geen veilige geheugenwissing/)
  assert.match(source, /Haal het record opnieuw op om de inhoud weer te bekijken/)
  assert.match(source, /<input id="record-id"[^>]*aria-describedby="record-id-help"/)
  assert.match(source, /id="record-id-help"[^>]*>Een ander record-ID wist alleen het lokale leesresultaat en stopt lokaal wachten/)
  assert.match(source, /Verwijdert niets uit de database; haalt niet automatisch een record op/)
  assert.match(source, /<div v-if="result" class="result"><h3>Leesbare inhoud<\/h3><p>Record-ID: \{\{ result\.id \}\}<\/p><pre>\{\{ result\.plaintext \}\}<\/pre><\/div>/)
})

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
