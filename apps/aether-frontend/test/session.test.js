import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { computed, effectScope, ref } from 'vue'
import { useRecordSession } from '../src/session.js'

function deferred() {
  let resolve, reject
  const promise = new Promise((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}

function setup(t, eventTarget = new EventTarget(), options = {}) {
  const calls = []
  const send = (action) => (input, token, fetcher, signal) => {
    const pending = deferred()
    calls.push({ action, input, token, fetcher, signal, ...pending })
    return pending.promise
  }
  const scope = effectScope()
  const session = scope.run(() => useRecordSession({ create: send('create'), read: send('read'), eventTarget, ...options }))
  t.after(() => scope.stop())
  session.token.value = 'test-only-input'
  session.plaintext.value = 'private text'
  session.recordId.value = 'record-1'
  return { session, calls, scope, eventTarget }
}

function state(session) {
  return Object.fromEntries(['token', 'plaintext', 'recordId', 'lastCreatedId', 'result', 'resultReceivedAt', 'busy', 'message', 'error']
    .map(key => [key, session[key].value]))
}

const empty = { token: '', plaintext: '', recordId: '', lastCreatedId: '', result: null, resultReceivedAt: null, busy: '', message: '', error: '' }

test('default clock stamps a successful read only after it resolves, not create or failure', async (t) => {
  let now = 100
  let clockCalls = 0
  t.mock.method(Date, 'now', () => { clockCalls++; return now })
  const { session, calls } = setup(t)
  assert.equal(session.resultReceivedAt.value, null)
  const pending = session.perform('read')
  assert.equal(clockCalls, 0)
  assert.equal(session.resultReceivedAt.value, null)
  now = 200
  calls[0].resolve({ id: 'record-1', plaintext: 'loaded' })
  await pending
  assert.equal(clockCalls, 1)
  assert.equal(session.resultReceivedAt.value, 200)
  const failed = session.perform('read')
  assert.equal(session.result.value, null)
  assert.equal(session.resultReceivedAt.value, null)
  calls[1].reject(new Error('read failed'))
  await failed
  const created = session.perform('create')
  calls[2].resolve({ id: 'created' })
  await created
  assert.equal(clockCalls, 1)
  assert.equal(session.result.value, null)
  assert.equal(session.resultReceivedAt.value, null)
})

for (const now of [0, 1, 1700000000123, 8640000000000000]) {
  test(`injected clock accepts Date-representable receipt ${now}`, async (t) => {
    let clockCalls = 0
    const { session, calls } = setup(t, undefined, { getNow: () => { clockCalls++; return now } })
    const pending = session.perform('read')
    assert.equal(clockCalls, 0)
    calls[0].resolve({ id: 'record-1', plaintext: 'loaded' })
    await pending
    assert.equal(clockCalls, 1)
    assert.equal(session.resultReceivedAt.value, now)
    assert.equal(session.result.value.plaintext, 'loaded')
    assert.equal(session.message.value, 'Record opgehaald.')
    assert.equal(session.error.value, '')
    assert.equal(session.busy.value, '')
  })
}

const invalidClocks = [
  ['null', null], ['undefined', undefined], ['numeric string', '1700000000123'],
  ['empty string', ''], ['negative', -1], ['fraction', 1.5], ['NaN', NaN],
  ['Infinity', Infinity], ['negative Infinity', -Infinity], ['bigint', 0n],
  ['symbol', Symbol('clock')], ['outside Date range', 8640000000000001],
  ['unsafe integer', Number.MAX_SAFE_INTEGER + 1], ['boolean', false],
  ['Date object', new Date(0)], ['boxed number', new Number(0)],
  ['coercion trap', { valueOf() { throw new Error('must not coerce') } }],
]
for (const [label, now] of invalidClocks) {
  test(`invalid local clock (${label}) leaves a successful read visible without a receipt`, async (t) => {
    const { session, calls } = setup(t, undefined, { getNow: () => now })
    const pending = session.perform('read')
    calls[0].resolve({ id: 'record-1', plaintext: 'loaded' })
    await pending
    assert.equal(session.resultReceivedAt.value, null)
    assert.deepEqual(session.result.value, { id: 'record-1', plaintext: 'loaded' })
    assert.equal(session.message.value, 'Record opgehaald.')
    assert.equal(session.error.value, '')
    assert.equal(session.busy.value, '')
  })
}

test('throwing local clock cannot turn a successful read into an error', async (t) => {
  const { session, calls } = setup(t, undefined, { getNow: () => { throw new Error('clock failed') } })
  const pending = session.perform('read')
  calls[0].resolve({ id: 'record-1', plaintext: 'loaded' })
  await pending
  assert.equal(session.resultReceivedAt.value, null)
  assert.equal(session.result.value.plaintext, 'loaded')
  assert.equal(session.message.value, 'Record opgehaald.')
  assert.equal(session.error.value, '')
  assert.equal(session.busy.value, '')
})

for (const cleanup of ['retry read', 'create', 'selective clear', 'ID edit', 'token clear', 'session clear', 'pagehide', 'dispose', 'scope']) {
  test(`${cleanup} synchronously clears a loaded result and its receipt together`, async (t) => {
    const { session, calls, eventTarget, scope } = setup(t, undefined, { getNow: () => 0 })
    session.lastCreatedId.value = 'confirmed'
    const loaded = session.perform('read')
    calls[0].resolve({ id: 'record-1', plaintext: 'loaded' })
    await loaded
    assert.equal(session.resultReceivedAt.value, 0)
    const before = state(session)
    let pending
    if (cleanup === 'retry read') pending = session.perform('read')
    else if (cleanup === 'create') pending = session.perform('create')
    else if (cleanup === 'selective clear') session.clearReadResult()
    else if (cleanup === 'ID edit') session.recordId.value = 'other'
    else if (cleanup === 'token clear') session.token.value = ''
    else if (cleanup === 'session clear') session.clearSession()
    else if (cleanup === 'pagehide') eventTarget.dispatchEvent(pageTransition('pagehide', true))
    else if (cleanup === 'dispose') session.dispose()
    else scope.stop()
    assert.equal(session.result.value, null)
    assert.equal(session.resultReceivedAt.value, null)
    if (['retry read', 'create', 'selective clear', 'ID edit'].includes(cleanup)) {
      assert.equal(session.token.value, before.token)
      assert.equal(session.plaintext.value, before.plaintext)
      assert.equal(session.lastCreatedId.value, before.lastCreatedId)
    } else assert.deepEqual(state(session), empty)
    if (pending) {
      calls[1].reject(new Error('request failed'))
      await pending
      assert.equal(session.result.value, null)
      assert.equal(session.resultReceivedAt.value, null)
    }
  })
}

test('trim-equivalent ID edits retain the result and receipt without reading the clock again', async (t) => {
  let clockCalls = 0
  const { session, calls } = setup(t, undefined, { getNow: () => { clockCalls++; return 0 } })
  const pending = session.perform('read')
  calls[0].resolve({ id: 'record-1', plaintext: 'loaded' })
  await pending
  const before = state(session)
  session.recordId.value = ' \trecord-1\n '
  assert.deepEqual(state(session), { ...before, recordId: ' \trecord-1\n ' })
  assert.equal(clockCalls, 1)
  assert.equal(calls.length, 1)
})

for (const cleanup of ['selective clear', 'ID edit', 'token clear', 'pagehide', 'dispose']) {
  for (const settleFirst of ['stale', 'current']) {
    test(`stale read after ${cleanup}, ${settleFirst} first, never reads the clock or replaces the receipt`, async (t) => {
      let clockCalls = 0
      const { session, calls, eventTarget } = setup(t, undefined, { getNow: () => ++clockCalls })
      const stale = session.perform('read')
      if (cleanup === 'selective clear') session.clearReadResult()
      else if (cleanup === 'ID edit') session.recordId.value = 'next-id'
      else if (cleanup === 'token clear') session.token.value = ''
      else if (cleanup === 'pagehide') eventTarget.dispatchEvent(pageTransition('pagehide', true))
      else session.dispose()
      let current
      if (cleanup !== 'dispose') {
        session.token.value = 'new-token'
        session.recordId.value = 'next-id'
        current = session.perform('read')
      }
      if (settleFirst === 'current' && current) {
        calls[1].resolve({ id: 'next-id', plaintext: 'current' })
        await current
      }
      const before = state(session)
      const count = clockCalls
      calls[0].resolve({ id: 'old-id', plaintext: 'stale' })
      await stale
      assert.deepEqual(state(session), before)
      assert.equal(clockCalls, count)
      if (settleFirst === 'stale' && current) {
        calls[1].resolve({ id: 'next-id', plaintext: 'current' })
        await current
      }
      assert.equal(clockCalls, current ? 1 : 0)
      assert.equal(session.resultReceivedAt.value, current ? 1 : null)
    })
  }
}

for (const cleanup of ['session clear', 'selective clear', 'token clear', 'ID edit', 'pagehide', 'dispose']) {
  for (const throws of [false, true]) {
    test(`reentrant clock ${cleanup}, throwing=${throws}, cannot resurrect read state`, async (t) => {
      let session, eventTarget, atClear
      const fixture = setup(t, undefined, { getNow: () => {
        if (cleanup === 'session clear') session.clearSession()
        else if (cleanup === 'selective clear') session.clearReadResult()
        else if (cleanup === 'token clear') session.token.value = ''
        else if (cleanup === 'ID edit') session.recordId.value = 'next-id'
        else if (cleanup === 'pagehide') eventTarget.dispatchEvent(pageTransition('pagehide', true))
        else session.dispose()
        atClear = state(session)
        if (throws) throw new Error('clock failed after clear')
        return 123
      } })
      session = fixture.session
      eventTarget = fixture.eventTarget
      const pending = session.perform('read')
      fixture.calls[0].resolve({ id: 'record-1', plaintext: 'must not return' })
      await pending
      assert.deepEqual(state(session), atClear)
      assert.equal(session.result.value, null)
      assert.equal(session.resultReceivedAt.value, null)
      assert.equal(session.message.value, '')
      assert.equal(session.error.value, '')
      assert.equal(fixture.calls[0].signal.aborted, true)
    })
  }
}

test('receipt UI formats epoch zero and maximum Date safely and explains local-only manual refresh', async () => {
  const source = await readFile(new URL('../src/App.vue', import.meta.url), 'utf8')
  const expression = source.match(/const resultReceivedAtIso = (computed\([^\n]+\))/)?.[1]
  assert.ok(expression)
  const resultReceivedAt = ref(null)
  const formatted = new Function('computed', 'resultReceivedAt', `return ${expression}`)(computed, resultReceivedAt)
  assert.equal(formatted.value, null)
  resultReceivedAt.value = 0
  assert.equal(formatted.value, '1970-01-01T00:00:00.000Z')
  resultReceivedAt.value = 8640000000000000
  assert.equal(formatted.value, '+275760-09-13T00:00:00.000Z')
  resultReceivedAt.value = null
  assert.equal(formatted.value, null)
  assert.match(source, /<div v-if="result" class="result">[\s\S]*Lokaal ontvangen:[\s\S]*<time v-if="resultReceivedAtIso !== null" :datetime="resultReceivedAtIso">\{\{ resultReceivedAtIso \}\}<\/time>\s*<span v-else>Niet beschikbaar<\/span>[\s\S]*<\/div>/)
  assert.match(source, /lokale klok, niet van de server/)
  assert.match(source, /geen audit- of aanmaaktijd en geen garantie dat de inhoud actueel is/)
  assert.match(source, /Geen timers of automatische verversing; haal het record zelf opnieuw op/)
  assert.doesNotMatch(source, /setInterval|setTimeout|v-html/)
})

for (const cleanup of ['clear', 'empty-token clear', 'pagehide', 'persisted pagehide', 'token replacement']) {
  for (const action of ['read', 'create']) {
    for (const outcome of ['success', 'failure']) {
      for (const settleFirst of ['stale', 'current']) {
        test(`${cleanup} allows synchronous abort callback to replace ${action}; ${outcome}, ${settleFirst} settles first`, async (t) => {
          const { session, calls, eventTarget } = setup(t)
          if (cleanup === 'empty-token clear') session.token.value = ''
          session.plaintext.value = 'old draft'
          session.recordId.value = 'old-id'
          session.lastCreatedId.value = 'old-confirmed'
          const stale = session.perform(action)
          session.result.value = { id: 'old-id', plaintext: 'old result' }
          session.resultReceivedAt.value = 42
          session.message.value = 'old message'
          session.error.value = 'old error'
          const next = action === 'read' ? 'create' : 'read'
          let atAbort, current, restarted
          let aborts = 0
          calls[0].signal.addEventListener('abort', () => {
            aborts++
            atAbort = state(session)
            session.token.value = 'fresh-token'
            session.plaintext.value = 'fresh draft'
            session.recordId.value = 'fresh-id'
            session.lastCreatedId.value = 'fresh-confirmed'
            current = session.perform(next)
            session.message.value = 'current pending message'
            session.error.value = 'current pending feedback'
            restarted = state(session)
          }, { once: true })
          if (cleanup === 'token replacement') session.token.value = 'replacement-token'
          else if (cleanup.includes('pagehide')) {
            eventTarget.dispatchEvent(pageTransition('pagehide', cleanup === 'persisted pagehide'))
          } else session.clearSession()
          assert.deepEqual(atAbort, { ...empty, token: cleanup === 'token replacement' ? 'replacement-token' : '' })
          assert.equal(aborts, 1)
          assert.equal(calls.length, 2)
          assert.deepEqual(state(session), restarted)
          assert.equal(session.busy.value, next)
          assert.equal(calls[0].signal.aborted, true)
          assert.equal(calls[1].signal.aborted, false)
          assert.equal(calls[1].token, 'fresh-token')
          assert.equal(calls[1].input, next === 'read' ? 'fresh-id' : 'fresh draft')

          if (settleFirst === 'current') {
            calls[1].resolve({ id: 'fresh-id', plaintext: 'fresh result' })
            await current
          }
          const before = state(session)
          if (outcome === 'success') calls[0].resolve({ id: 'stale-id', plaintext: 'stale result' })
          else calls[0].reject(new Error('stale failure'))
          await stale
          assert.deepEqual(state(session), before)
          assert.equal(calls[1].signal.aborted, false)
          if (settleFirst === 'stale') {
            calls[1].resolve({ id: 'fresh-id', plaintext: 'fresh result' })
            await current
          }
          assert.equal(session.busy.value, '')
          assert.equal(session.error.value, 'current pending feedback')
          assert.equal(session.token.value, 'fresh-token')
          if (next === 'read') {
            assert.deepEqual(session.result.value, { id: 'fresh-id', plaintext: 'fresh result' })
            assert.equal(session.message.value, 'Record opgehaald.')
            assert.equal(session.lastCreatedId.value, 'fresh-confirmed')
          } else {
            assert.equal(session.lastCreatedId.value, 'fresh-id')
            assert.equal(session.plaintext.value, '')
            assert.match(session.message.value, /Record opgeslagen/)
          }
        })
      }
    }
  }
}

test('full clear wipes populated state even when the token is already empty', (t) => {
  const { session, calls } = setup(t)
  session.token.value = ''
  for (const key of Object.keys(empty).filter(key => key !== 'token')) {
    session[key].value = key === 'result' ? { plaintext: 'old result' } : 'old state'
  }
  session.clearSession()
  assert.deepEqual(state(session), empty)
  session.clearSession()
  assert.deepEqual(state(session), empty)
  assert.equal(calls.length, 0)
})

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
  for (const action of ['read', 'create']) {
    test(`${cleanup} removes the exact pagehide listener before aborting ${action} and leaves disposed refs alone`, async (t) => {
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
      const pending = session.perform(action)
      assert.equal(added.length, 1)
      assert.equal(added[0][0], 'pagehide')
      let atAbort, removedAtAbort, attempted
      calls[0].signal.addEventListener('abort', () => {
        atAbort = state(session)
        removedAtAbort = [...removed]
        attempted = [session.perform('read'), session.perform('create'), session.readLastCreated()]
      }, { once: true })
      if (cleanup === 'scope') scope.stop()
      else session.dispose()
      assert.equal(removed.length, 1)
      assert.deepEqual(removed[0], added[0])
      assert.deepEqual(removedAtAbort, [added[0]])
      assert.deepEqual(atAbort, empty)
      await Promise.all(attempted)
      assert.equal(calls.length, 1)
      assert.equal(calls[0].signal.aborted, true)
      assert.deepEqual(state(session), empty)
      for (const key of Object.keys(empty)) {
        session[key].value = key === 'result' ? { plaintext: 'sentinel' } : 'sentinel'
      }
      const before = state(session)
      await session.perform('read')
      await session.perform('create')
      await session.readLastCreated()
      assert.equal(calls.length, 1)
      assert.deepEqual(state(session), before)
      for (const persisted of [false, true]) {
        eventTarget.dispatchEvent(pageTransition('pagehide', persisted))
        assert.deepEqual(state(session), before)
      }
      calls[0].resolve({ id: 'stale-id', plaintext: 'stale text' })
      await pending
      assert.deepEqual(state(session), before)
    })
  }
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
    ...before, recordId: '  record-2  ', result: null, resultReceivedAt: null, message: '', error: '',
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
  const cleared = { ...before, result: null, resultReceivedAt: null, message: '', error: '' }
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
    session.resultReceivedAt.value = 42
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
  assert.match(source, /<div v-if="result" class="result">\s*<h3>Leesbare inhoud<\/h3><p>Record-ID: \{\{ result\.id \}\}<\/p><pre>\{\{ result\.plaintext \}\}<\/pre>/)
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
