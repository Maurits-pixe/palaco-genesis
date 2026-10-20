import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { effectScope } from 'vue'
import { useModuleVerification } from '../src/useModuleVerification.js'
import { launchUrl, MAX_AGE_MS, TRUSTED_MODULES } from '../src/verification.js'

const [aether, bastion] = TRUSTED_MODULES
const evidence = (module, verifiedAt) => ({
  status: 'verified', moduleId: module.id, health: 'ok', verifiedAt,
})

function setup(t, verifier, eventTarget = new EventTarget()) {
  let time = 100_000
  let tick
  const timer = {}
  const cleared = []
  const calls = []
  const signals = []
  const pending = []
  const scope = effectScope()
  const model = scope.run(() => useModuleVerification({
    verifier: (module, _fetcher, _timeout, signal) => {
      calls.push(module)
      signals.push(signal)
      if (verifier) return verifier(module, model, signal)
      return new Promise((resolve, reject) => pending.push({ module, signal, resolve, reject }))
    },
    getNow: () => time,
    schedule: (callback, delay) => {
      assert.equal(delay, 500)
      tick = callback
      return timer
    },
    unschedule: (handle) => cleared.push(handle),
    eventTarget,
  }))
  t.after(() => scope.stop())
  return {
    model, calls, signals, pending, scope, timer, cleared, eventTarget,
    setTime: (value) => { time = value },
    tick: () => tick(),
  }
}

test('initialization and clock ticks never automatically verify', (t) => {
  const { model, calls, tick } = setup(t)
  assert.deepEqual(Object.values(model.states.value), [{ status: 'idle' }, { status: 'idle' }])
  tick()
  assert.deepEqual(calls, [])
  assert.equal(model.launchableCount.value, 0)
  assert.equal(model.isVerifying.value, false)
})

test('batch starts all fixed modules concurrently and keeps mixed outcomes independent', async (t) => {
  for (const failing of [aether, bastion]) {
    const { model, calls, pending } = setup(t)
    const batch = model.verifyAll()
    assert.deepEqual(calls, TRUSTED_MODULES)
    assert.equal(model.isVerifying.value, true)
    assert.ok(Object.values(model.states.value).every(({ status }) => status === 'verifying'))
    const healthy = pending.find(({ module }) => module !== failing)
    healthy.resolve(evidence(healthy.module, 100_000))
    await Promise.resolve()
    assert.equal(model.launchableCount.value, 1)
    assert.equal(model.isVerifying.value, true)
    pending.find(({ module }) => module === failing).reject(new Error('Service unavailable'))
    await batch
    assert.deepEqual(model.states.value[failing.id], { status: 'error', message: 'Service unavailable' })
    assert.equal(launchUrl(healthy.module, model.states.value[healthy.module.id], model.now.value), healthy.module.origin)
    assert.equal(model.launchableCount.value, 1)
    assert.equal(model.isVerifying.value, false)
  }
})

test('a synchronous verifier failure does not prevent another module from running', async (t) => {
  const { model, calls } = setup(t, (module) => {
    if (module === aether) throw new Error('Unavailable')
    return evidence(module, 100_000)
  })
  await model.verifyAll()
  assert.deepEqual(calls, TRUSTED_MODULES)
  assert.equal(model.states.value.aether.status, 'error')
  assert.equal(model.states.value.bastion.status, 'verified')
  assert.equal(model.launchableCount.value, 1)
})

test('rerunning a batch invalidates every old approval before invoking the verifier', async (t) => {
  let checkStart = false
  const { model, calls } = setup(t, (module, current) => {
    if (checkStart) {
      for (const trusted of TRUSTED_MODULES) {
        assert.deepEqual(current.states.value[trusted.id], { status: 'verifying' })
        assert.equal(launchUrl(trusted, current.states.value[trusted.id], 100_000), null)
      }
      assert.equal(current.launchableCount.value, 0)
    }
    return evidence(module, 100_000)
  })
  await model.verifyAll()
  assert.equal(model.launchableCount.value, 2)
  checkStart = true
  const rerun = model.verifyAll()
  assert.equal(model.launchableCount.value, 0)
  assert.equal(calls.length, 4)
  await rerun
  assert.equal(model.launchableCount.value, 2)
})

test('batch repeats and individual duplicates are no-ops until every batch module settles', async (t) => {
  const { model, calls, pending } = setup(t)
  const batch = model.verifyAll()
  await Promise.all([model.verifyAll(), model.verify(aether), model.verify(bastion)])
  assert.equal(calls.length, 2)
  pending[0].resolve(evidence(aether, 100_000))
  await Promise.resolve()
  await model.verifyAll()
  assert.equal(calls.length, 2)
  pending[1].resolve(evidence(bastion, 100_000))
  await batch
  assert.equal(model.isVerifying.value, false)
})

test('individual verification blocks batches and same-module duplicates, not the other module', async (t) => {
  const { model, calls, pending } = setup(t)
  const first = model.verify(aether)
  await Promise.all([model.verify(aether), model.verifyAll()])
  assert.deepEqual(calls, [aether])
  const second = model.verify(bastion)
  assert.deepEqual(calls, TRUSTED_MODULES)
  pending[1].resolve(evidence(bastion, 100_000))
  await second
  assert.equal(model.states.value.aether.status, 'verifying')
  assert.equal(model.launchableCount.value, 1)
  const otherRerun = model.verify(bastion)
  assert.deepEqual(calls, [aether, bastion, bastion])
  assert.equal(model.launchableCount.value, 0)
  pending[2].resolve(evidence(bastion, 100_000))
  pending[0].reject(new Error('Offline'))
  await Promise.all([first, otherRerun])
  assert.equal(model.states.value.aether.status, 'error')
  assert.equal(model.launchableCount.value, 1)
})

test('individual rerun immediately removes its old launch approval', async (t) => {
  const { model, pending } = setup(t)
  const first = model.verify(aether)
  pending[0].resolve(evidence(aether, 100_000))
  await first
  assert.equal(model.launchableCount.value, 1)
  const rerun = model.verify(aether)
  assert.equal(launchUrl(aether, model.states.value.aether, 100_000), null)
  assert.equal(model.launchableCount.value, 0)
  pending[1].reject(new Error('Offline'))
  await rerun
  assert.equal(model.launchableCount.value, 0)
})

test('clock summary uses the exact launch gate without extending verification timestamps', async (t) => {
  const { model, pending, setTime, tick } = setup(t)
  const batch = model.verifyAll()
  for (const request of pending) request.resolve(evidence(request.module, 100_000))
  await batch
  for (const [time, expected] of [
    [100_000, 2],
    [100_000 + MAX_AGE_MS - 1, 2],
    [100_000 + MAX_AGE_MS, 0],
    [100_000 - 1, 0],
  ]) {
    setTime(time)
    tick()
    assert.equal(model.now.value, time)
    assert.equal(model.launchableCount.value, expected)
    for (const module of TRUSTED_MODULES) {
      assert.equal(model.states.value[module.id].verifiedAt, 100_000)
      assert.equal(Boolean(launchUrl(module, model.states.value[module.id], time)), expected === 2)
    }
  }
})

test('an initially undefined scheduler clock is stored as null for UI and count gates', (t) => {
  t.mock.method(Date, 'now', () => 100_000)
  const scope = effectScope()
  t.after(() => scope.stop())
  const model = scope.run(() => useModuleVerification({
    getNow: () => undefined,
    schedule: () => 0,
    unschedule: () => {},
  }))
  model.states.value.aether = evidence(aether, 100_000)
  assert.equal(model.now.value, null)
  assert.equal(model.launchableCount.value, 0)
  assert.equal(launchUrl(aether, model.states.value.aether, model.now.value), null)
})

test('invalid scheduler clocks fail closed at completion and on ticks without automatic verification', async (t) => {
  t.mock.method(Date, 'now', () => 100_000)
  for (const invalid of [
    undefined, null, -1, 100_000.5, Number.MAX_SAFE_INTEGER + 1,
    8_640_000_000_000_001, '100000', NaN, Infinity, -Infinity,
  ]) {
    const { model, pending, calls, setTime, tick } = setup(t)
    const batch = model.verifyAll()
    setTime(invalid)
    for (const request of pending) request.resolve(evidence(request.module, 100_000))
    await batch
    assert.equal(model.now.value, invalid ?? null)
    assert.equal(model.launchableCount.value, 0)
    for (const [time, expected] of [
      [100_000, 2], [invalid, 0], [159_999, 2], [160_000, 0], [99_999, 0],
    ]) {
      setTime(time)
      tick()
      assert.equal(model.now.value, time ?? null)
      assert.equal(model.launchableCount.value, expected)
      for (const module of TRUSTED_MODULES) {
        assert.deepEqual(model.states.value[module.id], evidence(module, 100_000))
        assert.equal(Boolean(launchUrl(module, model.states.value[module.id], model.now.value)), expected === 2)
      }
    }
    assert.deepEqual(calls, TRUSTED_MODULES)
  }
})

test('scheduler clock normalization preserves epoch zero', async (t) => {
  const { model, pending, calls, setTime, tick } = setup(t)
  setTime(0)
  const batch = model.verifyAll()
  for (const request of pending) request.resolve(evidence(request.module, 0))
  await batch
  assert.equal(model.now.value, 0)
  assert.equal(model.launchableCount.value, 2)
  tick()
  assert.equal(model.now.value, 0)
  assert.equal(model.launchableCount.value, 2)
  assert.deepEqual(calls, TRUSTED_MODULES)
})

test('scope disposal clears the timer and ignores late successes, failures, and new requests', async (t) => {
  const { model, calls, signals, pending, scope, timer, cleared, setTime, tick } = setup(t)
  const batch = model.verifyAll()
  scope.stop()
  assert.ok(signals.every((signal) => signal.aborted))
  assert.deepEqual(cleared, [timer])
  const before = structuredClone(JSON.parse(JSON.stringify(model.states.value)))
  setTime(200_000)
  tick()
  pending[0].resolve(evidence(aether, 200_000))
  pending[1].reject(new Error('Late failure'))
  await batch
  await Promise.all([model.verifyAll(), model.verify(aether), model.reset()])
  assert.deepEqual(model.states.value, before)
  assert.equal(model.now.value, 100_000)
  assert.equal(calls.length, 2)
  assert.deepEqual(cleared, [timer])
})

test('reset removes completed approvals, count, and launch links and is repeatable', async (t) => {
  const { model, pending, calls } = setup(t)
  const batch = model.verifyAll()
  for (const request of pending) request.resolve(evidence(request.module, 100_000))
  await batch
  assert.equal(model.launchableCount.value, 2)
  for (let i = 0; i < 3; i++) {
    model.reset()
    assert.deepEqual(Object.values(model.states.value), [{ status: 'idle' }, { status: 'idle' }])
    assert.equal(model.isVerifying.value, false)
    assert.equal(model.launchableCount.value, 0)
    for (const module of TRUSTED_MODULES) {
      assert.equal(launchUrl(module, model.states.value[module.id], model.now.value), null)
    }
  }
  assert.equal(calls.length, 2)
})

test('reset aborts a pending batch and permits fresh individuals despite an ignoring-abort verifier', async (t) => {
  const { model, pending, setTime, calls } = setup(t)
  const oldBatch = model.verifyAll()
  model.reset()
  assert.ok(pending.every(({ signal }) => signal.aborted))
  assert.equal(model.isVerifying.value, false)
  assert.equal(model.launchableCount.value, 0)
  const first = model.verify(aether)
  const second = model.verify(bastion)
  assert.equal(calls.length, 4)
  assert.ok(pending.slice(2).every(({ signal }) => !signal.aborted))
  setTime(200_000)
  pending[0].resolve(evidence(aether, 200_000))
  pending[1].reject(new Error('Old batch error'))
  await oldBatch
  assert.deepEqual(Object.values(model.states.value), [{ status: 'verifying' }, { status: 'verifying' }])
  assert.equal(model.isVerifying.value, true)
  assert.equal(model.launchableCount.value, 0)
  assert.equal(model.now.value, 100_000)
  await Promise.all([model.verify(aether), model.verifyAll()])
  assert.equal(calls.length, 4)
  pending[2].resolve(evidence(aether, 200_000))
  pending[3].resolve(evidence(bastion, 200_000))
  await Promise.all([first, second])
  assert.equal(model.launchableCount.value, 2)
  assert.equal(model.now.value, 200_000)
  assert.equal(model.isVerifying.value, false)
})

test('reset pending individuals permits a fresh batch; late old results cannot overwrite new approvals or clock', async (t) => {
  const { model, pending, setTime } = setup(t)
  const oldFirst = model.verify(aether)
  const oldSecond = model.verify(bastion)
  model.reset()
  model.reset()
  assert.ok(pending.every(({ signal }) => signal.aborted))
  const batch = model.verifyAll()
  setTime(150_000)
  for (const request of pending.slice(2)) request.resolve(evidence(request.module, 150_000))
  await batch
  const before = JSON.parse(JSON.stringify(model.states.value))
  setTime(200_000)
  pending[0].reject(new Error('Old individual error'))
  pending[1].resolve(evidence(bastion, 200_000))
  await Promise.all([oldFirst, oldSecond])
  assert.deepEqual(model.states.value, before)
  assert.equal(model.now.value, 150_000)
  assert.equal(model.launchableCount.value, 2)
  assert.equal(model.isVerifying.value, false)
})

test('old finally cannot remove a newer attempt from subsequent reset or disposal cancellation', async (t) => {
  for (const dispose of [false, true]) {
    const { model, pending, scope } = setup(t)
    const old = model.verify(aether)
    model.reset()
    const fresh = model.verify(aether)
    pending[0].resolve(evidence(aether, 100_000))
    await old
    assert.equal(model.states.value.aether.status, 'verifying')
    if (dispose) scope.stop()
    else model.reset()
    assert.equal(pending[1].signal.aborted, true)
    pending[1].resolve(evidence(aether, 100_000))
    await fresh
    assert.equal(model.launchableCount.value, 0)
    if (!dispose) assert.equal(model.states.value.aether.status, 'idle')
  }
})

test('late results after repeated resets without new attempts leave all states idle', async (t) => {
  const { model, pending, setTime } = setup(t)
  const old = model.verifyAll()
  model.reset()
  model.reset()
  setTime(300_000)
  pending[0].resolve(evidence(aether, 300_000))
  pending[1].reject(new Error('Late error'))
  await old
  assert.deepEqual(Object.values(model.states.value), [{ status: 'idle' }, { status: 'idle' }])
  assert.equal(model.now.value, 100_000)
  assert.equal(model.launchableCount.value, 0)
  assert.equal(model.isVerifying.value, false)
})

function pageEvent(type, persisted) {
  const event = new Event(type)
  Object.defineProperty(event, 'persisted', { value: persisted })
  return event
}

for (const persisted of [false, true]) {
  test(`pagehide (persisted=${persisted}) clears approvals and return requires manual verification`, async (t) => {
    const { model, pending, calls, eventTarget, cleared, setTime, tick } = setup(t)
    const batch = model.verifyAll()
    for (const request of pending) request.resolve(evidence(request.module, 100_000))
    await batch
    assert.equal(model.launchableCount.value, 2)
    eventTarget.dispatchEvent(new Event('visibilitychange'))
    assert.equal(model.launchableCount.value, 2)
    eventTarget.dispatchEvent(pageEvent('pagehide', persisted))
    assert.deepEqual(Object.values(model.states.value), [{ status: 'idle' }, { status: 'idle' }])
    assert.equal(model.launchableCount.value, 0)
    assert.equal(model.isVerifying.value, false)
    for (const module of TRUSTED_MODULES) {
      assert.equal(launchUrl(module, model.states.value[module.id], model.now.value), null)
    }
    eventTarget.dispatchEvent(pageEvent('pageshow', persisted))
    setTime(110_000)
    tick()
    assert.equal(model.now.value, 110_000)
    assert.deepEqual(cleared, [])
    assert.equal(calls.length, 2)
    assert.equal(model.launchableCount.value, 0)
    const individual = model.verify(aether)
    pending[2].resolve(evidence(aether, 110_000))
    await individual
    assert.equal(model.launchableCount.value, 1)
    const freshBatch = model.verifyAll()
    for (const request of pending.slice(3)) request.resolve(evidence(request.module, 110_000))
    await freshBatch
    assert.equal(model.launchableCount.value, 2)
    setTime(110_000 + MAX_AGE_MS)
    tick()
    assert.equal(model.launchableCount.value, 0)
  })

  for (const batch of [false, true]) {
    test(`pagehide (persisted=${persisted}) aborts ${batch ? 'batch' : 'individual'} attempts and ignores stale results`, async (t) => {
      const { model, pending, calls, eventTarget, setTime } = setup(t)
      const old = batch ? model.verifyAll() : Promise.all(TRUSTED_MODULES.map(model.verify))
      eventTarget.dispatchEvent(new Event('visibilitychange'))
      assert.ok(pending.every(({ signal }) => !signal.aborted))
      assert.equal(model.isVerifying.value, true)
      eventTarget.dispatchEvent(pageEvent('pagehide', persisted))
      assert.ok(pending.every(({ signal }) => signal.aborted))
      assert.deepEqual(Object.values(model.states.value), [{ status: 'idle' }, { status: 'idle' }])
      assert.equal(model.isVerifying.value, false)
      eventTarget.dispatchEvent(pageEvent('pageshow', persisted))
      assert.equal(calls.length, 2)
      const fresh = batch ? Promise.all(TRUSTED_MODULES.map(model.verify)) : model.verifyAll()
      assert.ok(pending.slice(2).every(({ signal }) => !signal.aborted))
      setTime(150_000)
      // Exercise stale completion both during fresh attempts and after new approvals.
      if (!batch) {
        for (const request of pending.slice(2)) request.resolve(evidence(request.module, 150_000))
        await fresh
      }
      const before = JSON.parse(JSON.stringify(model.states.value))
      const clockBefore = model.now.value
      setTime(200_000)
      pending[0].resolve(evidence(aether, 200_000))
      pending[1].reject(new Error('Stale page error'))
      await old
      assert.deepEqual(model.states.value, before)
      assert.equal(model.now.value, clockBefore)
      assert.equal(model.launchableCount.value, batch ? 0 : 2)
      if (batch) {
        await Promise.all([model.verify(aether), model.verifyAll()])
        assert.equal(calls.length, 4)
        // Stale finally blocks must not remove the fresh controllers.
        eventTarget.dispatchEvent(pageEvent('pagehide', persisted))
        assert.ok(pending.slice(2).every(({ signal }) => signal.aborted))
        pending[2].reject(new Error('Late fresh error'))
        pending[3].resolve(evidence(bastion, 200_000))
        await fresh
        assert.deepEqual(Object.values(model.states.value), [{ status: 'idle' }, { status: 'idle' }])
        assert.equal(model.launchableCount.value, 0)
      }
    })
  }
}

test('scope disposal removes the exact pagehide listener before timer and request cleanup', async (t) => {
  const listeners = []
  const removed = []
  class TrackedTarget extends EventTarget {
    addEventListener(type, listener) {
      listeners.push({ type, listener })
      super.addEventListener(type, listener)
    }

    removeEventListener(type, listener) {
      removed.push({ type, listener })
      super.removeEventListener(type, listener)
    }
  }
  const eventTarget = new TrackedTarget()
  const { model, scope, pending, cleared } = setup(t, undefined, eventTarget)
  assert.deepEqual(listeners, [{ type: 'pagehide', listener: model.reset }])
  const batch = model.verifyAll()
  for (const { signal } of pending) {
    signal.addEventListener('abort', () => {
      assert.deepEqual(removed, listeners)
      assert.equal(cleared.length, 1)
    })
  }
  scope.stop()
  assert.deepEqual(removed, listeners)
  eventTarget.dispatchEvent(pageEvent('pagehide', true))
  assert.ok(Object.values(model.states.value).every(({ status }) => status === 'verifying'))
  pending[0].resolve(evidence(aether, 100_000))
  pending[1].reject(new Error('Disposed'))
  await batch
})

test('the default event target is safe without a browser window', () => {
  assert.equal(globalThis.window, undefined)
  const scope = effectScope()
  try {
    const model = scope.run(() => useModuleVerification({
      schedule: () => 0,
      unschedule: () => {},
    }))
    assert.equal(model.launchableCount.value, 0)
    model.reset()
  } finally {
    scope.stop()
  }
})

test('UI wires manual batch, independent controls, live count, and click-time launch gate', async () => {
  const app = await readFile(new URL('../src/App.vue', import.meta.url), 'utf8')
  assert.match(app, /useModuleVerification\(\)/)
  assert.match(app, /<button :disabled="isVerifying" @click="verifyAll">Controleer alle modules<\/button>/)
  assert.match(app, /<button @click="reset">Wis controles<\/button>/)
  assert.match(app, /Wissen verwijdert alleen lokale controles: het stopt geen services, trekt geen tickets in en sluit geen reeds geopende tabbladen/)
  assert.match(app, /Bij ontvangst van pagehide worden lokale controles gewist; controleer na terugkeer handmatig opnieuw/)
  assert.match(app, /Aflevering is niet gegarandeerd\. Dit stopt geen services, trekt geen tokens of tickets in en is geen autorisatie/)
  assert.match(app, /role="status" aria-live="polite" aria-atomic="true">\{\{ launchableCount \}\} van \{\{ TRUSTED_MODULES.length \}\} modules momenteel te openen/)
  assert.match(app, /:disabled="states\[module.id\].status === 'verifying'" @click="verify\(module\)"/)
  assert.match(app, /if \(!launchUrl\(module, states.value\[module.id\], Date.now\(\)\)\) \{\s*event.preventDefault\(\)/)
  assert.match(app, /v-if="launchUrl\(module, states\[module.id\], now\)" :href="launchUrl\(module, states\[module.id\], now\)"/)
  assert.match(app, /@click="follow\(\$event, module\)"/)
})
