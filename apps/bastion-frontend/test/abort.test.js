import test from 'node:test'
import assert from 'node:assert/strict'
import { getEventListeners } from 'node:events'
import { setImmediate as nextTurn } from 'node:timers/promises'
import { commitCommand, getTicketStatus, issueTicket, listCommands, request, revokeTicket } from '../src/api.js'

const token = 'test-abort-input'
const command = 'journal only'
const ticket = () => ({ id: 'ticket-1', command, not_before: Date.now() - 1000, expires_at: Date.now() + 30000 })
const entry = () => ({ id: 'record-1', command, committed_at: Date.now() })
const status = () => ({ ...ticket(), checked_at: Date.now(), status: 'active', revoked: false, record: null })
const headers = { 'Content-Type': 'application/json' }
const helpers = [
  { name: 'request', invoke: (fetcher, signal) => request('/v1/commands', { token, fetcher, signal }), result: () => ({}), code: 200 },
  { name: 'ticket', invoke: (fetcher, signal) => issueTicket(command, 1000, token, fetcher, signal), result: () => ({ id: 'ticket-1', not_before: 1000, expires_at: 2000 }), code: 201 },
  { name: 'commit', invoke: (fetcher, signal) => commitCommand(ticket(), command, token, fetcher, signal), result: entry, code: 201 },
  { name: 'revoke', invoke: (fetcher, signal) => revokeTicket(ticket(), token, fetcher, signal), result: () => ({ revoked: true }), code: 200 },
  { name: 'status', invoke: (fetcher, signal) => getTicketStatus('ticket-1', token, fetcher, signal), result: status, code: 200 },
  { name: 'list', invoke: (fetcher, signal) => listCommands(token, fetcher, signal), result: () => ({ commands: [] }), code: 200 },
]
const noListeners = signal => assert.equal(getEventListeners(signal, 'abort').length, 0)
const safe = failure => {
  assert.match(failure.message, /^Geen geldig antwoord/)
  assert.ok(!failure.message.includes(token))
  return true
}
const deferred = () => {
  let resolve, reject
  const promise = new Promise((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}

for (const helper of helpers) {
  test(`${helper.name}: preaborted external signal makes no network request and leaves no listeners`, async () => {
    const controller = new AbortController()
    controller.abort(new Error(token))
    await assert.rejects(helper.invoke(() => assert.fail('must not fetch'), controller.signal), safe)
    noListeners(controller.signal)
  })

  test(`${helper.name}: external abort interrupts ignored headers and cleans up late responses/failures`, async () => {
    for (const late of ['resolve', 'reject', 'never']) {
      const controller = new AbortController()
      const pending = deferred()
      let internal, calls = 0, cancelled = 0
      const operation = helper.invoke((_path, options) => {
        internal = options.signal
        calls++
        return pending.promise
      }, controller.signal)
      assert.equal(calls, 1)
      assert.equal(internal.aborted, false)
      controller.abort(new Error(token))
      await assert.rejects(operation, safe)
      assert.equal(internal.aborted, true)
      noListeners(controller.signal)
      noListeners(internal)
      if (late === 'resolve') {
        const response = new Response(new ReadableStream({
          cancel() { cancelled++; return new Promise(() => {}) },
        }), { headers, status: helper.code })
        pending.resolve(response)
        await nextTurn()
        assert.equal(cancelled, 1)
        assert.equal(response.body.locked, false)
      } else if (late === 'reject') {
        pending.reject(new Error(token))
        await nextTurn()
      }
      noListeners(controller.signal)
      noListeners(internal)
    }
  })

  test(`${helper.name}: external abort interrupts a hanging body and releases locks/listeners`, async () => {
    const controller = new AbortController()
    let internal, cancelled = 0, stream
    const response = new Response(new ReadableStream({
      start(value) { stream = value; value.enqueue(new TextEncoder().encode('{"partial":')) },
      cancel() { cancelled++; return new Promise(() => {}) },
    }), { headers, status: helper.code })
    const operation = helper.invoke(async (_path, options) => {
      internal = options.signal
      return response
    }, controller.signal)
    await nextTurn()
    assert.equal(response.body.locked, true)
    controller.abort(new Error(token))
    await assert.rejects(operation, safe)
    assert.equal(internal.aborted, true)
    assert.equal(cancelled, 1)
    assert.equal(response.body.locked, false)
    noListeners(controller.signal)
    noListeners(internal)
    assert.throws(() => stream.enqueue(new TextEncoder().encode('{}')), TypeError)
  })

  test(`${helper.name}: success and failures remove external/internal listeners without aborting completed work`, async () => {
    for (const outcome of ['success', 'http', 'json', 'network']) {
      const controller = new AbortController()
      let internal, response
      const operation = helper.invoke(async (_path, options) => {
        internal = options.signal
        if (outcome === 'network') throw new Error(token)
        response = new Response(outcome === 'json' ? '{' : JSON.stringify(helper.result()), {
          headers, status: outcome === 'http' ? 503 : helper.code,
        })
        return response
      }, controller.signal)
      if (outcome === 'success') await operation
      else await assert.rejects(operation)
      noListeners(controller.signal)
      noListeners(internal)
      assert.equal(internal.aborted, false)
      assert.equal(response?.body.locked ?? false, false)
      controller.abort()
      assert.equal(internal.aborted, false)
    }
  })
}

test('deadline still aborts without external cancellation and removes its external listener', async () => {
  const controller = new AbortController()
  let internal
  await assert.rejects(request('/v1/commands', {
    token, signal: controller.signal, timeoutMs: 10,
    fetcher: (_path, options) => {
      internal = options.signal
      return new Promise(() => {})
    },
  }), safe)
  assert.equal(controller.signal.aborted, false)
  assert.equal(internal.aborted, true)
  noListeners(controller.signal)
  noListeners(internal)
})
