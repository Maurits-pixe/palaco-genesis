import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { effectScope, isRef } from 'vue'
import * as Vue from 'vue'
import { compile } from '@vue/compiler-dom'
import { renderToString } from 'vue/server-renderer'
import { realtimeLabels, useSession } from '../src/useSession.js'
import { createRealtime } from '../src/realtime.js'
import { commandLength, isValidToken, MAX_COMMAND_LENGTH, listCommands, normalizeCommand, timestamp, ticketUsable, validateTicketStatus } from '../src/api.js'

const held = () => ({ id: 'ticket-1', command: 'journal only', not_before: 1000, expires_at: 1100 })
const record = (id = 'record-1') => ({ id, command: 'journal only', committed_at: 1050 })
const snapshot = (changes = {}) => ({
  ...held(), checked_at: 1050, status: 'active', revoked: false, record: null, ...changes,
})
const actions = { ticket: 'issueTicket', commit: 'commitCommand', revoke: 'revokeTicket', status: 'getTicketStatus', list: 'listCommands' }
const results = { ticket: held(), commit: record(), revoke: undefined, status: snapshot(), list: [record()] }
const commitCaution = 'Vastlegging niet bevestigd. Controleer de laatste inzending via het ticket-ID. Dien niet automatisch opnieuw in.'
const revokeCaution = 'Intrekking niet bevestigd. Vastleggen en nieuwe tickets blijven geblokkeerd. Controleer dit ticket of trek het expliciet opnieuw in.'
const ticketCaution = 'Ticketuitgifte niet bevestigd. Er kan al een serverticket bestaan. Zonder ontvangen ticket is lokaal vastleggen niet mogelijk. Geen automatische nieuwe aanvraag.'
const statusCaution = 'Ticketstatus niet bevestigd. Er is geen geldige nieuwe momentopname ontvangen. Deze fout bevestigt geen vastlegging of intrekking en herstelt geen toestemming. Controleer het ticket expliciet opnieuw; geen automatische herhaling.'
const localCommitBlocked = 'Niet ingezonden: de lokale ticketcontrole blokkeert vastleggen. Voor deze actie is geen commitverzoek verstuurd. Dit zegt niets over eerdere inzendingen.'
const deferred = () => {
  let resolve, reject
  const promise = new Promise((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}

function fixture(t, eventTarget = new EventTarget(), apiOverrides = {}, clockOverrides = {}, realtimeFactory = null) {
  const scope = effectScope()
  const calls = []
  const sockets = []
  const realtimeCallbacks = []
  const clock = { time: 1050, reads: 0, tick: null, cleared: [], interval: null, ...clockOverrides }
  const api = { ...Object.fromEntries(Object.entries(actions).map(([action, name]) => [name, (...args) => {
    const call = { action, args, signal: args.at(-1), ...deferred() }
    calls.push(call)
    return call.promise
  }])), ...apiOverrides }
  const state = scope.run(() => useSession({
    api,
    eventTarget,
    scheduler: {
      now: () => { clock.reads++; return clock.now ? clock.now() : clock.time },
      setInterval(callback, interval) { clock.tick = callback; clock.interval = interval; return 42 },
      clearInterval(id) { clock.cleared.push(id) },
    },
    realtimeFactory: realtimeFactory ?? (callbacks => {
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
    }),
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
  assert.equal(state.validToken.value, isValidToken(token))
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
  assert.equal(state.canClearOutcome.value, false)
  assert.equal(state.validTtl.value, true)
  assert.equal(state.canRequestTicket.value, false)
  assert.equal(state.validLookupId.value, false)
  assert.equal(state.canCheckStatus.value, false)
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
    .filter(([key, value]) => isRef(value) && !['outcome', 'outcomeReceivedAt', 'outcomeMismatch', 'canClearOutcome', 'message', 'error', 'busy'].includes(key))
    .map(([key, value]) => [key, JSON.parse(JSON.stringify(value.value))])))
}

function commandState(state, excluded = []) {
  return Object.fromEntries(Object.entries(state)
    .filter(([key, value]) => isRef(value) && !excluded.includes(key))
    .map(([key, value]) => [key, value.value]))
}

function compileFragment(source) {
  const { code } = compile(source, { mode: 'function', prefixIdentifiers: true })
  const render = new Function('Vue', code)(Vue)
  return async state => {
    let vnode
    const html = await renderToString(Vue.createSSRApp({
      setup: () => state,
      render() {
        vnode = render(this, {})
        return vnode
      },
    }))
    const find = predicate => {
      function visit(node) {
        if (predicate(node)) return node
        return Array.isArray(node.children) ? node.children.map(visit).find(Boolean) : undefined
      }
      return visit(vnode)
    }
    return { html, find }
  }
}

function tokenAccess() {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  return compileFragment(app.match(/<section aria-labelledby="access-title">[\s\S]*?<\/section>/)[0])
}

test('compiled clear-session button links unique static help and stays enabled idle and during every request without side effects', async t => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const pair = app.match(/<button[^>]*>Wis sessie<\/button>\s*<p id="clear-session-help" class="muted">[\s\S]*?<\/p>/)[0]
  const help = pair.slice(pair.indexOf('<p '))
  assert.doesNotMatch(help, /\{\{|v-|@/)
  assert.equal(app.match(/\bid="clear-session-help"/g).length, 1)
  assert.equal(app.match(/\baria-describedby="clear-session-help"/g).length, 1)
  const expectedHelp = "Wissen en afbreken zijn alleen lokaal: geen intrekking van servertickets of terugdraaien. Een al verzonden wijziging kan nog worden voltooid. Wissen verwijdert ook lokale ID's: kopieer het ticket-ID vóór het wissen om later handmatig de status op te zoeken. Dien nooit automatisch opnieuw in."
  const render = tokenAccess()
  for (const action of ['', ...Object.keys(actions)]) {
    const { state, calls, sockets, clock } = fixture(t)
    prepare(state, action)
    const pending = action ? state.perform(action) : null
    assert.equal(state.busy.value, action)
    const before = JSON.stringify(commandState(state))
    const callsBefore = calls.slice()
    const readsBefore = clock.reads
    for (let pass = 0; pass < 2; pass++) {
      const { html, find } = await render(state)
      const button = find(node => node.type === 'button' && node.children === 'Wis sessie')
      assert.equal(button.props['aria-describedby'], 'clear-session-help')
      assert.equal(Object.hasOwn(button.props, 'disabled'), false)
      assert.doesNotMatch(html.match(/<button[^>]*>Wis sessie<\/button>/)[0], /\sdisabled(?:[=>\s])/)
      const renderedHelp = find(node => node.props?.id === 'clear-session-help')
      assert.equal(renderedHelp.type, 'p')
      assert.equal(renderedHelp.props.class, 'muted')
      assert.equal(renderedHelp.children, expectedHelp)
      assert.equal(html.match(/\bid="clear-session-help"/g).length, 1)
      assert.equal(html.match(/\baria-describedby="clear-session-help"/g).length, 1)
      assert.equal(JSON.stringify(commandState(state)), before)
      assert.deepEqual(calls, callsBefore)
      assert.deepEqual(sockets, [])
      assert.equal(clock.reads, readsBefore)
    }
    if (pending) {
      calls[0].resolve(results[action])
      await pending
    }
  }
})

test('compiled clear-session click aborts pending status once and late resolution cannot refill the cleared session', async t => {
  const { state, calls, sockets } = fixture(t)
  state.realtime.connect(state.token.value)
  prepare(state, 'status')
  const pending = state.perform('status')
  assert.equal(calls.length, 1)
  assert.equal(calls[0].action, 'status')
  assert.equal(state.busy.value, 'status')
  assert.equal(calls[0].signal.aborted, false)
  let aborts = 0
  calls[0].signal.addEventListener('abort', () => {
    aborts++
    assertEmpty(state)
  })
  const { find } = await tokenAccess()(state)
  find(node => node.type === 'button' && node.children === 'Wis sessie').props.onClick()
  assert.equal(aborts, 1)
  assert.equal(calls[0].signal.aborted, true)
  assertEmpty(state)
  assertDisconnected(sockets[0])
  calls[0].resolve(snapshot({ status: 'committed', record: record() }))
  await pending
  assertEmpty(state)
  assert.equal(aborts, 1)
  assert.equal(calls.length, 1)
  assert.equal(sockets.length, 1)
  assertDisconnected(sockets[0])
})

test('compiled token input exposes neutral empty and linked static invalid feedback without changing input', async t => {
  const { state, calls, sockets } = fixture(t)
  const render = tokenAccess()
  assert.equal(Vue.isReadonly(state.validToken), true)
  let { find } = await render(state)
  const update = find(node => node.props?.id === 'token').props['onUpdate:modelValue']
  for (const [token, valid] of [
    ['', false], [' ', false], ['\t\u00a0', false], ['private\rvalue', false],
    ['private\nvalue', false], ['private\r\nvalue', false],
    ['unverified-token', true], [' unverified-token ', true], ['\ttoken\t', true],
    ['a b', true], ['a\tb', true], ['é😀', true], ['a\u2028b', true], ['a\0b', true],
  ]) {
    update(token)
    assert.equal(state.token.value, token, 'the compiled model never trims or normalizes tokens')
    assert.equal(state.validToken.value, valid)
    const invalid = token !== '' && !valid
    const { html, find } = await render(state)
    const input = find(node => node.props?.id === 'token')
    const error = find(node => node.props?.id === 'token-error')
    assert.equal(input.props.type, 'password')
    assert.equal(input.props.autocomplete, 'off')
    assert.equal(input.props.spellcheck, 'false')
    assert.equal(input.props['aria-invalid'], invalid)
    const describedBy = invalid ? 'token-help token-error' : 'token-help'
    assert.equal(input.props['aria-describedby'], describedBy)
    const renderedInput = html.match(/<input[^>]*id="token"[^>]*>/)[0]
    assert.ok(renderedInput.includes(`aria-invalid="${invalid}"`))
    assert.ok(renderedInput.includes(`aria-describedby="${describedBy}"`))
    assert.equal(!!error, invalid)
    assert.equal(html.includes('id="token-error"'), invalid)
    if (invalid) {
      assert.equal(error.children, 'Ongeldig tokenformaat: gebruik niet alleen witruimte en geen CR- of LF-regeleinden.')
      assert.ok(!error.children.includes('private'))
    }
    assert.match(html, /De invoer blijft ongewijzigd; alleen de server beslist over toegang\./)
    state.busy.value = 'list'
    assert.equal((await render(state)).find(node => node.props?.id === 'token').props.disabled, true)
    state.busy.value = ''
  }
  assert.deepEqual(calls, [])
  assert.deepEqual(sockets, [])
})

test('compiled commit help stays linked and static across real session guards without side effects', async t => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const panel = app.slice(app.indexOf('<h2>2. Apart bevestigen</h2>'), app.indexOf('</section>', app.indexOf('<h2>2. Apart bevestigen</h2>')))
  const button = panel.match(/<button[^>]*>Commando vastleggen<\/button>/)[0]
  assert.equal(button, '<button :disabled="!!busy || !canCommit || !validToken" aria-describedby="commit-help" @click="perform(\'commit\')">Commando vastleggen</button>')
  const help = panel.match(/<p id="commit-help" class="muted">[\s\S]*?<\/p>/)[0]
  assert.doesNotMatch(help, /\{\{|v-|@/)
  assert.equal(app.match(/\bid="commit-help"/g).length, 1)
  assert.equal(app.match(/\baria-describedby="commit-help"/g).length, 1)
  assert.ok(panel.indexOf(help) > panel.indexOf('<p v-else class="muted">Nog geen ticket.'))
  const expectedHelp = 'Lokale geschiktheid en een eerdere actieve status garanderen geen actuele servertoestemming: een andere client kan het ticket al hebben ingetrokken of verbruikt. De server controleert opnieuw bij vastleggen; een statuscontrole reserveert het ticket niet. Geen automatische herhaling.'
  const helpers = app.match(/function date\(value\) \{[\s\S]*?\n\}[\s\S]*?function receiptIso\(value\) \{[\s\S]*?\n\}/)[0]
  const formatters = new Function('timestamp', `${helpers}; return { date, receiptIso }`)(timestamp)
  const render = compileFragment(`<div>${panel}</div>`)
  for (const [scenario, canCommit, disabled] of [
    ['eligible without status', true, false],
    ['earlier active status', true, false],
    ['absent ticket', false, true],
    ['expired ticket', false, true],
    ['uncertain revocation', false, true],
    ['busy', true, true],
    ['invalid token', true, true],
  ]) {
    await t.test(scenario, async t => {
      const { state, calls, sockets, clock } = fixture(t)
      if (scenario === 'invalid token') state.token.value = 'invalid\nformat'
      prepare(state, 'commit')
      let pending
      if (scenario === 'eligible without status') {
        state.clearOutcome()
        assert.equal(state.outcome.value, null)
      } else if (scenario === 'absent ticket') {
        state.clearCommand()
        assert.equal(state.ticket.value, null)
      } else if (scenario === 'expired ticket') {
        clock.time = held().expires_at
        clock.tick()
      } else if (scenario === 'uncertain revocation') {
        pending = state.perform('revoke')
        calls[0].reject(new Error('Revocation not confirmed'))
        await pending
        assert.equal(state.revocationUncertain.value, true)
      } else if (scenario === 'busy') {
        pending = state.perform('status')
        assert.equal(state.busy.value, 'status')
      }
      assert.equal(state.canCommit.value, canCommit)
      assert.equal(state.validToken.value, scenario !== 'invalid token')
      const before = JSON.stringify(commandState(state))
      const callsBefore = calls.slice()
      const readsBefore = clock.reads
      for (let pass = 0; pass < 2; pass++) {
        const { html, find } = await render({ ...state, ...formatters })
        const renderedButton = find(node => node.type === 'button' && node.children === 'Commando vastleggen')
        assert.equal(renderedButton.props.disabled, disabled)
        assert.equal(renderedButton.props['aria-describedby'], 'commit-help')
        assert.equal(/\sdisabled(?:[=>\s])/.test(html.match(/<button[^>]*>Commando vastleggen<\/button>/)[0]), disabled)
        assert.equal(html.match(/\bid="commit-help"/g).length, 1)
        assert.equal(html.match(/\baria-describedby="commit-help"/g).length, 1)
        const renderedHelp = find(node => node.props?.id === 'commit-help')
        assert.equal(renderedHelp.type, 'p')
        assert.equal(renderedHelp.props.class, 'muted')
        assert.equal(renderedHelp.children, expectedHelp)
        assert.equal(JSON.stringify(commandState(state)), before)
        assert.deepEqual(calls, callsBefore)
        assert.deepEqual(sockets, [])
        assert.equal(clock.reads, readsBefore)
      }
      if (scenario === 'busy') {
        calls[0].resolve(snapshot())
        await pending
      }
    })
  }
})

test('compiled revoke help stays linked and static across real session guards without side effects', async t => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const panel = app.slice(app.indexOf('<h2>2. Apart bevestigen</h2>'), app.indexOf('</section>', app.indexOf('<h2>2. Apart bevestigen</h2>')))
  const button = panel.match(/<button[^>]*>Ticket intrekken<\/button>/)[0]
  assert.equal(button, '<button class="secondary" :disabled="!!busy || !ticket || !validToken" aria-describedby="revoke-help" @click="perform(\'revoke\')">Ticket intrekken</button>')
  const help = panel.match(/<p id="revoke-help" class="muted">[\s\S]*?<\/p>/)[0]
  assert.doesNotMatch(help, /\{\{|v-|@/)
  assert.equal(app.match(/\bid="revoke-help"/g).length, 1)
  assert.equal(app.match(/\baria-describedby="revoke-help"/g).length, 1)
  assert.ok(panel.indexOf(help) > panel.indexOf('<p v-else class="muted">Nog geen ticket.'))
  const expectedHelp = 'Intrekken wijzigt het ticket op de server; eerder opgeslagen records blijven behouden. Een sessie wissen of invoer wijzigen is geen intrekking. Een verloren antwoord bewijst geen intrekking: controleer expliciet hetzelfde ticket of trek het bewust opnieuw in. Geen automatische herhaling.'
  const helpers = app.match(/function date\(value\) \{[\s\S]*?\n\}[\s\S]*?function receiptIso\(value\) \{[\s\S]*?\n\}/)[0]
  const formatters = new Function('timestamp', `${helpers}; return { date, receiptIso }`)(timestamp)
  const render = compileFragment(`<div>${panel}</div>`)
  for (const [scenario, disabled] of [
    ['eligible ticket', false],
    ['absent ticket', true],
    ['expired ticket', false],
    ['uncertain revocation', false],
    ['busy', true],
    ['empty token', true],
    ['invalid token', true],
  ]) {
    await t.test(scenario, async t => {
      const { state, calls, sockets, clock } = fixture(t)
      if (scenario === 'empty token') state.token.value = ''
      if (scenario === 'invalid token') state.token.value = 'invalid\nformat'
      prepare(state, scenario === 'uncertain revocation' ? 'revoke' : 'commit')
      if (scenario === 'absent ticket') state.clearCommand()
      if (scenario === 'expired ticket') {
        clock.time = held().expires_at
        clock.tick()
        assert.equal(state.canCommit.value, false)
      }
      if (scenario === 'uncertain revocation') {
        assert.equal(state.revocationUncertain.value, true)
        assert.equal(state.canCommit.value, false)
      }
      if (scenario === 'busy') state.busy.value = 'status'
      const before = JSON.stringify(commandState(state))
      const readsBefore = clock.reads
      for (let pass = 0; pass < 2; pass++) {
        const { html, find } = await render({ ...state, ...formatters })
        const renderedButton = find(node => node.type === 'button' && node.children === 'Ticket intrekken')
        assert.equal(renderedButton.props.disabled, disabled)
        assert.equal(renderedButton.props['aria-describedby'], 'revoke-help')
        assert.equal(/\sdisabled(?:[=>\s])/.test(html.match(/<button[^>]*>Ticket intrekken<\/button>/)[0]), disabled)
        assert.equal(html.match(/\bid="revoke-help"/g).length, 1)
        assert.equal(html.match(/\baria-describedby="revoke-help"/g).length, 1)
        const renderedHelp = find(node => node.props?.id === 'revoke-help')
        assert.equal(renderedHelp.type, 'p')
        assert.equal(renderedHelp.props.class, 'muted')
        assert.equal(renderedHelp.children, expectedHelp)
        assert.equal(JSON.stringify(commandState(state)), before)
        assert.deepEqual(calls, [])
        assert.deepEqual(sockets, [])
        assert.equal(clock.reads, readsBefore)
      }
    })
  }
})

test('compiled action buttons consistently gate on token format while retaining their other guards', async t => {
  const { state, calls, sockets } = fixture(t)
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const labels = [
    'Ticket aanvragen', 'Status controleren', 'Commando vastleggen', 'Ticket intrekken',
    'Controleer huidig ticket', 'Controleer laatste inzending', 'Realtime verbinden', 'Logboek vernieuwen',
  ]
  const buttons = labels.map(label => app.match(new RegExp(`<button[^>]*>${label}</button>`))[0])
  const render = compileFragment(`<div>${buttons.join('')}</div>`)
  async function check(disabled) {
    const { find, html } = await render(state)
    for (const label of labels) {
      assert.equal(find(node => node.type === 'button' && node.children === label).props.disabled, disabled, label)
      const button = html.match(new RegExp(`<button[^>]*>${label}</button>`))[0]
      assert.equal(/\sdisabled(?:[=>\s])/.test(button), disabled, label)
    }
  }
  for (const token of ['', ' ', '\t\u00a0', 'private\rvalue', 'private\nvalue', 'private\r\nvalue', ' unverified-token ', 'é😀', 'a\tb']) {
    state.token.value = token
    prepare(state, 'status')
    state.message.value = ''
    state.error.value = ''
    assert.equal(state.canCommit.value, true, 'token formatting must not create or retire ticket authority')
    await check(!state.validToken.value)
    state.busy.value = 'list'
    await check(true)
    state.busy.value = ''
  }
  state.token.value = 'unverified-token'
  prepare(state, 'status')
  state.revocationUncertain.value = true
  let rendered = await render(state)
  for (const label of ['Ticket aanvragen', 'Commando vastleggen']) {
    assert.equal(rendered.find(node => node.type === 'button' && node.children === label).props.disabled, true)
  }
  for (const label of ['Ticket intrekken', 'Controleer huidig ticket', 'Controleer laatste inzending', 'Status controleren']) {
    assert.equal(rendered.find(node => node.type === 'button' && node.children === label).props.disabled, false)
  }
  state.ticket.value = null
  rendered = await render(state)
  for (const label of ['Commando vastleggen', 'Ticket intrekken', 'Controleer huidig ticket']) {
    assert.equal(rendered.find(node => node.type === 'button' && node.children === label).props.disabled, true)
  }
  for (const status of ['connecting', 'connected']) {
    state.realtimeStatus.value = status
    rendered = await render(state)
    assert.equal(rendered.find(node => node.children === 'Realtime verbinden').props.disabled, true)
    assert.equal(rendered.find(node => node.children === 'Logboek vernieuwen').props.disabled, false)
  }
  assert.deepEqual(calls, [])
  assert.deepEqual(sockets, [])
})

for (const token of ['', ' \t ', 'private\rvalue', 'private\nvalue', 'private\r\nvalue', ' unverified-token ']) {
  test(`compiled token changes preserve reset and stale-result isolation for ${JSON.stringify(token)}`, async t => {
    const { state, calls, sockets } = fixture(t)
    state.realtime.connect(state.token.value)
    const socket = sockets[0]
    prepare(state, 'revoke')
    const checking = state.perform('status')
    const { find } = await tokenAccess()(state)
    find(node => node.props?.id === 'token').props['onUpdate:modelValue'](token)
    assertEmpty(state, token)
    assertDisconnected(socket)
    assert.equal(calls[0].signal.aborted, true)
    calls[0].resolve(snapshot({ status: 'committed', record: record() }))
    await checking
    socket.handlers.connect()
    socket.handlers['command:committed'](record())
    assertEmpty(state, token)
    assert.equal(calls.length, 1, 'token edits never request automatically')
    assert.equal(sockets.length, 1, 'token edits never reconnect automatically')
  })
}

function outcomeClearButton() {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const button = app.match(/<button[^>]*@click="clearOutcome"[^>]*>Wis ticketuitkomst<\/button>/)[0]
  const { code } = compile(button, { mode: 'function', prefixIdentifiers: true })
  const render = new Function('Vue', code)(Vue)
  return async (state, enabled) => {
    assert.equal(state.canClearOutcome.value, enabled)
    const vnode = render(Vue.proxyRefs(state), {})
    assert.equal(vnode.props.disabled, !enabled)
    assert.equal(vnode.props.onClick, state.clearOutcome)
    const html = await renderToString(Vue.createSSRApp({ setup: () => state, render }))
    assert.equal(/\sdisabled(?:[=>\s])/.test(html), !enabled, html)
    return vnode
  }
}

function ticketForm() {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const form = app.match(/<form @submit.prevent="perform\('ticket'\)">[\s\S]*?<\/form>/)[0]
  const { code } = compile(form, { mode: 'function', prefixIdentifiers: true })
  const render = new Function('Vue', code)(Vue)
  return async (state, enabled, valid = state.validTtl.value) => {
    const before = sessionSnapshot(state)
    const context = { ...state, commandLength, MAX_COMMAND_LENGTH }
    let vnode
    const html = await renderToString(Vue.createSSRApp({
      setup: () => context,
      render() {
        vnode = render(this, {})
        return vnode
      },
    }))
    const find = (node, predicate) => {
      if (predicate(node)) return node
      return Array.isArray(node.children)
        ? node.children.map(child => find(child, predicate)).find(Boolean)
        : undefined
    }
    const button = find(vnode, node => node.type === 'button')
    const input = find(vnode, node => node.props?.id === 'ttl')
    const textarea = find(vnode, node => node.props?.id === 'command')
    const commandError = find(vnode, node => node.props?.id === 'command-error')
    const invalidCommand = state.command.value !== '' &&
      (!state.command.value.trim() || state.command.value.length > MAX_COMMAND_LENGTH)
    const commandDescription = invalidCommand ? 'command-limit command-error' : 'command-limit'
    assert.equal(textarea.props['aria-invalid'], invalidCommand)
    assert.equal(textarea.props['aria-describedby'], commandDescription)
    assert.equal(textarea.props.maxlength, MAX_COMMAND_LENGTH)
    assert.equal(textarea.props.required, '')
    assert.equal(textarea.props.disabled, !!state.busy.value)
    assert.equal(!!commandError, invalidCommand)
    const renderedTextarea = html.match(/<textarea[^>]*id="command"[^>]*>[\s\S]*?<\/textarea>/)[0]
    assert.ok(renderedTextarea.includes(`aria-invalid="${invalidCommand}"`))
    assert.ok(renderedTextarea.includes(`aria-describedby="${commandDescription}"`))
    assert.equal(html.includes('id="command-error"'), invalidCommand)
    assert.ok(html.includes(`${state.command.value.length} / ${MAX_COMMAND_LENGTH} UTF-16-tekeneenheden`))
    if (invalidCommand) {
      const expected = state.command.value.length > MAX_COMMAND_LENGTH
        ? `Commando te lang: maximaal ${MAX_COMMAND_LENGTH} UTF-16-tekeneenheden.`
        : 'Commando mag niet alleen uit witruimte bestaan.'
      assert.equal(commandError.children, expected)
      assert.ok(html.includes(expected))
    }
    assert.equal(state.canRequestTicket.value, enabled)
    assert.equal(state.validTtl.value, valid)
    assert.equal(button.props.disabled, !enabled)
    assert.equal(input.props['aria-invalid'], !valid)
    assert.equal(input.props['aria-describedby'], 'ttl-help')
    assert.equal(input.props.type, 'number')
    assert.equal(input.props.min, '1')
    assert.equal(input.props.max, '60000')
    assert.equal(input.props.step, '1')
    assert.equal(input.props.required, '')
    assert.equal(input.props.disabled, !!state.busy.value)
    const renderedButton = html.match(/<button[^>]*>Ticket aanvragen<\/button>/)[0]
    const renderedInput = html.match(/<input[^>]*id="ttl"[^>]*>/)[0]
    assert.equal(/\sdisabled(?:[=>\s])/.test(renderedButton), !enabled, html)
    assert.match(renderedInput, new RegExp(`aria-invalid="${!valid}"`))
    assert.match(renderedInput, /aria-describedby="ttl-help"/)
    assert.match(html, /id="ttl-help"/)
    assert.match(html, /Vul een geheel aantal milliseconden in van 1 tot en met 60000\./)
    const help = find(vnode, node => node.props?.id === 'ttl-help')
    const guidance = help.children.find(node => node.type === 'p' &&
      typeof node.children === 'string' && node.children.startsWith('Duur wijzigen'))
    assert.equal(guidance.props.class, 'muted')
    assert.equal(guidance.children, 'Duur wijzigen maakt een normaal lokaal ticket ongeldig; het uitgegeven geldigheidsvenster op de server verandert niet en het ticket wordt niet ingetrokken. Een onzekere intrekking behoudt het oorspronkelijke ticket en blijft vastleggen en nieuwe tickets blokkeren. Terugwijzigen herstelt geen verloren toestemming. Geen automatische verzoeken.')
    assert.ok(html.includes(guidance.children))
    assert.equal(html.includes('Ongeldige duur: kies een geheel getal van 1 tot en met 60000.'), !valid)
    assert.deepEqual(sessionSnapshot(state), before, 'rendering the TTL form has no session side effects')
    return { vnode, input, textarea, html }
  }
}

function statusForm() {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const form = app.match(/<form @submit.prevent="perform\('status'\)">[\s\S]*?<\/form>/)[0]
  const { code } = compile(form, { mode: 'function', prefixIdentifiers: true })
  const render = new Function('Vue', code)(Vue)
  return async (state, enabled, valid = state.validLookupId.value) => {
    let vnode
    const html = await renderToString(Vue.createSSRApp({
      setup: () => state,
      render() {
        vnode = render(this, {})
        return vnode
      },
    }))
    const input = vnode.children.find(node => node.props?.id === 'lookup-id')
    const button = vnode.children.find(node => node.type === 'button')
    const error = vnode.children.find(node => node.props?.id === 'lookup-id-error')
    const invalid = state.lookupId.value !== '' && !valid
    const describedBy = invalid ? 'lookup-id-help lookup-id-error' : 'lookup-id-help'
    assert.equal(state.validLookupId.value, valid)
    assert.equal(state.canCheckStatus.value, enabled)
    assert.equal(button.props.disabled, !enabled)
    assert.equal(input.props['aria-invalid'], invalid)
    assert.equal(input.props['aria-describedby'], describedBy)
    assert.equal(input.props.maxlength, '128')
    assert.equal(input.props.required, '')
    assert.equal(input.props.disabled, !!state.busy.value)
    assert.equal(!!error, invalid)
    const renderedButton = html.match(/<button[^>]*>Status controleren<\/button>/)[0]
    const renderedInput = html.match(/<input[^>]*id="lookup-id"[^>]*>/)[0]
    assert.equal(/\sdisabled(?:[=>\s])/.test(renderedButton), !enabled, html)
    assert.match(renderedInput, new RegExp(`aria-invalid="${invalid}"`))
    assert.ok(renderedInput.includes(`aria-describedby="${describedBy}"`))
    assert.equal(html.includes('id="lookup-id-error"'), invalid)
    assert.equal(html.includes('Ongeldig ticket-ID:'), invalid)
    assert.match(html, /id="lookup-id-help"/)
    assert.match(html, /Formaat: 1–128 ASCII-letters/)
    assert.match(html, /Een ander ID wist alleen de lokale status en breekt een lopende statuscontrole lokaal af\./)
    assert.match(html, /Geen herstel van toestemming of intrekking op de server; geen automatisch verzoek\. Gebruik het exacte ID, zonder omringende spaties\./)
    return { vnode, input }
  }
}

for (const [id, valid] of [
  ['', false], ['a', true], ['Z', true], ['0', true], ['_', true], ['-', true],
  ['aZ09_-', true], ['a'.repeat(128), true], ['a'.repeat(129), false],
  ['é', false], ['票', false], ['😀', false], [' ', false], [' a', false],
  ['a ', false], ['a b', false], ['a/b', false], ['a\r', false],
  ['a\n', false], ['a\r\n', false], ['a\tb', false],
]) {
  test(`compiled status form reacts to exact lookup ID ${JSON.stringify(id)}`, async t => {
    const { state, calls } = fixture(t)
    const checkForm = statusForm()
    assert.equal(Vue.isReadonly(state.validLookupId), true)
    assert.equal(Vue.isReadonly(state.canCheckStatus), true)
    const { input } = await checkForm(state, false, false)
    input.props['onUpdate:modelValue'](id)
    assert.equal(state.lookupId.value, id, 'the model never trims or normalizes IDs')
    await checkForm(state, valid, valid)
    input.props['onUpdate:modelValue']('valid_ID-1')
    await checkForm(state, true, true)
    input.props['onUpdate:modelValue']('')
    await checkForm(state, false, false)
    assert.equal(calls.length, 0, 'editing and rendering never issue requests')
  })
}

test('status eligibility and compiled form react to token, busy and disposal guards', async t => {
  const { state, scope, calls } = fixture(t)
  const checkForm = statusForm()
  state.lookupId.value = 'valid_ID-1'
  await checkForm(state, true)
  for (const token of ['', ' \t ', 'token\rvalue', 'token\nvalue', 'token\r\n', null, undefined, 1, {}]) {
    state.token.value = token
    state.lookupId.value = 'valid_ID-1'
    await checkForm(state, false, true)
    state.token.value = 'test-session-token'
    state.lookupId.value = 'valid_ID-1'
    await checkForm(state, true, true)
  }
  for (const action of Object.keys(actions)) {
    state.busy.value = action
    await checkForm(state, false, true)
    state.busy.value = ''
    await checkForm(state, true, true)
  }
  state.token.value = ' test-session-token '
  state.lookupId.value = 'valid_ID-1'
  await checkForm(state, true, true)
  state.revocationUncertain.value = true
  await checkForm(state, true, true)
  scope.stop()
  state.token.value = 'test-session-token'
  state.lookupId.value = 'valid_ID-1'
  assert.equal(state.busy.value, '')
  await checkForm(state, false, true)
  assert.equal(calls.length, 0)
})

test('compiled status form submits only explicitly with the exact ID and status action', async t => {
  const { state, calls } = fixture(t)
  const checkForm = statusForm()
  const { input } = await checkForm(state, false, false)
  for (const id of ['_', 'A_z-09'.repeat(21) + '_-']) {
    input.props['onUpdate:modelValue'](id)
    const { vnode } = await checkForm(state, true, true)
    const previousCalls = calls.length
    let prevented = false
    const operation = vnode.props.onSubmit({ preventDefault() { prevented = true } })
    assert.equal(prevented, true)
    assert.equal(calls.length, previousCalls + 1)
    const call = calls.at(-1)
    assert.equal(call.action, 'status')
    assert.deepEqual(call.args.slice(0, 2), [id, 'test-session-token'])
    await checkForm(state, false, true)
    call.resolve(snapshot({ id }))
    await operation
    await checkForm(state, true, true)
    assert.equal(state.outcome.value.id, id)
  }
  assert.equal(calls.length, 2)
})

for (const [value, valid] of [
  [1, true], [60000, true], [0, false], [60001, false], [1.5, false],
  [NaN, false], [Infinity, false], [-Infinity, false], ['', false],
  ['1', true], ['60000', true], [' 42 ', true], ['1e3', true], ['1.0', true],
  ['0', false], ['60001', false], ['1.5', false], ['NaN', false],
  ['Infinity', false], [' ', false], ['not a number', false],
]) {
  test(`ticket form renders TTL ${typeof value === 'string' ? JSON.stringify(value) : String(value)} (${typeof value}) as ${valid ? 'valid' : 'invalid'}`, async t => {
    const { state, calls } = fixture(t)
    const checkForm = ticketForm()
    state.command.value = 'journal only'
    assert.equal(Vue.isReadonly(state.validTtl), true)
    assert.equal(Vue.isReadonly(state.canRequestTicket), true)
    await checkForm(state, true, true)
    state.ttlMs.value = value
    await checkForm(state, valid, valid)
    state.ttlMs.value = 10000
    await checkForm(state, true, true)
    assert.equal(calls.length, 0, 'editing and rendering do not issue requests')
  })
}

test('ticket eligibility and compiled form react to every non-TTL guard', async t => {
  const { state, scope, calls } = fixture(t)
  const checkForm = ticketForm()
  state.command.value = 'journal only'
  await checkForm(state, true)
  for (const token of ['', ' \t ', 'token\rvalue', 'token\nvalue', 'token\r\n']) {
    state.token.value = token
    state.command.value = 'journal only'
    await checkForm(state, false)
    state.token.value = 'test-session-token'
    state.command.value = 'journal only'
    await checkForm(state, true)
  }
  for (const command of ['', ' \t\n ', 'a'.repeat(MAX_COMMAND_LENGTH + 1), '😀'.repeat(513)]) {
    state.command.value = command
    await checkForm(state, false)
    state.command.value = 'journal only'
    await checkForm(state, true)
  }
  for (const command of ['a'.repeat(MAX_COMMAND_LENGTH), '😀'.repeat(512), ' journal only ']) {
    state.command.value = command
    await checkForm(state, true)
  }
  for (const action of Object.keys(actions)) {
    state.busy.value = action
    await checkForm(state, false)
    state.busy.value = ''
    await checkForm(state, true)
  }
  state.revocationUncertain.value = true
  await checkForm(state, false)
  state.ttlMs.value = 0
  await checkForm(state, false, false)
  state.ttlMs.value = 1
  await checkForm(state, false, true)
  state.revocationUncertain.value = false
  await checkForm(state, true)
  scope.stop()
  state.token.value = 'test-session-token'
  state.command.value = 'journal only'
  state.ttlMs.value = 60000
  assert.equal(state.busy.value, '')
  assert.equal(state.revocationUncertain.value, false)
  await checkForm(state, false, true)
  assert.equal(calls.length, 0)
})

test('compiled command model preserves exact text and reacts without requests or restored authority', async t => {
  const { state, calls, sockets } = fixture(t)
  const checkForm = ticketForm()
  const { textarea } = await checkForm(state, false)
  assert.equal(state.command.value, '')
  state.command.value = held().command
  state.ticket.value = held()
  assert.equal(state.canCommit.value, true)

  for (const [command, enabled] of [
    [' \t\n\u00a0', false],
    ['a'.repeat(1024), true],
    ['a'.repeat(1025), false],
    ['😀'.repeat(512), true],
    ['😀'.repeat(513), false],
    [' \t😀 <script>alert("tekst")</script> & \n ', true],
    ['', false],
    [' journal only ', true],
    [held().command, true],
  ]) {
    textarea.props['onUpdate:modelValue'](command)
    const { html } = await checkForm(state, enabled)
    assert.equal(state.command.value, command, 'the compiled model never trims or normalizes text')
    const escaped = command.replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
    assert.ok(html.includes(`>${escaped}</textarea>`), 'the textarea renders exact text as escaped markup')
    assert.ok(!html.includes('<script>'))
    assert.equal(state.ticket.value, null)
    assert.equal(state.canCommit.value, false, 'returning to the original text does not restore authority')
    assert.equal(calls.length, 0)
    assert.equal(sockets.length, 0)
  }
})

test('compiled TTL model updates eligibility without changing the ticket submit action', async t => {
  const { state, calls } = fixture(t)
  const checkForm = ticketForm()
  state.command.value = 'journal only'
  const { input } = await checkForm(state, true)
  input.props['onUpdate:modelValue']('')
  await checkForm(state, false, false)
  input.props['onUpdate:modelValue']('60000')
  const { vnode } = await checkForm(state, true, true)
  let prevented = false
  const operation = vnode.props.onSubmit({ preventDefault() { prevented = true } })
  assert.equal(prevented, true)
  assert.equal(calls.length, 1)
  assert.equal(calls[0].action, 'ticket')
  assert.deepEqual(calls[0].args.slice(0, 3), ['journal only', 60000, 'test-session-token'])
  await checkForm(state, false, true)
  calls[0].resolve(held())
  await operation
  await checkForm(state, true, true)
})

for (const uncertain of [false, true]) {
  test(`compiled TTL edits retire only normal local authority without restoring it, uncertainty=${uncertain}`, async t => {
    const { state, calls, sockets, clock } = fixture(t)
    prepare(state, uncertain ? 'revoke' : 'ticket')
    const checkForm = ticketForm()
    const { input } = await checkForm(state, !uncertain)
    const originalTicket = state.ticket.value
    const issuedWindow = structuredClone(held())
    const outcome = state.outcome.value
    const journal = state.commands.value
    const retained = sessionSnapshot(state, [
      'ttlMs', 'validTtl', 'canRequestTicket', 'ticket', 'canCommit', 'remaining',
    ])
    const reads = clock.reads
    assert.equal(state.canCommit.value, !uncertain)

    for (const value of [51, '', 50]) {
      input.props['onUpdate:modelValue'](value)
      assert.equal(state.ttlMs.value, value)
      assert.equal(state.ticket.value, uncertain ? originalTicket : null)
      assert.equal(state.revocationUncertain.value, uncertain)
      assert.equal(state.canCommit.value, false, 'returning to the original duration never restores authority')
      await checkForm(state, !uncertain && value !== '', value !== '')
      assert.deepEqual(originalTicket, issuedWindow, 'duration edits never change the issued server window')
      assert.deepEqual(sessionSnapshot(state, [
        'ttlMs', 'validTtl', 'canRequestTicket', 'ticket', 'canCommit', 'remaining',
      ]), retained, 'outcome, submission ID, journal and other session state remain unchanged')
      assert.equal(state.outcome.value, outcome)
      assert.equal(state.commands.value, journal)
      assert.equal(calls.length, 0, 'edits and renders send no requests')
      assert.equal(sockets.length, 0, 'edits and renders create no sockets')
      assert.equal(clock.reads, reads)
      assert.deepEqual(clock.cleared, [])
    }
  })
}

test('eligible numeric TTL strings retain the existing request Number conversion', async t => {
  const { state, calls } = fixture(t)
  state.command.value = 'journal only'
  for (const value of ['1', '60000', ' 42 ', '1e3', '1.0']) {
    state.ttlMs.value = value
    assert.equal(state.validTtl.value, true)
    assert.equal(state.canRequestTicket.value, true)
    const operation = state.perform('ticket')
    const call = calls.at(-1)
    assert.equal(call.args[1], Number(value))
    assert.equal(state.canRequestTicket.value, false)
    call.resolve(held())
    await operation
    assert.equal(state.canRequestTicket.value, true)
  }
  assert.equal(calls.length, 5)
})

for (const value of [0, 1050, 8_640_000_000_000_000]) {
  test(`startup preserves valid clock ${value}`, t => {
    const { state, clock } = fixture(t, undefined, {}, { time: value })
    assert.equal(state.now.value, value)
    assert.equal(clock.reads, 1)
  })
}

for (const value of [null, '1050', NaN, 8_640_000_000_000_001, 'throw']) {
  test(`startup clock ${String(value)} fails closed without throwing`, t => {
    const { state, clock } = fixture(t, undefined, {}, {
      now: () => {
        if (value === 'throw') throw new Error('startup clock unavailable')
        return value
      },
    })
    assert.equal(state.now.value, null)
    assert.equal(clock.reads, 1)
    state.command.value = held().command
    state.ticket.value = held()
    assert.equal(state.canCommit.value, false)
    assert.equal(state.remaining.value, null)
    assert.equal(state.error.value, '')
  })
}

test('throwing startup clock still registers and cleans up lifecycle hooks', t => {
  class TrackedTarget extends EventTarget {
    added = []
    removed = []
    addEventListener(...args) { this.added.push(args); super.addEventListener(...args) }
    removeEventListener(...args) { this.removed.push(args); super.removeEventListener(...args) }
  }
  const eventTarget = new TrackedTarget()
  const { state, clock, scope, calls } = fixture(t, eventTarget, {}, {
    now: () => { throw new Error('startup clock unavailable') },
  })
  assert.equal(clock.interval, 100)
  assert.equal(typeof clock.tick, 'function')
  assert.equal(eventTarget.added.length, 1)
  assert.equal(eventTarget.added[0][0], 'pagehide')
  state.command.value = held().command
  eventTarget.dispatchEvent(pageTransition('pagehide', true))
  assertEmpty(state)
  scope.stop()
  assert.deepEqual(eventTarget.removed, eventTarget.added)
  assert.deepEqual(clock.cleared, [42])
  const reads = clock.reads
  clock.tick()
  assert.equal(clock.reads, reads)
  assert.equal(calls.length, 0)
})

test('clock outage from startup through issuance retains a ticket for explicit status and revoke', async t => {
  const { state, calls, clock } = fixture(t, undefined, {}, {
    now: () => { throw new Error('clock unavailable') },
  })
  state.command.value = held().command
  const issuing = state.perform('ticket')
  calls[0].resolve(held())
  await issuing
  assert.deepEqual(state.ticket.value, held())
  assert.equal(state.now.value, null)
  assert.equal(state.canCommit.value, false)
  assert.equal(state.remaining.value, null)
  assert.equal(state.error.value, '')
  assert.equal(state.busy.value, '')
  assert.doesNotThrow(() => clock.tick())
  await state.perform('commit')
  assert.equal(calls.length, 1, 'no submission during the outage')
  const checking = state.checkCurrentTicket()
  assert.equal(calls[1].action, 'status')
  assert.equal(calls[1].args[0], held().id)
  calls[1].resolve(snapshot())
  await checking
  assert.deepEqual(state.ticket.value, held())
  assert.equal(state.outcomeReceivedAt.value, null)
  assert.equal(state.canCommit.value, false)
  assert.equal(state.remaining.value, null)
  const revoking = state.perform('revoke')
  assert.equal(calls[2].action, 'revoke')
  assert.deepEqual(calls[2].args[0], held())
  calls[2].resolve()
  await revoking
  assert.equal(state.ticket.value, null)
  assert.equal(state.revocationUncertain.value, false)
  assert.equal(state.error.value, '')
  assert.equal(state.busy.value, '')
})

test('explicit recovery after startup outage permits only a fresh valid commit preflight', async t => {
  const { state, calls, clock } = fixture(t, undefined, {}, { time: null })
  state.command.value = held().command
  const issuing = state.perform('ticket')
  calls[0].resolve(held())
  await issuing
  assert.equal(state.canCommit.value, false)
  clock.time = 1050
  clock.tick()
  assert.equal(state.canCommit.value, true)
  assert.equal(state.remaining.value, 1)
  assert.equal(calls.length, 1, 'clock recovery does not submit automatically')
  clock.time = null
  await state.perform('commit')
  assert.equal(state.now.value, null)
  assert.equal(state.canCommit.value, false)
  assert.deepEqual(state.ticket.value, held())
  assert.equal(calls.length, 1, 'fresh preflight rejects a renewed outage')
  clock.time = 1050
  const reads = clock.reads
  const committing = state.perform('commit')
  assert.equal(clock.reads, reads + 1)
  assert.equal(state.now.value, 1050)
  assert.equal(calls[1].action, 'commit')
  assert.deepEqual(calls[1].args[0], held())
  assert.equal(state.ticket.value, null)
  calls[1].resolve(record())
  await committing
  assert.equal(state.lastSubmissionId.value, held().id)
  assert.deepEqual(state.commands.value, [record()])
  assert.equal(state.error.value, '')
  await state.perform('commit')
  assert.equal(calls.length, 2, 'consumed ticket cannot be submitted twice')
})

for (const value of [
  1100, null, undefined, '', '1050', true, {}, [], -1, 0.5, NaN, Infinity, -Infinity,
  8_640_000_000_000_001, Number.MAX_SAFE_INTEGER, 'throw',
]) {
  test(`commit freshly rejects expiry or unavailable clock ${String(value)} without a countdown tick`, async t => {
    const { state, calls, clock } = fixture(t)
    prepare(state, 'commit')
    const retained = commandState(state, ['now', 'canCommit', 'remaining', 'message', 'error'])
    assert.equal(state.canCommit.value, true)
    const reads = clock.reads
    clock.now = () => {
      assert.equal(state.ticket.value, retained.ticket)
      assert.equal(state.lastSubmissionId.value, retained.lastSubmissionId)
      assert.equal(state.outcome.value, retained.outcome)
      assert.equal(calls.length, 0)
      if (value === 'throw') throw new Error('commit clock unavailable')
      return value
    }

    await state.perform('commit')
    assert.equal(clock.reads, reads + 1)
    assert.equal(state.now.value, value === 1100 ? 1100 : null)
    assert.equal(state.canCommit.value, false)
    assert.deepEqual(commandState(state, ['now', 'canCommit', 'remaining', 'message', 'error']), retained)
    assert.equal(state.busy.value, '')
    assert.equal(state.error.value, '')
    assert.equal(state.message.value, localCommitBlocked)
    assert.equal(calls.length, 0)
    assert.equal(clock.interval, 100)
  })
}

for (const reason of ['not yet valid', 'command mismatch', 'no ticket', 'uncertain revoke']) {
  test(`local commit feedback preserves session state for ${reason}`, async t => {
    const { state, calls, clock } = fixture(t)
    prepare(state, 'commit')
    if (reason === 'not yet valid') clock.time = 999
    if (reason === 'command mismatch') state.ticket.value = { ...held(), command: 'other command' }
    if (reason === 'no ticket') state.ticket.value = null
    if (reason === 'uncertain revoke') state.revocationUncertain.value = true
    const retained = commandState(state, ['now', 'canCommit', 'remaining', 'message', 'error'])

    await state.perform('commit')

    assert.deepEqual(commandState(state, ['now', 'canCommit', 'remaining', 'message', 'error']), retained)
    assert.equal(state.message.value, localCommitBlocked)
    assert.equal(state.error.value, '')
    assert.equal(calls.length, 0)
  })
}

for (const settlement of ['resolve', 'reject']) {
  test(`actual commit ${settlement} replaces local rejection feedback`, async t => {
    const { state, calls, clock } = fixture(t)
    prepare(state, 'commit')
    clock.time = 1100
    await state.perform('commit')
    assert.equal(state.message.value, localCommitBlocked)
    clock.time = 1050
    const committing = state.perform('commit')
    assert.equal(state.message.value, '')
    assert.equal(calls.length, 1)
    if (settlement === 'resolve') calls[0].resolve(record())
    else calls[0].reject(new Error('response lost'))
    await committing
    assert.equal(state.message.value, settlement === 'resolve'
      ? 'Commando vastgelegd in het logboek; er is niets uitgevoerd.' : commitCaution)
    assert.equal(state.error.value, settlement === 'resolve' ? '' : 'response lost')
  })
}

test('local commit feedback survives selective clears until a new explicit action', async t => {
  const { state, calls, clock } = fixture(t)
  prepare(state, 'commit')
  clock.time = 1100
  await state.perform('commit')
  state.lookupId.value = 'other-id'
  assert.equal(state.outcome.value, null)
  assert.equal(state.message.value, localCommitBlocked)
  for (const clear of ['clearCommand', 'clearOutcome', 'clearJournal']) {
    state[clear]()
    assert.equal(state.message.value, localCommitBlocked, clear)
    assert.equal(state.error.value, '')
    assert.equal(calls.length, 0)
  }
  const checking = state.checkLastSubmission()
  assert.equal(state.message.value, '')
  calls[0].resolve(snapshot({ id: 'retained-id' }))
  await checking
  assert.match(state.message.value, /Ticketstatus opgehaald/)
})

for (const reset of ['clearSession', 'pagehide', 'token', 'dispose']) {
  test(`${reset} clears local commit feedback`, async t => {
    const { state, calls, clock, eventTarget, scope } = fixture(t)
    prepare(state, 'commit')
    clock.time = 1100
    await state.perform('commit')
    assert.equal(state.message.value, localCommitBlocked)
    if (reset === 'pagehide') eventTarget.dispatchEvent(pageTransition('pagehide', true))
    else if (reset === 'token') state.token.value = 'replacement-token'
    else if (reset === 'dispose') scope.stop()
    else state.clearSession()
    assertEmpty(state, reset === 'token' ? 'replacement-token' : '')
    assert.equal(calls.length, 0)
  })
}

for (const guard of ['busy', 'disposed']) {
  test(`${guard} commit leaves existing feedback untouched`, async t => {
    const { state, calls, scope, clock } = fixture(t)
    if (guard === 'disposed') scope.stop()
    prepare(state, 'commit')
    if (guard === 'busy') state.busy.value = 'status'
    const retained = commandState(state)
    const reads = clock.reads
    await state.perform('commit')
    assert.deepEqual(commandState(state), retained)
    assert.equal(clock.reads, reads)
    assert.equal(calls.length, 0)
  })
}

for (const cachedTime of [1050, null, 1100]) {
  for (const uncertain of [false, true]) {
    test(`commit samples valid fresh time before cached guard, cached=${cachedTime}, uncertainty=${uncertain}`, async t => {
      const { state, calls, clock } = fixture(t)
      prepare(state, 'commit')
      state.now.value = cachedTime
      state.revocationUncertain.value = uncertain
      assert.equal(state.canCommit.value, !uncertain && cachedTime === 1050)
      const heldTicket = state.ticket.value
      const outcome = state.outcome.value
      const reads = clock.reads
      clock.time = 1099

      const operation = state.perform('commit')
      assert.equal(clock.reads, reads + 1)
      assert.equal(state.now.value, 1099)
      assert.equal(calls.length, uncertain ? 0 : 1)
      if (uncertain) {
        assert.equal(state.ticket.value, heldTicket)
        assert.equal(state.lastSubmissionId.value, 'retained-id')
        assert.equal(state.outcome.value, outcome)
        assert.equal(state.revocationUncertain.value, true)
        assert.equal(state.message.value, localCommitBlocked)
      } else {
        assert.equal(calls[0].action, 'commit')
        assert.equal(calls[0].args[0], heldTicket)
        assert.equal(state.ticket.value, null)
        assert.equal(state.lastSubmissionId.value, heldTicket.id)
        assert.equal(state.lookupId.value, heldTicket.id)
        assert.equal(state.outcome.value, null)
        calls[0].resolve(record())
      }
      await operation
      await state.perform('commit')
      assert.equal(calls.length, uncertain ? 0 : 1, 'no repeat submission')
      assert.equal(state.busy.value, '')
    })
  }
}

for (const reset of ['clearSession', 'pagehide', 'token', 'dispose', 'new action']) {
  for (const throws of [false, true]) {
    test(`commit clock ${reset}, throws=${throws}: obsolete preflight cannot publish, consume or send`, async t => {
      const { state, calls, clock, eventTarget, scope } = fixture(t)
      prepare(state, 'commit')
      let retained, newer
      clock.now = () => {
        assert.deepEqual(state.ticket.value, held())
        assert.equal(state.lastSubmissionId.value, 'retained-id')
        assert.deepEqual(state.outcome.value, snapshot())
        assert.equal(calls.length, 0)
        clock.now = null
        if (reset === 'pagehide') eventTarget.dispatchEvent(pageTransition('pagehide', true))
        else if (reset === 'token') state.token.value = 'replacement-token'
        else if (reset === 'dispose') scope.stop()
        else state.clearSession()
        if (reset === 'new action') {
          state.token.value = 'replacement-token'
          prepare(state, 'status')
          state.now.value = 1070
          newer = state.perform('status')
        }
        retained = commandState(state)
        if (throws) throw new Error('old commit clock unavailable')
        return 1090
      }

      await state.perform('commit')
      assert.deepEqual(commandState(state), retained)
      assert.equal(calls.filter(call => call.action === 'commit').length, 0)
      if (newer) {
        assert.equal(calls.length, 1)
        assert.equal(calls[0].signal.aborted, false)
        assert.equal(state.busy.value, 'status')
        assert.equal(state.now.value, 1070)
        clock.time = 1080
        calls[0].resolve(snapshot({ checked_at: 1080 }))
        await newer
        assert.equal(state.outcomeReceivedAt.value, 1080)
        assert.equal(state.busy.value, '')
      } else {
        assertEmpty(state, reset === 'token' ? 'replacement-token' : '')
        assert.equal(state.now.value, 1050)
        assert.equal(calls.length, 0)
      }
    })
  }
}

for (const uncertain of [false, true]) {
  test(`clearing command only clears draft and normal authority, uncertainty=${uncertain}`, async t => {
    const { state, calls, sockets, clock, realtimeCallbacks } = fixture(t)
    prepare(state, uncertain ? 'revoke' : 'commit')
    state.realtime.connect(state.token.value)
    sockets[0].handlers.connect()
    // Connecting intentionally resets the journal; seed retained data afterwards.
    prepare(state, uncertain ? 'revoke' : 'commit')
    const originalTicket = state.ticket.value
    const retained = {
      ...commandState(state, ['command', 'ticket', 'canCommit', 'remaining']),
      canRequestTicket: false,
    }
    const reads = clock.reads
    assert.equal(state.canCommit.value, !uncertain)
    assert.equal(state.canRequestTicket.value, !uncertain)

    state.clearCommand()
    assert.equal(state.command.value, '')
    assert.equal(state.ticket.value, uncertain ? originalTicket : null)
    assert.equal(state.canCommit.value, false)
    assert.equal(state.canRequestTicket.value, false)
    assert.deepEqual(commandState(state, ['command', 'ticket', 'canCommit', 'remaining']), retained)
    for (const [key, value] of Object.entries(retained)) assert.equal(state[key].value, value, key)
    const cleared = commandState(state)
    state.clearCommand()
    assert.deepEqual(commandState(state), cleared)
    assert.equal(clock.reads, reads)
    assert.equal(calls.length, 0)
    assert.equal(sockets.length, 1)
    assert.equal(sockets[0].disconnects, 0)
    assert.equal(sockets[0].connects, 1)
    realtimeCallbacks[0].onEntry(record('still-connected'))
    assert.equal(state.commands.value[0].id, 'still-connected')

    state.command.value = originalTicket.command
    assert.equal(state.canCommit.value, false, 'restoring text cannot restore normal authority or bypass uncertainty')
    await state.perform('commit')
    if (uncertain) await state.perform('ticket')
    assert.equal(calls.length, 0)
    assert.equal(state.ticket.value, uncertain ? originalTicket : null)
    assert.equal(state.revocationUncertain.value, uncertain)
  })
}

test('clearing whitespace is allowed and clearing an empty draft is idempotent', t => {
  const { state, calls } = fixture(t)
  prepare(state, 'commit')
  state.command.value = ' \t\n '
  const retained = commandState(state, ['command'])
  state.clearCommand()
  assert.equal(state.command.value, '')
  assert.deepEqual(commandState(state, ['command']), retained)
  state.clearCommand()
  assert.deepEqual(commandState(state, ['command']), retained)
  assert.equal(calls.length, 0)
})

for (const action of Object.keys(actions)) {
  test(`clearing command is a no-op during pending ${action}`, async t => {
    const { state, calls, sockets } = fixture(t)
    prepare(state, action)
    state.realtime.connect(state.token.value)
    sockets[0].handlers.connect()
    prepare(state, action)
    const pending = state.perform(action)
    assert.equal(state.busy.value, action)
    const retained = commandState(state)
    state.clearCommand()
    assert.deepEqual(commandState(state), retained)
    assert.equal(calls.length, 1)
    assert.equal(calls[0].signal.aborted, false)
    assert.equal(sockets[0].disconnects, 0)
    calls[0].resolve(results[action])
    await pending
    assert.equal(state.busy.value, '')
    assert.equal(state.command.value, 'journal only')
  })
}

test('clearing command after disposal is a no-op even if refs are subsequently populated', t => {
  const { state, scope, calls } = fixture(t)
  scope.stop()
  prepare(state, 'revoke')
  const retained = commandState(state)
  state.clearCommand()
  assert.deepEqual(commandState(state), retained)
  assert.equal(calls.length, 0)
})

test('command clear UI is an explicit local-only secondary action inside the issue form', () => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  assert.match(app, /checkCurrentTicket, clearCommand, clearSession/)
  const form = app.match(/<form @submit.prevent="perform\('ticket'\)">([\s\S]*?)<\/form>/)[1]
  const button = form.match(/<button[^>]*@click="clearCommand"[^>]*>Wis commandotekst<\/button>/)?.[0]
  assert.ok(button)
  assert.match(button, /type="button"/)
  assert.match(button, /class="secondary"/)
  assert.match(button, /:disabled="!!busy \|\| !command"/)
  assert.match(button, /aria-describedby="clear-command-help"/)
  assert.ok(form.indexOf('@click="clearCommand"') > form.indexOf('Ticket aanvragen</button>'))
  const help = form.match(/<p id="clear-command-help" class="muted">([\s\S]*?)<\/p>/)[1]
  assert.match(help, /alleen lokaal de concepttekst/)
  assert.match(help, /normaal lokaal ticket ongeldig; geen intrekking op de server/)
  assert.match(help, /onzekere intrekking behoudt het oorspronkelijke ticket/)
  assert.match(help, /blijft vastleggen en nieuwe tickets blokkeren/)
  assert.match(help, /Geen verzoeken, verbreking van realtime of veilige geheugenwissing/)
  assert.match(help, /Logboek en ticketuitkomst kunnen commandotekst behouden/)
})

test('held ticket ID is readonly, labelled and selectable while busy with accessible manual-copy help', async () => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const block = app.match(/<div v-if="ticket" class="result">([\s\S]*?)<\/div>/)[1]
  const label = block.match(/<label for="current-ticket-id">[^<]*<\/label>/)?.[0]
  const input = block.match(/<input id="current-ticket-id"[^>]*\/>/)?.[0]
  const help = block.match(/<p id="current-ticket-id-help"[^>]*>[\s\S]*?<\/p>/)?.[0]
  assert.ok(label)
  assert.match(label, /Huidig ticket-ID \(selecteer en kopieer\)/)
  assert.ok(input)
  assert.match(input, /:value="ticket.id"/)
  assert.match(input, /\sreadonly\s/)
  assert.match(input, /@focus="\$event.target.select\(\)"/)
  assert.match(input, /aria-describedby="current-ticket-id-help"/)
  assert.doesNotMatch(input, /disabled|v-model|@(?!focus=)|v-on|v-bind|v-if/)
  assert.equal(app.match(/\bid="current-ticket-id"/g).length, 1)
  assert.equal(app.match(/\bid="current-ticket-id-help"/g).length, 1)
  assert.ok(help)
  assert.match(help, /Selecteer en kopieer dit exacte ID handmatig vóór Wis sessie om later de status op te zoeken/)
  assert.match(help, /Kopieën op het klembord staan buiten de lokale sessie en worden niet gewist door Wis sessie/)
  assert.match(help, /geen automatische verzoeken en herstellen geen toestemming/)

  const { code } = compile(label + input + help, { mode: 'function', prefixIdentifiers: true })
  const render = new Function('Vue', code)(Vue)
  for (const busy of ['', 'ticket', 'commit', 'revoke', 'status', 'list']) {
    const html = await renderToString(Vue.createSSRApp({
      data: () => ({ ticket: { ...held(), id: ' exact-É🚀<&"ticket> ' }, busy }),
      render,
    }))
    assert.ok(html.includes('<input id="current-ticket-id" value=" exact-É🚀&lt;&amp;&quot;ticket&gt; " readonly aria-describedby="current-ticket-id-help">'), busy)
    assert.ok(html.includes(label))
    assert.ok(html.includes(help.replace(/\s+/g, ' ')))
    assert.doesNotMatch(html, /\sdisabled(?:[=>\s])/)
  }
})

test('held ticket ID focus only selects text without state mutation or requests', t => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const input = app.match(/<input id="current-ticket-id"[^>]*\/>/)[0]
  const { code } = compile(input, { mode: 'function', prefixIdentifiers: true })
  const render = new Function('Vue', code)(Vue)
  const { state, calls, sockets } = fixture(t)
  prepare(state, 'revoke')
  state.busy.value = 'status'
  const before = commandState(state)
  const ticketBefore = { ...state.ticket.value }
  const vnode = render(Vue.proxyRefs(state), {})
  assert.deepEqual(Object.keys(vnode.props).sort(), ['aria-describedby', 'id', 'onFocus', 'readonly', 'value'])
  assert.equal(vnode.props.value, held().id)
  let selections = 0
  const target = { select() { assert.equal(this, target); selections++ } }
  vnode.props.onFocus({ target })
  assert.equal(selections, 1)
  assert.deepEqual(commandState(state), before)
  assert.deepEqual(state.ticket.value, ticketBefore)
  assert.equal(calls.length, 0)
  assert.equal(sockets.length, 0)
})

test('last submission ID renders labelled, linked readonly manual-copy help only with a retained ID', async t => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const panel = app.match(/<div v-if="lastSubmissionId">[\s\S]*?<\/div>/)[0]
  const label = panel.match(/<label for="last-submission">[^<]*<\/label>/)[0]
  const input = panel.match(/<input id="last-submission"[^>]*\/>/)[0]
  const help = panel.match(/<p id="last-submission-help" class="muted">[\s\S]*?<\/p>/)[0]
  assert.match(label, /Laatste ingezonden ticket-ID \(selecteer en kopieer\)/)
  assert.match(input, /:value="lastSubmissionId"/)
  assert.match(input, /\sreadonly\s/)
  assert.match(input, /@focus="\$event.target.select\(\)"/)
  assert.match(input, /aria-describedby="last-submission-help"/)
  assert.doesNotMatch(input, /disabled|v-model|@(?!focus=)|v-on|v-bind|v-if/)
  assert.match(help, /ID van de laatste inzendpoging, geen bevestiging van geslaagde opslag\./)
  assert.match(help, /Selecteer en kopieer dit exacte ID handmatig vóór Wis sessie om later de status op te zoeken/)
  assert.match(help, /kopieën op het klembord worden niet lokaal gewist/)
  assert.match(help, /Selecteren en kopiëren versturen geen verzoeken en herstellen geen toestemming; controleer de status expliciet\./)
  assert.doesNotMatch(help, /\{\{|v-|@/)
  for (const id of ['last-submission', 'last-submission-help']) {
    assert.equal(app.match(new RegExp(`\\bid="${id}"`, 'g')).length, 1)
  }
  const render = compileFragment(panel)
  const { state, calls, sockets } = fixture(t)
  prepare(state, 'revoke')
  state.lastSubmissionId.value = ' \t exact-É🚀<&"ticket>\n '
  state.lookupId.value = 'different-lookup-id'
  state.ticket.value = { ...held(), id: 'different-current-id' }
  state.outcome.value = snapshot({ id: 'different-outcome-id' })
  for (const busy of ['', 'ticket', 'commit', 'revoke', 'status', 'list']) {
    state.busy.value = busy
    const before = JSON.parse(JSON.stringify(commandState(state)))
    const { html, find } = await render(state)
    const field = find(node => node.type === 'input' && node.props?.id === 'last-submission')
    assert.equal(field.props.value, state.lastSubmissionId.value, busy)
    assert.equal(field.props.readonly, '', busy)
    assert.equal(field.props.disabled, undefined, busy)
    assert.equal(typeof field.props.onFocus, 'function', busy)
    assert.equal(field.props['aria-describedby'], 'last-submission-help')
    assert.ok(html.includes('<input id="last-submission" value=" \t exact-É🚀&lt;&amp;&quot;ticket&gt;\n " readonly aria-describedby="last-submission-help">'), busy)
    assert.ok(html.includes(label))
    assert.ok(html.includes(help.replace(/\s+/g, ' ')))
    assert.doesNotMatch(html, /different-lookup-id|different-current-id|different-outcome-id/)
    assert.deepEqual(commandState(state), before)
    state.lastSubmissionId.value = ''
    const emptyBefore = JSON.parse(JSON.stringify(commandState(state)))
    const empty = await render(state)
    assert.doesNotMatch(empty.html, /last-submission|Laatste ingezonden ticket-ID|Selecteer en kopieer|Controleer laatste inzending/, busy)
    assert.equal(empty.find(node => node.type === 'div'), undefined, busy)
    assert.deepEqual(commandState(state), emptyBefore)
    state.lastSubmissionId.value = before.lastSubmissionId
  }
  assert.equal(calls.length, 0)
  assert.equal(sockets.length, 0)
})

test('last submission ID compiled focus only selects text without state mutation or requests', t => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const input = app.match(/<input id="last-submission"[^>]*\/>/)[0]
  const { code } = compile(input, { mode: 'function', prefixIdentifiers: true })
  const render = new Function('Vue', code)(Vue)
  const { state, calls, sockets } = fixture(t)
  prepare(state, 'revoke')
  state.lastSubmissionId.value = ' \t exact-É🚀<&"ticket>\n '
  for (const busy of ['', 'ticket', 'commit', 'revoke', 'status', 'list']) {
    state.busy.value = busy
    const before = JSON.parse(JSON.stringify(commandState(state)))
    const vnode = render(Vue.proxyRefs(state), {})
    assert.deepEqual(Object.keys(vnode.props).sort(), ['aria-describedby', 'id', 'onFocus', 'readonly', 'value'])
    assert.equal(vnode.props.value, state.lastSubmissionId.value)
    let selections = 0
    const target = { select() { assert.equal(this, target); selections++ } }
    vnode.props.onFocus({ target })
    assert.equal(selections, 1, busy)
    assert.deepEqual(commandState(state), before, busy)
  }
  assert.equal(calls.length, 0)
  assert.equal(sockets.length, 0)
})

test('outcome ticket ID renders exact escaped text with accessible manual-copy help only with an outcome', async () => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const panel = app.match(/<div v-if="outcome" class="result">[\s\S]*?<\/div>/)[0]
  const label = panel.match(/<label for="outcome-ticket-id">[^<]*<\/label>/)[0]
  const input = panel.match(/<input id="outcome-ticket-id"[^>]*\/>/)[0]
  const help = panel.match(/<p id="outcome-ticket-id-help"[^>]*>[\s\S]*?<\/p>/)[0]
  assert.match(label, /Ticketuitkomst-ID \(selecteer en kopieer\)/)
  assert.match(input, /:value="outcome.id"/)
  assert.doesNotMatch(input, /disabled|v-model|@(?!focus=)|v-on|v-bind|v-if/)
  assert.match(help, /Selecteer en kopieer dit exacte ID handmatig vóór Wis ticketuitkomst of Wis sessie om later de status op te zoeken/)
  assert.match(help, /Wis ticketuitkomst behoudt het opzoekveld/)
  assert.match(help, /Kopieën op het klembord staan buiten de lokale sessie en worden niet gewist/)
  assert.match(help, /geen automatische verzoeken en herstellen geen toestemming/)
  for (const id of ['outcome-ticket-id', 'outcome-ticket-id-help']) {
    assert.equal(app.match(new RegExp(`\\bid="${id}"`, 'g')).length, 1)
  }
  const { code } = compile(panel, { mode: 'function', prefixIdentifiers: true })
  const render = new Function('Vue', code)(Vue)
  for (const busy of ['', 'ticket', 'commit', 'revoke', 'status', 'list']) {
    const html = await renderToString(Vue.createSSRApp({
      data: () => ({
        outcome: snapshot({ id: ' exact-É🚀<&"ticket> ' }), outcomeMismatch: false, outcomeReceivedAt: null, busy,
        lookupId: 'different-lookup-id', ticket: { ...held(), id: 'different-current-id' },
        lastSubmissionId: 'different-submission-id',
      }),
      methods: { date: value => String(value), receiptIso: value => String(value) },
      render,
    }))
    assert.ok(html.includes('<input id="outcome-ticket-id" value=" exact-É🚀&lt;&amp;&quot;ticket&gt; " readonly aria-describedby="outcome-ticket-id-help">'), busy)
    assert.ok(html.includes(label))
    assert.ok(html.includes(help.replace(/\s+/g, ' ')))
    assert.doesNotMatch(html, /different-lookup-id|different-current-id|different-submission-id|\sdisabled(?:[=>\s])/)
  }
  const html = await renderToString(Vue.createSSRApp({ data: () => ({ outcome: null }), render }))
  assert.doesNotMatch(html, /outcome-ticket-id|Ticketuitkomst-ID|Selecteer en kopieer/)
})

test('outcome ticket ID focus only selects text without state mutation or requests', t => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const input = app.match(/<input id="outcome-ticket-id"[^>]*\/>/)[0]
  const { code } = compile(input, { mode: 'function', prefixIdentifiers: true })
  const render = new Function('Vue', code)(Vue)
  const { state, calls, sockets } = fixture(t)
  prepare(state, 'revoke')
  state.lookupId.value = 'different-lookup-id'
  state.outcome.value = snapshot({ id: ' exact-É🚀<&"ticket> ' })
  state.busy.value = 'status'
  const before = JSON.parse(JSON.stringify(commandState(state)))
  const vnode = render(Vue.proxyRefs(state), {})
  assert.deepEqual(Object.keys(vnode.props).sort(), ['aria-describedby', 'id', 'onFocus', 'readonly', 'value'])
  assert.equal(vnode.props.value, state.outcome.value.id)
  let selections = 0
  const target = { select() { assert.equal(this, target); selections++ } }
  vnode.props.onFocus({ target })
  assert.equal(selections, 1)
  assert.deepEqual(commandState(state), before)
  assert.equal(calls.length, 0)
  assert.equal(sockets.length, 0)
})

test('issued ticket text is labelled, explained and rendered as escaped text rather than the draft', async () => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const block = app.match(/<div v-if="ticket" class="result">([\s\S]*?)<\/div>/)[1]
  assert.match(block, /<p id="ticket-command-label">Commandotekst van dit ticket<\/p>/)
  const pre = block.match(/<pre[^>]*>[\s\S]*?<\/pre>/)[0]
  assert.match(pre, /aria-labelledby="ticket-command-label"/)
  assert.match(pre, /aria-describedby="ticket-command-help"/)
  assert.match(pre, />{{ ticket\.command }}<\/pre>/)
  assert.doesNotMatch(block, /v-html|{{\s*command\s*}}/)
  const help = block.match(/<p id="ticket-command-help" class="muted">([\s\S]*?)<\/p>/)[1]
  assert.match(help, /exacte tekst waarvoor dit ticket is uitgegeven, niet de huidige concepttekst/)
  assert.match(help, /onzekere intrekking[\s\S]*na Wis commandotekst zichtbaar blijven/)
  assert.match(help, /geen uitvoering of nieuwe toestemming/)

  const { code } = compile(pre, { mode: 'function', prefixIdentifiers: true })
  const render = new Function('Vue', code)(Vue)
  const html = await renderToString(Vue.createSSRApp({
    data: () => ({ ticket: { ...held(), command: 'één 🚀\n<script>alert("x")</script> & <b>tekst</b>' }, command: 'different draft' }),
    render,
  }))
  assert.equal(html, '<pre aria-labelledby="ticket-command-label" aria-describedby="ticket-command-help">één 🚀\n&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; &lt;b&gt;tekst&lt;/b&gt;</pre>')
})

test('compiled held-ticket window times link static half-open guidance without changing local authority', async t => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const panel = app.match(/<div v-if="ticket" class="result">[\s\S]*?<\/div>/)?.[0]
  assert.ok(panel)
  assert.match(panel, /<p aria-describedby="ticket-window-help">Geldig vanaf: <time :datetime="receiptIso\(ticket.not_before\)">{{ date\(ticket.not_before\) }}<\/time><\/p>/)
  assert.match(panel, /<p aria-describedby="ticket-window-help">Verloopt: <time :datetime="receiptIso\(ticket.expires_at\)">{{ date\(ticket.expires_at\) }}<\/time><\/p>/)
  const help = panel.match(/<p id="ticket-window-help" class="muted">[\s\S]*?<\/p>/)?.[0]
  assert.ok(help)
  assert.match(help, /Begintijd inbegrepen, vervaltijd uitgesloten\./)
  assert.match(help, /Alleen de server beslist over geldigheid; de lokale aftelling geeft geen garantie\./)
  assert.doesNotMatch(help, /\{\{|v-|@/)
  assert.equal(app.match(/\bid="ticket-window-help"/g).length, 1)
  assert.equal(app.match(/\baria-describedby="ticket-window-help"/g).length, 2)
  const helpers = app.match(/function date\(value\) \{[\s\S]*?\n\}[\s\S]*?function receiptIso\(value\) \{[\s\S]*?\n\}/)?.[0]
  assert.ok(helpers)
  const formatters = new Function('timestamp', `${helpers}; return { date, receiptIso }`)(timestamp)
  const render = compileFragment(panel)
  const maxDate = 8_640_000_000_000_000
  for (const [notBefore, expiresAt] of [[0, 1], [1000, 3000], [maxDate - 1, maxDate]]) {
    for (const iso of [false, true]) {
      await t.test(`window=${notBefore}/${expiresAt}, ISO=${iso}`, async t => {
        const { state, calls, sockets } = fixture(t)
        prepare(state, 'commit')
        state.ticket.value = {
          ...held(),
          not_before: iso ? new Date(notBefore).toISOString() : notBefore,
          expires_at: iso ? new Date(expiresAt).toISOString() : expiresAt,
        }
        assert.equal(ticketUsable(state.ticket.value, state.command.value, notBefore), true)
        assert.equal(ticketUsable(state.ticket.value, state.command.value, expiresAt), false)
        state.now.value = notBefore
        const before = commandState(state)
        const { html, find } = await render({ ...state, ...formatters })
        assert.equal(html.match(/\bid="ticket-window-help"/g).length, 1)
        assert.equal(html.match(/\baria-describedby="ticket-window-help"/g).length, 2)
        assert.ok(find(node => node.type === 'p' && node.props?.id === 'ticket-window-help'))
        for (const [label, value] of [['Geldig vanaf', state.ticket.value.not_before], ['Verloopt', state.ticket.value.expires_at]]) {
          const datetime = new Date(timestamp(value)).toISOString()
          const paragraph = find(node => node.type === 'p' &&
            node.props?.['aria-describedby'] === 'ticket-window-help' &&
            node.children?.some(child => child.type === 'time' && child.props?.datetime === datetime))
          assert.ok(paragraph, label)
          assert.ok(html.includes(`<p aria-describedby="ticket-window-help">${label}: <time datetime="${datetime}">${formatters.date(value)}</time></p>`))
        }
        assert.ok(html.includes(help))
        assert.deepEqual(commandState(state), before)
        assert.equal(calls.length, 0)
        assert.equal(sockets.length, 0)
        state.ticket.value = null
        const { html: hidden, find: findHidden } = await render({ ...state, ...formatters })
        assert.doesNotMatch(hidden, /<time|Geldig vanaf|Verloopt|ticket-window-help|Begintijd inbegrepen/)
        assert.equal(findHidden(node => node.type === 'time' || node.props?.id === 'ticket-window-help'), undefined)
      })
    }
  }
})

test('outcome explanations render the validated server status without restoring authority', async t => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const panel = app.match(/<div v-if="outcome" class="result">[\s\S]*?<\/div>/)?.[0]
  assert.ok(panel)
  assert.ok(panel.includes("<p>Status: {{ outcome.status }} · ingetrokken: {{ outcome.revoked ? 'ja' : 'nee' }}</p>"))
  assert.match(panel, /<pre aria-labelledby="outcome-command-label" aria-describedby="outcome-command-help">{{ outcome\.command }}<\/pre>/)
  for (const id of ['outcome-command-label', 'outcome-command-help', 'outcome-record-help', 'outcome-server-time-help', 'outcome-window-help', 'outcome-receipt-help']) {
    assert.equal(app.match(new RegExp(`\\bid="${id}"`, 'g')).length, 1)
  }
  const helpers = app.match(/function date\(value\) \{[\s\S]*?\n\}[\s\S]*?function receiptIso\(value\) \{[\s\S]*?\n\}/)?.[0]
  assert.ok(helpers)
  const formatters = new Function('timestamp', `${helpers}; return { date, receiptIso }`)(timestamp)
  assert.doesNotMatch(panel, /v-html/)
  const { code } = compile(panel, { mode: 'function', prefixIdentifiers: true })
  const render = new Function('Vue', code)(Vue)
  const explanations = {
    pending: 'De server controleerde dit ticket vóór de begintijd.',
    active: 'Bij de servercontrole lag dit ticket binnen het geldigheidsvenster.',
    expired: 'De server controleerde dit ticket op of na de vervaltijd.',
    revoked: 'Dit ticket is ingetrokken en geeft geen verdere toestemming.',
    committed: 'Het commando is al opgeslagen als logboekrecord, niet uitgevoerd.',
  }
  const laterRevocation = 'Een latere intrekking maakt het eerdere logboekrecord niet ongedaan.'
  const command = ' \n  één 🚀\n<script>alert("x")</script> & <b>tekst</b>\n  '
  const label = '<p id="outcome-command-label">Commandotekst van deze ticketuitkomst</p>'
  const help = '<p id="outcome-command-help" class="muted">De exacte tekst uit de ontvangen statusmomentopname, niet de huidige concepttekst of het huidige ticket. Kan na Wis commandotekst zichtbaar blijven. Alleen tekst: geen uitvoering of nieuwe toestemming.</p>'
  const recordHelp = '<p id="outcome-record-help" class="muted">Het record-ID identificeert het opgeslagen logboekrecord, niet het ticket-ID voor statuscontrole. Alleen-lezen historie: herstelt geen toestemming en voegt niets toe aan het recente logboek.</p>'
  const serverHelp = '<p id="outcome-server-time-help" class="muted">Het tijdstip waarop de server deze statusmomentopname controleerde, niet de lokale ontvangsttijd of de huidige tijd. Geen garantie dat de uitkomst actueel is. Controleer de status handmatig opnieuw voor een nieuwe momentopname.</p>'
  const windowHelp = '<p id="outcome-window-help" class="muted">Begintijd inbegrepen, vervaltijd uitgesloten. Het historische geldigheidsvenster van deze ticketuitkomst, niet van de huidige concepttekst. Geeft geen nieuwe toestemming.</p>'
  const receiptHelp = '<p id="outcome-receipt-help" class="muted">Volgens de lokale klok; geen server- of audittijd en geen garantie dat de uitkomst actueel is. Controleer de status handmatig opnieuw voor een nieuwe momentopname.</p>'
  const cases = [
    { status: 'pending', checked_at: 999 },
    ...[1000, 1099].map(checked_at => ({ status: 'active', checked_at })),
    ...[1100, 1200].map(checked_at => ({ status: 'expired', checked_at })),
    ...[999, 1000, 1099, 1100, 1200].map(checked_at => ({ status: 'revoked', revoked: true, checked_at })),
    ...[false, true].flatMap(revoked => [1050, 1100, 1200].map(checked_at => ({
      status: 'committed', revoked, checked_at, record: { ...record(), command },
    }))),
    ...[false, true].flatMap(revoked => [0, 8_640_000_000_000_000 - 1].map(committed_at => ({
      status: 'committed', revoked, not_before: committed_at, expires_at: committed_at + 1,
      checked_at: committed_at + 1, record: { ...record('distinct-record-id'), command, committed_at },
    }))),
    ...[0, 8_640_000_000_000_000 - 60_000].flatMap(not_before => {
      const expires_at = not_before + 60_000
      return [
        { status: 'pending', checked_at: not_before, not_before: not_before + 1, expires_at },
        { status: 'active', checked_at: not_before, not_before, expires_at },
        { status: 'expired', checked_at: expires_at, not_before, expires_at },
        { status: 'revoked', revoked: true, checked_at: expires_at, not_before, expires_at },
      ]
    }),
  ]
  for (const changes of cases) {
    await t.test(`${changes.status}, revoked ${changes.revoked ?? false}, checked at ${changes.checked_at}`, async t => {
      const outcome = snapshot({ command, ...changes })
      assert.equal(validateTicketStatus(outcome, outcome.id), outcome)
      const before = structuredClone(outcome)
      const { state, calls, sockets, clock } = fixture(t)
      prepare(state, 'status')
      state.command.value = 'different current draft'
      state.ticket.value = { ...held(), command: 'different held ticket' }
      state.revocationUncertain.value = true
      state.outcome.value = outcome
      state.outcomeReceivedAt.value = null
      const stateBefore = sessionSnapshot(state)
      const readsBefore = clock.reads
      const html = await renderToString(Vue.createSSRApp({
        setup: () => ({ ...state, ...formatters }),
        render,
      }))
      const time = value => `<time datetime="${new Date(timestamp(value)).toISOString()}">${formatters.date(value)}</time>`
      assert.ok(html.includes(`<p aria-describedby="outcome-server-time-help">Gecontroleerd door server: ${time(outcome.checked_at)}</p>`))
      assert.ok(html.includes(`<p aria-describedby="outcome-window-help">Geldig vanaf: ${time(outcome.not_before)} · verloopt: ${time(outcome.expires_at)}</p>`))
      for (const help of [serverHelp, windowHelp, receiptHelp]) assert.ok(html.includes(help))
      for (const id of ['outcome-server-time-help', 'outcome-window-help', 'outcome-receipt-help']) {
        assert.equal(html.match(new RegExp(`\\bid="${id}"`, 'g')).length, 1)
        assert.equal(html.match(new RegExp(`aria-describedby="${id}"`, 'g')).length, 1)
      }
      assert.ok(html.includes('<p aria-describedby="outcome-receipt-help">Uitkomst lokaal ontvangen: <span>Geen ontvangsttijdstip beschikbaar.</span></p>'))
      assert.equal(html.match(/<time\b/g).length, outcome.record ? 4 : 3)
      assert.ok(html.includes(`Status: ${outcome.status} · ingetrokken: ${outcome.revoked ? 'ja' : 'nee'}`))
      for (const [status, explanation] of Object.entries(explanations)) {
        assert.equal(html.includes(explanation), status === outcome.status, status)
      }
      assert.ok(html.includes('Deze statuscontrole geeft geen nieuwe toestemming en herstelt geen lokaal ticket.'))
      assert.ok(html.includes('Geen uitvoering of automatische herinzending.'))
      assert.equal(html.includes('geen garantie dat het ticket nu nog bruikbaar is'), outcome.status === 'active')
      assert.equal(html.includes(laterRevocation), outcome.status === 'committed' && outcome.revoked)
      assert.equal(html.includes('Vastgelegd:'), outcome.status === 'committed')
      assert.equal(html.includes('Record-ID:'), outcome.status === 'committed')
      assert.equal(html.includes(recordHelp), outcome.status === 'committed')
      assert.equal(html.match(/\bid="outcome-record-help"/g)?.length ?? 0, outcome.record ? 1 : 0)
      assert.equal(html.match(/aria-describedby="outcome-record-help"/g)?.length ?? 0, outcome.record ? 1 : 0)
      if (outcome.record) {
        assert.notEqual(outcome.id, outcome.record.id)
        assert.ok(html.includes(`id="outcome-ticket-id" value="${outcome.id}"`))
        assert.ok(html.includes(`<time datetime="${new Date(outcome.record.committed_at).toISOString()}">${formatters.date(outcome.record.committed_at)}</time>`))
        assert.ok(html.includes(`Record-ID: <code>${outcome.record.id}</code>`))
        assert.ok(!html.includes(`Record-ID: <code>${outcome.id}</code>`))
      } else {
        assert.doesNotMatch(html, /outcome-record-help|<code\b/)
      }
      assert.equal(html.match(/<pre\b[^>]*>[\s\S]*?<\/pre>/)[0], '<pre aria-labelledby="outcome-command-label" aria-describedby="outcome-command-help"> \n  één 🚀\n&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; &lt;b&gt;tekst&lt;/b&gt;\n  </pre>')
      assert.ok(html.includes(label))
      assert.ok(html.includes(help))
      for (const id of ['outcome-command-label', 'outcome-command-help']) {
        assert.equal(html.match(new RegExp(`\\bid="${id}"`, 'g')).length, 1)
      }
      assert.doesNotMatch(html, /different current draft|different held ticket/)
      assert.doesNotMatch(html, /<script>|<b>|teruggedraaid|ongedaan gemaakt|geen (?:eerder |eerdere )?(?:logboekrecord|vastlegging)/i)
      assert.deepEqual(outcome, before)
      assert.deepEqual(sessionSnapshot(state), stateBefore)
      assert.equal(clock.reads, readsBefore)
      assert.equal(calls.length, 0)
      assert.equal(sockets.length, 0)
      for (const receivedAt of [0, 8_640_000_000_000_000]) {
        state.outcomeReceivedAt.value = receivedAt
        const receivedBefore = sessionSnapshot(state)
        const receivedHtml = await renderToString(Vue.createSSRApp({
          setup: () => ({ ...state, ...formatters }),
          render,
        }))
        assert.ok(receivedHtml.includes(`<p aria-describedby="outcome-receipt-help">Uitkomst lokaal ontvangen: ${time(receivedAt)}</p>`))
        assert.ok(receivedHtml.includes(`<p aria-describedby="outcome-server-time-help">Gecontroleerd door server: ${time(outcome.checked_at)}</p>`))
        assert.ok(receivedHtml.includes(receiptHelp))
        assert.doesNotMatch(receivedHtml, /Geen ontvangsttijdstip beschikbaar/)
        assert.equal(receivedHtml.match(/<time\b/g).length, outcome.record ? 5 : 4)
        assert.deepEqual(sessionSnapshot(state), receivedBefore)
        assert.equal(clock.reads, readsBefore)
        assert.equal(calls.length, 0)
        assert.equal(sockets.length, 0)
      }
    })
  }
  await t.test('no outcome hides the panel and all explanations', async () => {
    const html = await renderToString(Vue.createSSRApp({ data: () => ({ outcome: null }), render }))
    assert.doesNotMatch(html, /Status:|statuscontrole|logboekrecord|servercontrole/)
    assert.doesNotMatch(html, /outcome-server-time-help|outcome-window-help|outcome-receipt-help|Gecontroleerd door server:|Geldig vanaf:|verloopt:|Uitkomst lokaal ontvangen:|Geen ontvangsttijdstip beschikbaar|historische geldigheidsvenster|lokale ontvangsttijd/)
    assert.doesNotMatch(html, /outcome-command-label|outcome-command-help|outcome-record-help|Vastgelegd:|Record-ID:|<time\b|<code\b|Commandotekst van deze ticketuitkomst|exacte tekst uit de ontvangen statusmomentopname|<pre/)
  })
  await t.test('record IDs remain escaped text even outside validated server input', async () => {
    const outcome = snapshot({ status: 'committed', record: record('<script>&"\'') })
    assert.equal(validateTicketStatus(outcome, outcome.id), null)
    const before = structuredClone(outcome)
    const html = await renderToString(Vue.createSSRApp({
      data: () => ({ outcome, outcomeMismatch: false, outcomeReceivedAt: null }),
      methods: formatters,
      render,
    }))
    assert.ok(html.includes('Record-ID: <code>&lt;script&gt;&amp;&quot;&#39;</code>'))
    assert.doesNotMatch(html, /<script>/)
    assert.deepEqual(outcome, before)
  })
})

test('uncertain revocation retains exact issued Unicode and multiline markup text after draft clear and edit', async t => {
  const { state, calls } = fixture(t)
  const issued = { ...held(), command: 'één 🚀\n<script>alert("x")</script> & <b>tekst</b>\n' }
  state.command.value = issued.command
  const issuing = state.perform('ticket')
  calls[0].resolve(issued)
  await issuing
  assert.deepEqual(state.ticket.value, issued)
  assert.equal(state.canCommit.value, true)
  const revoking = state.perform('revoke')
  calls[1].reject(new Error('confirmation lost'))
  await revoking
  assert.equal(state.revocationUncertain.value, true)
  const retained = state.ticket.value
  for (const edit of [() => state.clearCommand(), () => { state.command.value = 'new draft' }]) {
    edit()
    assert.equal(state.ticket.value, retained)
    assert.deepEqual(state.ticket.value, issued)
    assert.notEqual(state.command.value, issued.command)
    assert.equal(state.canCommit.value, false)
  }
  assert.equal(state.command.value, 'new draft')
  assert.equal(calls.length, 2, 'draft changes do not issue requests')
})

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

for (const value of [
  null, undefined, '', '1050', true, {}, [], -1, 0.5, NaN, Infinity, -Infinity,
  8_640_000_000_000_001, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER + 1, 'throw',
]) {
  test(`ticket issuance with unavailable clock ${String(value)} retains the server ticket without local authority`, async t => {
    const { state, calls, clock } = fixture(t)
    prepare(state, 'ticket')
    const operation = state.perform('ticket')
    const reads = clock.reads
    clock.now = () => {
      assert.equal(state.ticket.value, null, 'do not publish before sampling')
      if (value === 'throw') throw new Error('local clock unavailable')
      return value
    }
    calls[0].resolve(held())
    await operation
    assert.equal(clock.reads, reads + 1)
    assert.deepEqual(state.ticket.value, held())
    assert.equal(state.now.value, null)
    assert.equal(state.canCommit.value, false)
    assert.equal(state.remaining.value, null)
    assert.equal(state.error.value, '')
    assert.equal(state.message.value, 'Ticket ontvangen. Bevestig het commando in een aparte stap.')
    assert.equal(state.busy.value, '')
    await state.perform('commit')
    assert.equal(calls.length, 1, 'invalid local clock cannot submit')
    assert.deepEqual(state.ticket.value, held())

    await t.test('retained ticket remains available for manual status and revoke', async () => {
      clock.now = () => null
      const checking = state.checkCurrentTicket()
      assert.equal(calls[1].action, 'status')
      assert.equal(calls[1].args[0], held().id)
      calls[1].resolve(snapshot())
      await checking
      assert.deepEqual(state.ticket.value, held())
      assert.equal(state.canCommit.value, false)
      const revoking = state.perform('revoke')
      assert.equal(calls[2].action, 'revoke')
      assert.deepEqual(calls[2].args[0], held())
      calls[2].resolve()
      await revoking
      assert.equal(state.ticket.value, null)
      assert.equal(state.error.value, '')
    })
  })
}

test('ticket issuance preserves epoch zero and half-open Date-limit boundaries', async t => {
  const { state, calls, clock } = fixture(t)
  const maxDate = 8_640_000_000_000_000
  for (const [notBefore, expiresAt] of [[0, 1], [1000, 1100], [maxDate - 1, maxDate]]) {
    for (const time of [Math.max(0, notBefore - 1), notBefore, expiresAt - 1, expiresAt]) {
      state.command.value = held().command
      const operation = state.perform('ticket')
      clock.time = time
      const issued = { ...held(), not_before: notBefore, expires_at: expiresAt }
      calls.at(-1).resolve(issued)
      await operation
      assert.deepEqual(state.ticket.value, issued)
      assert.equal(state.now.value, time)
      assert.equal(state.canCommit.value, time >= notBefore && time < expiresAt)
      assert.equal(state.remaining.value, Math.max(0, Math.ceil((expiresAt - time) / 1000)))
      assert.equal(state.error.value, '')
      assert.equal(state.busy.value, '')
    }
  }
})

for (const reset of ['clearSession', 'pagehide', 'token', 'dispose']) {
  for (const throws of [false, true]) {
    test(`ticket clock ${reset}, throws=${throws}: stale issuance cannot publish ticket, time or feedback`, async t => {
      const { state, calls, clock, eventTarget, scope } = fixture(t)
      prepare(state, 'ticket')
      const operation = state.perform('ticket')
      let retained
      clock.now = () => {
        assert.equal(state.ticket.value, null)
        if (reset === 'pagehide') eventTarget.dispatchEvent(pageTransition('pagehide', true))
        else if (reset === 'token') state.token.value = 'replacement-token'
        else if (reset === 'dispose') scope.stop()
        else state.clearSession()
        retained = commandState(state)
        if (throws) throw new Error('clock failed after reset')
        return 1090
      }
      calls[0].resolve(held())
      await operation
      assert.equal(calls[0].signal.aborted, true)
      assertEmpty(state, reset === 'token' ? 'replacement-token' : '')
      assert.deepEqual(commandState(state), retained)
      assert.equal(state.now.value, 1050)
    })
  }
}

for (const throws of [false, true]) {
  test(`ticket clock starts a new action, throws=${throws}: stale completion cannot overwrite or finish it`, async t => {
    const { state, calls, clock } = fixture(t)
    prepare(state, 'ticket')
    const old = state.perform('ticket')
    let newer
    let retained
    clock.now = () => {
      assert.equal(state.ticket.value, null)
      clock.now = null
      state.clearSession()
      state.token.value = 'replacement-token'
      prepare(state, 'status')
      state.now.value = 1070
      newer = state.perform('status')
      retained = commandState(state)
      if (throws) throw new Error('old clock unavailable')
      return 1060
    }
    calls[0].resolve({ ...held(), id: 'stale-ticket' })
    await old
    assert.equal(calls.length, 2)
    assert.equal(calls[0].signal.aborted, true)
    assert.equal(calls[1].signal.aborted, false)
    assert.deepEqual(commandState(state), retained)
    assert.deepEqual(state.ticket.value, held())
    assert.equal(state.now.value, 1070)
    assert.equal(state.busy.value, 'status')
    assert.equal(state.message.value, '')
    assert.equal(state.error.value, '')
    clock.time = 1080
    calls[1].resolve(snapshot({ checked_at: 1080 }))
    await newer
    assert.equal(state.outcomeReceivedAt.value, 1080)
    assert.equal(state.busy.value, '')
    assert.match(state.message.value, /Ticketstatus opgehaald/)
    assert.equal(state.error.value, '')
  })
}

test('interval clock exceptions and invalid samples fail closed without losing the ticket or feedback', async t => {
  const { state, calls, clock } = fixture(t)
  prepare(state, 'ticket')
  const operation = state.perform('ticket')
  calls[0].resolve(held())
  await operation
  const retained = commandState(state, ['now', 'canCommit', 'remaining'])
  for (const value of ['throw', null, undefined, '1050', -1, 0.5, NaN, Infinity, 8_640_000_000_000_001]) {
    clock.now = null
    clock.time = 1050
    clock.tick()
    assert.equal(state.canCommit.value, true)
    assert.equal(state.remaining.value, 1)
    clock.now = () => {
      if (value === 'throw') throw new Error('interval clock unavailable')
      return value
    }
    assert.doesNotThrow(() => clock.tick())
    assert.equal(state.now.value, null)
    assert.equal(state.canCommit.value, false)
    assert.equal(state.remaining.value, null)
    assert.deepEqual(commandState(state, ['now', 'canCommit', 'remaining']), retained)
  }
  await state.perform('commit')
  assert.equal(calls.length, 1)
  assert.equal(state.error.value, '')
})

for (const throws of [false, true]) {
  test(`interval clock disposal, throws=${throws}: sampled time and later callbacks stay inert`, t => {
    const { state, clock, scope } = fixture(t)
    prepare(state, 'ticket')
    let retained
    clock.now = () => {
      scope.stop()
      retained = commandState(state)
      if (throws) throw new Error('clock failed after disposal')
      return 1090
    }
    assert.doesNotThrow(() => clock.tick())
    assertEmpty(state)
    assert.deepEqual(commandState(state), retained)
    assert.equal(state.now.value, 1050)
    assert.deepEqual(clock.cleared, [42])
    const reads = clock.reads
    clock.tick()
    assert.equal(clock.reads, reads)
    assert.deepEqual(commandState(state), retained)
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

test('countdown UI separates unavailable, positive and locally elapsed time and disclaims server authority', () => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const result = app.match(/<div v-if="ticket" class="result">([\s\S]*?)<\/div>/)[1]
  assert.match(result, /<p v-if="remaining === null">Resterende tijd niet beschikbaar\. Controleer de lokale klok en ticketgegevens\.<\/p>\s*<p v-else-if="remaining > 0">Volgens de lokale klok nog circa \{\{ remaining \}\} seconden\.<\/p>\s*<p v-else>Volgens de lokale klok is de vervaltijd bereikt\.\s*<span v-if="revocationUncertain">Controleer de status van hetzelfde ticket of trek dit ticket expliciet opnieuw in\. Nieuwe tickets blijven geblokkeerd\.<\/span>\s*<span v-else>Je kunt expliciet een nieuw ticket aanvragen; geen automatische aanvraag\.<\/span>\s*<\/p>/)
  assert.match(result, /<p v-if="remaining > 0 && !canCommit && !revocationUncertain">Niet geldig voor de huidige invoer of begintijd\.<\/p>/)
  assert.match(result, /De aftelling gebruikt de lokale klok; alleen de server beslist over geldigheid\./)
})

test('compiled countdown renders local-only guidance without requests or authority changes', async t => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const countdown = app.match(/<p v-if="remaining === null">[\s\S]*?<p class="muted">De aftelling[\s\S]*?<\/p>/)?.[0]
  assert.ok(countdown)
  assert.doesNotMatch(countdown, /@|v-on|v-model|v-bind|v-html|<button|<a\b|<input|<form|canCommit|ticket\.|outcome|perform|fetch|checkCurrentTicket/)
  assert.deepEqual([...countdown.matchAll(/\{\{([\s\S]*?)\}\}/g)].map(match => match[1].trim()), ['remaining'])
  const { code } = compile(countdown, { mode: 'function', prefixIdentifiers: true })
  const render = new Function('Vue', code)(Vue)
  for (const remaining of [null, 12, 0]) {
    for (const revocationUncertain of [false, true]) {
      await t.test(`remaining=${remaining}, uncertainty=${revocationUncertain}`, async t => {
        const { state, calls, sockets } = fixture(t)
        prepare(state, 'revoke')
        state.revocationUncertain.value = revocationUncertain
        const before = commandState(state)
        const ticketBefore = state.ticket.value
        const canCommitBefore = state.canCommit.value
        const html = await renderToString(Vue.createSSRApp({
          setup: () => ({ ...state, remaining }),
          render,
        }))
        assert.equal(html.includes('Resterende tijd niet beschikbaar. Controleer de lokale klok en ticketgegevens.'), remaining === null)
        assert.equal(html.includes('Volgens de lokale klok nog circa 12 seconden.'), remaining === 12)
        assert.equal(html.includes('Volgens de lokale klok is de vervaltijd bereikt.'), remaining === 0)
        assert.equal(html.includes('Controleer de status van hetzelfde ticket of trek dit ticket expliciet opnieuw in. Nieuwe tickets blijven geblokkeerd.'), remaining === 0 && revocationUncertain)
        assert.equal(html.includes('Je kunt expliciet een nieuw ticket aanvragen; geen automatische aanvraag.'), remaining === 0 && !revocationUncertain)
        if (revocationUncertain) assert.doesNotMatch(html, /nieuw ticket aanvragen|Vraag een nieuw ticket/)
        assert.ok(html.includes('De aftelling gebruikt de lokale klok; alleen de server beslist over geldigheid.'))
        assert.doesNotMatch(html, /Verlopen\.|ticket is (?:ingetrokken|verlopen)|<button|<a\b|<input|<form|onClick/i)
        assert.deepEqual(commandState(state), before)
        assert.equal(state.ticket.value, ticketBefore)
        assert.equal(state.revocationUncertain.value, revocationUncertain)
        assert.equal(state.canCommit.value, canCommitBefore)
        assert.equal(calls.length, 0)
        assert.equal(sockets.length, 0)
      })
    }
  }
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
  assert.match(result, /<input id="outcome-ticket-id" :value="outcome.id" readonly/)
  assert.match(result, /<p v-if="outcomeMismatch" role="alert" class="error">Statusgegevens wijken af van het lokaal bewaarde ticket\. Deze uitkomst wijzigt het lokale ticket of de onzekerheidsblokkering niet\.<\/p>/)
  assert.match(result, /\{\{ outcome.command \}\}/)
  assert.doesNotMatch(result, /zijn geblokkeerd/)
})

for (const settlement of ['resolve', 'reject']) {
  test(`outcome clear button follows initial, pending, ${settlement}, cleared and disposed session states`, async t => {
    const { state, scope, calls } = fixture(t)
    const checkButton = outcomeClearButton()
    await checkButton(state, false)
    state.lookupId.value = held().id
    const checking = state.perform('status')
    assert.equal(state.outcome.value, null)
    await checkButton(state, true)
    if (settlement === 'resolve') calls[0].resolve(snapshot())
    else calls[0].reject(new Error('status unavailable'))
    await checking
    assert.equal(state.busy.value, '')
    if (settlement === 'reject') {
      assert.equal(state.outcome.value, null)
      assert.equal(state.message.value, statusCaution)
    }
    const button = await checkButton(state, true)
    button.props.onClick()
    assert.equal(state.outcome.value, null)
    assert.equal(state.message.value, '')
    assert.equal(state.error.value, '')
    await checkButton(state, false)
    state.outcome.value = snapshot()
    await checkButton(state, true)
    scope.stop()
    await checkButton(state, false)
    state.outcome.value = snapshot()
    state.busy.value = 'status'
    await checkButton(state, false)
    assert.equal(calls.length, 1)
  })

  test(`cleared pending status button remains disabled after stale ${settlement}`, async t => {
    const { state, calls } = fixture(t)
    const checkButton = outcomeClearButton()
    const checking = state.perform('status')
    const button = await checkButton(state, true)
    button.props.onClick()
    assert.equal(calls[0].signal.aborted, true)
    await checkButton(state, false)
    if (settlement === 'resolve') calls[0].resolve(snapshot())
    else calls[0].reject(new Error('stale status failure'))
    await checking
    await checkButton(state, false)
    assert.equal(state.outcome.value, null)
    assert.equal(state.message.value, '')
    assert.equal(state.error.value, '')
    assert.equal(calls.length, 1)
  })
}

for (const action of ['ticket', 'commit', 'revoke', 'list']) {
  test(`outcome clear button blocks busy ${action} even with a prior outcome, not enabled by unrelated caution`, async t => {
    const { state, calls } = fixture(t)
    const checkButton = outcomeClearButton()
    prepare(state, action)
    await checkButton(state, true)
    const operation = state.perform(action)
    state.outcome.value = snapshot()
    await checkButton(state, false)
    calls[0].reject(new Error(`${action} unavailable`))
    await operation
    await checkButton(state, true)
    const feedback = [state.message.value, state.error.value]
    assert.ok(feedback.some(Boolean))
    state.clearOutcome()
    await checkButton(state, false)
    assert.deepEqual([state.message.value, state.error.value], feedback)
    assert.equal(calls.length, 1)
  })
}

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
  const before = retainedOutcomeState(state)
  const ticket = state.ticket.value
  const operation = state.perform('status')
  assert.equal(state.outcome.value, null)
  assert.equal(state.outcomeReceivedAt.value, null)
  calls[0].reject(new Error('status failure'))
  await operation
  assert.equal(state.error.value, 'status failure')
  assert.equal(state.message.value, statusCaution)
  assert.equal(state.busy.value, '')
  assert.equal(state.outcome.value, null)
  assert.equal(state.outcomeReceivedAt.value, null)
  assert.equal(state.ticket.value, ticket)
  assert.equal(state.revocationUncertain.value, true)
  assert.equal(state.canCommit.value, false)
  assert.deepEqual(retainedOutcomeState(state), before)
  state.clearOutcome()
  state.clearOutcome()
  assert.equal(state.error.value, '')
  assert.equal(state.message.value, '')
  assert.deepEqual(retainedOutcomeState(state), before)
  assert.equal(calls.length, 1)
})

for (const clear of ['clearCommand', 'clearJournal']) {
  test(`${clear} preserves failed status caution and the uncertain ticket without retry`, async t => {
    const { state, calls } = fixture(t)
    prepare(state, 'revoke')
    const checking = state.perform('status')
    calls[0].reject(new Error('status response unavailable'))
    await checking
    state[clear]()
    assert.equal(state.message.value, statusCaution)
    assert.equal(state.error.value, 'status response unavailable')
    assert.deepEqual(state.ticket.value, held())
    assert.equal(state.revocationUncertain.value, true)
    assert.equal(state.canCommit.value, false)
    assert.equal(state.lookupId.value, held().id)
    assert.equal(state.lastSubmissionId.value, 'retained-id')
    assert.equal(state.outcome.value, null)
    assert.equal(state.outcomeReceivedAt.value, null)
    assert.equal(calls.length, 1)
  })
}

for (const action of Object.keys(actions)) {
  test(`next explicit ${action} resets failed status feedback without automatic requests`, async t => {
    const { state, calls } = fixture(t)
    prepare(state, 'status')
    const checking = state.perform('status')
    calls[0].reject(new Error('status unavailable'))
    await checking
    assert.equal(state.message.value, statusCaution)
    assert.equal(state.error.value, 'status unavailable')
    assert.equal(calls.length, 1)
    const next = state.perform(action)
    assert.equal(state.message.value, '')
    assert.equal(state.error.value, '')
    assert.equal(state.busy.value, action)
    assert.equal(calls.length, 2)
    calls[1].resolve(results[action])
    await next
    assert.notEqual(state.message.value, statusCaution)
    assert.equal(state.error.value, '')
    assert.equal(state.busy.value, '')
    assert.equal(calls.length, 2)
  })
}

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
    before.canCheckStatus = true
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
    before.validLookupId = false
    before.canCheckStatus = false
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
    before.validLookupId = false
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
  assert.match(app, /<input id="lookup-id"[^>]*:aria-describedby="[^"]*'lookup-id-help lookup-id-error' : 'lookup-id-help'"/)
  assert.match(app, /id="lookup-id-help"[^>]*>Een ander ID wist alleen de lokale status/)
  assert.match(app, /Geen herstel van toestemming of intrekking op de server; geen automatisch verzoek\./)
  assert.match(app, /Gebruik het exacte ID, zonder omringende spaties\./)
  assert.match(app, /<input id="outcome-ticket-id" :value="outcome.id" readonly/)
})

test('outcome clear UI is an explicit local-only button with status-only busy eligibility and honest help', () => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  assert.match(app, /clearSession, clearOutcome, clearJournal,\s*\} = useSession\(\)/)
  const button = app.match(/<button[^>]*@click="clearOutcome"[^>]*>Wis ticketuitkomst<\/button>/)?.[0]
  assert.ok(button)
  assert.match(button, /type="button"/)
  assert.match(app, /canCommit, canClearOutcome, remaining,/)
  assert.match(button, /:disabled="!canClearOutcome"/)
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

for (const reset of ['token', 'pagehide']) {
  for (const settlement of ['resolve', 'reject']) {
    for (const newerCompleted of [false, true]) {
      test(`${reset}: synchronous abort can explicitly start a new session; stale ${settlement}, newer completed=${newerCompleted}`, async t => {
        const { state, calls, sockets, eventTarget } = fixture(t)
        state.realtime.connect(state.token.value)
        sockets[0].handlers.connect()
        prepare(state, 'list')
        state.revocationUncertain.value = true
        const old = state.perform('list')
        sockets[0].handlers['command:committed'](record('old-buffer'))
        let newer
        let aborts = 0
        calls[0].signal.addEventListener('abort', () => {
          aborts++
          assertEmpty(state, reset === 'token' ? 'replacement-token' : '')
          assertDisconnected(sockets[0])
          assert.equal(calls.length, 1)
          if (reset === 'pagehide') state.token.value = 'replacement-token'
          state.realtime.connect(state.token.value)
          sockets[1].handlers.connect()
          state.command.value = 'new draft'
          state.ttlMs.value = 60
          state.ticket.value = { ...held(), id: 'new-ticket', command: 'new draft' }
          state.lookupId.value = 'new-ticket'
          state.lastSubmissionId.value = 'new-submission'
          newer = state.perform('list')
          state.outcome.value = snapshot({ id: 'new-ticket', command: 'new draft' })
          state.outcomeReceivedAt.value = 1050
          state.message.value = 'new feedback'
          state.error.value = 'new warning'
          state.search.value = 'new'
          sockets[1].handlers['command:committed'](record('new-buffer'))
        })
        if (reset === 'token') state.token.value = 'replacement-token'
        else eventTarget.dispatchEvent(pageTransition('pagehide', true))
        assert.equal(aborts, 1)
        assert.equal(calls.length, 2)
        assert.equal(state.busy.value, 'list')
        assert.equal(state.message.value, 'new feedback')
        assert.equal(state.error.value, 'new warning')
        assert.equal(state.ticket.value.id, 'new-ticket')
        assert.equal(state.lookupId.value, 'new-ticket')
        assert.equal(state.lastSubmissionId.value, 'new-submission')
        assert.equal(state.outcome.value.id, 'new-ticket')
        assert.equal(state.outcomeReceivedAt.value, 1050)
        assert.equal(state.command.value, 'new draft')
        assert.equal(state.ttlMs.value, 60)
        assert.equal(state.search.value, 'new')
        assert.equal(state.token.value, 'replacement-token')
        assert.ok(calls[1].args.includes('replacement-token'))
        assert.notEqual(calls[1].signal, calls[0].signal)
        assert.equal(calls[1].signal.aborted, false)
        const loaded = [record('new-snapshot')]
        if (newerCompleted) {
          calls[1].resolve(loaded)
          await newer
        }
        const before = retainedOutcomeState(state)
        const feedback = [state.busy.value, state.message.value, state.error.value, state.outcome.value, state.outcomeReceivedAt.value]
        if (settlement === 'resolve') calls[0].resolve([record('stale-snapshot')])
        else calls[0].reject(new Error('stale private failure'))
        await old
        sockets[0].handlers['command:committed'](record('stale-event'))
        sockets[0].handlers.connect_error()
        assert.deepEqual(retainedOutcomeState(state), before)
        assert.deepEqual([state.busy.value, state.message.value, state.error.value, state.outcome.value, state.outcomeReceivedAt.value], feedback)
        assert.equal(calls[1].signal.aborted, false)
        if (!newerCompleted) {
          sockets[1].handlers['command:committed'](record('after-stale-finally'))
          calls[1].resolve(loaded)
          await newer
        }
        assert.deepEqual(state.commands.value.map(entry => entry.id),
          newerCompleted ? ['new-buffer', 'new-snapshot'] : ['after-stale-finally', 'new-buffer', 'new-snapshot'])
        assert.equal(state.busy.value, '')
        assert.equal(state.hasLoaded.value, true)
        assert.equal(state.lastJournalRefreshAt.value, 1050)
        assert.equal(state.message.value, 'Logboek bijgewerkt.')
        assert.equal(state.error.value, 'new warning')
        assert.equal(state.ticket.value.id, 'new-ticket')
        assert.equal(state.outcome.value.id, 'new-ticket')
        assert.equal(calls.length, 2)
      })
    }
  }
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
        let aborts = 0
        calls[0].signal.addEventListener('abort', () => {
          aborts++
          assertEmpty(state, reset === 'clear' ? '' : 'replacement-token')
          assertDisconnected(socket)
        })
        if (reset === 'clear') state.clearSession()
        else state.token.value = 'replacement-token'
        assert.equal(aborts, 1)
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
      let aborts = 0
      calls[0].signal.addEventListener('abort', () => {
        aborts++
        assertEmpty(state)
        assertDisconnected(socket)
        assert.deepEqual(clock.cleared, [42])
        state.perform('list')
        state.checkCurrentTicket()
        state.checkLastSubmission()
        state.realtime.connect('not-allowed-during-disposal')
        assert.equal(calls.length, 1)
        assert.equal(sockets.length, 1)
        assertEmpty(state)
      })
      scope.stop()
      assert.equal(aborts, 1)
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
  assert.equal(state.message.value, commitCaution)
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
  assert.equal(state.message.value, revokeCaution)
  assert.equal(state.error.value, 'confirmation lost')
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
  assert.match(state.message.value, /geen nieuwe toestemming/)
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

for (const guard of ['no ticket', 'empty token', 'blank token', 'CR token', 'LF token', 'CRLF token', 'nonstring token', 'disposed']) {
  test(`current-ticket shortcut: ${guard} does not change lookup or call the API`, async t => {
    const { state, calls, scope } = fixture(t)
    if (guard === 'disposed') scope.stop()
    if (guard === 'empty token') state.token.value = ''
    if (guard === 'blank token') state.token.value = ' \t\n '
    if (guard === 'CR token') state.token.value = 'private\rvalue'
    if (guard === 'LF token') state.token.value = 'private\nvalue'
    if (guard === 'CRLF token') state.token.value = 'private\r\nvalue'
    if (guard === 'nonstring token') state.token.value = null
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

test('compiled current-ticket help stays linked and static across real session guards without side effects', async t => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const panel = app.slice(app.indexOf('<h2>2. Apart bevestigen</h2>'), app.indexOf('</section>', app.indexOf('<h2>2. Apart bevestigen</h2>')))
  const button = panel.match(/<button[^>]*>Controleer huidig ticket<\/button>/)[0]
  assert.equal(button, '<button class="secondary" :disabled="!!busy || !ticket || !validToken" aria-describedby="current-ticket-status-help" @click="checkCurrentTicket">Controleer huidig ticket</button>')
  const help = panel.match(/<p id="current-ticket-status-help" class="muted">[\s\S]*?<\/p>/)[0]
  assert.doesNotMatch(help, /\{\{|v-|@/)
  assert.equal(app.match(/\bid="current-ticket-status-help"/g).length, 1)
  assert.equal(app.match(/\baria-describedby="current-ticket-status-help"/g).length, 1)
  assert.ok(panel.indexOf(help) > panel.indexOf('<p v-else class="muted">Nog geen ticket.'))
  const expectedHelp = 'Kiest expliciet het bewaarde huidige ticket-ID in het opzoekveld en vraagt een statusmomentopname op. Geen vastlegging, intrekking, reservering of herstel van toestemming. Alleen een geldige, passende terminale uitkomst sluit het lokale ticket en de onzekerheidsblokkering af; een fout, afwijkende uitkomst, active of pending niet.'
  const helpers = app.match(/function date\(value\) \{[\s\S]*?\n\}[\s\S]*?function receiptIso\(value\) \{[\s\S]*?\n\}/)[0]
  const formatters = new Function('timestamp', `${helpers}; return { date, receiptIso }`)(timestamp)
  const render = compileFragment(`<div>${panel}</div>`)
  for (const [scenario, disabled] of [
    ['eligible ticket', false],
    ['expired ticket', false],
    ['uncertain revocation', false],
    ['busy', true],
    ['absent ticket', true],
    ['empty token', true],
    ['invalid token', true],
  ]) {
    await t.test(scenario, async t => {
      const { state, calls, sockets, clock } = fixture(t)
      if (scenario === 'empty token') state.token.value = ''
      if (scenario === 'invalid token') state.token.value = 'invalid\nformat'
      prepare(state, scenario === 'uncertain revocation' ? 'revoke' : 'commit')
      state.lookupId.value = 'unrelated-ticket'
      if (scenario === 'expired ticket') {
        clock.time = held().expires_at
        clock.tick()
        assert.equal(state.canCommit.value, false)
      }
      if (scenario === 'uncertain revocation') {
        assert.equal(state.revocationUncertain.value, true)
        assert.equal(state.canCommit.value, false)
      }
      if (scenario === 'absent ticket') state.clearCommand()
      if (scenario === 'busy') state.busy.value = 'status'
      const before = JSON.stringify(commandState(state))
      const readsBefore = clock.reads
      for (let pass = 0; pass < 2; pass++) {
        const { html, find } = await render({ ...state, ...formatters })
        const renderedButton = find(node => node.type === 'button' && node.children === 'Controleer huidig ticket')
        assert.equal(renderedButton.props.disabled, disabled)
        assert.equal(renderedButton.props['aria-describedby'], 'current-ticket-status-help')
        assert.equal(/\sdisabled(?:[=>\s])/.test(html.match(/<button[^>]*>Controleer huidig ticket<\/button>/)[0]), disabled)
        assert.equal(html.match(/\bid="current-ticket-status-help"/g).length, 1)
        assert.equal(html.match(/\baria-describedby="current-ticket-status-help"/g).length, 1)
        const renderedHelp = find(node => node.props?.id === 'current-ticket-status-help')
        assert.equal(renderedHelp.type, 'p')
        assert.equal(renderedHelp.props.class, 'muted')
        assert.equal(renderedHelp.children, expectedHelp)
        assert.equal(JSON.stringify(commandState(state)), before)
        assert.deepEqual(calls, [])
        assert.deepEqual(sockets, [])
        assert.equal(clock.reads, readsBefore)
      }
    })
  }
})

test('compiled current-ticket click explicitly selects the held ID and checks once without restoring authority', async t => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const render = compileFragment(app.match(/<button[^>]*>Controleer huidig ticket<\/button>/)[0])
  const { state, calls, sockets } = fixture(t)
  prepare(state, 'commit')
  state.lookupId.value = 'unrelated-ticket'
  assert.equal(state.canCommit.value, true)
  const before = JSON.stringify(commandState(state))
  const { find } = await render(state)
  const button = find(node => node.type === 'button')
  assert.equal(button.props.disabled, false)
  assert.equal(JSON.stringify(commandState(state)), before)
  assert.deepEqual(calls, [])
  const checking = button.props.onClick()
  assert.equal(state.lookupId.value, held().id)
  assert.equal(state.busy.value, 'status')
  assert.equal(calls.length, 1)
  assert.equal(calls[0].action, 'status')
  assert.equal(calls[0].args[0], held().id)
  assert.equal(calls[0].args[1], state.token.value)
  const terminal = snapshot({ status: 'revoked', revoked: true })
  calls[0].resolve(terminal)
  await checking
  assert.deepEqual(state.outcome.value, terminal)
  assert.equal(state.ticket.value, null)
  assert.equal(state.revocationUncertain.value, false)
  assert.equal(state.canCommit.value, false)
  assert.deepEqual(state.commands.value, [record()])
  assert.equal(state.lastSubmissionId.value, 'retained-id')
  assert.match(state.message.value, /geen nieuwe toestemming/)
  await render(state)
  assert.equal(state.ticket.value, null)
  assert.equal(state.canCommit.value, false)
  assert.equal(calls.length, 1)
  assert.ok(calls.every(call => call.action === 'status'))
  assert.deepEqual(sockets, [])
})

test('current-ticket button delegates to the composable without gating on expiry or uncertainty; manual lookup remains', () => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  assert.match(app, /checkCurrentTicket, clearCommand, clearSession,[\s\S]*} = useSession\(\)/)
  assert.match(app, /Ticket intrekken<\/button>\s*<button class="secondary" :disabled="!!busy \|\| !ticket \|\| !validToken" aria-describedby="current-ticket-status-help" @click="checkCurrentTicket">Controleer huidig ticket<\/button>/)
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

for (const guard of ['busy', 'missing ID', 'empty token', 'blank token', 'CR token', 'LF token', 'CRLF token', 'nonstring token', 'disposed']) {
  test(`last-submission shortcut: ${guard} leaves lookup unchanged and makes no request`, async t => {
    const { state, calls, scope } = fixture(t)
    if (guard === 'disposed') scope.stop()
    if (guard === 'empty token') state.token.value = ''
    if (guard === 'blank token') state.token.value = ' \t\n '
    if (guard === 'CR token') state.token.value = 'private\rvalue'
    if (guard === 'LF token') state.token.value = 'private\nvalue'
    if (guard === 'CRLF token') state.token.value = 'private\r\nvalue'
    if (guard === 'nonstring token') state.token.value = null
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
  assert.match(app, /<div v-if="lastSubmissionId">\s*<label[^>]*>[^<]*<\/label>\s*<input id="last-submission" :value="lastSubmissionId" readonly @focus="\$event.target.select\(\)" aria-describedby="last-submission-help" \/>\s*<p id="last-submission-help" class="muted">[^<]*<\/p>\s*<button type="button" class="secondary" :disabled="!!busy \|\| !validToken" @click="checkLastSubmission">Controleer laatste inzending<\/button>\s*<\/div>/)
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
    assert.equal(state.message.value, action === 'ticket' ? ticketCaution : action === 'commit' ? commitCaution : action === 'revoke' ? revokeCaution : action === 'status' ? statusCaution : '')
    assert.equal(calls.length, 1)
  }
})

test('unconfirmed issuance preserves the draft, journal and previous submission identifiers without authority or retry', async t => {
  const { state, calls } = fixture(t)
  prepare(state, 'ticket')
  const before = commandState(state, ['ticket', 'canCommit', 'remaining', 'busy', 'message', 'error'])
  const issuing = state.perform('ticket')
  assert.equal(state.ticket.value, null, 'discard previous local ticket before requesting another')
  calls[0].reject(new Error('issuance response lost'))
  await issuing
  assert.equal(state.message.value, ticketCaution)
  assert.equal(state.error.value, 'issuance response lost')
  assert.equal(state.busy.value, '')
  assert.equal(state.ticket.value, null)
  assert.equal(state.canCommit.value, false)
  assert.equal(state.revocationUncertain.value, false)
  assert.deepEqual(commandState(state, ['ticket', 'canCommit', 'remaining', 'busy', 'message', 'error']), before)
  assert.equal(calls.length, 1)

  for (const clear of ['clearCommand', 'clearOutcome', 'clearJournal']) {
    state[clear]()
    assert.equal(state.message.value, ticketCaution, clear)
    assert.equal(state.error.value, 'issuance response lost', clear)
    assert.equal(state.ticket.value, null, clear)
    assert.equal(state.canCommit.value, false, clear)
    assert.equal(state.lastSubmissionId.value, 'retained-id', clear)
    assert.equal(state.lookupId.value, held().id, clear)
    assert.equal(calls.length, 1, 'local clears do not retry issuance')
  }
  await state.perform('commit')
  assert.equal(state.message.value, localCommitBlocked)
  assert.equal(calls.length, 1, 'explicit commit without a received ticket sends no request')
})

for (const reset of ['clearSession', 'token', 'pagehide', 'dispose']) {
  for (const settled of [false, true]) {
    test(`unconfirmed issuance ${settled ? 'feedback clears' : 'late rejection stays inert'} after ${reset}`, async t => {
      const { state, calls, scope, eventTarget } = fixture(t)
      prepare(state, 'ticket')
      const issuing = state.perform('ticket')
      if (settled) {
        calls[0].reject(new Error('issuance response lost'))
        await issuing
        assert.equal(state.message.value, ticketCaution)
      }
      if (reset === 'pagehide') eventTarget.dispatchEvent(pageTransition('pagehide', true))
      else if (reset === 'dispose') scope.stop()
      else if (reset === 'token') state.token.value = 'replacement-token'
      else state.clearSession()
      assertEmpty(state, reset === 'token' ? 'replacement-token' : '')
      if (!settled) {
        assert.equal(calls[0].signal.aborted, true)
        calls[0].reject(new Error('stale issuance response lost'))
        await issuing
      }
      assertEmpty(state, reset === 'token' ? 'replacement-token' : '')
      assert.equal(calls.length, 1)
    })
  }
}

for (const nextAction of ['status', 'revoke']) {
  test(`unconfirmed revoke feedback survives local clears until explicit ${nextAction} starts`, async t => {
    const { state, calls } = fixture(t)
    prepare(state, 'revoke')
    const previousTicket = state.ticket.value
    const revoking = state.perform('revoke')
    calls[0].reject(new Error('revocation response lost'))
    await revoking

    for (const clear of ['clearCommand', 'clearOutcome', 'clearJournal']) {
      state[clear]()
      assert.equal(state.message.value, revokeCaution, clear)
      assert.equal(state.error.value, 'revocation response lost', clear)
      assert.equal(state.ticket.value, previousTicket, clear)
      assert.equal(state.revocationUncertain.value, true, clear)
      assert.equal(state.canCommit.value, false, clear)
      assert.equal(calls.length, 1, 'local clears do not retry or reconcile')
    }

    const next = nextAction === 'status' ? state.checkCurrentTicket() : state.perform('revoke')
    assert.equal(state.busy.value, nextAction)
    assert.equal(state.message.value, '', 'clear caution before awaiting the explicit request')
    assert.equal(state.error.value, '')
    assert.equal(state.ticket.value, previousTicket)
    assert.equal(state.revocationUncertain.value, true)
    calls[1].resolve(nextAction === 'status' ? snapshot({ status: 'revoked', revoked: true }) : undefined)
    await next
    assert.equal(state.ticket.value, null)
    assert.equal(state.revocationUncertain.value, false)
    assert.equal(state.canCommit.value, false)
    assert.notEqual(state.message.value, revokeCaution)
    assert.deepEqual(calls.map(call => call.action), ['revoke', nextAction])
  })
}

test('session reset, pagehide and disposal clear settled unconfirmed revoke feedback', async t => {
  for (const reset of ['clearSession', 'pagehide', 'dispose']) {
    const { state, calls, scope, eventTarget } = fixture(t)
    prepare(state, 'revoke')
    const revoking = state.perform('revoke')
    calls[0].reject(new Error('revocation response lost'))
    await revoking
    assert.equal(state.message.value, revokeCaution)
    assert.equal(state.error.value, 'revocation response lost')
    if (reset === 'pagehide') eventTarget.dispatchEvent(pageTransition('pagehide', true))
    else if (reset === 'dispose') scope.stop()
    else state.clearSession()
    assertEmpty(state)
    assert.equal(calls.length, 1)
  }
})

for (const nextAction of ['status', 'list']) {
  test(`unconfirmed commit feedback survives local clears until explicit ${nextAction} starts`, async t => {
    const { state, calls } = fixture(t)
    prepare(state, 'commit')
    const previousJournal = state.commands.value
    const operation = state.perform('commit')
    calls[0].reject(new Error('commit response lost'))
    await operation
    assert.equal(state.message.value, commitCaution)
    assert.equal(state.error.value, 'commit response lost')
    assert.equal(state.ticket.value, null)
    assert.equal(state.canCommit.value, false)
    assert.equal(state.revocationUncertain.value, false)
    assert.equal(state.lastSubmissionId.value, held().id)
    assert.equal(state.lookupId.value, held().id)
    assert.equal(state.command.value, held().command)
    assert.equal(state.commands.value, previousJournal)
    assert.equal(state.outcome.value, null)
    assert.equal(state.outcomeReceivedAt.value, null)

    state.clearCommand()
    state.clearOutcome()
    assert.equal(state.commands.value, previousJournal)
    state.clearJournal()
    assert.equal(state.command.value, '')
    assert.deepEqual(state.commands.value, [])
    assert.equal(state.message.value, commitCaution)
    assert.equal(state.error.value, 'commit response lost')
    assert.equal(state.ticket.value, null)
    assert.equal(state.lastSubmissionId.value, held().id)
    assert.equal(state.lookupId.value, held().id)
    assert.equal(calls.length, 1, 'local clears do not reconcile or resubmit')

    const next = nextAction === 'status' ? state.checkLastSubmission() : state.perform('list')
    assert.equal(state.busy.value, nextAction)
    assert.equal(state.message.value, '', 'clear caution before awaiting the explicit request')
    assert.equal(state.error.value, '')
    calls[1].resolve(results[nextAction])
    await next
    assert.equal(state.ticket.value, null)
    assert.equal(state.canCommit.value, false)
    assert.equal(calls.length, 2)
    assert.deepEqual(calls.map(call => call.action), ['commit', nextAction])
  })
}

test('session reset, pagehide and disposal clear settled unconfirmed commit feedback', async t => {
  for (const reset of ['clearSession', 'pagehide', 'dispose']) {
    const { state, calls, scope, eventTarget } = fixture(t)
    prepare(state, 'commit')
    const operation = state.perform('commit')
    calls[0].reject(new Error('commit response lost'))
    await operation
    assert.equal(state.message.value, commitCaution)
    assert.equal(state.error.value, 'commit response lost')
    if (reset === 'pagehide') eventTarget.dispatchEvent(pageTransition('pagehide', true))
    else if (reset === 'dispose') scope.stop()
    else state.clearSession()
    assertEmpty(state)
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

test('compiled global status region renders local action progress without side effects or success claims', async t => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const script = app.match(/<script setup>([\s\S]*?)<\/script>/)?.[1]
  const initializer = script?.match(/const busyLabels = (\{[\s\S]*?\n\})/)?.[1]
  assert.ok(initializer)
  const busyLabels = new Function(`return (${initializer})`)()
  assert.equal(Object.getPrototypeOf(busyLabels), null)
  assert.deepEqual(Object.keys(busyLabels).sort(), ['commit', 'list', 'revoke', 'status', 'ticket'])
  const region = app.match(/<div role="status" aria-live="polite">[\s\S]*?<\/div>/)?.[0]
  assert.ok(region)
  assert.doesNotMatch(region, /@|v-on|v-model|v-html|<button|<input|<form|perform|fetch/)
  const { code } = compile(region, { mode: 'function', prefixIdentifiers: true })
  const render = new Function('Vue', code)(Vue)
  const cases = [
    ['ticket', 'Ticket aanvragen…'],
    ['commit', 'Commando indienen…'],
    ['revoke', 'Ticket intrekken…'],
    ['status', 'Ticketstatus controleren…'],
    ['list', 'Logboek vernieuwen…'],
    ['', null],
    ['unknown-action', 'Verzoek verwerken…'],
    ['__proto__', 'Verzoek verwerken…'],
    ['constructor', 'Verzoek verwerken…'],
  ]
  for (const [busy, label] of cases) {
    for (const message of ['', '<em>Afzonderlijke melding & tekst</em>']) {
      await t.test(`busy=${busy || 'idle'}, message=${!!message}`, async t => {
        const { state, calls, sockets } = fixture(t)
        prepare(state, 'status')
        state.busy.value = busy
        state.message.value = message
        const before = commandState(state)
        const html = await renderToString(Vue.createSSRApp({
          setup: () => ({ ...state, busyLabels }),
          render,
        }))
        assert.match(html, /^<div role="status" aria-live="polite">/)
        const notices = [...html.matchAll(/<p class="notice">([\s\S]*?)<\/p>/g)].map(match => match[1])
        assert.deepEqual(notices, [
          ...(label ? [label] : []),
          ...(message ? ['&lt;em&gt;Afzonderlijke melding &amp; tekst&lt;/em&gt;'] : []),
        ])
        assert.doesNotMatch(html, /Even wachten|geslaagd|opgeslagen|uitgevoerd|bevestigd|<em>|onClick/i)
        for (const value of [state.token.value, state.command.value, state.ticket.value.id, state.lastSubmissionId.value]) {
          assert.ok(!html.includes(value))
        }
        assert.deepEqual(commandState(state), before)
        assert.deepEqual(calls, [])
        assert.deepEqual(sockets, [])
      })
    }
  }
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

test('compiled journal labels stored records with ISO times, escaped exact text and supplied order', async () => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const help = app.match(/<p id="journal-record-help"[^>]*>[\s\S]*?<\/p>/)?.[0]
  const journal = app.match(/<ol class="journal"[^>]*>[\s\S]*?<\/ol>/)?.[0]
  assert.ok(help)
  assert.ok(journal)
  assert.equal(app.match(/\bid="journal-record-help"/g)?.length, 1)
  assert.doesNotMatch(help, /v-|@|\{\{|:id/)
  assert.match(help, /record-ID identificeert het opgeslagen logboekrecord, niet het ticket-ID voor statuscontrole/)
  assert.match(help, /Opgeslagen tekst, geen uitvoering\./)
  const helpers = app.match(/function date\(value\) \{[\s\S]*?\n\}[\s\S]*?function receiptIso\(value\) \{[\s\S]*?\n\}/)?.[0]
  assert.ok(helpers)
  const formatters = new Function('timestamp', `${helpers}; return { date, receiptIso }`)(timestamp)
  const render = compileFragment(`<div>${help}${journal}</div>`)
  const entries = [
    { id: 'numeric', command: '  first\n  exact text  ', committed_at: 1_700_000_000_123 },
    { id: '<id>&"\'', command: '  <script>alert("x")</script> & \'text\'\n  ', committed_at: 0 },
    { id: 'maximum', command: 'maximum numeric date', committed_at: 8_640_000_000_000_000 },
    { id: 'iso', command: 'normal ISO date', committed_at: '2025-01-02T03:04:05.678+02:00' },
    { id: 'maximum-iso', command: 'maximum ISO date', committed_at: '+275760-09-13T00:00:00.000Z' },
  ]
  const expectedIso = [
    '2023-11-14T22:13:20.123Z', '1970-01-01T00:00:00.000Z',
    '+275760-09-13T00:00:00.000Z', '2025-01-02T01:04:05.678Z',
    '+275760-09-13T00:00:00.000Z',
  ]
  const escaped = value => value.replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character])
  entries.forEach((entry, index) => {
    const accepted = { ...entry, id: `record-${index}` }
    assert.deepEqual(normalizeCommand(accepted), accepted)
  })
  const before = structuredClone(entries)
  const { html, find } = await render({ filteredCommands: entries, ...formatters })
  assert.equal(find(node => node.type === 'ol').props['aria-describedby'], 'journal-record-help')
  assert.equal(html.match(/\bid="journal-record-help"/g)?.length, 1)
  const rows = [...html.matchAll(/<li>([\s\S]*?)<\/li>/g)].map(match => match[1])
  assert.equal(rows.length, entries.length)
  entries.forEach((entry, index) => {
    const displayDate = new Date(timestamp(entry.committed_at)).toLocaleString('nl-NL')
    assert.equal(rows[index], `<pre>${escaped(entry.command)}</pre><small>Vastgelegd: <time datetime="${expectedIso[index]}">${escaped(displayDate)}</time> · Record-ID: <code>${escaped(entry.id)}</code></small>`)
  })
  assert.doesNotMatch(html, /<script>/)
  assert.deepEqual(entries, before)

  const { html: empty, find: findEmpty } = await render({ filteredCommands: [], ...formatters })
  assert.equal(findEmpty(node => node.type === 'ol').props['aria-describedby'], 'journal-record-help')
  assert.equal(empty.match(/\bid="journal-record-help"/g)?.length, 1)
  assert.doesNotMatch(empty, /<li\b|<time\b|<code\b|Vastgelegd:|Record-ID:|datetime=/)
})

test('compiled realtime controls retain scoped guidance in every connection and busy state', async t => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const panel = app.match(/<p role="status"[^>]*>{{ realtimeLabels\[realtimeStatus\] }}<\/p>[\s\S]*?<\/div>/)?.[0]
  assert.ok(panel)
  assert.equal(app.match(/\bid="realtime-help"/g)?.length, 1)
  assert.equal(app.match(/\baria-describedby="realtime-help"/g)?.length, 2)
  const help = panel.match(/<p id="realtime-help" class="muted">([\s\S]*?)<\/p>/)?.[1]
  assert.ok(help)
  assert.doesNotMatch(help, /v-if|v-html|v-text|\{\{|@|v-on/)
  const text = help.replace(/\s+/g, ' ').trim()
  assert.equal(text, 'Realtime ontvangt alleen nieuwe gebeurtenissen zolang de verbinding actief is. Verbinden of opnieuw verbinden haalt geen eerdere of gemiste records op. Verbonden betekent geen volledige historie. Kies expliciet Logboek vernieuwen voor een momentopname van de nieuwste maximaal 100 records, niet de hele historie. Geen garantie op ontvangst zonder gaten of precies één ontvangst per live record.')
  const { code } = compile(panel, { mode: 'function', prefixIdentifiers: true })
  const render = new Function('Vue', code)(Vue)

  for (const realtimeStatus of ['disconnected', 'connecting', 'connected', 'error']) {
    for (const busy of ['', 'list']) {
      await t.test(`${realtimeStatus}, busy=${!!busy}`, async t => {
        const { state, calls, sockets } = fixture(t)
        state.realtimeStatus.value = realtimeStatus
        state.busy.value = busy
        const before = commandState(state)
        const html = await renderToString(Vue.createSSRApp({
          setup: () => ({ ...state, realtimeLabels }), render,
        }))
        assert.equal(html.match(/\bid="realtime-help"/g)?.length, 1)
        assert.equal(html.match(/\baria-describedby="realtime-help"/g)?.length, 2)
        assert.ok(html.includes(`<p role="status" aria-describedby="realtime-help">${realtimeLabels[realtimeStatus]}</p>`))
        assert.equal(html.match(/<p id="realtime-help" class="muted">([\s\S]*?)<\/p>/)?.[1].replace(/\s+/g, ' ').trim(), text)
        const connect = html.match(/<button\b[^>]*>Realtime verbinden<\/button>/)?.[0]
        assert.ok(connect)
        assert.match(connect, /aria-describedby="realtime-help"/)
        assert.equal(connect.includes(' disabled'), !!busy || ['connecting', 'connected'].includes(realtimeStatus))
        const disconnect = html.match(/<button\b[^>]*>Verbinding verbreken<\/button>/)?.[0]
        assert.ok(disconnect)
        assert.equal(disconnect.includes(' disabled'), !!busy || !['connecting', 'connected'].includes(realtimeStatus))
        assert.deepEqual(commandState(state), before)
        assert.equal(state.realtimeStatus.value, realtimeStatus)
        assert.equal(state.busy.value, busy)
        assert.equal(calls.length, 0)
        assert.equal(sockets.length, 0)
      })
    }
  }
})

test('compiled journal limit notice depends only on loaded count, including realtime-only and failed-refresh states', async t => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const notice = app.match(/<p\b[^>]*\bid="journal-limit-help"[^>]*>[\s\S]*?<\/p>/)?.[0]
  const text = 'De lokale limiet van 100 records is bereikt. Er kunnen oudere records op de server staan die hier niet zichtbaar zijn. Zoeken doorzoekt alleen de geladen records, niet de volledige historie.'
  assert.equal(notice, `<p v-if="commands.length === 100" id="journal-limit-help" class="muted" role="status">${text}</p>`)
  assert.equal(app.match(/\bid="journal-limit-help"/g).length, 1)
  assert.doesNotMatch(notice, /v-html|v-text|\{\{|@|v-on|fetch|request/)
  const count = '<p role="status" aria-live="polite">{{ filteredCommands.length }} van {{ commands.length }} geladen records</p>'
  const start = app.indexOf(count)
  assert.ok(start >= 0)
  const panel = app.slice(start, app.indexOf('<ol class="journal"', start))
  assert.ok(panel.includes(notice))
  const { code } = compile(panel, { mode: 'function', prefixIdentifiers: true })
  const render = new Function('Vue', code)(Vue)

  for (const length of [0, 99, 100]) {
    for (const search of ['', 'no matches']) {
      for (const hasLoaded of [false, true]) {
        for (const journalRefreshFailed of [false, true]) {
          await t.test(`loaded=${length}, search=${search || 'all'}, snapshot=${hasLoaded}, failed=${journalRefreshFailed}`, async t => {
            const { state, calls, sockets } = fixture(t)
            state.commands.value = Array.from({ length }, (_, index) => record(`record-${index}`))
            state.search.value = search
            state.hasLoaded.value = hasLoaded
            state.journalRefreshFailed.value = journalRefreshFailed
            const before = commandState(state)
            const html = await renderToString(Vue.createSSRApp({ setup: () => state, render }))
            const filtered = search ? 0 : length
            assert.equal(state.filteredCommands.value.length, filtered)
            assert.ok(html.includes(`${filtered} van ${length} geladen records`))
            assert.equal(html.includes(`<p id="journal-limit-help" class="muted" role="status">${text}</p>`), length === 100)
            assert.equal(html.includes('id="journal-limit-help"'), length === 100)
            assert.equal(html.includes(text), length === 100)
            if (!length) {
              assert.ok(html.includes(journalRefreshFailed
                ? 'Geen records beschikbaar na mislukte verversing.'
                : hasLoaded ? 'Het logboek is leeg.' : 'Nog geen records geladen.'))
            } else {
              assert.equal(html.includes('Geen geladen records gevonden voor deze zoekopdracht.'), !!search)
            }
            assert.deepEqual(commandState(state), before)
            assert.equal(calls.length, 0)
            assert.equal(sockets.length, 0)
          })
        }
      }
    }
  }
})

test('compiled clear-search button links static muted help and only disables for an empty search, even while busy', async t => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const pair = app.match(/<button[^>]*>Wis zoekopdracht<\/button>\s*<p id="clear-search-help" class="muted">[\s\S]*?<\/p>/)?.[0]
  assert.ok(pair)
  assert.equal(app.match(/\bid="clear-search-help"/g).length, 1)
  assert.equal(app.match(/\baria-describedby="clear-search-help"/g).length, 1)
  assert.doesNotMatch(pair.slice(pair.indexOf('<p ')), /\{\{|v-|@/)
  const render = compileFragment(pair)
  const { state, calls, sockets } = fixture(t)
  for (const busy of ['', ...Object.keys(actions)]) {
    state.busy.value = busy
    for (const search of ['', 'journal', ' ']) {
      state.search.value = search
      const before = commandState(state)
      const { html, find } = await render(state)
      const button = find(node => node.type === 'button')
      assert.equal(button.props.disabled, !search)
      assert.equal(button.props['aria-describedby'], 'clear-search-help')
      assert.equal(html.match(/<button[^>]*>/)[0].includes(' disabled'), !search)
      const help = find(node => node.props?.id === 'clear-search-help')
      assert.equal(help.type, 'p')
      assert.equal(help.props.class, 'muted')
      assert.equal(help.children, 'Wist alleen het lokale zoekfilter; geladen records blijven behouden. Geen verversing, onderbreking van de verbinding of wijziging van tickets.')
      assert.deepEqual(commandState(state), before)
      assert.equal(calls.length, 0)
      assert.equal(sockets.length, 0)
    }
  }
})

test('compiled clear-search click reveals all loaded records without changing session state, pending refresh or active realtime', async t => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  const panel = app.match(/<button[^>]*>Wis zoekopdracht<\/button>[\s\S]*?<\/ol>/)?.[0]
  assert.ok(panel)
  const render = compileFragment(panel)
  for (const busy of [false, true]) {
    const { state, calls, sockets, clock } = fixture(t)
    state.realtime.connect(state.token.value)
    const socket = sockets[0]
    socket.handlers.connect()
    prepare(state, 'list')
    state.commands.value = [record(), { ...record('other-record'), command: 'other text' }]
    const pending = busy ? state.perform('list') : null
    const before = commandState(state, ['search', 'filteredCommands'])
    const callsBefore = calls.slice()
    const socketBefore = structuredClone({
      auth: socket.auth, options: socket.io.opts, connects: socket.connects,
      disconnects: socket.disconnects, removed: socket.removed,
    })
    const readsBefore = clock.reads
    const viewState = { ...state, date: value => String(value), receiptIso: value => new Date(value).toISOString() }
    const { html, find } = await render(viewState)
    assert.match(html, /1 van 2 geladen records/)
    assert.doesNotMatch(html, /<code>other-record<\/code>/)
    const button = find(node => node.type === 'button' && node.children === 'Wis zoekopdracht')
    assert.equal(button.props.disabled, false)
    button.props.onClick()
    assert.equal(state.search.value, '')
    assert.deepEqual(state.filteredCommands.value, state.commands.value)
    const cleared = await render(viewState)
    assert.match(cleared.html, /2 van 2 geladen records/)
    for (const entry of state.commands.value) {
      assert.ok(cleared.html.includes(`<code>${entry.id}</code>`))
      assert.ok(cleared.html.includes(`<pre>${entry.command}</pre>`))
    }
    assert.equal(cleared.find(node => node.type === 'button').props.disabled, true)
    const after = commandState(state, ['search', 'filteredCommands'])
    for (const key of Object.keys(before)) assert.strictEqual(after[key], before[key], key)
    assert.deepEqual(calls, callsBefore)
    assert.equal(calls.some(call => call.signal.aborted), false)
    assert.equal(sockets.length, 1)
    assert.equal(sockets[0], socket)
    assert.equal(state.realtimeStatus.value, 'connected')
    assert.deepEqual({
      auth: socket.auth, options: socket.io.opts, connects: socket.connects,
      disconnects: socket.disconnects, removed: socket.removed,
    }, socketBefore)
    assert.equal(clock.reads, readsBefore)
    if (pending) {
      calls[0].resolve(state.commands.value)
      await pending
    }
  }
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
  assert.match(app, /return value !== null \? new Date\(timestamp\(value\)\).toISOString\(\) : undefined/)
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

for (const action of ['status', 'list']) {
  for (const clockFailure of ['invalid', 'throw']) {
    test(`${action}: ${clockFailure} receipt clock preserves successful result without a receipt`, async t => {
      const { state, calls, clock } = fixture(t)
      prepare(state, action)
      state.revocationUncertain.value = true
      const operation = state.perform(action)
      const checked = snapshot({ status: 'revoked', revoked: true })
      clock.now = () => {
        if (clockFailure === 'throw') throw new Error('receipt clock unavailable')
        return NaN
      }
      calls[0].resolve(action === 'status' ? checked : [record('fresh-record')])
      await operation
      if (action === 'status') {
        assert.deepEqual(state.outcome.value, checked)
        assert.equal(state.outcomeReceivedAt.value, null)
        assert.equal(state.ticket.value, null)
        assert.equal(state.revocationUncertain.value, false)
        assert.match(state.message.value, /Ticketstatus opgehaald/)
      } else {
        assert.deepEqual(state.commands.value, [record('fresh-record')])
        assert.equal(state.lastJournalRefreshAt.value, null)
        assert.equal(state.hasLoaded.value, true)
        assert.equal(state.journalRefreshFailed.value, false)
        assert.equal(state.message.value, 'Logboek bijgewerkt.')
      }
      assert.equal(state.error.value, '')
      assert.equal(state.busy.value, '')
      assert.equal(calls.length, 1)
    })
  }

  for (const reset of ['clearSession', 'pagehide', 'token', 'dispose', action === 'status' ? 'clearOutcome' : 'clearJournal']) {
    test(`${action}: receipt clock ${reset} prevents stale result and feedback publication`, async t => {
      const { state, calls, clock, eventTarget, scope } = fixture(t)
      prepare(state, action)
      state.revocationUncertain.value = true
      const operation = state.perform(action)
      let retainedTicket
      let beforeReset
      clock.now = () => {
        beforeReset = action === 'status' ? state.outcome.value : [...state.commands.value]
        if (reset === 'pagehide') eventTarget.dispatchEvent(pageTransition('pagehide', true))
        else if (reset === 'token') state.token.value = 'replacement-token'
        else if (reset === 'dispose') scope.stop()
        else state[reset]()
        retainedTicket = state.ticket.value
        return 1090
      }
      calls[0].resolve(action === 'status'
        ? snapshot({ status: 'revoked', revoked: true })
        : [record('stale-record')])
      await operation
      assert.deepEqual(beforeReset, action === 'status' ? null : [record()])
      assert.equal(calls[0].signal.aborted, true)
      assert.equal(state.busy.value, '')
      assert.equal(state.message.value, '')
      assert.equal(state.error.value, '')
      assert.equal(state.ticket.value, retainedTicket)
      if (action === 'status') {
        assert.equal(state.outcome.value, null)
        assert.equal(state.outcomeReceivedAt.value, null)
        assert.equal(state.revocationUncertain.value, reset === 'clearOutcome')
      } else {
        assert.deepEqual(state.commands.value, [])
        assert.equal(state.lastJournalRefreshAt.value, null)
        assert.equal(state.hasLoaded.value, false)
        assert.equal(state.journalRefreshFailed.value, false)
      }
    })
  }

  test(`${action}: receipt clock starts a new request that stale completion cannot finish or overwrite`, async t => {
    const { state, calls, clock } = fixture(t)
    prepare(state, action)
    const old = state.perform(action)
    let newer
    clock.now = () => {
      clock.now = null
      if (action === 'status') state.clearOutcome()
      else state.clearJournal()
      newer = state.perform(action)
      return 1060
    }
    calls[0].resolve(action === 'status'
      ? snapshot({ status: 'revoked', revoked: true })
      : [record('stale-record')])
    await old
    assert.equal(calls.length, 2)
    assert.equal(calls[0].signal.aborted, true)
    assert.equal(calls[1].signal.aborted, false)
    assert.equal(state.busy.value, action)
    assert.equal(state.message.value, '')
    assert.equal(state.error.value, '')
    assert.deepEqual(state.ticket.value, held())
    if (action === 'status') {
      assert.equal(state.outcome.value, null)
      assert.equal(state.outcomeReceivedAt.value, null)
    } else {
      assert.deepEqual(state.commands.value, [])
      assert.equal(state.lastJournalRefreshAt.value, null)
      assert.equal(state.hasLoaded.value, false)
    }
    clock.time = 1080
    const fresh = snapshot({ checked_at: 1080 })
    calls[1].resolve(action === 'status' ? fresh : [record('fresh-record')])
    await newer
    assert.equal(state.busy.value, '')
    if (action === 'status') {
      assert.deepEqual(state.outcome.value, fresh)
      assert.equal(state.outcomeReceivedAt.value, 1080)
    } else {
      assert.deepEqual(state.commands.value, [record('fresh-record')])
      assert.equal(state.lastJournalRefreshAt.value, 1080)
      assert.equal(state.hasLoaded.value, true)
    }
  })
}

test('list: realtime generation reset during receipt sampling rejects the stale snapshot', async t => {
  const { state, calls, clock, realtimeCallbacks } = fixture(t)
  state.realtime.connect(state.token.value)
  prepare(state, 'list')
  const operation = state.perform('list')
  clock.now = () => {
    realtimeCallbacks[0].onReset()
    realtimeCallbacks[0].onEntry(record('after-reset'))
    return 1090
  }
  calls[0].resolve([record('stale-record')])
  await operation
  assert.deepEqual(state.commands.value, [record('after-reset')])
  assert.equal(state.lastJournalRefreshAt.value, null)
  assert.equal(state.hasLoaded.value, false)
  assert.equal(state.journalRefreshFailed.value, false)
  assert.equal(state.message.value, '')
  assert.equal(state.error.value, '')
  assert.equal(state.busy.value, '')
  assert.equal(calls[0].signal.aborted, false)
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
      const beforeStale = commandState(state)
      if (settlement === 'resolve') calls[0].resolve(snapshot())
      else calls[0].reject(new Error('stale status failure'))
      await old
      assert.deepEqual(commandState(state), beforeStale)
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
      const beforeLate = commandState(state)
      if (settlement === 'resolve') calls[2].resolve(snapshot())
      else calls[2].reject(new Error('late status failure'))
      await late
      assert.deepEqual(commandState(state), beforeLate)
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
  assert.match(result, /<p aria-describedby="outcome-server-time-help">Gecontroleerd door server: <time :datetime="receiptIso\(outcome.checked_at\)">{{ date\(outcome.checked_at\) }}<\/time><\/p>/)
  assert.match(result, /<p aria-describedby="outcome-window-help">Geldig vanaf: <time :datetime="receiptIso\(outcome.not_before\)">{{ date\(outcome.not_before\) }}<\/time> · verloopt: <time :datetime="receiptIso\(outcome.expires_at\)">{{ date\(outcome.expires_at\) }}<\/time><\/p>/)
  assert.match(result, /aria-describedby="outcome-receipt-help">Uitkomst lokaal ontvangen:/)
  assert.match(result, /<time v-if="outcomeReceivedAt !== null" :datetime="receiptIso\(outcomeReceivedAt\)">{{ date\(outcomeReceivedAt\) }}<\/time>/)
  assert.match(result, /v-else>Geen ontvangsttijdstip beschikbaar\./)
  assert.match(result, /id="outcome-receipt-help"[^>]*>Volgens de lokale klok; geen server- of audittijd en geen garantie dat de uitkomst actueel is\./)
  assert.match(result, /Controleer de status handmatig opnieuw voor een nieuwe momentopname\./)
})

const journalRefs = [
  'commands', 'filteredCommands', 'search', 'hasLoaded', 'journalRefreshFailed',
  'lastJournalRefreshAt', 'realtimeStatus', 'busy', 'message', 'error',
]

function sessionSnapshot(state, excluded = []) {
  return JSON.parse(JSON.stringify(Object.fromEntries(Object.entries(state)
    .filter(([key, value]) => isRef(value) && !excluded.includes(key))
    .map(([key, value]) => [key, value.value]))))
}

function assertJournalCleared(state) {
  assert.deepEqual(state.commands.value, [])
  assert.deepEqual(state.filteredCommands.value, [])
  assert.equal(state.search.value, '')
  assert.equal(state.hasLoaded.value, false)
  assert.equal(state.journalRefreshFailed.value, false)
  assert.equal(state.lastJournalRefreshAt.value, null)
  assert.equal(state.realtimeStatus.value, 'disconnected')
  assert.equal(state.busy.value, '')
}

for (const uncertain of [false, true]) {
  for (const mismatch of [false, true]) {
    test(`local journal clear retains authority and separate historical outcome, uncertainty=${uncertain}, mismatch=${mismatch}`, t => {
      const { state, calls, sockets, clock } = fixture(t)
      state.realtime.connect(state.token.value)
      sockets[0].handlers.connect()
      prepare(state, 'list')
      state.revocationUncertain.value = uncertain
      state.outcome.value = snapshot({
        status: 'committed', record: record('historical'),
        ...(mismatch ? { expires_at: 1101 } : {}),
      })
      assert.equal(state.outcomeMismatch.value, mismatch)
      const retained = sessionSnapshot(state, journalRefs)
      const ticket = state.ticket.value
      const outcome = state.outcome.value
      const reads = clock.reads
      state.clearJournal()
      state.clearJournal()
      assertJournalCleared(state)
      assertDisconnected(sockets[0])
      assert.deepEqual(sessionSnapshot(state, journalRefs), retained)
      assert.equal(state.ticket.value, ticket)
      assert.equal(state.outcome.value, outcome)
      assert.deepEqual(state.outcome.value.record, record('historical'))
      assert.equal(state.message.value, 'previous message')
      assert.equal(state.error.value, 'previous error')
      assert.equal(calls.length, 0)
      assert.equal(sockets.length, 1)
      assert.equal(clock.reads, reads)
      assert.deepEqual(clock.cleared, [])
    })
  }
}

for (const action of Object.keys(actions)) {
  for (const settlement of ['resolve', 'reject']) {
    test(`journal clear only removes list-owned idle feedback, action=${action}, settlement=${settlement}`, async t => {
      const { state, calls } = fixture(t)
      prepare(state, action)
      const operation = state.perform(action)
      if (settlement === 'resolve') calls[0].resolve(results[action])
      else calls[0].reject(new Error(`${action} failed`))
      await operation
      const retained = sessionSnapshot(state, journalRefs)
      const feedback = [state.message.value, state.error.value]
      assert.ok(feedback.some(Boolean))
      state.clearJournal()
      state.clearJournal()
      assertJournalCleared(state)
      assert.deepEqual(sessionSnapshot(state, journalRefs), retained)
      assert.deepEqual([state.message.value, state.error.value], action === 'list' ? ['', ''] : feedback)
      assert.equal(calls.length, 1)
      assert.equal(calls[0].signal.aborted, false)
    })
  }
}

for (const action of ['ticket', 'commit', 'revoke', 'status']) {
  for (const settlement of ['resolve', 'reject']) {
    test(`journal clear is a complete no-op during ${action}, later ${settlement} is unaffected`, async t => {
      const { state, calls, sockets } = fixture(t)
      state.realtime.connect(state.token.value)
      sockets[0].handlers.connect()
      prepare(state, action)
      const operation = state.perform(action)
      state.message.value = 'busy message'
      state.error.value = 'busy error'
      const before = sessionSnapshot(state)
      const rows = state.commands.value
      state.clearJournal()
      state.clearJournal()
      assert.deepEqual(sessionSnapshot(state), before)
      assert.equal(state.commands.value, rows)
      assert.equal(calls[0].signal.aborted, false)
      assert.equal(calls.length, 1)
      assert.equal(sockets[0].disconnects, 0)
      assert.deepEqual(sockets[0].auth, { token: state.token.value })
      if (settlement === 'resolve') calls[0].resolve(results[action])
      else calls[0].reject(new Error(`${action} failed`))
      await operation
      assert.equal(state.busy.value, '')
      if (settlement === 'reject') assert.equal(state.error.value, `${action} failed`)
      else if (action === 'status') assert.deepEqual(state.outcome.value, snapshot())
      else if (action === 'ticket') assert.deepEqual(state.ticket.value, held())
      else assert.equal(state.ticket.value, null)
      assert.equal(calls.length, 1)
    })
  }
}

for (const settlement of ['resolve', 'reject']) {
  test(`clearing a pending list rejects late ${settlement} without changing retained status or authority`, async t => {
    const { state, calls, sockets } = fixture(t)
    state.realtime.connect(state.token.value)
    sockets[0].handlers.connect()
    prepare(state, 'revoke')
    const retained = sessionSnapshot(state, journalRefs)
    const old = state.perform('list')
    sockets[0].handlers['command:committed'](record('buffered-private-record'))
    let aborted = false
    calls[0].signal.addEventListener('abort', () => {
      aborted = true
      assertJournalCleared(state)
      assertDisconnected(sockets[0])
      assert.equal(state.message.value, '')
      assert.equal(state.error.value, '')
      assert.deepEqual(sessionSnapshot(state, journalRefs), retained)
    })
    state.clearJournal()
    assert.equal(aborted, true)
    const cleared = sessionSnapshot(state)
    if (settlement === 'resolve') calls[0].resolve([record('late-private-record')])
    else calls[0].reject(new Error('late private error'))
    await old
    assert.deepEqual(sessionSnapshot(state), cleared)
    assert.equal(calls.length, 1)
    assert.equal(sockets.length, 1)
  })

  for (const action of Object.keys(actions)) {
    for (const completed of [false, true]) {
      test(`cleared list late ${settlement} cannot affect next ${action}, completed=${completed}`, async t => {
        const { state, calls } = fixture(t)
        prepare(state, 'list')
        const old = state.perform('list')
        state.clearJournal()
        assert.equal(calls[0].signal.aborted, true)
        const newer = state.perform(action)
        assert.equal(calls.length, 2)
        if (completed) {
          calls[1].resolve(results[action])
          await newer
        }
        const before = sessionSnapshot(state)
        if (settlement === 'resolve') calls[0].resolve([record('stale-private-record')])
        else calls[0].reject(new Error('stale private failure'))
        await old
        assert.deepEqual(sessionSnapshot(state), before)
        assert.equal(calls[1].signal.aborted, false)
        if (!completed) {
          assert.equal(state.busy.value, action)
          calls[1].resolve(results[action])
          await newer
        }
        assert.equal(state.busy.value, '')
        assert.equal(state.error.value, '')
        if (action === 'list') {
          assert.deepEqual(state.commands.value, results.list)
          assert.equal(state.hasLoaded.value, true)
          assert.equal(state.lastJournalRefreshAt.value, 1050)
        } else if (action === 'status') {
          assert.deepEqual(state.outcome.value, results.status)
          assert.equal(state.outcomeReceivedAt.value, 1050)
        } else if (action === 'ticket') assert.deepEqual(state.ticket.value, held())
        else assert.equal(state.ticket.value, null)
        assert.equal(calls.length, 2)
      })
    }
  }
}

for (const settlement of ['resolve', 'reject']) {
  test(`list abort callback can explicitly reconnect and refresh; old ${settlement}/finally cannot clear new event buffer`, async t => {
    const { state, calls, sockets } = fixture(t)
    state.realtime.connect(state.token.value)
    sockets[0].handlers.connect()
    prepare(state, 'list')
    const old = state.perform('list')
    sockets[0].handlers['command:committed'](record('old-buffer'))
    let newer
    calls[0].signal.addEventListener('abort', () => {
      assertJournalCleared(state)
      assertDisconnected(sockets[0])
      assert.equal(state.message.value, '')
      assert.equal(state.error.value, '')
      state.realtime.connect(state.token.value)
      sockets[1].handlers.connect()
      newer = state.perform('list')
      sockets[1].handlers['command:committed'](record('fresh-buffer-before-finally'))
      state.message.value = 'fresh feedback'
      state.search.value = 'fresh'
    })
    state.clearJournal()
    assert.equal(calls.length, 2)
    assert.equal(state.busy.value, 'list')
    assert.equal(state.realtimeStatus.value, 'connected')
    assert.equal(state.message.value, 'fresh feedback')
    assert.equal(state.search.value, 'fresh')
    if (settlement === 'resolve') calls[0].resolve([record('old-response')])
    else calls[0].reject(new Error('old error'))
    await old
    assert.equal(state.busy.value, 'list')
    assert.equal(state.message.value, 'fresh feedback')
    assert.equal(state.error.value, '')
    assert.equal(calls[1].signal.aborted, false)
    sockets[1].handlers['command:committed'](record('fresh-buffer-after-finally'))
    calls[1].resolve([record('fresh-snapshot')])
    await newer
    assert.deepEqual(state.commands.value.map(entry => entry.id), [
      'fresh-buffer-after-finally', 'fresh-buffer-before-finally', 'fresh-snapshot',
    ])
    assert.equal(state.hasLoaded.value, true)
    assert.equal(state.journalRefreshFailed.value, false)
    assert.equal(state.busy.value, '')
  })
}

for (const action of ['clearSession', 'token change', 'scope.stop', 'disconnect', 'replacement connect']) {
  test(`realtime factory synchronous ${action} invalidates the returned connection`, t => {
    const connections = []
    let state, scope
    const deliver = (callbacks, id) => {
      callbacks.onEntry(record(id))
      callbacks.onStatus('error')
      callbacks.onReset()
    }
    const injectedFactory = callbacks => {
      const created = {
        callbacks, connects: [], disconnects: 0,
        connect(value) { this.connects.push(value) },
        disconnect() {
          this.disconnects++
          const before = sessionSnapshot(state)
          deliver(callbacks, 'stale-cleanup-entry')
          assert.deepEqual(sessionSnapshot(state), before)
        },
      }
      connections.push(created)
      if (connections.length === 1) {
        if (action === 'clearSession') state.clearSession()
        else if (action === 'token change') state.token.value = 'changed-token'
        else if (action === 'scope.stop') scope.stop()
        else if (action === 'disconnect') state.realtime.disconnect()
        else {
          state.realtime.connect('winning-token')
          connections[1].callbacks.onEntry(record('winning-entry'))
          connections[1].callbacks.onStatus('connected')
        }
        const afterReentry = sessionSnapshot(state)
        deliver(callbacks, 'stale-factory-entry')
        assert.deepEqual(sessionSnapshot(state), afterReentry)
      }
      return created
    }
    const fixtureState = fixture(t, undefined, {}, {}, injectedFactory)
    state = fixtureState.state
    scope = fixtureState.scope
    prepare(state, 'revoke')
    const retained = sessionSnapshot(state, journalRefs)
    state.realtime.connect('superseded-token')
    const stale = connections[0]
    assert.deepEqual(stale.connects, [])
    assert.equal(stale.disconnects, 1)
    if (action === 'clearSession' || action === 'scope.stop') assertEmpty(state)
    else if (action === 'token change') assertEmpty(state, 'changed-token')
    else if (action === 'disconnect') {
      assert.deepEqual(state.commands.value, [])
      assert.equal(state.hasLoaded.value, false)
      assert.equal(state.journalRefreshFailed.value, false)
      assert.equal(state.lastJournalRefreshAt.value, null)
      assert.equal(state.realtimeStatus.value, 'disconnected')
      assert.deepEqual(sessionSnapshot(state, journalRefs), retained)
    }
    const afterReturn = sessionSnapshot(state)
    deliver(stale.callbacks, 'stale-after-return')
    assert.deepEqual(sessionSnapshot(state), afterReturn)
    if (action !== 'scope.stop') {
      if (action !== 'replacement connect') {
        state.realtime.connect('winning-token')
        connections[1].callbacks.onEntry(record('winning-entry'))
        connections[1].callbacks.onStatus('connected')
      }
      const winner = connections[1]
      assert.deepEqual(winner.connects, ['winning-token'])
      assert.equal(winner.disconnects, 0)
      assert.deepEqual(state.commands.value, [record('winning-entry')])
      assert.equal(state.realtimeStatus.value, 'connected')
      const winning = sessionSnapshot(state)
      deliver(stale.callbacks, 'stale-after-replacement')
      assert.deepEqual(sessionSnapshot(state), winning)
      scope.stop()
      assert.equal(winner.disconnects, 1)
      deliver(winner.callbacks, 'disposed-winning-entry')
    }
    scope.stop()
    deliver(stale.callbacks, 'disposed-stale-entry')
    state.realtime.connect('disposed-token')
    assert.equal(connections.length, action === 'scope.stop' ? 1 : 2)
    assert.equal(stale.disconnects, 1)
    assertEmpty(state)
    assert.equal(fixtureState.calls.length, 0)
    assert.equal(fixtureState.sockets.length, 0)
  })
}

for (const transport of ['factory', 'socket']) {
  for (const action of ['disconnect', 'disconnect and reconnect', 'connect and reconnect']) {
    test(`${transport}: ${action} clears old state before external disconnect callbacks`, t => {
      const connections = []
      const callbacks = []
      const injectedFactory = handlers => {
        callbacks.push(handlers)
        const connection = {
          connects: [], disconnects: 0,
          connect(value) { this.connects.push(value) },
          disconnect() { this.disconnects++ },
        }
        connections.push(connection)
        return connection
      }
      const { state, scope, sockets, realtimeCallbacks, calls } = fixture(
        t, undefined, {}, {}, transport === 'factory' ? injectedFactory : null,
      )
      const handlers = transport === 'factory' ? callbacks : realtimeCallbacks
      const transports = transport === 'factory' ? connections : sockets
      state.realtime.connect(state.token.value)
      handlers[0].onStatus('connected')
      prepare(state, 'revoke')
      const retained = sessionSnapshot(state, journalRefs)
      const stale = handlers[0]
      const oldEntry = transport === 'socket' ? sockets[0].handlers['command:committed'] : () => {}
      const deliverStale = () => {
        stale.onEntry(record('stale-disconnect-entry'))
        stale.onStatus('error')
        stale.onReset()
        oldEntry(record('stale-socket-entry'))
      }
      const old = transports[0]
      const originalDisconnect = old.disconnect.bind(old)
      let callbackCount = 0
      old.disconnect = () => {
        originalDisconnect()
        callbackCount++
        assert.deepEqual(state.commands.value, [])
        assert.equal(state.hasLoaded.value, false)
        assert.equal(state.journalRefreshFailed.value, false)
        assert.equal(state.lastJournalRefreshAt.value, null)
        assert.equal(state.realtimeStatus.value, 'disconnected')
        assert.deepEqual(sessionSnapshot(state, journalRefs), retained)
        deliverStale()
        assert.deepEqual(state.commands.value, [])
        assert.equal(state.realtimeStatus.value, 'disconnected')
        if (action.endsWith('reconnect')) {
          state.realtime.connect('replacement-token')
          handlers[1].onEntry(record('replacement-entry'))
          handlers[1].onStatus('connected')
        }
      }
      if (action.startsWith('connect')) state.realtime.connect('superseded-token')
      else state.realtime.disconnect()
      assert.equal(callbackCount, 1)
      assert.equal(old.disconnects, 1)
      assert.equal(transports.length, action.endsWith('reconnect') ? 2 : 1)
      if (action.endsWith('reconnect')) {
        assert.deepEqual(state.commands.value, [record('replacement-entry')])
        assert.equal(state.realtimeStatus.value, 'connected')
        assert.equal(transports[1].disconnects, 0)
        if (transport === 'factory') assert.deepEqual(connections[1].connects, ['replacement-token'])
        else assert.deepEqual(sockets[1].auth, { token: 'replacement-token' })
      }
      const afterDisconnect = sessionSnapshot(state)
      deliverStale()
      assert.deepEqual(sessionSnapshot(state), afterDisconnect)
      assert.equal(calls.length, 0)
      scope.stop()
      assertEmpty(state)
      if (action.endsWith('reconnect')) {
        assert.equal(transports[1].disconnects, 1)
        if (transport === 'socket') assertDisconnected(sockets[1])
        handlers[1].onEntry(record('disposed-replacement-entry'))
        handlers[1].onStatus('connected')
        handlers[1].onReset()
      }
      deliverStale()
      assertEmpty(state)
    })
  }
}

test('journal clear invalidates direct realtime callbacks before and after an explicit reconnect', t => {
  const { state, calls, sockets, realtimeCallbacks } = fixture(t)
  state.realtime.connect(state.token.value)
  sockets[0].handlers.connect()
  prepare(state, 'list')
  const stale = realtimeCallbacks[0]
  const oldEntry = sockets[0].handlers['command:committed']
  state.clearJournal()
  const cleared = sessionSnapshot(state)
  function deliverStale() {
    stale.onEntry(record('stale-private-record'))
    stale.onStatus('connected')
    stale.onStatus('error')
    stale.onReset()
    oldEntry(record('stale-socket-record'))
  }
  deliverStale()
  assert.deepEqual(sessionSnapshot(state), cleared)
  assertDisconnected(sockets[0])
  assert.equal(calls.length, 0)
  assert.equal(sockets.length, 1)
  state.realtime.connect(state.token.value)
  sockets[1].handlers.connect()
  sockets[1].handlers['command:committed'](record('fresh-live-record'))
  const fresh = sessionSnapshot(state)
  deliverStale()
  assert.deepEqual(sessionSnapshot(state), fresh)
  assert.deepEqual(sockets[1].auth, { token: state.token.value })
  assert.equal(sockets[1].disconnects, 0)
})

for (const busy of ['', 'list', 'status']) {
  test(`journal clear is inert after disposal even with manually repopulated refs, busy=${busy || 'idle'}`, async t => {
    const { state, calls, scope } = fixture(t)
    prepare(state, 'list')
    const old = state.perform('list')
    scope.stop()
    prepare(state, 'revoke')
    state.busy.value = busy
    const before = sessionSnapshot(state)
    state.clearJournal()
    assert.deepEqual(sessionSnapshot(state), before)
    calls[0].resolve([record('late-after-disposal')])
    await old
    assert.deepEqual(sessionSnapshot(state), before)
    assert.equal(calls.length, 1)
  })
}

test('manual refresh after local clear retains normal snapshot replacement, receipt and no automatic reconnect', async t => {
  const { state, calls, sockets, clock } = fixture(t)
  prepare(state, 'list')
  state.realtime.connect(state.token.value)
  let operation = state.perform('list')
  calls[0].resolve([record('original')])
  await operation
  assert.equal(state.hasLoaded.value, true)
  state.clearJournal()
  assertJournalCleared(state)
  assert.equal(calls.length, 1)
  assert.equal(sockets.length, 1)
  clock.time = 1080
  operation = state.perform('list')
  assert.equal(state.busy.value, 'list')
  calls[1].resolve([record('fresh')])
  await operation
  assert.deepEqual(state.commands.value, [record('fresh')])
  assert.deepEqual(state.filteredCommands.value, [record('fresh')])
  assert.equal(state.hasLoaded.value, true)
  assert.equal(state.journalRefreshFailed.value, false)
  assert.equal(state.lastJournalRefreshAt.value, 1080)
  assert.equal(state.message.value, 'Logboek bijgewerkt.')
  assert.equal(state.realtimeStatus.value, 'disconnected')
  assert.equal(sockets.length, 1)
  operation = state.perform('list')
  assert.deepEqual(state.commands.value, [record('fresh')])
  calls[2].reject(new Error('manual refresh failed'))
  await operation
  assert.deepEqual(state.commands.value, [record('fresh')])
  assert.equal(state.lastJournalRefreshAt.value, 1080)
  assert.equal(state.journalRefreshFailed.value, true)
})

test('journal UI exposes a local-only clear beside refresh, retains separate outcome and requires explicit reload/reconnect', () => {
  const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
  assert.match(app, /clearJournal,\s*\} = useSession\(\)/)
  const button = app.match(/<button[^>]*@click="clearJournal"[^>]*>Wis lokaal logboek<\/button>/)?.[0]
  assert.ok(button)
  assert.match(button, /type="button"/)
  assert.match(button, /:disabled="!!busy && busy !== 'list'"/)
  assert.match(button, /aria-describedby="clear-journal-help"/)
  assert.match(app, /Logboek vernieuwen<\/button>\s*<button[^>]*@click="clearJournal"/)
  assert.match(app, /id="clear-journal-help"[^>]*>Wist alleen lokaal de geladen records en zoekopdracht, verbreekt realtime en breekt een lopende verversing lokaal af\./)
  assert.match(app, /Geen verwijdering uit de database of intrekking van tickets\./)
  assert.match(app, /De aparte ticketuitkomst blijft behouden en kan een historisch logboekrecord bevatten\./)
  assert.match(app, /Kies expliciet Logboek vernieuwen of Realtime verbinden/)
  assert.match(app, /geen automatische verzoeken of herverbinding\./)
})
