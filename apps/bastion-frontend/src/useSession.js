import { computed, onScopeDispose, ref, watch } from 'vue'
import * as defaultApi from './api.js'
import { createRealtime } from './realtime.js'

export const realtimeLabels = {
  disconnected: 'Niet verbonden. Ontvangst van nieuwe records staat uit.',
  connecting: 'Verbinding maken…',
  connected: 'Verbonden. Nieuwe logboekrecords verschijnen automatisch.',
  error: 'Verbinding mislukt. Controleer token en lokale service; verbind handmatig opnieuw.',
}

export function useSession({
  api = defaultApi,
  realtimeFactory = createRealtime,
  scheduler = { now: () => Date.now(), setInterval, clearInterval },
} = {}) {
  const token = ref('')
  const command = ref('')
  const ttlMs = ref(10000)
  const ticket = ref(null)
  const revocationUncertain = ref(false)
  const commands = ref([])
  const search = ref('')
  const filteredCommands = computed(() => {
    const query = search.value.trim().toLowerCase()
    return commands.value.filter(entry =>
      entry.command.toLowerCase().includes(query) || entry.id.toLowerCase().includes(query))
  })
  const hasLoaded = ref(false)
  const journalRefreshFailed = ref(false)
  const lastJournalRefreshAt = ref(null)
  const busy = ref('')
  const message = ref('')
  const error = ref('')
  const lookupId = ref('')
  const outcome = ref(null)
  const lastSubmissionId = ref('')
  const realtimeStatus = ref('disconnected')
  const now = ref(scheduler.now())
  let session = 0
  let disposed = false
  let pending = null
  let connection = null
  let connectionGeneration = 0
  let journalGeneration = 0
  let journalRequest = null

  function resetJournal() {
    journalGeneration++
    if (journalRequest) journalRequest.entries = []
    commands.value = []
    hasLoaded.value = false
    journalRefreshFailed.value = false
    lastJournalRefreshAt.value = null
  }

  function disconnect() {
    connectionGeneration++
    const previous = connection
    connection = null
    previous?.disconnect()
    resetJournal()
    realtimeStatus.value = 'disconnected'
  }

  const realtime = {
    disconnect,
    connect(value) {
      if (disposed) return
      disconnect()
      const generation = connectionGeneration
      const current = () => !disposed && generation === connectionGeneration
      connection = realtimeFactory({
        onEntry: entry => {
          if (!current()) return
          const normalized = defaultApi.normalizeCommand(entry)
          if (!normalized) return
          commands.value = defaultApi.mergeCommands(commands.value, normalized)
          if (journalRequest?.generation === journalGeneration) {
            journalRequest.entries = defaultApi.mergeCommands(journalRequest.entries, normalized)
          }
        },
        onStatus: status => { if (current()) realtimeStatus.value = status },
        onReset: () => {
          if (current()) resetJournal()
        },
      })
      connection.connect(value)
    },
  }
  const clock = scheduler.setInterval(() => {
    if (!disposed) now.value = scheduler.now()
  }, 100)
  const canCommit = computed(() => !revocationUncertain.value &&
    defaultApi.ticketUsable(ticket.value, command.value, now.value))
  const remaining = computed(() => ticket.value
    ? Math.max(0, Math.ceil((defaultApi.timestamp(ticket.value.expires_at) - now.value) / 1000)) : 0)

  watch([command, ttlMs], () => {
    if (!revocationUncertain.value) ticket.value = null
  }, { flush: 'sync' })

  function resetSession() {
    session++
    const previous = pending
    pending = null
    previous?.abort()
    busy.value = ''
    disconnect()
    ticket.value = null
    revocationUncertain.value = false
    commands.value = []
    hasLoaded.value = false
    command.value = ''
    search.value = ''
    ttlMs.value = 10000
    message.value = ''
    error.value = ''
    lookupId.value = ''
    outcome.value = null
    lastSubmissionId.value = ''
  }
  watch(token, resetSession, { flush: 'sync' })

  function clearSession() {
    if (token.value) token.value = ''
    else resetSession()
  }

  onScopeDispose(() => {
    disposed = true
    resetSession()
    token.value = ''
    scheduler.clearInterval(clock)
  })

  function checkCurrentTicket() {
    if (disposed || busy.value || !ticket.value || !token.value.trim()) return
    lookupId.value = ticket.value.id
    return perform('status')
  }

  function checkLastSubmission() {
    if (disposed || busy.value || !lastSubmissionId.value || !token.value.trim()) return
    lookupId.value = lastSubmissionId.value
    return perform('status')
  }

  async function perform(action) {
    if (disposed || busy.value) return
    const started = session
    const controller = new AbortController()
    pending = controller
    const current = () => !disposed && started === session && pending === controller
    const refresh = action === 'list' ? { generation: journalGeneration, entries: [] } : null
    if (refresh) {
      journalRequest = refresh
      journalRefreshFailed.value = false
    }
    busy.value = action
    error.value = ''
    message.value = ''
    try {
      if (action === 'ticket') {
        if (revocationUncertain.value) return
        ticket.value = null
        const issued = await api.issueTicket(command.value, Number(ttlMs.value), token.value, undefined, controller.signal)
        if (!current()) return
        ticket.value = issued
        now.value = scheduler.now()
        message.value = 'Ticket ontvangen. Bevestig het commando in een aparte stap.'
      } else if (action === 'revoke') {
        // Een onzekere intrekking blokkeert nieuwe toestemming tot bevestiging.
        revocationUncertain.value = true
        await api.revokeTicket(ticket.value, token.value, undefined, controller.signal)
        if (!current()) return
        ticket.value = null
        revocationUncertain.value = false
        message.value = "Ticket door de server ingetrokken. Eerder vastgelegde commando's blijven behouden."
      } else if (action === 'commit') {
        if (!canCommit.value) return
        const currentTicket = ticket.value
        // Een onzekere netwerkuitkomst mag nooit een automatische tweede inzending veroorzaken.
        const submission = defaultApi.beginSubmission(currentTicket)
        ticket.value = submission.ticket
        lastSubmissionId.value = submission.lastSubmissionId
        lookupId.value = submission.lastSubmissionId
        outcome.value = null
        revocationUncertain.value = false
        const committed = await api.commitCommand(currentTicket, command.value, token.value, undefined, controller.signal)
        if (!current()) return
        commands.value = defaultApi.mergeCommands(commands.value, committed)
        message.value = 'Commando vastgelegd in het logboek; er is niets uitgevoerd.'
      } else if (action === 'status') {
        outcome.value = null
        const checked = await api.getTicketStatus(lookupId.value, token.value, undefined, controller.signal)
        if (!current()) return
        outcome.value = checked
        const reconciled = defaultApi.reconcileTicketStatus(ticket.value, revocationUncertain.value, commands.value, checked)
        ticket.value = reconciled.ticket
        revocationUncertain.value = reconciled.revocationUncertain
        message.value = 'Ticketstatus opgehaald. Dit is een momentopname, geen nieuwe toestemming.'
      } else {
        const loaded = await api.listCommands(token.value, undefined, controller.signal)
        if (!current() || refresh.generation !== journalGeneration) return
        // Alleen events uit deze verversing aanvullen, nooit de oude snapshot.
        commands.value = [...refresh.entries].reverse().reduce(defaultApi.mergeCommands, loaded)
        const receivedAt = scheduler.now()
        lastJournalRefreshAt.value = Number.isSafeInteger(receivedAt) && receivedAt >= 0 &&
          Number.isFinite(new Date(receivedAt).getTime()) ? receivedAt : null
        hasLoaded.value = true
        journalRefreshFailed.value = false
        message.value = 'Logboek bijgewerkt.'
      }
    } catch (failure) {
      if (current() && (!refresh || refresh.generation === journalGeneration)) {
        error.value = failure.message
        if (refresh) journalRefreshFailed.value = true
      }
    } finally {
      if (refresh && journalRequest === refresh) journalRequest = null
      if (current()) {
        pending = null
        busy.value = ''
      }
    }
  }

  return {
    token, command, ttlMs, ticket, revocationUncertain, commands, search, filteredCommands, hasLoaded, journalRefreshFailed, lastJournalRefreshAt, busy,
    message, error, lookupId, outcome, lastSubmissionId, realtimeStatus, now,
    canCommit, remaining, realtime, perform, checkLastSubmission, checkCurrentTicket, clearSession,
  }
}
