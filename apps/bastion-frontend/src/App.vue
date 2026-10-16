<script setup>
import { computed, onUnmounted, ref, watch } from 'vue'
import { commandLength, commitCommand, issueTicket, listCommands, MAX_COMMAND_LENGTH, mergeCommands, revokeTicket, ticketUsable, timestamp } from './api.js'
import { createRealtime } from './realtime.js'

const token = ref('')
const command = ref('')
const ttlMs = ref(10000)
const ticket = ref(null)
const revocationUncertain = ref(false)
const commands = ref([])
const hasLoaded = ref(false)
const busy = ref('')
const message = ref('')
const error = ref('')
const realtimeStatus = ref('disconnected')
const realtime = createRealtime({
  onEntry: (entry) => { commands.value = mergeCommands(commands.value, entry) },
  onStatus: (status) => { realtimeStatus.value = status },
  onReset: () => { commands.value = []; hasLoaded.value = false },
})
const realtimeLabels = {
  disconnected: 'Niet verbonden. Ontvangst van nieuwe records staat uit.',
  connecting: 'Verbinding maken…',
  connected: 'Verbonden. Nieuwe logboekrecords verschijnen automatisch.',
  error: 'Verbinding mislukt. Controleer token en lokale service; verbind handmatig opnieuw.',
}
const now = ref(Date.now())
const clock = setInterval(() => { now.value = Date.now() }, 100)
onUnmounted(() => { clearInterval(clock); realtime.disconnect() })
const canCommit = computed(() => !revocationUncertain.value && ticketUsable(ticket.value, command.value, now.value))
const remaining = computed(() => ticket.value ? Math.max(0, Math.ceil((timestamp(ticket.value.expires_at) - now.value) / 1000)) : 0)

watch([command, ttlMs], () => {
  if (!revocationUncertain.value) ticket.value = null
}, { flush: 'sync' })
watch(token, () => {
  realtime.disconnect()
  ticket.value = null
  revocationUncertain.value = false
  commands.value = []
  hasLoaded.value = false
  command.value = ''
  message.value = ''
  error.value = ''
}, { flush: 'sync' })

async function perform(action) {
  if (busy.value) return
  busy.value = action
  error.value = ''
  message.value = ''
  try {
    if (action === 'ticket') {
      if (revocationUncertain.value) return
      ticket.value = null
      ticket.value = await issueTicket(command.value, Number(ttlMs.value), token.value)
      now.value = Date.now()
      message.value = 'Ticket ontvangen. Bevestig het commando in een aparte stap.'
    } else if (action === 'revoke') {
      // Bij een onzekere uitkomst blijft alleen opnieuw intrekken toegestaan.
      revocationUncertain.value = true
      await revokeTicket(ticket.value, token.value)
      ticket.value = null
      revocationUncertain.value = false
      message.value = "Ticket door de server ingetrokken. Eerder vastgelegde commando's blijven behouden."
    } else if (action === 'commit') {
      if (!canCommit.value) return
      const currentTicket = ticket.value
      // Een onzekere netwerkuitkomst mag nooit een automatische tweede inzending veroorzaken.
      ticket.value = null
      revocationUncertain.value = false
      const committed = await commitCommand(currentTicket, command.value, token.value)
      commands.value = mergeCommands(commands.value, committed)
      message.value = 'Commando vastgelegd in het logboek; er is niets uitgevoerd.'
    } else {
      commands.value = []
      hasLoaded.value = false
      const loaded = await listCommands(token.value)
      // Behoud ook events die tijdens het ophalen zijn ontvangen.
      commands.value = [...commands.value].reverse().reduce(mergeCommands, loaded)
      hasLoaded.value = true
      message.value = 'Logboek bijgewerkt.'
    }
  } catch (failure) {
    error.value = failure.message
  } finally {
    busy.value = ''
  }
}

function clearSession() {
  realtime.disconnect()
  token.value = ''
  command.value = ''
  ticket.value = null
  commands.value = []
  hasLoaded.value = false
  message.value = ''
  error.value = ''
}

function date(value) {
  return new Date(timestamp(value)).toLocaleString('nl-NL')
}
</script>

<template>
  <main>
    <header><p class="eyebrow">PALACO / LOKALE ALPHA</p><h1>BASTION</h1><p>Eerst een ticket. Dan een bewuste bevestiging.</p></header>
    <aside class="notice">Commando's zijn uitsluitend logboekrecords: geen shell, geen uitvoering.
      Tickets zijn tijdelijk en gebonden aan de exacte tekst. De server beslist over geldigheid.
      Lokaal HTTP is niet versleuteld; gebruik geen productiegegevens.</aside>
    <section aria-labelledby="access-title">
      <h2 id="access-title">Toegang</h2>
      <label for="token">Toegangstoken</label>
      <input id="token" v-model="token" type="password" autocomplete="off" spellcheck="false" :disabled="!!busy" aria-describedby="token-help" />
      <p id="token-help" class="muted">Alleen in componentgeheugen; niet in opslag of een URL. Vernieuwen wist de sessie.</p>
      <button class="secondary" :disabled="!!busy" @click="clearSession">Wis sessie</button>
    </section>
    <div role="status" aria-live="polite"><p v-if="busy" class="notice">Even wachten…</p><p v-if="message" class="notice">{{ message }}</p></div>
    <p v-if="error" role="alert" class="error">{{ error }} Bij een onzekere inzending: vernieuw eerst het logboek voordat je opnieuw indient.</p>
    <div class="grid">
      <section aria-labelledby="ticket-title" :aria-busy="!!busy">
        <h2 id="ticket-title">1. Ticket aanvragen</h2>
        <form @submit.prevent="perform('ticket')">
          <label for="command">Commando als tekst</label>
          <textarea id="command" v-model="command" rows="4" :maxlength="MAX_COMMAND_LENGTH" required :disabled="!!busy" aria-describedby="command-limit" />
          <p id="command-limit" class="muted">{{ commandLength(command) }} / {{ MAX_COMMAND_LENGTH }} UTF-16-tekeneenheden (een emoji telt meestal als twee).</p>
          <label for="ttl">Geldigheidsduur (milliseconden)</label>
          <input id="ttl" v-model="ttlMs" type="number" min="1" max="60000" step="1" required :disabled="!!busy" />
          <button :disabled="!!busy || revocationUncertain || !token.trim() || !command.trim() || commandLength(command) > MAX_COMMAND_LENGTH">Ticket aanvragen</button>
        </form>
        <h2>2. Apart bevestigen</h2>
        <div v-if="ticket" class="result">
          <p>Ticket: <code>{{ ticket.id }}</code></p>
          <p>Geldig vanaf: {{ date(ticket.not_before) }}</p>
          <p>Verloopt: {{ date(ticket.expires_at) }}</p>
          <p>{{ remaining ? `Nog circa ${remaining} seconden.` : 'Verlopen. Vraag een nieuw ticket aan.' }}</p>
          <p v-if="remaining && !canCommit && !revocationUncertain">Niet geldig voor de huidige invoer of begintijd.</p>
        </div>
        <p v-else class="muted">Nog geen ticket. Tekst of duur wijzigen maakt het lokale ticket ongeldig.</p>
        <button :disabled="!!busy || !canCommit || !token.trim()" @click="perform('commit')">Commando vastleggen</button>
        <button class="secondary" :disabled="!!busy || !ticket || !token.trim()" @click="perform('revoke')">Ticket intrekken</button>
        <p v-if="revocationUncertain" role="alert" class="error">Intrekking nog niet bevestigd. Vastleggen en nieuwe tickets zijn geblokkeerd. Probeer dit ticket opnieuw in te trekken.</p>
        <p class="muted">Intrekken wijzigt het ticket op de server. Een sessie wissen of invoer wijzigen trekt geen toestemming in.</p>
        <p class="muted">Na iedere inzendpoging vervalt het lokale ticket. Geen automatische herhaling.</p>
      </section>
      <section aria-labelledby="journal-title" :aria-busy="busy === 'list'">
        <h2 id="journal-title">Commandologboek</h2>
        <p class="muted">Maximaal 100 records. Realtime is optioneel en gebruikt het ingevoerde token; geen automatische herverbinding.</p>
        <p role="status">{{ realtimeLabels[realtimeStatus] }}</p>
        <div class="actions">
          <button :disabled="!!busy || !token.trim() || realtimeStatus === 'connecting' || realtimeStatus === 'connected'" @click="realtime.connect(token)">Realtime verbinden</button>
          <button class="secondary" :disabled="!!busy || (realtimeStatus !== 'connecting' && realtimeStatus !== 'connected')" @click="realtime.disconnect()">Verbinding verbreken</button>
        </div>
        <button :disabled="!!busy || !token.trim()" @click="perform('list')">Logboek vernieuwen</button>
        <p v-if="!commands.length" class="muted">{{ hasLoaded ? 'Het logboek is leeg.' : 'Nog geen records geladen.' }}</p>
        <ol class="journal">
          <li v-for="entry in commands" :key="entry.id"><pre>{{ entry.command }}</pre><small>{{ date(entry.committed_at) }} · {{ entry.id }}</small></li>
        </ol>
      </section>
    </div>
    <footer>API: 127.0.0.1:8788 · Start met <code>npm run dev</code> op 127.0.0.1:5175.
      De ontwikkelproxy (inclusief Socket.IO) is niet opgenomen in de statische build.</footer>
  </main>
</template>
