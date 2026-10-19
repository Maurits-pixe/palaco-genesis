<script setup>
import { commandLength, MAX_COMMAND_LENGTH, timestamp } from './api.js'
import { realtimeLabels, useSession } from './useSession.js'

const {
  token, command, ttlMs, ticket, revocationUncertain, commands, search, filteredCommands, hasLoaded, busy,
  message, error, lookupId, outcome, lastSubmissionId, realtimeStatus,
  canCommit, remaining, realtime, perform, clearSession,
} = useSession()

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
      <button class="secondary" @click="clearSession">Wis sessie</button>
      <p class="muted">Wissen en afbreken zijn alleen lokaal: geen intrekking van servertickets of terugdraaien.
        Een al verzonden wijziging kan nog worden voltooid. Wissen verwijdert ook lokale ID's:
        kopieer het ticket-ID vóór het wissen om later handmatig de status op te zoeken. Dien nooit automatisch opnieuw in.</p>
    </section>
    <div role="status" aria-live="polite"><p v-if="busy" class="notice">Even wachten…</p><p v-if="message" class="notice">{{ message }}</p></div>
    <p v-if="error" role="alert" class="error">{{ error }} Bij een onzekere inzending: controleer handmatig het ticket-ID. Dien niet automatisch opnieuw in.</p>
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
        <p v-if="revocationUncertain" role="alert" class="error">Intrekking nog niet bevestigd. Vastleggen en nieuwe tickets zijn geblokkeerd. Trek dit ticket opnieuw in of controleer de status van hetzelfde ticket.</p>
        <p class="muted">Intrekken wijzigt het ticket op de server. Een sessie wissen of invoer wijzigen trekt geen toestemming in.</p>
        <p class="muted">Na iedere inzendpoging vervalt het lokale ticket. Geen automatische herhaling.</p>
      </section>
      <section aria-labelledby="status-title" :aria-busy="busy === 'status'">
        <h2 id="status-title">Ticketuitkomst controleren</h2>
        <div v-if="lastSubmissionId">
          <label for="last-submission">Laatste ingezonden ticket-ID (selecteer en kopieer)</label>
          <input id="last-submission" :value="lastSubmissionId" readonly @focus="$event.target.select()" />
        </div>
        <form @submit.prevent="perform('status')">
          <label for="lookup-id">Ticket-ID</label>
          <input id="lookup-id" v-model="lookupId" maxlength="128" required :disabled="!!busy" autocomplete="off" spellcheck="false" />
          <button :disabled="!!busy || !token.trim() || !lookupId">Status controleren</button>
        </form>
        <div v-if="outcome" class="result">
          <p>Ticket: <code>{{ outcome.id }}</code></p>
          <p>Status: {{ outcome.status }} · ingetrokken: {{ outcome.revoked ? 'ja' : 'nee' }}</p>
          <p>Gecontroleerd: {{ date(outcome.checked_at) }}</p>
          <p>Geldig vanaf: {{ date(outcome.not_before) }} · verloopt: {{ date(outcome.expires_at) }}</p>
          <pre>{{ outcome.command }}</pre>
          <p v-if="outcome.record">Vastgelegd: {{ date(outcome.record.committed_at) }} · {{ outcome.record.id }}</p>
        </div>
        <p class="muted">Alleen een momentopname. Active of pending herstelt geen lokaal ticket. Geen uitvoering, nieuwe toestemming of automatische herinzending.</p>
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
        <label for="journal-search">Zoek in geladen logboek</label>
        <input id="journal-search" v-model="search" type="search" autocomplete="off" spellcheck="false" maxlength="1024" aria-describedby="journal-search-help" />
        <p id="journal-search-help" class="muted">Zoekt letterlijk, zonder hoofdletterverschil, in commandotekst of record-ID van maximaal 100 lokaal geladen records.
          Niet in de hele database of ticket-ID's. De zoekopdracht blijft alleen in sessiegeheugen.</p>
        <button type="button" class="secondary" :disabled="!search" @click="search = ''">Wis zoekopdracht</button>
        <p role="status" aria-live="polite">{{ filteredCommands.length }} van {{ commands.length }} geladen records</p>
        <p v-if="!commands.length" class="muted">{{ hasLoaded ? 'Het logboek is leeg.' : 'Nog geen records geladen.' }}</p>
        <p v-else-if="!filteredCommands.length" class="muted">Geen geladen records gevonden voor deze zoekopdracht.</p>
        <ol class="journal">
          <li v-for="entry in filteredCommands" :key="entry.id"><pre>{{ entry.command }}</pre><small>{{ date(entry.committed_at) }} · {{ entry.id }}</small></li>
        </ol>
      </section>
    </div>
    <footer>API: 127.0.0.1:8788 · Start met <code>npm run dev</code> op 127.0.0.1:5175.
      De ontwikkelproxy (inclusief Socket.IO) is niet opgenomen in de statische build.</footer>
  </main>
</template>
