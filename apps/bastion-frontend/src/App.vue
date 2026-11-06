<script setup>
import { commandLength, MAX_COMMAND_LENGTH, timestamp } from './api.js'
import { realtimeLabels, useSession } from './useSession.js'

const busyLabels = {
  __proto__: null,
  ticket: 'Ticket aanvragen…',
  commit: 'Commando indienen…',
  revoke: 'Ticket intrekken…',
  status: 'Ticketstatus controleren…',
  list: 'Logboek vernieuwen…',
}

const {
  token, command, ttlMs, ticket, revocationUncertain, commands, search, filteredCommands, hasLoaded, journalRefreshFailed, lastJournalRefreshAt, busy,
  message, error, lookupId, outcome, outcomeReceivedAt, outcomeMismatch, lastSubmissionId, realtimeStatus,
  validToken, validLookupId, canCheckStatus, validTtl, canRequestTicket, canCommit, canClearOutcome, remaining, realtime, perform, checkLastSubmission, checkCurrentTicket, clearCommand, clearSession, clearOutcome, clearJournal,
} = useSession()

function date(value) {
  return new Date(timestamp(value)).toLocaleString('nl-NL')
}

function receiptIso(value) {
  return value !== null ? new Date(timestamp(value)).toISOString() : undefined
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
      <input id="token" v-model="token" type="password" autocomplete="off" spellcheck="false" :disabled="!!busy" :aria-invalid="token !== '' && !validToken" :aria-describedby="token !== '' && !validToken ? 'token-help token-error' : 'token-help'" />
      <p v-if="token !== '' && !validToken" id="token-error" class="error">Ongeldig tokenformaat: gebruik niet alleen witruimte en geen CR- of LF-regeleinden.</p>
      <p id="token-help" class="muted">Formaat: niet alleen witruimte en geen CR- of LF-regeleinden. De invoer blijft ongewijzigd; alleen de server beslist over toegang.
        Alleen in componentgeheugen; niet in opslag of een URL.
        Bij pagehide (ook bij terug/vooruit-cache) wissen we de lokale sessie. Voer na terugkeer het token opnieuw in
        en kies zelf een actie; geen automatische verzoeken of herverbinding.
        De browser levert pagehide niet gegarandeerd; dit garandeert geen veilige geheugenwissing.</p>
      <button class="secondary" @click="clearSession">Wis sessie</button>
      <p class="muted">Wissen en afbreken zijn alleen lokaal: geen intrekking van servertickets of terugdraaien.
        Een al verzonden wijziging kan nog worden voltooid. Wissen verwijdert ook lokale ID's:
        kopieer het ticket-ID vóór het wissen om later handmatig de status op te zoeken. Dien nooit automatisch opnieuw in.</p>
    </section>
    <div role="status" aria-live="polite"><p v-if="busy" class="notice">{{ busyLabels[busy] ?? 'Verzoek verwerken…' }}</p><p v-if="message" class="notice">{{ message }}</p></div>
    <p v-if="error" role="alert" class="error">{{ error }} Bij een onzekere inzending: controleer handmatig het ticket-ID. Dien niet automatisch opnieuw in.</p>
    <div class="grid">
      <section aria-labelledby="ticket-title" :aria-busy="!!busy">
        <h2 id="ticket-title">1. Ticket aanvragen</h2>
        <form @submit.prevent="perform('ticket')">
          <label for="command">Commando als tekst</label>
          <textarea id="command" v-model="command" rows="4" :maxlength="MAX_COMMAND_LENGTH" required :disabled="!!busy" :aria-invalid="command !== '' && (!command.trim() || commandLength(command) > MAX_COMMAND_LENGTH)" :aria-describedby="command !== '' && (!command.trim() || commandLength(command) > MAX_COMMAND_LENGTH) ? 'command-limit command-error' : 'command-limit'" />
          <p id="command-limit" class="muted">{{ commandLength(command) }} / {{ MAX_COMMAND_LENGTH }} UTF-16-tekeneenheden (een emoji telt meestal als twee).</p>
          <p v-if="command !== '' && (!command.trim() || commandLength(command) > MAX_COMMAND_LENGTH)" id="command-error" class="error">{{ commandLength(command) > MAX_COMMAND_LENGTH ? `Commando te lang: maximaal ${MAX_COMMAND_LENGTH} UTF-16-tekeneenheden.` : 'Commando mag niet alleen uit witruimte bestaan.' }}</p>
          <label for="ttl">Geldigheidsduur (milliseconden)</label>
          <input id="ttl" v-model="ttlMs" type="number" min="1" max="60000" step="1" required :disabled="!!busy" aria-describedby="ttl-help" :aria-invalid="!validTtl" />
          <div id="ttl-help">
            <p class="muted">Vul een geheel aantal milliseconden in van 1 tot en met 60000.</p>
            <p v-if="!validTtl" class="error">Ongeldige duur: kies een geheel getal van 1 tot en met 60000.</p>
          </div>
          <button :disabled="!canRequestTicket">Ticket aanvragen</button>
          <button type="button" class="secondary" :disabled="!!busy || !command" aria-describedby="clear-command-help" @click="clearCommand">Wis commandotekst</button>
          <p id="clear-command-help" class="muted">Wist alleen lokaal de concepttekst en maakt een normaal lokaal ticket ongeldig; geen intrekking op de server.
            Een onzekere intrekking behoudt het oorspronkelijke ticket en blijft vastleggen en nieuwe tickets blokkeren.
            Geen verzoeken, verbreking van realtime of veilige geheugenwissing. Logboek en ticketuitkomst kunnen commandotekst behouden.</p>
        </form>
        <h2>2. Apart bevestigen</h2>
        <div v-if="ticket" class="result">
          <label for="current-ticket-id">Huidig ticket-ID (selecteer en kopieer)</label>
          <input id="current-ticket-id" :value="ticket.id" readonly @focus="$event.target.select()" aria-describedby="current-ticket-id-help" />
          <p id="current-ticket-id-help" class="muted">Selecteer en kopieer dit exacte ID handmatig vóór Wis sessie om later de status op te zoeken.
            Kopieën op het klembord staan buiten de lokale sessie en worden niet gewist door Wis sessie.
            Selecteren en kopiëren versturen geen automatische verzoeken en herstellen geen toestemming.</p>
          <p id="ticket-command-label">Commandotekst van dit ticket</p>
          <pre aria-labelledby="ticket-command-label" aria-describedby="ticket-command-help">{{ ticket.command }}</pre>
          <p id="ticket-command-help" class="muted">De exacte tekst waarvoor dit ticket is uitgegeven, niet de huidige concepttekst.
            Bij een onzekere intrekking kan deze tekst ook na Wis commandotekst zichtbaar blijven.
            Alleen tekst: geen uitvoering of nieuwe toestemming.</p>
          <p aria-describedby="ticket-window-help">Geldig vanaf: <time :datetime="receiptIso(ticket.not_before)">{{ date(ticket.not_before) }}</time></p>
          <p aria-describedby="ticket-window-help">Verloopt: <time :datetime="receiptIso(ticket.expires_at)">{{ date(ticket.expires_at) }}</time></p>
          <p id="ticket-window-help" class="muted">Begintijd inbegrepen, vervaltijd uitgesloten. Alleen de server beslist over geldigheid; de lokale aftelling geeft geen garantie.</p>
          <p v-if="remaining === null">Resterende tijd niet beschikbaar. Controleer de lokale klok en ticketgegevens.</p>
          <p v-else-if="remaining > 0">Volgens de lokale klok nog circa {{ remaining }} seconden.</p>
          <p v-else>Volgens de lokale klok is de vervaltijd bereikt.
            <span v-if="revocationUncertain">Controleer de status van hetzelfde ticket of trek dit ticket expliciet opnieuw in. Nieuwe tickets blijven geblokkeerd.</span>
            <span v-else>Je kunt expliciet een nieuw ticket aanvragen; geen automatische aanvraag.</span>
          </p>
          <p class="muted">De aftelling gebruikt de lokale klok; alleen de server beslist over geldigheid.</p>
          <p v-if="remaining > 0 && !canCommit && !revocationUncertain">Niet geldig voor de huidige invoer of begintijd.</p>
        </div>
        <p v-else class="muted">Nog geen ticket. Tekst of duur wijzigen maakt het lokale ticket ongeldig.</p>
        <button :disabled="!!busy || !canCommit || !validToken" aria-describedby="commit-help" @click="perform('commit')">Commando vastleggen</button>
        <p id="commit-help" class="muted">Lokale geschiktheid en een eerdere actieve status garanderen geen actuele servertoestemming: een andere client kan het ticket al hebben ingetrokken of verbruikt.
          De server controleert opnieuw bij vastleggen; een statuscontrole reserveert het ticket niet.
          Geen automatische herhaling.</p>
        <button class="secondary" :disabled="!!busy || !ticket || !validToken" @click="perform('revoke')">Ticket intrekken</button>
        <button class="secondary" :disabled="!!busy || !ticket || !validToken" @click="checkCurrentTicket">Controleer huidig ticket</button>
        <p v-if="revocationUncertain" role="alert" class="error">Intrekking nog niet bevestigd. Vastleggen en nieuwe tickets zijn geblokkeerd. Trek dit ticket opnieuw in of controleer de status van hetzelfde ticket.</p>
        <p class="muted">Intrekken wijzigt het ticket op de server. Een sessie wissen of invoer wijzigen trekt geen toestemming in.</p>
        <p class="muted">Na iedere inzendpoging vervalt het lokale ticket. Geen automatische herhaling.</p>
      </section>
      <section aria-labelledby="status-title" :aria-busy="busy === 'status'">
        <h2 id="status-title">Ticketuitkomst controleren</h2>
        <div v-if="lastSubmissionId">
          <label for="last-submission">Laatste ingezonden ticket-ID (selecteer en kopieer)</label>
          <input id="last-submission" :value="lastSubmissionId" readonly @focus="$event.target.select()" aria-describedby="last-submission-help" />
          <p id="last-submission-help" class="muted">ID van de laatste inzendpoging, geen bevestiging van geslaagde opslag.
            Selecteer en kopieer dit exacte ID handmatig vóór Wis sessie om later de status op te zoeken; kopieën op het klembord worden niet lokaal gewist.
            Selecteren en kopiëren versturen geen verzoeken en herstellen geen toestemming; controleer de status expliciet.</p>
          <button type="button" class="secondary" :disabled="!!busy || !validToken" @click="checkLastSubmission">Controleer laatste inzending</button>
        </div>
        <form @submit.prevent="perform('status')">
          <label for="lookup-id">Ticket-ID</label>
          <input id="lookup-id" v-model="lookupId" maxlength="128" required :disabled="!!busy" autocomplete="off" spellcheck="false" :aria-invalid="lookupId !== '' && !validLookupId" :aria-describedby="lookupId !== '' && !validLookupId ? 'lookup-id-help lookup-id-error' : 'lookup-id-help'" />
          <p id="lookup-id-help" class="muted">Een ander ID wist alleen de lokale status en breekt een lopende statuscontrole lokaal af.
            Geen herstel van toestemming of intrekking op de server; geen automatisch verzoek. Gebruik het exacte ID, zonder omringende spaties.
            Formaat: 1–128 ASCII-letters (a–z, A–Z), cijfers (0–9), underscores (_) of koppeltekens (-).</p>
          <p v-if="lookupId !== '' && !validLookupId" id="lookup-id-error" class="error">Ongeldig ticket-ID: gebruik 1–128 ASCII-letters, cijfers, underscores (_) of koppeltekens (-).</p>
          <button :disabled="!canCheckStatus">Status controleren</button>
        </form>
        <div v-if="outcome" class="result">
          <label for="outcome-ticket-id">Ticketuitkomst-ID (selecteer en kopieer)</label>
          <input id="outcome-ticket-id" :value="outcome.id" readonly @focus="$event.target.select()" aria-describedby="outcome-ticket-id-help" />
          <p id="outcome-ticket-id-help" class="muted">Selecteer en kopieer dit exacte ID handmatig vóór Wis ticketuitkomst of Wis sessie om later de status op te zoeken.
            Wis ticketuitkomst behoudt het opzoekveld. Kopieën op het klembord staan buiten de lokale sessie en worden niet gewist.
            Selecteren en kopiëren versturen geen automatische verzoeken en herstellen geen toestemming.</p>
          <p v-if="outcomeMismatch" role="alert" class="error">Statusgegevens wijken af van het lokaal bewaarde ticket. Deze uitkomst wijzigt het lokale ticket of de onzekerheidsblokkering niet.</p>
          <p>Status: {{ outcome.status }} · ingetrokken: {{ outcome.revoked ? 'ja' : 'nee' }}</p>
          <p v-if="outcome.status === 'pending'" class="muted">De server controleerde dit ticket vóór de begintijd.</p>
          <p v-else-if="outcome.status === 'active'" class="muted">Bij de servercontrole lag dit ticket binnen het geldigheidsvenster.
            Dit is een momentopname, geen garantie dat het ticket nu nog bruikbaar is.</p>
          <p v-else-if="outcome.status === 'expired'" class="muted">De server controleerde dit ticket op of na de vervaltijd. Het geldigheidsvenster is verstreken.</p>
          <p v-else-if="outcome.status === 'revoked'" class="muted">Dit ticket is ingetrokken en geeft geen verdere toestemming.</p>
          <p v-else-if="outcome.status === 'committed'" class="muted">Het commando is al opgeslagen als logboekrecord, niet uitgevoerd.
            <span v-if="outcome.revoked">Een latere intrekking maakt het eerdere logboekrecord niet ongedaan.</span>
          </p>
          <p class="muted">Deze statuscontrole geeft geen nieuwe toestemming en herstelt geen lokaal ticket.
            Geen uitvoering of automatische herinzending.</p>
          <p aria-describedby="outcome-server-time-help">Gecontroleerd door server: <time :datetime="receiptIso(outcome.checked_at)">{{ date(outcome.checked_at) }}</time></p>
          <p id="outcome-server-time-help" class="muted">Het tijdstip waarop de server deze statusmomentopname controleerde, niet de lokale ontvangsttijd of de huidige tijd.
            Geen garantie dat de uitkomst actueel is. Controleer de status handmatig opnieuw voor een nieuwe momentopname.</p>
          <p aria-describedby="outcome-receipt-help">Uitkomst lokaal ontvangen:
            <time v-if="outcomeReceivedAt !== null" :datetime="receiptIso(outcomeReceivedAt)">{{ date(outcomeReceivedAt) }}</time>
            <span v-else>Geen ontvangsttijdstip beschikbaar.</span>
          </p>
          <p id="outcome-receipt-help" class="muted">Volgens de lokale klok; geen server- of audittijd en geen garantie dat de uitkomst actueel is.
            Controleer de status handmatig opnieuw voor een nieuwe momentopname.</p>
          <p aria-describedby="outcome-window-help">Geldig vanaf: <time :datetime="receiptIso(outcome.not_before)">{{ date(outcome.not_before) }}</time> · verloopt: <time :datetime="receiptIso(outcome.expires_at)">{{ date(outcome.expires_at) }}</time></p>
          <p id="outcome-window-help" class="muted">Begintijd inbegrepen, vervaltijd uitgesloten. Het historische geldigheidsvenster van deze ticketuitkomst, niet van de huidige concepttekst.
            Geeft geen nieuwe toestemming.</p>
          <p id="outcome-command-label">Commandotekst van deze ticketuitkomst</p>
          <pre aria-labelledby="outcome-command-label" aria-describedby="outcome-command-help">{{ outcome.command }}</pre>
          <p id="outcome-command-help" class="muted">De exacte tekst uit de ontvangen statusmomentopname, niet de huidige concepttekst of het huidige ticket.
            Kan na Wis commandotekst zichtbaar blijven. Alleen tekst: geen uitvoering of nieuwe toestemming.</p>
          <p v-if="outcome.record" aria-describedby="outcome-record-help">Vastgelegd:
            <time :datetime="receiptIso(outcome.record.committed_at)">{{ date(outcome.record.committed_at) }}</time> · Record-ID: <code>{{ outcome.record.id }}</code>
          </p>
          <p v-if="outcome.record" id="outcome-record-help" class="muted">Het record-ID identificeert het opgeslagen logboekrecord, niet het ticket-ID voor statuscontrole.
            Alleen-lezen historie: herstelt geen toestemming en voegt niets toe aan het recente logboek.</p>
        </div>
        <button type="button" class="secondary" :disabled="!canClearOutcome" aria-describedby="clear-outcome-help" @click="clearOutcome">Wis ticketuitkomst</button>
        <p id="clear-outcome-help" class="muted">Wist alleen lokaal de getoonde uitkomst en statusmeldingen; breekt een lopende statuscontrole lokaal af.
          Ticket-ID's blijven behouden. Geen intrekking, terugdraaien of herstel van toestemming.
          Controleer de status opnieuw met een expliciete actie; geen automatische verzoeken.</p>
        <p class="muted">Alleen een momentopname. Active of pending herstelt geen lokaal ticket. Geen uitvoering, nieuwe toestemming of automatische herinzending.</p>
      </section>
      <section aria-labelledby="journal-title" :aria-busy="busy === 'list'">
        <h2 id="journal-title">Commandologboek</h2>
        <p class="muted">Maximaal 100 records. Realtime is optioneel en gebruikt het ingevoerde token; geen automatische herverbinding.</p>
        <p role="status" aria-describedby="realtime-help">{{ realtimeLabels[realtimeStatus] }}</p>
        <p id="realtime-help" class="muted">Realtime ontvangt alleen nieuwe gebeurtenissen zolang de verbinding actief is.
          Verbinden of opnieuw verbinden haalt geen eerdere of gemiste records op. Verbonden betekent geen volledige historie.
          Kies expliciet Logboek vernieuwen voor een momentopname van de nieuwste maximaal 100 records, niet de hele historie.
          Geen garantie op ontvangst zonder gaten of precies één ontvangst per live record.</p>
        <div class="actions">
          <button :disabled="!!busy || !validToken || realtimeStatus === 'connecting' || realtimeStatus === 'connected'" aria-describedby="realtime-help" @click="realtime.connect(token)">Realtime verbinden</button>
          <button class="secondary" :disabled="!!busy || (realtimeStatus !== 'connecting' && realtimeStatus !== 'connected')" @click="realtime.disconnect()">Verbinding verbreken</button>
        </div>
        <button :disabled="!!busy || !validToken" @click="perform('list')">Logboek vernieuwen</button>
        <button type="button" class="secondary" :disabled="!!busy && busy !== 'list'" aria-describedby="clear-journal-help" @click="clearJournal">Wis lokaal logboek</button>
        <p id="clear-journal-help" class="muted">Wist alleen lokaal de geladen records en zoekopdracht, verbreekt realtime en breekt een lopende verversing lokaal af.
          Geen verwijdering uit de database of intrekking van tickets. De aparte ticketuitkomst blijft behouden en kan een historisch logboekrecord bevatten.
          Kies expliciet Logboek vernieuwen of Realtime verbinden om opnieuw gegevens te laden; geen automatische verzoeken of herverbinding.</p>
        <p v-if="busy === 'list'" role="status" aria-live="polite">Logboek vernieuwen… Bestaande records blijven zichtbaar.</p>
        <p v-if="journalRefreshFailed" role="alert" class="error">Logboek vernieuwen mislukt. Getoonde gegevens kunnen verouderd zijn. Er worden geen automatische nieuwe pogingen gedaan.</p>
        <p role="status" aria-live="polite" aria-describedby="journal-receipt-help">
          <template v-if="lastJournalRefreshAt !== null">Laatste geslaagde verversing ontvangen:
            <time :datetime="receiptIso(lastJournalRefreshAt)">{{ date(lastJournalRefreshAt) }}</time>
          </template>
          <template v-else>Geen ontvangsttijdstip beschikbaar.</template>
        </p>
        <p id="journal-receipt-help" class="muted">Volgens de lokale klok; geen server- of audittijd en geen garantie dat het logboek actueel is.
          Realtime-events vernieuwen dit ontvangsttijdstip van de snapshot niet.</p>
        <label for="journal-search">Zoek in geladen logboek</label>
        <input id="journal-search" v-model="search" type="search" autocomplete="off" spellcheck="false" maxlength="1024" aria-describedby="journal-search-help" />
        <p id="journal-search-help" class="muted">Zoekt letterlijk, zonder hoofdletterverschil, in commandotekst of record-ID van maximaal 100 lokaal geladen records.
          Niet in de hele database of ticket-ID's. De zoekopdracht blijft alleen in sessiegeheugen.</p>
        <button type="button" class="secondary" :disabled="!search" @click="search = ''">Wis zoekopdracht</button>
        <p role="status" aria-live="polite">{{ filteredCommands.length }} van {{ commands.length }} geladen records</p>
        <p v-if="commands.length === 100" id="journal-limit-help" class="muted" role="status">De lokale limiet van 100 records is bereikt. Er kunnen oudere records op de server staan die hier niet zichtbaar zijn. Zoeken doorzoekt alleen de geladen records, niet de volledige historie.</p>
        <p v-if="!commands.length" class="muted">{{ journalRefreshFailed ? 'Geen records beschikbaar na mislukte verversing.' : hasLoaded ? 'Het logboek is leeg.' : 'Nog geen records geladen.' }}</p>
        <p v-else-if="!filteredCommands.length" class="muted">Geen geladen records gevonden voor deze zoekopdracht.</p>
        <p id="journal-record-help" class="muted">Het record-ID identificeert het opgeslagen logboekrecord, niet het ticket-ID voor statuscontrole. Opgeslagen tekst, geen uitvoering.</p>
        <ol class="journal" aria-describedby="journal-record-help">
          <li v-for="entry in filteredCommands" :key="entry.id"><pre>{{ entry.command }}</pre><small>Vastgelegd: <time :datetime="receiptIso(entry.committed_at)">{{ date(entry.committed_at) }}</time> · Record-ID: <code>{{ entry.id }}</code></small></li>
        </ol>
      </section>
    </div>
    <footer>API: 127.0.0.1:8788 · Start met <code>npm run dev</code> op 127.0.0.1:5175.
      De ontwikkelproxy (inclusief Socket.IO) is niet opgenomen in de statische build.</footer>
  </main>
</template>
