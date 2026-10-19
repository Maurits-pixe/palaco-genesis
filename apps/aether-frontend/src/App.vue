<script setup>
import { MAX_PLAINTEXT_BYTES, plaintextBytes } from './api.js'
import { useRecordSession } from './session.js'

const { token, plaintext, recordId, lastCreatedId, result, busy, message, error, perform, readLastCreated, clearSession } = useRecordSession()
</script>

<template>
  <main>
    <header><p class="eyebrow">PALACO / LOKALE ALPHA</p><h1>AETHER</h1><p>Je records, bewust opgeslagen.</p></header>
    <aside class="notice">De lokale backend versleutelt records bij opslag. Deze interface verstuurt en toont leesbare tekst.
      Lokaal HTTP biedt geen transportversleuteling. Gebruik geen gevoelige productiegegevens.</aside>
    <section aria-labelledby="access-title">
      <h2 id="access-title">Toegang</h2>
      <label for="token">Toegangstoken</label>
      <input id="token" v-model="token" type="password" autocomplete="off" spellcheck="false" aria-describedby="token-help" />
      <p id="token-help" class="muted">Alleen in componentgeheugen; niet in opslag of een URL. Vernieuwen wist de sessie.</p>
      <button class="secondary" @click="clearSession">Wis sessie en tekst</button>
      <p class="muted">Annuleren of de sessie wissen stopt alleen het lokale wachten. Een al verstuurd opslagverzoek
        kan het record al hebben opgeslagen. Probeer niet automatisch opnieuw.</p>
    </section>
    <div role="status" aria-live="polite"><p v-if="busy" class="notice">Even wachten…</p><p v-if="message" class="notice">{{ message }}</p></div>
    <p v-if="error" role="alert" class="error">{{ error }}</p>
    <div class="grid">
      <section aria-labelledby="create-title" :aria-busy="busy === 'create'">
        <h2 id="create-title">Record opslaan</h2>
        <form @submit.prevent="perform('create')">
          <label for="plaintext">Leesbare tekst</label>
          <textarea id="plaintext" v-model="plaintext" rows="7" required :maxlength="MAX_PLAINTEXT_BYTES" :disabled="!!busy" aria-describedby="plaintext-limit" />
          <p id="plaintext-limit" class="muted">{{ plaintextBytes(plaintext) }} / {{ MAX_PLAINTEXT_BYTES }} UTF-8-bytes</p>
          <button :disabled="!!busy || !token.trim() || !plaintext.trim() || plaintextBytes(plaintext) > MAX_PLAINTEXT_BYTES">Versleuteld opslaan</button>
        </form>
      </section>
      <section aria-labelledby="read-title" :aria-busy="busy === 'read'">
        <h2 id="read-title">Record teruglezen</h2>
        <div v-if="lastCreatedId">
          <label for="last-created-id">Laatst bevestigd opgeslagen record-ID</label>
          <input id="last-created-id" :value="lastCreatedId" readonly autocomplete="off" spellcheck="false" aria-describedby="last-created-help" />
          <p id="last-created-help" class="muted">Alleen in sessiegeheugen; geen volledige recordhistorie.
            Na een onzekere of mislukte opslag blijft het vorige bevestigde ID staan.
            Een ontbrekend antwoord op een opslagverzoek kan hiermee niet worden gereconstrueerd.
            Tokenwijziging, sessiewissen of herladen wist dit ID.</p>
          <button type="button" :disabled="!!busy || !token.trim()" @click="readLastCreated">Lees laatst opgeslagen record</button>
        </div>
        <form @submit.prevent="perform('read')">
          <label for="record-id">Record-ID</label>
          <input id="record-id" v-model="recordId" required maxlength="200" :disabled="!!busy" autocomplete="off" spellcheck="false" />
          <button :disabled="!!busy || !token.trim() || !recordId.trim()">Record ophalen</button>
        </form>
        <div v-if="result" class="result"><h3>Leesbare inhoud</h3><pre>{{ result.plaintext }}</pre></div>
      </section>
    </div>
    <footer>API: 127.0.0.1:8787 · Start met <code>npm run dev</code> op 127.0.0.1:5174.
      De ontwikkelproxy is niet opgenomen in de statische build.</footer>
  </main>
</template>
