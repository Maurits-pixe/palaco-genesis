<script setup>
import { launchUrl, remainingVerificationSeconds, TRUSTED_MODULES } from './verification.js'
import { useModuleVerification } from './useModuleVerification.js'

const { states, now, isVerifying, launchableCount, verify, verifyAll, reset, resetModule } = useModuleVerification()

function follow(event, module) {
  if (!launchUrl(module, states.value[module.id], Date.now())) {
    event.preventDefault()
    now.value = Date.now()
  }
}

function status(module) {
  const state = states.value[module.id]
  if (state.status === 'verifying') return 'Identiteit en backendstatus controleren…'
  if (state.status === 'error') return state.message
  if (launchUrl(module, state, now.value)) return 'Identiteit klopt en backend antwoordde ok · momentopname geldig gedurende 60 seconden.'
  return state.status === 'verified' ? 'Verificatie verlopen. Controleer opnieuw.' : 'Nog niet gecontroleerd.'
}

function remainingSeconds(module) {
  return remainingVerificationSeconds(module, states.value[module.id], now.value ?? null)
}
</script>

<template>
  <main>
    <header><p class="eyebrow">PALACO / LOKALE ALPHA</p><h1>NEO</h1><p>Een rustig startpunt voor je lokale modules.</p></header>
    <aside class="notice">
      <strong>Wat wordt gecontroleerd?</strong>
      De module-identiteit, naam en het protocol in het manifest, plus een publiek backendantwoord met status ok.
      Dit is een momentopname, geen garantie op voortdurende beschikbaarheid.
      De resterende tijd is gebaseerd op de lokale klok.
      Dit is geen cryptografische code-integriteitscontrole en geen autorisatie.
      Startadressen staan vast; manifesten kunnen ze niet wijzigen.
    </aside>
    <div class="actions">
      <button :disabled="isVerifying" @click="verifyAll">Controleer alle modules</button>
      <button @click="reset">Wis controles</button>
      <p role="status" aria-live="polite" aria-atomic="true">{{ launchableCount }} van {{ TRUSTED_MODULES.length }} modules momenteel te openen.</p>
    </div>
    <p>Wissen verwijdert alleen lokale controles: het stopt geen services, trekt geen tickets in en sluit geen reeds geopende tabbladen.</p>
    <p>Bij ontvangst van pagehide worden lokale controles gewist; controleer na terugkeer handmatig opnieuw.
      Aflevering is niet gegarandeerd. Dit stopt geen services, trekt geen tokens of tickets in en is geen autorisatie.</p>
    <section class="grid" aria-label="Lokale modules">
      <article v-for="module in TRUSTED_MODULES" :key="module.id" :aria-busy="states[module.id].status === 'verifying'">
        <p class="eyebrow">MODULE / {{ module.id }}</p>
        <h2>{{ module.name }}</h2>
        <p>{{ module.description }}</p>
        <p class="address">{{ module.origin }}</p>
        <p class="status" role="status">{{ status(module) }}</p>
        <p v-if="remainingSeconds(module) !== null">Startlink nog circa {{ remainingSeconds(module) }} seconden beschikbaar.</p>
        <div class="actions">
          <button :disabled="states[module.id].status === 'verifying'" @click="verify(module)">Controleer identiteit en backendstatus</button>
          <button type="button" :disabled="states[module.id].status === 'idle'" :aria-label="`Wis deze controle voor ${module.name}`" @click="resetModule(module)">Wis deze controle</button>
          <a v-if="launchUrl(module, states[module.id], now)" :href="launchUrl(module, states[module.id], now)" rel="noreferrer" @click="follow($event, module)">Open {{ module.name }} →</a>
          <span v-else class="disabled" role="link" aria-disabled="true">Open {{ module.name }} →</span>
        </div>
      </article>
    </section>
    <footer>Alleen lokaal HTTP op vaste 127.0.0.1-adressen; voor overige oorsprongen is HTTPS vereist.
      Start de API's op 8787/8788 en de interfaces op 5174/5175. Deze proxyconfiguratie geldt voor <code>npm run dev</code>, niet voor een losse statische build.</footer>
  </main>
</template>
