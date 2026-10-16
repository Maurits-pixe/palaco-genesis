<script setup>
import { onUnmounted, ref } from 'vue'
import { launchUrl, TRUSTED_MODULES, verifyModule } from './verification.js'

const states = ref(Object.fromEntries(TRUSTED_MODULES.map(({ id }) => [id, { status: 'idle' }])))
const now = ref(Date.now())
const clock = setInterval(() => { now.value = Date.now() }, 500)
onUnmounted(() => clearInterval(clock))

async function verify(module) {
  if (states.value[module.id].status === 'verifying') return
  states.value[module.id] = { status: 'verifying' }
  try {
    states.value[module.id] = await verifyModule(module)
    now.value = Date.now()
  } catch (error) {
    states.value[module.id] = { status: 'error', message: error.message }
  }
}

function follow(event, module) {
  if (!launchUrl(module, states.value[module.id], Date.now())) {
    event.preventDefault()
    now.value = Date.now()
  }
}

function status(module) {
  const state = states.value[module.id]
  if (state.status === 'verifying') return 'Manifest controleren…'
  if (state.status === 'error') return state.message
  if (launchUrl(module, state, now.value)) return 'Manifest komt overeen · geldig gedurende 60 seconden.'
  return state.status === 'verified' ? 'Verificatie verlopen. Controleer opnieuw.' : 'Nog niet gecontroleerd.'
}
</script>

<template>
  <main>
    <header><p class="eyebrow">PALACO / LOKALE ALPHA</p><h1>NEO</h1><p>Een rustig startpunt voor je lokale modules.</p></header>
    <aside class="notice">
      <strong>Wat wordt gecontroleerd?</strong>
      Alleen de module-identiteit, naam en het protocol in het manifest.
      Dit is geen cryptografische code-integriteitscontrole en geen autorisatie.
      Startadressen staan vast; manifesten kunnen ze niet wijzigen.
    </aside>
    <section class="grid" aria-label="Lokale modules">
      <article v-for="module in TRUSTED_MODULES" :key="module.id" :aria-busy="states[module.id].status === 'verifying'">
        <p class="eyebrow">MODULE / {{ module.id }}</p>
        <h2>{{ module.name }}</h2>
        <p>{{ module.description }}</p>
        <p class="address">{{ module.origin }}</p>
        <p class="status" role="status">{{ status(module) }}</p>
        <div class="actions">
          <button :disabled="states[module.id].status === 'verifying'" @click="verify(module)">Verifieer manifest</button>
          <a v-if="launchUrl(module, states[module.id], now)" :href="launchUrl(module, states[module.id], now)" rel="noreferrer" @click="follow($event, module)">Open {{ module.name }} →</a>
          <span v-else class="disabled" role="link" aria-disabled="true">Open {{ module.name }} →</span>
        </div>
      </article>
    </section>
    <footer>Alleen lokaal HTTP op vaste 127.0.0.1-adressen; voor overige oorsprongen is HTTPS vereist.
      Start de API's op 8787/8788 en de interfaces op 5174/5175. Deze proxyconfiguratie geldt voor <code>npm run dev</code>, niet voor een losse statische build.</footer>
  </main>
</template>
