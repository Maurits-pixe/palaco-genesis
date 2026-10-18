import { computed, onScopeDispose, ref } from 'vue'
import { launchUrl, TRUSTED_MODULES, verifyModule } from './verification.js'

export function useModuleVerification({
  verifier = verifyModule,
  getNow = Date.now,
  schedule = setInterval,
  unschedule = clearInterval,
} = {}) {
  const states = ref(Object.fromEntries(TRUSTED_MODULES.map(({ id }) => [id, { status: 'idle' }])))
  const now = ref(getNow())
  let disposed = false
  const clock = schedule(() => {
    if (!disposed) now.value = getNow()
  }, 500)
  onScopeDispose(() => {
    disposed = true
    unschedule(clock)
  })

  const isVerifying = computed(() =>
    TRUSTED_MODULES.some(({ id }) => states.value[id].status === 'verifying'))
  const launchableCount = computed(() =>
    TRUSTED_MODULES.filter((module) => launchUrl(module, states.value[module.id], now.value)).length)

  async function run(module) {
    try {
      const result = await verifier(module)
      if (!disposed) {
        states.value[module.id] = result
        now.value = getNow()
      }
    } catch (error) {
      if (!disposed) {
        states.value[module.id] = { status: 'error', message: error?.message || 'Verificatie mislukt.' }
      }
    }
  }

  async function verify(module) {
    if (disposed || !TRUSTED_MODULES.includes(module) ||
        states.value[module.id].status === 'verifying') return
    states.value[module.id] = { status: 'verifying' }
    await run(module)
  }

  async function verifyAll() {
    if (disposed || isVerifying.value) return
    // Invalidate every old approval before starting any verification request.
    for (const { id } of TRUSTED_MODULES) states.value[id] = { status: 'verifying' }
    await Promise.all(TRUSTED_MODULES.map(run))
  }

  return { states, now, isVerifying, launchableCount, verify, verifyAll }
}
