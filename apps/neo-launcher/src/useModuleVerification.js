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
  const attempts = new Map()
  let disposed = false
  const clock = schedule(() => {
    if (!disposed) now.value = getNow()
  }, 500)
  onScopeDispose(() => {
    disposed = true
    unschedule(clock)
    abortAttempts()
  })

  const isVerifying = computed(() =>
    TRUSTED_MODULES.some(({ id }) => states.value[id].status === 'verifying'))
  const launchableCount = computed(() =>
    TRUSTED_MODULES.filter((module) => launchUrl(module, states.value[module.id], now.value)).length)

  function abortAttempts() {
    const controllers = [...attempts.values()]
    attempts.clear()
    for (const controller of controllers) controller.abort()
  }

  function reset() {
    if (disposed) return
    states.value = Object.fromEntries(TRUSTED_MODULES.map(({ id }) => [id, { status: 'idle' }]))
    abortAttempts()
  }

  function begin(module) {
    const controller = new AbortController()
    attempts.set(module.id, controller)
    states.value[module.id] = { status: 'verifying' }
    return controller
  }

  async function run(module, controller) {
    const isCurrent = () => !disposed && attempts.get(module.id) === controller
    try {
      if (!isCurrent()) return
      const result = await verifier(module, undefined, undefined, controller.signal)
      if (isCurrent()) {
        states.value[module.id] = result
        now.value = getNow()
      }
    } catch (error) {
      if (isCurrent()) {
        states.value[module.id] = { status: 'error', message: error?.message || 'Verificatie mislukt.' }
      }
    } finally {
      if (isCurrent()) attempts.delete(module.id)
    }
  }

  async function verify(module) {
    if (disposed || !TRUSTED_MODULES.includes(module) ||
        states.value[module.id].status === 'verifying') return
    await run(module, begin(module))
  }

  async function verifyAll() {
    if (disposed || isVerifying.value) return
    // Invalidate every old approval before starting any verification request.
    const controllers = TRUSTED_MODULES.map(begin)
    await Promise.all(TRUSTED_MODULES.map((module, index) => run(module, controllers[index])))
  }

  return { states, now, isVerifying, launchableCount, verify, verifyAll, reset }
}
