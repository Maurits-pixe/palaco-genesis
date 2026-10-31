import { computed, onScopeDispose, ref } from 'vue'
import { launchUrl, TRUSTED_MODULES, verifyModule } from './verification.js'

export function useModuleVerification({
  verifier = verifyModule,
  getNow = Date.now,
  schedule = setInterval,
  unschedule = clearInterval,
  eventTarget = globalThis.window,
} = {}) {
  const states = ref(Object.fromEntries(TRUSTED_MODULES.map(({ id }) => [id, { status: 'idle' }])))
  const readNow = () => getNow() ?? null
  const now = ref(readNow())
  const attempts = new Map()
  let disposed = false
  const clock = schedule(() => {
    if (!disposed) now.value = readNow()
  }, 500)
  eventTarget?.addEventListener('pagehide', reset)
  onScopeDispose(() => {
    eventTarget?.removeEventListener('pagehide', reset)
    disposed = true
    unschedule(clock)
    states.value = Object.fromEntries(TRUSTED_MODULES.map(({ id }) => [id, { status: 'idle' }]))
    abortAttempts()
  })

  const isVerifying = computed(() =>
    TRUSTED_MODULES.some(({ id }) => states.value[id].status === 'verifying'))
  const launchableCount = computed(() =>
    TRUSTED_MODULES.filter((module) => launchUrl(module, states.value[module.id], now.value ?? null)).length)

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

  function resetModule(module) {
    if (disposed || !TRUSTED_MODULES.includes(module) ||
        states.value[module.id].status === 'idle') return
    const controller = attempts.get(module.id)
    attempts.delete(module.id)
    states.value[module.id] = { status: 'idle' }
    controller?.abort()
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
        now.value = readNow()
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

  return { states, now, isVerifying, launchableCount, verify, verifyAll, reset, resetModule }
}
