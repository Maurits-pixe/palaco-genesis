import { getCurrentScope, onScopeDispose, ref, watch } from 'vue'
import { createRecord, readRecord } from './api.js'

export function useRecordSession({ create = createRecord, read = readRecord, eventTarget = globalThis.window, getNow = Date.now } = {}) {
  const token = ref('')
  const plaintext = ref('')
  const recordId = ref('')
  const lastCreatedId = ref('')
  const result = ref(null)
  const resultReceivedAt = ref(null)
  const busy = ref('')
  const message = ref('')
  const error = ref('')
  let activeRequest = null
  let feedbackAction = ''
  let disposed = false

  function resetResult() {
    result.value = null
    resultReceivedAt.value = null
  }

  function invalidate() {
    const previous = activeRequest
    activeRequest = null
    feedbackAction = ''
    busy.value = ''
    plaintext.value = ''
    recordId.value = ''
    lastCreatedId.value = ''
    resetResult()
    message.value = ''
    error.value = ''
    previous?.abort()
  }

  const stopWatchingToken = watch(token, invalidate, { flush: 'sync' })
  const stopWatchingId = watch(recordId, (id, previousId) => {
    if (disposed || busy.value === 'create' || id.trim() === previousId.trim()) return
    if (result.value || busy.value === 'read' || feedbackAction === 'read') clearReadResult()
  }, { flush: 'sync' })

  function clearSession() {
    if (!disposed && token.value !== '') {
      token.value = ''
    } else {
      token.value = ''
      invalidate()
    }
  }

  function clearReadResult() {
    if (disposed || busy.value === 'create') return
    const previous = activeRequest
    activeRequest = null
    feedbackAction = ''
    busy.value = ''
    resetResult()
    message.value = ''
    error.value = ''
    previous?.abort()
  }

  function dispose() {
    eventTarget?.removeEventListener('pagehide', clearSession)
    disposed = true
    stopWatchingToken()
    stopWatchingId()
    clearSession()
  }

  eventTarget?.addEventListener('pagehide', clearSession)
  if (getCurrentScope()) onScopeDispose(dispose)

  async function perform(action) {
    if (disposed || busy.value) return
    const controller = new AbortController()
    activeRequest = controller
    feedbackAction = action
    const isCurrent = () => !disposed && activeRequest === controller
    busy.value = action
    resetResult()
    error.value = ''
    message.value = ''
    try {
      if (action === 'create') {
        const record = await create(plaintext.value, token.value, undefined, controller.signal)
        if (!isCurrent()) return
        recordId.value = record.id
        lastCreatedId.value = record.id
        plaintext.value = ''
        message.value = 'Record opgeslagen. Bewaar het record-ID om het later terug te lezen.'
      } else {
        const record = await read(recordId.value.trim(), token.value, undefined, controller.signal)
        if (!isCurrent()) return
        let receivedAt = null
        try {
          const now = getNow()
          if (Number.isSafeInteger(now) && now >= 0 && now <= 8640000000000000) receivedAt = now
        } catch {
          // A local clock failure must not discard a successful read.
        }
        if (!isCurrent()) return
        resultReceivedAt.value = receivedAt
        result.value = record
        message.value = 'Record opgehaald.'
      }
    } catch (failure) {
      if (isCurrent()) error.value = failure.message
    } finally {
      if (isCurrent()) {
        activeRequest = null
        busy.value = ''
      }
    }
  }

  function readLastCreated() {
    if (disposed || busy.value || !token.value.trim() || !lastCreatedId.value) return
    recordId.value = lastCreatedId.value
    return perform('read')
  }

  return { token, plaintext, recordId, lastCreatedId, result, resultReceivedAt, busy, message, error, perform, readLastCreated, clearReadResult, clearSession, dispose }
}
