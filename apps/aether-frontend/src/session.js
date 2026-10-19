import { getCurrentScope, onScopeDispose, ref, watch } from 'vue'
import { createRecord, readRecord } from './api.js'

export function useRecordSession({ create = createRecord, read = readRecord } = {}) {
  const token = ref('')
  const plaintext = ref('')
  const recordId = ref('')
  const lastCreatedId = ref('')
  const result = ref(null)
  const busy = ref('')
  const message = ref('')
  const error = ref('')
  let activeRequest = null
  let disposed = false

  function invalidate() {
    const previous = activeRequest
    activeRequest = null
    busy.value = ''
    plaintext.value = ''
    recordId.value = ''
    lastCreatedId.value = ''
    result.value = null
    message.value = ''
    error.value = ''
    previous?.abort()
  }

  const stopWatching = watch(token, invalidate, { flush: 'sync' })

  function clearSession() {
    invalidate()
    token.value = ''
  }

  function dispose() {
    disposed = true
    stopWatching()
    clearSession()
  }

  if (getCurrentScope()) onScopeDispose(dispose)

  async function perform(action) {
    if (disposed || busy.value) return
    const controller = new AbortController()
    activeRequest = controller
    const isCurrent = () => !disposed && activeRequest === controller
    busy.value = action
    result.value = null
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

  return { token, plaintext, recordId, lastCreatedId, result, busy, message, error, perform, readLastCreated, clearSession, dispose }
}
