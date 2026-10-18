const errors = {
  400: 'Ongeldige invoer. Controleer je gegevens.',
  401: 'Toegang geweigerd. Controleer je token.',
  403: 'Geen toestemming voor deze actie.',
  404: 'Record niet gevonden.',
  413: 'Het record is te groot.',
  429: 'Te veel verzoeken. Probeer later opnieuw.',
}

class ApiError extends Error {}

export const MAX_PLAINTEXT_BYTES = 16 * 1024
export const MAX_RESPONSE_BYTES = 128 * 1024
export const plaintextBytes = (value) => new TextEncoder().encode(value).byteLength

function cancel(target) {
  try {
    Promise.resolve(target?.cancel()).catch(() => {})
  } catch {
    // Cancellation is best effort, including for already locked or errored bodies.
  }
}

function abortable(pending, signal, onLateValue) {
  return new Promise((resolve, reject) => {
    const abort = () => {
      signal.removeEventListener('abort', abort)
      reject(signal.reason)
    }
    signal.addEventListener('abort', abort, { once: true })
    if (signal.aborted) abort()
    Promise.resolve(pending).then(value => {
      signal.removeEventListener('abort', abort)
      if (signal.aborted) {
        onLateValue?.(value)
        reject(signal.reason)
      } else {
        resolve(value)
      }
    }, error => {
      signal.removeEventListener('abort', abort)
      reject(error)
    })
  })
}

async function readJson(response, signal) {
  const reader = response.body.getReader()
  let complete = false
  try {
    const decoder = new TextDecoder('utf-8', { fatal: true })
    let bytes = 0
    let text = ''
    while (true) {
      const { done, value } = await abortable(reader.read(), signal)
      signal.throwIfAborted()
      if (done) {
        complete = true
        break
      }
      bytes += value.byteLength
      if (bytes > MAX_RESPONSE_BYTES) throw new ApiError('Onverwacht antwoord van de service.')
      text += decoder.decode(value, { stream: true })
    }
    text += decoder.decode()
    const result = JSON.parse(text)
    if (result === null || typeof result !== 'object' || Array.isArray(result)) {
      throw new ApiError('Onverwacht antwoord van de service.')
    }
    return result
  } finally {
    if (!complete) cancel(reader)
    reader.releaseLock()
  }
}

export function validId(id) {
  return typeof id === 'string' && /^[a-zA-Z0-9_-]{1,200}$/.test(id)
}

export async function request(path, { token, body, method = 'GET', fetcher = fetch, timeoutMs = 8000, signal }) {
  if (typeof token !== 'string' || !token.trim() || /[\r\n]/.test(token)) {
    throw new ApiError('Vul een geldig toegangstoken in.')
  }
  if (!/^\/v1\/records(?:\/[a-zA-Z0-9_-]{1,200})?$/.test(path)) {
    throw new ApiError('Ongeldig recordadres.')
  }
  const controller = new AbortController()
  const abort = () => controller.abort()
  signal?.addEventListener('abort', abort, { once: true })
  if (signal?.aborted) abort()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  let response
  try {
    controller.signal.throwIfAborted()
    response = await abortable(fetcher(path, {
      method,
      headers: {
        Authorization: ['Bearer', token].join(' '),
        Accept: 'application/json',
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
      redirect: 'error',
      cache: 'no-store',
      credentials: 'omit',
    }), controller.signal, late => cancel(late?.body))
    controller.signal.throwIfAborted()
    if (!response.ok) throw new ApiError(errors[response.status] || 'De service kan dit verzoek niet verwerken.')
    if (response.redirected || response.status !== (method === 'POST' ? 201 : 200)) {
      throw new ApiError('Onverwacht antwoord van de service.')
    }
    if (!/^application\/json(?:\s*;.*)?$/i.test(response.headers.get('content-type')?.trim() || '') || !response.body) {
      throw new ApiError('Onverwacht antwoord van de service.')
    }
    const result = await readJson(response, controller.signal)
    controller.signal.throwIfAborted()
    return result
  } catch (error) {
    if (response?.body && !response.body.locked) cancel(response.body)
    if (error instanceof ApiError) throw error
    throw new ApiError('Geen geldig antwoord. Controleer de lokale service en probeer opnieuw.')
  } finally {
    clearTimeout(timer)
    signal?.removeEventListener('abort', abort)
  }
}

export async function createRecord(plaintext, token, fetcher, signal) {
  if (typeof plaintext !== 'string' || !plaintext.trim()) throw new ApiError('Vul tekst voor het record in.')
  if (plaintextBytes(plaintext) > MAX_PLAINTEXT_BYTES) throw new ApiError('Een record mag maximaal 16384 UTF-8-bytes bevatten.')
  const result = await request('/v1/records', { token, method: 'POST', body: { plaintext }, fetcher, signal })
  if (!validId(result?.id)) throw new ApiError('Onverwacht antwoord van de service.')
  return { id: result.id }
}

export async function readRecord(id, token, fetcher, signal) {
  if (!validId(id)) throw new ApiError('Vul een geldig record-ID in.')
  const result = await request(`/v1/records/${encodeURIComponent(id)}`, { token, fetcher, signal })
  if (result?.id !== id || typeof result?.plaintext !== 'string' || plaintextBytes(result.plaintext) > MAX_PLAINTEXT_BYTES) {
    throw new ApiError('Onverwacht antwoord van de service.')
  }
  return { id: result.id, plaintext: result.plaintext }
}
