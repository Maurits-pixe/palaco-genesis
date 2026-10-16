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
export const plaintextBytes = (value) => new TextEncoder().encode(value).byteLength

export function validId(id) {
  return typeof id === 'string' && /^[a-zA-Z0-9_-]{1,200}$/.test(id)
}

export async function request(path, { token, body, method = 'GET', fetcher = fetch, timeoutMs = 8000 }) {
  if (typeof token !== 'string' || !token.trim() || /[\r\n]/.test(token)) {
    throw new ApiError('Vul een geldig toegangstoken in.')
  }
  if (!/^\/v1\/records(?:\/[a-zA-Z0-9_-]{1,200})?$/.test(path)) {
    throw new ApiError('Ongeldig recordadres.')
  }
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const response = await fetcher(path, {
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
    })
    if (!response.ok) throw new ApiError(errors[response.status] || 'De service kan dit verzoek niet verwerken.')
    if (response.redirected || response.status !== (method === 'POST' ? 201 : 200)) {
      throw new ApiError('Onverwacht antwoord van de service.')
    }
    return await response.json()
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw new ApiError('Geen geldig antwoord. Controleer de lokale service en probeer opnieuw.')
  } finally {
    clearTimeout(timer)
  }
}

export async function createRecord(plaintext, token, fetcher) {
  if (typeof plaintext !== 'string' || !plaintext.trim()) throw new ApiError('Vul tekst voor het record in.')
  if (plaintextBytes(plaintext) > MAX_PLAINTEXT_BYTES) throw new ApiError('Een record mag maximaal 16384 UTF-8-bytes bevatten.')
  const result = await request('/v1/records', { token, method: 'POST', body: { plaintext }, fetcher })
  if (!validId(result?.id)) throw new ApiError('Onverwacht antwoord van de service.')
  return { id: result.id }
}

export async function readRecord(id, token, fetcher) {
  if (!validId(id)) throw new ApiError('Vul een geldig record-ID in.')
  const result = await request(`/v1/records/${encodeURIComponent(id)}`, { token, fetcher })
  if (result?.id !== id || typeof result?.plaintext !== 'string') {
    throw new ApiError('Onverwacht antwoord van de service.')
  }
  return { id: result.id, plaintext: result.plaintext }
}
