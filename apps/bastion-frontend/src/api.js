const errors = {
  400: 'Ongeldige invoer. Controleer commando en geldigheidsduur.',
  401: 'Toegang geweigerd. Controleer je token.',
  403: 'Geen toestemming, of ticket nog niet geldig.',
  404: 'Ticket niet gevonden.',
  409: 'Ticket niet bruikbaar: gewijzigd, ingetrokken of al gebruikt.',
  410: 'Ticket verlopen of ingetrokken. Vraag een nieuw ticket aan.',
  422: 'Ticket of commando voldoet niet aan de voorwaarden.',
  429: 'Te veel verzoeken. Probeer later opnieuw.',
}

class ApiError extends Error {}

export const MAX_COMMAND_LENGTH = 1024
export const MAX_RESPONSE_BYTES = 1024 * 1024
export const commandLength = (value) => value.length

function cancel(target) {
  try {
    Promise.resolve(target?.cancel()).catch(() => {})
  } catch {
    // Cancellation is best effort, including for locked or errored bodies.
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

function validId(id) {
  return typeof id === 'string' && /^[a-zA-Z0-9_-]{1,200}$/.test(id)
}

export function timestamp(value) {
  if (typeof value !== 'string' && typeof value !== 'number') return NaN
  return typeof value === 'number' ? value : Date.parse(value)
}

export function ticketUsable(ticket, command, now = Date.now()) {
  const notBefore = timestamp(ticket?.not_before)
  const expiresAt = timestamp(ticket?.expires_at)
  return !!ticket && ticket.command === command &&
    [now, notBefore, expiresAt].every(time =>
      Number.isSafeInteger(time) && time >= 0 && Number.isFinite(new Date(time).getTime())) &&
    expiresAt > notBefore && expiresAt - notBefore <= 60_000 &&
    now >= notBefore && now < expiresAt
}

export async function request(path, { token, method = 'GET', body, fetcher = fetch, timeoutMs = 8000, signal }) {
  if (typeof token !== 'string' || !token.trim() || /[\r\n]/.test(token)) {
    throw new ApiError('Vul een geldig toegangstoken in.')
  }
  if (!/^\/v1\/(?:commands|tickets(?:\/[a-zA-Z0-9_-]{1,200})?)$/.test(path)) {
    throw new ApiError('Ongeldig serviceadres.')
  }
  const controller = new AbortController()
  const abort = () => controller.abort(signal.reason)
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

export async function issueTicket(command, ttlMs, token, fetcher, signal) {
  if (typeof command !== 'string' || !command.trim() ||
      !Number.isInteger(ttlMs) || ttlMs < 1 || ttlMs > 60_000) {
    throw new ApiError('Vul een commando en een gehele geldigheidsduur van 1 t/m 60000 ms in.')
  }
  if (commandLength(command) > MAX_COMMAND_LENGTH) throw new ApiError('Een commando mag maximaal 1024 UTF-16-tekeneenheden bevatten.')
  const result = await request('/v1/tickets', {
    token, method: 'POST', body: { command, ttl_ms: ttlMs }, fetcher, signal,
  })
  if (!validId(result?.id) || result.id.length > 128 ||
      ![result.not_before, result.expires_at].every(time =>
        Number.isSafeInteger(time) && time >= 0 && Number.isFinite(new Date(time).getTime())) ||
      result.expires_at <= result.not_before ||
      result.expires_at - result.not_before !== ttlMs) {
    throw new ApiError('Onverwacht ticketantwoord van de service.')
  }
  return { id: result.id, command, not_before: result.not_before, expires_at: result.expires_at }
}

function validCommand(value) {
  const time = timestamp(value?.committed_at)
  return value && validId(value.id) && typeof value.command === 'string' &&
    commandLength(value.command) <= MAX_COMMAND_LENGTH &&
    Number.isSafeInteger(time) && time >= 0 && Number.isFinite(new Date(time).getTime())
}

export function normalizeCommand(value) {
  return validCommand(value)
    ? { id: value.id, command: value.command, committed_at: value.committed_at }
    : null
}

export function mergeCommands(current, incoming) {
  const normalized = normalizeCommand(incoming)
  if (!normalized) return current
  return [normalized, ...current.filter(({ id }) => id !== normalized.id)].slice(0, 100)
}

export async function commitCommand(ticket, command, token, fetcher, signal) {
  if (!validId(ticket?.id) || !ticketUsable(ticket, command)) {
    throw new ApiError('Ticket niet geldig voor dit commando. Vraag een nieuw ticket aan.')
  }
  if (commandLength(command) > MAX_COMMAND_LENGTH) throw new ApiError('Een commando mag maximaal 1024 UTF-16-tekeneenheden bevatten.')
  const ticketId = ticket.id
  const notBefore = timestamp(ticket.not_before)
  const expiresAt = timestamp(ticket.expires_at)
  const exactCommand = command
  const result = await request('/v1/commands', {
    token, method: 'POST', body: { ticket_id: ticketId, command: exactCommand }, fetcher, signal,
  })
  if (!validCommand(result) || result.id.length > 128 || result.command !== exactCommand ||
      !Number.isSafeInteger(result.committed_at) || result.committed_at < 0 ||
      !Number.isFinite(new Date(result.committed_at).getTime()) ||
      result.committed_at < notBefore || result.committed_at >= expiresAt) {
    throw new ApiError('Onverwacht commandoantwoord van de service.')
  }
  return { id: result.id, command: result.command, committed_at: result.committed_at }
}

export async function listCommands(token, fetcher, signal) {
  const result = await request('/v1/commands', { token, fetcher, signal })
  if (!Array.isArray(result?.commands) || !result.commands.every(validCommand)) {
    throw new ApiError('Onverwacht logboekantwoord van de service.')
  }
  const ids = new Set()
  for (const { id } of result.commands) {
    if (ids.has(id)) throw new ApiError('Onverwacht logboekantwoord van de service.')
    ids.add(id)
  }
  return result.commands.slice(0, 100).map(({ id, command, committed_at }) => ({ id, command, committed_at }))
}

export async function revokeTicket(ticket, token, fetcher, signal) {
  if (!validId(ticket?.id)) {
    throw new ApiError('Geen geldig ticket om in te trekken.')
  }
  const result = await request(`/v1/tickets/${ticket.id}`, {
    token, method: 'DELETE', fetcher, signal,
  })
  if (result?.revoked !== true) {
    throw new ApiError('Intrekking niet bevestigd door de service.')
  }
}

function exactObject(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key))
}

export function validateTicketStatus(value, ticketId) {
  const keys = ['id', 'command', 'not_before', 'expires_at', 'checked_at', 'status', 'revoked', 'record']
  if (!exactObject(value, keys) || !validId(ticketId) || ticketId.length > 128 ||
      value.id !== ticketId || typeof value.command !== 'string' || !value.command.trim() ||
      commandLength(value.command) > MAX_COMMAND_LENGTH || typeof value.revoked !== 'boolean' ||
      ![value.not_before, value.expires_at, value.checked_at].every(time =>
        Number.isSafeInteger(time) && time >= 0 && Number.isFinite(new Date(time).getTime())) ||
      value.expires_at <= value.not_before || value.expires_at - value.not_before > 60_000) return null
  const record = value.record
  if (record !== null && (!exactObject(record, ['id', 'command', 'committed_at']) ||
      !validId(record.id) || record.id.length > 128 || record.command !== value.command ||
      !Number.isSafeInteger(record.committed_at) || record.committed_at < 0 ||
      !Number.isFinite(new Date(record.committed_at).getTime()) || record.committed_at < value.not_before ||
      record.committed_at >= value.expires_at || record.committed_at > value.checked_at)) return null
  const expected = record !== null ? 'committed' : value.revoked ? 'revoked' :
    value.checked_at >= value.expires_at ? 'expired' : value.checked_at < value.not_before ? 'pending' : 'active'
  return value.status === expected ? value : null
}

export async function getTicketStatus(ticketId, token, fetcher, signal) {
  if (!validId(ticketId) || ticketId.length > 128) throw new ApiError('Vul een geldig ticket-ID in.')
  const result = await request(`/v1/tickets/${ticketId}`, { token, fetcher, signal })
  const validated = validateTicketStatus(result, ticketId)
  if (!validated) throw new ApiError('Onverwacht ticketstatusantwoord van de service.')
  return validated
}

export function ticketMatchesStatus(ticket, outcome) {
  return !!ticket && !!outcome && ticket.id === outcome.id && ticket.command === outcome.command &&
    timestamp(ticket.not_before) === outcome.not_before && timestamp(ticket.expires_at) === outcome.expires_at
}

// A snapshot can retire existing authority, never create or restore it.
export function reconcileTicketStatus(ticket, revocationUncertain, commands, outcome) {
  const valid = validateTicketStatus(outcome, outcome?.id)
  if (!valid) return { ticket, revocationUncertain, commands }
  const terminal = ['revoked', 'expired', 'committed'].includes(valid.status)
  const sameTicket = ticketMatchesStatus(ticket, valid)
  return {
    ticket: sameTicket && terminal ? null : ticket,
    revocationUncertain: sameTicket && terminal ? false : revocationUncertain,
    commands,
  }
}

export function beginSubmission(ticket) {
  return { ticket: null, lastSubmissionId: ticket.id }
}
