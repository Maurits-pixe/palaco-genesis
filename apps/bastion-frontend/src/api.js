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
export const commandLength = (value) => value.length

function validId(id) {
  return typeof id === 'string' && /^[a-zA-Z0-9_-]{1,200}$/.test(id)
}

export function timestamp(value) {
  if (typeof value !== 'string' && typeof value !== 'number') return NaN
  return typeof value === 'number' ? value : Date.parse(value)
}

export function ticketUsable(ticket, command, now = Date.now()) {
  return !!ticket && ticket.command === command &&
    now >= timestamp(ticket.not_before) && now < timestamp(ticket.expires_at)
}

export async function request(path, { token, method = 'GET', body, fetcher = fetch, timeoutMs = 8000 }) {
  if (typeof token !== 'string' || !token.trim() || /[\r\n]/.test(token)) {
    throw new ApiError('Vul een geldig toegangstoken in.')
  }
  if (!/^\/v1\/(?:commands|tickets(?:\/[a-zA-Z0-9_-]{1,200})?)$/.test(path)) {
    throw new ApiError('Ongeldig serviceadres.')
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

export async function issueTicket(command, ttlMs, token, fetcher) {
  if (typeof command !== 'string' || !command.trim() ||
      !Number.isInteger(ttlMs) || ttlMs < 1 || ttlMs > 60_000) {
    throw new ApiError('Vul een commando en een gehele geldigheidsduur van 1 t/m 60000 ms in.')
  }
  if (commandLength(command) > MAX_COMMAND_LENGTH) throw new ApiError('Een commando mag maximaal 1024 UTF-16-tekeneenheden bevatten.')
  const result = await request('/v1/tickets', {
    token, method: 'POST', body: { command, ttl_ms: ttlMs }, fetcher,
  })
  if (!validId(result?.id) || !Number.isFinite(timestamp(result?.not_before)) ||
      !Number.isFinite(timestamp(result?.expires_at)) ||
      timestamp(result.expires_at) <= timestamp(result.not_before)) {
    throw new ApiError('Onverwacht ticketantwoord van de service.')
  }
  return { id: result.id, command, not_before: result.not_before, expires_at: result.expires_at }
}

function validCommand(value) {
  return value && validId(value.id) && typeof value.command === 'string' &&
    commandLength(value.command) <= MAX_COMMAND_LENGTH &&
    Number.isFinite(timestamp(value.committed_at))
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

export async function commitCommand(ticket, command, token, fetcher) {
  if (!validId(ticket?.id) || !ticketUsable(ticket, command)) {
    throw new ApiError('Ticket niet geldig voor dit commando. Vraag een nieuw ticket aan.')
  }
  if (commandLength(command) > MAX_COMMAND_LENGTH) throw new ApiError('Een commando mag maximaal 1024 UTF-16-tekeneenheden bevatten.')
  const result = await request('/v1/commands', {
    token, method: 'POST', body: { ticket_id: ticket.id, command }, fetcher,
  })
  if (!validCommand(result) || result.command !== command) {
    throw new ApiError('Onverwacht commandoantwoord van de service.')
  }
  return { id: result.id, command: result.command, committed_at: result.committed_at }
}

export async function listCommands(token, fetcher) {
  const result = await request('/v1/commands', { token, fetcher })
  if (!Array.isArray(result?.commands) || !result.commands.every(validCommand)) {
    throw new ApiError('Onverwacht logboekantwoord van de service.')
  }
  return result.commands.slice(0, 100).map(({ id, command, committed_at }) => ({ id, command, committed_at }))
}
