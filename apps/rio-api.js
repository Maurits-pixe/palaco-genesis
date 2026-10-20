const STORAGE_KEY = "rio-preview-conversation-id";
const SENDER_KEY = "rio-preview-sender-id";
const DISPLAY_NAME_KEY = "rio-preview-display-name";
const CONVERSATION_PARAM = "conversation";
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
let fallbackConversationId;
let fallbackSenderId;

function newId() {
  if (!globalThis.crypto?.randomUUID) {
    throw new Error("Deze browser ondersteunt geen veilige demo-ID's.");
  }
  return globalThis.crypto.randomUUID();
}

export function conversationId() {
  const sharedId = new URL(window.location.href).searchParams.get(CONVERSATION_PARAM);
  if (sharedId && UUID_PATTERN.test(sharedId)) {
    try {
      sessionStorage.setItem(STORAGE_KEY, sharedId);
    } catch {
      fallbackConversationId = sharedId;
    }
    return sharedId;
  }

  try {
    let id = sessionStorage.getItem(STORAGE_KEY);
    if (!id) {
      id = newId();
      sessionStorage.setItem(STORAGE_KEY, id);
    }
    return id;
  } catch {
    fallbackConversationId ??= newId();
    return fallbackConversationId;
  }
}

export function newConversation() {
  const id = newId();
  try {
    sessionStorage.setItem(STORAGE_KEY, id);
  } catch {
    fallbackConversationId = id;
  }
  const url = new URL(window.location.href);
  url.searchParams.delete(CONVERSATION_PARAM);
  window.history.replaceState(null, "", url);
  return id;
}

export function senderId() {
  try {
    let id = sessionStorage.getItem(SENDER_KEY);
    if (!id) {
      id = newId();
      sessionStorage.setItem(SENDER_KEY, id);
    }
    return id;
  } catch {
    fallbackSenderId ??= newId();
    return fallbackSenderId;
  }
}

export function displayName() {
  try {
    return sessionStorage.getItem(DISPLAY_NAME_KEY) || "Gast";
  } catch {
    return "Gast";
  }
}

export function saveDisplayName(value) {
  const normalized = value.trim().replace(/\s+/g, " ").slice(0, 32);
  try {
    if (normalized) sessionStorage.setItem(DISPLAY_NAME_KEY, normalized);
    else sessionStorage.removeItem(DISPLAY_NAME_KEY);
  } catch {
    return normalized || "Gast";
  }
  return normalized || "Gast";
}

export async function shareConversation(id) {
  const url = new URL(window.location.href);
  url.searchParams.set(CONVERSATION_PARAM, id);
  window.history.replaceState(null, "", url);
  try {
    await navigator.clipboard.writeText(url.href);
    return "Gesprekslink gekopieerd. Iedereen met deze link kan dit lokale gesprek lezen; deelnemers zijn niet geauthenticeerd.";
  } catch {
    return `Deel alleen met iemand die je vertrouwt. Gesprekslink: ${url.href}`;
  }
}

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(path, {
      ...options,
      cache: "no-store",
      credentials: "omit",
      signal: AbortSignal.timeout(10_000),
      headers: { accept: "application/json", ...options.headers },
    });
  } catch {
    throw new Error("RIO-berichtendienst niet bereikbaar. Start de lokale dienst om berichten te laden en versturen.");
  }

  let result;
  try {
    result = await response.json();
  } catch {
    throw new Error("De berichtendienst gaf een ongeldig antwoord.");
  }
  if (!response.ok) {
    throw new Error(result.error ?? "Bericht kon niet worden geaccepteerd.");
  }
  return result;
}

export async function loadMessages(id) {
  const result = await request(`/api/messages?conversationId=${encodeURIComponent(id)}`);
  return result.messages;
}

export async function sendMessage(id, messageId, senderId, senderName, content) {
  const result = await request("/api/messages", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ conversationId: id, messageId, senderId, senderName, content }),
  });
  return result.message;
}
