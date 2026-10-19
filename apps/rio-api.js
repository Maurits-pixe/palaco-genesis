const STORAGE_KEY = "rio-preview-conversation-id";
let fallbackConversationId;

function newId() {
  if (!globalThis.crypto?.randomUUID) {
    throw new Error("Deze browser ondersteunt geen veilige demo-ID's.");
  }
  return globalThis.crypto.randomUUID();
}

export function conversationId() {
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

export async function sendMessage(id, messageId, content) {
  const result = await request("/api/messages", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ conversationId: id, messageId, content }),
  });
  return result.message;
}
