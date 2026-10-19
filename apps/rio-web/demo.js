import { conversationId, loadMessages, sendMessage } from "../rio-api.js";

const transcript = document.querySelector("[data-transcript]");
const composer = document.querySelector("[data-composer]");
const input = composer.querySelector("input");
const feedback = document.querySelector("[data-feedback]");
const conversation = conversationId();
let pending = null;
let initialized = false;

function renderMessage(record) {
  const message = document.createElement("div");
  message.dataset.messageId = record.id;
  message.className = "message user";
  const paragraph = document.createElement("p");
  paragraph.textContent = record.content;
  message.append(paragraph);
  transcript.append(message);
}

async function refreshMessages() {
  try {
    const messages = await loadMessages(conversation);
    transcript.replaceChildren();
    messages.forEach(renderMessage);
    feedback.textContent = messages.length
      ? `${messages.length} lokaal geaccepteerd bericht${messages.length === 1 ? "" : "en"}.`
      : "Verbonden met de lokale berichtendienst. Je berichten worden alleen tijdelijk in het geheugen bewaard.";
  } catch (error) {
    feedback.textContent = error.message;
  } finally {
    initialized = true;
    composer.querySelector("button[type=submit]").disabled = false;
  }
}

input.addEventListener("input", () => {
  if (pending && input.value.trim() !== pending.content) pending = null;
});

composer.addEventListener("submit", async (event) => {
  event.preventDefault();
  const text = input.value.trim();
  if (!text || !initialized || composer.dataset.sending === "true") return;

  pending ??= { id: crypto.randomUUID(), content: text };
  composer.dataset.sending = "true";
  composer.querySelector("button[type=submit]").disabled = true;
  feedback.textContent = "Bericht wordt naar de lokale RIO-dienst gestuurd…";
  try {
    const accepted = await sendMessage(conversation, pending.id, pending.content);
    if (!transcript.querySelector(`[data-message-id="${accepted.id}"]`)) {
      const rendered = document.createElement("div");
      rendered.dataset.messageId = accepted.id;
      rendered.className = "message user";
      const paragraph = document.createElement("p");
      paragraph.textContent = accepted.content;
      rendered.append(paragraph);
      transcript.append(rendered);
    }
    pending = null;
    input.value = "";
    feedback.textContent = "Bericht is door de lokale dienst geaccepteerd. Opslag is alleen tijdelijk in het geheugen.";
  } catch (error) {
    feedback.textContent = `${error.message} Opnieuw verzenden met dezelfde tekst gebruikt dezelfde verzoek-ID.`;
  } finally {
    composer.dataset.sending = "false";
    composer.querySelector("button[type=submit]").disabled = false;
    input.focus();
  }
});

document.querySelector("[data-reset]").addEventListener("click", () => {
  try {
    sessionStorage.removeItem("rio-preview-conversation-id");
  } catch {
    // The in-memory fallback is replaced by reloading the page.
  }
  window.location.reload();
});

document.querySelectorAll("[data-prompt]").forEach((button) => {
  button.addEventListener("click", () => {
    input.value = button.dataset.prompt;
    input.dispatchEvent(new Event("input"));
    input.focus();
  });
});

composer.querySelector("button[type=submit]").disabled = true;
refreshMessages();
