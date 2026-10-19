import {
  conversationId as getConversationId,
  loadMessages,
  newConversation,
  sendMessage,
  senderId,
  shareConversation,
} from "../rio-api.js";

const tabs = [...document.querySelectorAll('[role="tab"]')];
const panels = tabs.map((tab) => document.getElementById(tab.getAttribute("aria-controls")));

function selectTab(selectedTab) {
  tabs.forEach((tab, index) => {
    const selected = tab === selectedTab;
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
    panels[index].hidden = !selected;
    tab.classList.toggle("active", selected);
  });
}

tabs.forEach((tab, index) => {
  tab.addEventListener("click", () => selectTab(tab));
  tab.addEventListener("keydown", (event) => {
    const offset = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
    if (!offset) return;
    event.preventDefault();
    const next = tabs[(index + offset + tabs.length) % tabs.length];
    selectTab(next);
    next.focus();
  });
});

const transcript = document.querySelector("[data-transcript]");
const composer = document.querySelector("[data-composer]");
const input = composer.querySelector("input");
const feedback = document.querySelector("[data-feedback]");
const submitButton = composer.querySelector("button[type=submit]");
const messageSenderId = senderId();
let conversation = getConversationId();
let pending = null;
let initialized = false;
let refreshing = false;

function renderMessage(record) {
  if (transcript.querySelector(`[data-message-id="${record.id}"]`)) return;
  const ownMessage = record.senderId === messageSenderId;
  const message = document.createElement("div");
  message.dataset.messageId = record.id;
  message.className = ownMessage ? "mobile-message" : "mobile-message received";
  message.textContent = record.content;
  transcript.append(message);
}

async function refreshMessages() {
  if (refreshing) return;
  refreshing = true;
  try {
    const messages = await loadMessages(conversation);
    messages.forEach(renderMessage);
    feedback.textContent = messages.length
      ? `${messages.length} lokaal geaccepteerd bericht${messages.length === 1 ? "" : "en"}.`
      : "Verbonden met de lokale berichtendienst. Berichten worden tijdelijk in het geheugen bewaard.";
  } catch (error) {
    feedback.textContent = error.message;
  } finally {
    initialized = true;
    refreshing = false;
    submitButton.disabled = false;
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
  submitButton.disabled = true;
  feedback.textContent = "Bericht wordt naar de lokale RIO-dienst gestuurd…";
  try {
    const accepted = await sendMessage(conversation, pending.id, messageSenderId, pending.content);
    renderMessage(accepted);
    pending = null;
    input.value = "";
    feedback.textContent = "Bericht is door de lokale dienst geaccepteerd. Opslag is alleen tijdelijk in het geheugen.";
  } catch (error) {
    feedback.textContent = `${error.message} Opnieuw verzenden met dezelfde tekst gebruikt dezelfde verzoek-ID.`;
  } finally {
    composer.dataset.sending = "false";
    submitButton.disabled = false;
    input.focus();
  }
});

document.querySelector("[data-reset]").addEventListener("click", () => {
  conversation = newConversation();
  transcript.replaceChildren();
  pending = null;
  input.value = "";
  feedback.textContent = "Nieuw lokaal gesprek gestart.";
  refreshMessages();
});

document.querySelector("[data-share]").addEventListener("click", async () => {
  feedback.textContent = await shareConversation(conversation);
});

submitButton.disabled = true;
refreshMessages();
window.setInterval(() => {
  if (!document.hidden) refreshMessages();
}, 2500);
