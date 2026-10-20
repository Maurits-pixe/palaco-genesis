import {
  conversationId as getConversationId,
  displayName,
  loadMessages,
  newConversation,
  saveDisplayName,
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
const nameForm = document.querySelector("[data-name-form]");
const nameInput = nameForm.querySelector("input");
const nameFeedback = nameForm.querySelector("[data-name-feedback]");
const messageSenderId = senderId();
let messageSenderName = displayName();
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
  const label = document.createElement("strong");
  label.textContent = `${record.senderName || "Gast"}${ownMessage ? " · jij" : " · niet geverifieerd"}`;
  const content = document.createElement("p");
  content.textContent = record.content;
  const timestamp = document.createElement("time");
  const date = new Date(record.acceptedAt);
  if (Number.isNaN(date.getTime())) {
    timestamp.textContent = "Tijd onbekend";
  } else {
    timestamp.dateTime = date.toISOString();
    timestamp.textContent = new Intl.DateTimeFormat("nl-NL", {
      hour: "2-digit",
      minute: "2-digit",
    }).format(date);
  }
  message.append(label, content, timestamp);
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

  pending ??= { id: crypto.randomUUID(), content: text, senderName: messageSenderName };
  composer.dataset.sending = "true";
  submitButton.disabled = true;
  feedback.textContent = "Bericht wordt naar de lokale RIO-dienst gestuurd…";
  try {
    const accepted = await sendMessage(conversation, pending.id, messageSenderId, pending.senderName, pending.content);
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

nameInput.value = messageSenderName;
nameForm.addEventListener("submit", (event) => {
  event.preventDefault();
  messageSenderName = saveDisplayName(nameInput.value);
  nameInput.value = messageSenderName;
  nameFeedback.textContent = `Opgeslagen: ${messageSenderName} (niet geverifieerd)`;
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
