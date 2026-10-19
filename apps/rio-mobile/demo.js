import { conversationId, loadMessages, sendMessage } from "../rio-api.js";

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
const conversation = conversationId();
let pending = null;
let initialized = false;

function renderMessage(record) {
  const message = document.createElement("div");
  message.className = "mobile-message";
  message.dataset.messageId = record.id;
  message.textContent = record.content;
  transcript.append(message);
}

async function refreshMessages() {
  try {
    const messages = await loadMessages(conversation);
    transcript.replaceChildren();
    messages.forEach(renderMessage);
    feedback.textContent = messages.length
      ? `${messages.length} lokaal geaccepteerd bericht${messages.length === 1 ? "" : "en"}.`
      : "Verbonden met de lokale berichtendienst. Berichten worden tijdelijk in het geheugen bewaard.";
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
    if (!transcript.querySelector(`[data-message-id="${accepted.id}"]`)) renderMessage(accepted);
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

composer.querySelector("button[type=submit]").disabled = true;
refreshMessages();
