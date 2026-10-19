const transcript = document.querySelector("[data-transcript]");
const composer = document.querySelector("[data-composer]");
const input = composer.querySelector("input");
const feedback = document.querySelector("[data-feedback]");

function addMessage(text, isUser) {
  const message = document.createElement("div");
  message.className = isUser ? "message user" : "message";

  if (!isUser) {
    const avatar = document.createElement("span");
    avatar.className = "avatar";
    avatar.textContent = "R";
    message.append(avatar);
  }

  const content = isUser ? message : document.createElement("div");
  if (!isUser) {
    const label = document.createElement("strong");
    label.textContent = "RIO · DEMO";
    content.append(label);
  }

  const paragraph = document.createElement("p");
  paragraph.textContent = text;
  content.append(paragraph);
  if (!isUser) message.append(content);
  transcript.append(message);
}

composer.addEventListener("submit", (event) => {
  event.preventDefault();
  const text = input.value.trim();
  if (!text) return;

  addMessage(text, true);
  addMessage("Dank je. Dit is een vaste voorbeeldreactie; deze preview gebruikt geen AI of externe dienst.", false);
  input.value = "";
  feedback.textContent = "Demo-bericht toegevoegd. Er is niets verstuurd of opgeslagen.";
  input.focus();
});

document.querySelectorAll("[data-prompt]").forEach((button) => {
  button.addEventListener("click", () => {
    input.value = button.dataset.prompt;
    input.focus();
  });
});

document.querySelector("[data-reset]").addEventListener("click", () => {
  transcript.replaceChildren(document.querySelector("#conversation-start").content.cloneNode(true));
  feedback.textContent = "Nieuw lokaal demo-gesprek gestart.";
  input.value = "";
  input.focus();
});
