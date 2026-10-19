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

composer.addEventListener("submit", (event) => {
  event.preventDefault();
  const text = input.value.trim();
  if (!text) return;

  const message = document.createElement("div");
  message.className = "mobile-message";
  message.textContent = text;
  transcript.append(message);

  const reply = document.createElement("div");
  reply.className = "mobile-reply";
  const mark = document.createElement("span");
  mark.className = "brand-mark";
  mark.textContent = "R";
  const response = document.createElement("span");
  response.textContent = "Dit is een vaste demo-reactie; deze preview gebruikt geen AI of externe dienst.";
  reply.append(mark, response);
  transcript.append(reply);

  input.value = "";
  feedback.textContent = "Demo-bericht toegevoegd. Er is niets verstuurd of opgeslagen.";
  input.focus();
});
