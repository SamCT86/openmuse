"""Static page, script, and styles for the local web chat.

Kept as strings so the chat works from an installed wheel without data files.
Planner and tool text is inserted with textContent only; the approval card is
host-rendered, escaped HTML from ``render_approval``.
"""

INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="openmuse-csrf" content="{{csrf}}">
<title>OpenMuse chat</title>
<link rel="icon" href="data:,">
<link rel="stylesheet" href="/app.css">
</head>
<body>
<header>
  <strong>OpenMuse</strong>
  <span class="badge">{{planner}}</span>
  <span class="hint">Reads run. Writes wait for your approval.</span>
</header>
<main id="log" aria-live="polite"></main>
<form id="composer" autocomplete="off">
  <textarea id="input" rows="1" maxlength="4000" placeholder="Message OpenMuse  (try: read README.md)" required></textarea>
  <button id="send" type="submit">Send</button>
</form>
<script src="/app.js"></script>
</body>
</html>
"""

APP_JS = r"""(() => {
  const csrf = document.querySelector('meta[name="openmuse-csrf"]').content;
  const log = document.getElementById("log");
  const form = document.getElementById("composer");
  const input = document.getElementById("input");
  const send = document.getElementById("send");
  const conversation = "web-" + Math.random().toString(36).slice(2, 10);

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function add(node) { log.appendChild(node); log.scrollTop = log.scrollHeight; return node; }
  function bubble(role, text) { return add(el("div", "msg " + role, text)); }

  async function post(path, body) {
    const res = await fetch(path, {
      method: "POST",
      headers: {"Content-Type": "application/json", "X-OpenMuse-CSRF": csrf},
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({error: "invalid response"}));
    if (!res.ok) throw new Error(data.error || res.statusText);
    return data;
  }

  function toolCard(ev) {
    const card = el("div", "tool " + ev.status);
    const head = el("div", "tool-head");
    head.appendChild(el("code", "", ev.tool));
    head.appendChild(el("span", "status", ev.status + (ev.error_code ? " · " + ev.error_code : "")));
    card.appendChild(head);
    card.appendChild(el("code", "args", JSON.stringify(ev.arguments)));
    if (ev.output) card.appendChild(el("pre", "", ev.output));
    add(card);
  }

  function approvalCard(ev) {
    const card = el("section", "approval");
    card.dataset.request = ev.request_id;
    // Host-rendered and escaped by render_approval; never planner text.
    const detail = el("div", "detail");
    detail.innerHTML = ev.html;
    card.appendChild(detail);
    const row = el("div", "actions");
    const approve = el("button", "approve", "Approve exact action");
    const deny = el("button", "deny", "Deny");
    const decide = async (decision) => {
      approve.disabled = deny.disabled = true;
      try {
        const data = await post("/api/approvals", {request_id: ev.request_id, session: ev.session, decision});
        render(data.events);
      } catch (err) {
        bubble("error", "Decision rejected: " + err.message);
      }
    };
    approve.addEventListener("click", () => decide("approved"));
    deny.addEventListener("click", () => decide("denied"));
    row.appendChild(approve);
    row.appendChild(deny);
    card.appendChild(row);
    add(card);
  }

  function render(events) {
    for (const ev of events) {
      if (ev.type === "message") bubble("assistant", ev.text);
      else if (ev.type === "tool") toolCard(ev);
      else if (ev.type === "approval") approvalCard(ev);
      else if (ev.type === "decision") {
        const card = log.querySelector('[data-request="' + ev.request_id + '"]');
        if (card) { card.classList.add(ev.status); card.querySelector(".actions").replaceChildren(el("span", "status", ev.status)); }
      }
    }
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = input.value.trim();
    if (!text) return;
    bubble("user", text);
    input.value = "";
    send.disabled = true;
    const typing = bubble("assistant typing", "…");
    try {
      const data = await post("/api/chat", {conversation_id: conversation, text});
      typing.remove();
      render(data.events);
    } catch (err) {
      typing.remove();
      bubble("error", err.message);
    } finally {
      send.disabled = false;
      input.focus();
    }
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); form.requestSubmit(); }
  });
  bubble("assistant", "Hi. Ask me to read, write, or fetch something. Anything that changes a file stops here for your approval first.");
  input.focus();
})();
"""

APP_CSS = """
* { box-sizing: border-box; }
html, body { height: 100%; }
body { margin: 0; display: flex; flex-direction: column; background: #0d1117; color: #e6edf3; font: 15px/1.5 system-ui, sans-serif; }
header { display: flex; gap: 12px; align-items: center; padding: 12px 20px; border-bottom: 1px solid #30363d; background: #161b22; }
.badge { font-size: 12px; padding: 2px 8px; border: 1px solid #30363d; border-radius: 999px; color: #8b949e; }
.hint { margin-left: auto; font-size: 13px; color: #8b949e; }
#log { flex: 1; overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 10px; max-width: 820px; width: 100%; margin: 0 auto; }
.msg { max-width: 80%; padding: 10px 14px; border-radius: 14px; white-space: pre-wrap; overflow-wrap: anywhere; }
.msg.user { align-self: flex-end; background: #1f6feb; color: #fff; }
.msg.assistant { align-self: flex-start; background: #21262d; }
.msg.typing { color: #8b949e; }
.msg.error { align-self: flex-start; background: #3d1418; color: #ffa198; }
.tool { align-self: flex-start; width: 90%; border: 1px solid #30363d; border-radius: 10px; padding: 10px 12px; background: #0f141a; }
.tool.completed { border-left: 3px solid #238636; }
.tool.failed, .tool.blocked { border-left: 3px solid #da3633; }
.tool-head { display: flex; justify-content: space-between; gap: 8px; }
.status { color: #8b949e; font-size: 13px; }
.args { display: block; color: #8b949e; font-size: 12px; margin-top: 4px; overflow-wrap: anywhere; }
pre { margin: 8px 0 0; max-height: 280px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; font-size: 13px; }
.approval { align-self: stretch; border: 1px solid #d29922; border-radius: 12px; padding: 4px 16px 14px; background: #1c1a12; }
.approval main { all: unset; display: block; }
.approval h1 { font-size: 16px; margin: 10px 0; }
.approval table { border-collapse: collapse; width: 100%; margin: 8px 0; }
.approval th, .approval td { border-bottom: 1px solid #30363d; padding: 6px 8px; text-align: left; vertical-align: top; white-space: pre-wrap; overflow-wrap: anywhere; }
.approval th { width: 28%; color: #8b949e; }
.approval.approved { border-color: #238636; }
.approval.denied { border-color: #6e7681; opacity: .75; }
.actions { display: flex; gap: 8px; margin-top: 8px; }
button { border: 0; border-radius: 8px; padding: 9px 16px; font-weight: 600; cursor: pointer; }
button:disabled { opacity: .5; cursor: default; }
.approve { background: #238636; color: #fff; }
.deny { background: #da3633; color: #fff; }
#composer { display: flex; gap: 8px; padding: 12px 20px 20px; max-width: 820px; width: 100%; margin: 0 auto; }
#input { flex: 1; resize: none; min-height: 44px; max-height: 160px; padding: 11px 14px; border-radius: 12px; border: 1px solid #30363d; background: #0d1117; color: inherit; font: inherit; }
#send { background: #1f6feb; color: #fff; }
"""
