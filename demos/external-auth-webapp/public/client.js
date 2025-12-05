(() => {
  const statusEl = document.getElementById("status");
  const listEl = document.getElementById("list");
  const historyEl = document.getElementById("history");
  const pending = new Map(); // requestId -> <li>

  function setStatus(text) {
    if (statusEl) {
      statusEl.textContent = text;
    }
  }

  const wsProtocol = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${wsProtocol}://${location.host}/ws`);

  ws.onopen = () => {
    setStatus("Connected. Waiting for approvals from acl-proxy…");
  };

  ws.onclose = () => {
    setStatus("WebSocket connection closed.");
  };

  ws.onerror = () => {
    setStatus("WebSocket error.");
  };

  ws.onmessage = (event) => {
    let msg;
    try {
      msg = JSON.parse(event.data);
    } catch {
      return;
    }

    if (msg.type === "pending" && msg.approval) {
      addPending(msg.approval);
    } else if (msg.type === "status" && msg.event) {
      addStatus(msg.event);
    } else if (msg.type === "callbackResult") {
      const li = pending.get(msg.requestId);
      if (li) {
        li.dataset.status = "completed";
        li.append(
          document.createTextNode(
            ` – callback status ${msg.status}${
              msg.error ? ` (${msg.error})` : ""
            }`,
          ),
        );
      }
    } else if (msg.type === "error" && msg.message) {
      setStatus(`Error from server: ${msg.message}`);
    }
  };

  function addPending(approval) {
    const li = document.createElement("li");
    li.dataset.requestId = approval.requestId;
    li.dataset.status = "pending";

    const text = document.createElement("div");
    text.textContent = `${
      approval.method || "GET"
    } ${approval.url} (id: ${approval.requestId}${
      approval.clientIp ? `, client: ${approval.clientIp}` : ""
    })`;

    const buttons = document.createElement("div");

    const approve = document.createElement("button");
    approve.textContent = "Approve";
    approve.onclick = () =>
      sendDecision(approval.requestId, "allow", li);

    const deny = document.createElement("button");
    deny.textContent = "Deny";
    deny.onclick = () =>
      sendDecision(approval.requestId, "deny", li);

    buttons.appendChild(approve);
    buttons.appendChild(deny);

    li.appendChild(text);
    li.appendChild(buttons);
    listEl.appendChild(li);
    pending.set(approval.requestId, li);
  }

  function addStatus(event) {
    if (!historyEl) return;
    const li = document.createElement("li");
    const parts = [];
    parts.push(event.status || "unknown");
    if (event.method && event.url) {
      parts.push(`for ${event.method} ${event.url}`);
    }
    if (event.requestId) {
      parts.push(`id: ${event.requestId}`);
    }
    if (event.reason) {
      parts.push(`reason: ${event.reason}`);
    }
    li.textContent = parts.join(" · ");
    historyEl.appendChild(li);
  }

  function sendDecision(requestId, decision, li) {
    if (ws.readyState !== WebSocket.OPEN) {
      setStatus("Cannot send decision: WebSocket not open.");
      return;
    }
    ws.send(
      JSON.stringify({
        type: "decision",
        requestId,
        decision,
      }),
    );
    li.dataset.status = "sent";
  }
})();
