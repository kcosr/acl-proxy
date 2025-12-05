(() => {
  const statusEl = document.getElementById("status");
  const activeListEl = document.getElementById("active-list");
  const inactiveListEl = document.getElementById("inactive-list");
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
    // eslint-disable-next-line no-console
    console.log("[ws:client] open");
  };

  ws.onclose = () => {
    setStatus("WebSocket connection closed.");
    // eslint-disable-next-line no-console
    console.log("[ws:client] close");
  };

  ws.onerror = (event) => {
    setStatus("WebSocket error.");
    // eslint-disable-next-line no-console
    console.log("[ws:client] error", event);
  };

  ws.onmessage = (event) => {
    // eslint-disable-next-line no-console
    console.log("[ws:client] message", event.data);

    let msg;
    try {
      msg = JSON.parse(event.data);
    } catch {
      return;
    }

    // eslint-disable-next-line no-console
    console.log("[ws:client] message parsed", msg);

    if (msg.type === "pending" && msg.approval) {
      addPending(msg.approval);
    } else if (msg.type === "status" && msg.event) {
      handleStatus(msg.event);
    } else if (msg.type === "callbackResult") {
      handleCallbackResult(msg);
    } else if (msg.type === "error" && msg.message) {
      setStatus(`Error from server: ${msg.message}`);
    }
  };

  function addPending(approval) {
    if (!activeListEl) return;

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
    activeListEl.appendChild(li);
    pending.set(approval.requestId, li);
  }

  function handleStatus(event) {
    const li = pending.get(event.requestId);

    const resultLabel = (() => {
      switch (event.status) {
        case "timed_out":
          return "timed out";
        case "cancelled":
          return "cancelled";
        case "error":
          return "error";
        case "webhook_failed":
          return "webhook failed";
        default:
          return event.status || "completed";
      }
    })();

    if (li) {
      moveToInactive(li, {
        summary: resultLabel,
        reason: event.reason,
      });
      pending.delete(event.requestId);
      return;
    }

    if (!inactiveListEl) return;
    const item = document.createElement("li");
    const parts = [];
    parts.push(resultLabel);
    if (event.method && event.url) {
      parts.push(`for ${event.method} ${event.url}`);
    }
    if (event.requestId) {
      parts.push(`id: ${event.requestId}`);
    }
    if (event.reason) {
      parts.push(`reason: ${event.reason}`);
    }
    item.textContent = parts.join(" · ");
    inactiveListEl.appendChild(item);
  }

  function handleCallbackResult(msg) {
    const li = pending.get(msg.requestId);
    if (!li) return;

    const decision = li.dataset.decision;
    const label =
      decision === "allow"
        ? "approved"
        : decision === "deny"
        ? "denied"
        : "completed";

    moveToInactive(li, {
      summary: `${label} (callback ${msg.status})`,
      reason: msg.error || null,
    });
    pending.delete(msg.requestId);
  }

  function moveToInactive(li, info) {
    if (!inactiveListEl) return;

    li.dataset.status = "inactive";

    const buttons = li.querySelector("button")?.parentElement;
    if (buttons) {
      buttons.remove();
    }

    const textDiv = li.querySelector("div");
    const parts = [];
    if (textDiv && textDiv.textContent) {
      parts.push(textDiv.textContent);
    }
    if (info.summary) {
      parts.push(`result: ${info.summary}`);
    }
    if (info.reason) {
      parts.push(`reason: ${info.reason}`);
    }
    if (textDiv) {
      textDiv.textContent = parts.join(" · ");
    } else if (parts.length > 0) {
      li.textContent = parts.join(" · ");
    }

    inactiveListEl.appendChild(li);
  }

  function sendDecision(requestId, decision, li) {
    if (ws.readyState !== WebSocket.OPEN) {
      setStatus("Cannot send decision: WebSocket not open.");
      return;
    }
    const payload = {
      type: "decision",
      requestId,
      decision,
    };
    // eslint-disable-next-line no-console
    console.log("[ws:client] send decision", payload);
    ws.send(JSON.stringify(payload));
    li.dataset.status = "sent";
    li.dataset.decision = decision;
  }
})();
