import http from "http";

import express from "express";
import { WebSocketServer, WebSocket } from "ws";

type PendingApproval = {
  requestId: string;
  profile: string;
  ruleIndex: number;
  url: string;
  method?: string | null;
  clientIp?: string | null;
};

type StatusEvent = {
  requestId: string;
  profile?: string;
  ruleIndex?: number;
  ruleId?: string | null;
  url?: string;
  method?: string | null;
  clientIp?: string | null;
  status: string;
  reason?: string | null;
  timestamp?: string;
  elapsedMs?: number;
  terminal?: boolean;
  eventId?: string;
  failureKind?: string | null;
  httpStatus?: number | null;
};

type WebsocketMessage =
  | {
      type: "decision";
      requestId: string;
      decision: "allow" | "deny";
    }
  | { type: string; [key: string]: unknown };

const app = express();
app.use(express.json());

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: "/ws" });

// In-memory pending approvals keyed by requestId.
const pending = new Map<string, PendingApproval>();

// Base URL for the acl-proxy HTTP listener, used to call the callback endpoint.
// For example: http://localhost:8881
const PROXY_BASE =
  process.env.ACL_PROXY_BASE ?? "http://localhost:8881";
const CALLBACK_URL = `${PROXY_BASE}/_acl-proxy/external-auth/callback`;

// Serve static UI.
// This assumes the process is started with CWD = demos/external-auth-webapp.
app.use(express.static("public"));

// Webhook endpoint that acl-proxy calls when an approval-required rule matches.
app.post("/webhook", (req, res) => {
  const eventTypeHeader =
    (req.header("x-acl-proxy-event") ?? "").toLowerCase();

  const body = req.body as {
    requestId?: string;
    profile?: string;
    ruleIndex?: number;
    url?: string;
    method?: string;
    clientIp?: string;
    status?: string;
    reason?: string;
    ruleId?: string;
    timestamp?: string;
    elapsedMs?: number;
    terminal?: boolean;
    eventId?: string;
    failureKind?: string;
    httpStatus?: number;
  };

  const {
    requestId,
    profile,
    ruleIndex,
    url,
    method,
    clientIp,
    status,
    reason,
    ruleId,
    timestamp,
    elapsedMs,
    terminal,
    eventId,
    failureKind,
    httpStatus,
  } = body;

  const eventType =
    eventTypeHeader === "status" || status === "webhook_failed" ||
    status === "timed_out" || status === "error" ||
    status === "cancelled"
      ? "status"
      : "pending";

  if (eventType === "status") {
    if (!requestId || !status) {
      return res.status(400).json({
        error: "InvalidStatusWebhook",
        message:
          "Missing requestId or status in lifecycle webhook payload",
      });
    }

    const statusEvent: StatusEvent = {
      requestId,
      profile: profile ?? "",
      ruleIndex,
      ruleId: ruleId ?? null,
      url,
      method: method ?? null,
      clientIp: clientIp ?? null,
      status,
      reason: reason ?? null,
      timestamp,
      elapsedMs,
      terminal,
      eventId,
      failureKind: failureKind ?? null,
      httpStatus: httpStatus ?? null,
    };

    const msg = JSON.stringify({
      type: "status",
      event: statusEvent,
    });
    wss.clients.forEach((ws) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(msg);
      }
    });

    return res.json({ status: "accepted" });
  }

  if (!requestId || !url || typeof ruleIndex !== "number") {
    return res.status(400).json({
      error: "InvalidWebhook",
      message:
        "Missing or invalid requestId, url, or ruleIndex in webhook payload",
    });
  }

  const approval: PendingApproval = {
    requestId,
    profile: profile ?? "",
    ruleIndex,
    url,
    method: method ?? null,
    clientIp: clientIp ?? null,
  };
  pending.set(requestId, approval);

  const msg = JSON.stringify({ type: "pending", approval });
  wss.clients.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(msg);
    }
  });

  res.json({ status: "accepted" });
});

// WebSocket handling for browser clients.
wss.on("connection", (ws) => {
  // On connect, send the current pending list.
  for (const approval of pending.values()) {
    ws.send(JSON.stringify({ type: "pending", approval }));
  }

  ws.on("message", async (data) => {
    let msg: WebsocketMessage;
    try {
      msg = JSON.parse(String(data));
    } catch {
      ws.send(
        JSON.stringify({
          type: "error",
          message: "Invalid JSON message",
        }),
      );
      return;
    }

    if (
      msg.type === "decision" &&
      typeof msg.requestId === "string" &&
      (msg.decision === "allow" || msg.decision === "deny")
    ) {
      const { requestId, decision } = msg;
      const approval = pending.get(requestId);

      if (!approval) {
        ws.send(
          JSON.stringify({
            type: "error",
            message: "Unknown requestId",
          }),
        );
        return;
      }

      pending.delete(requestId);

      try {
        const resp = await fetch(CALLBACK_URL, {
          method: "POST",
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({
            requestId,
            decision,
          }),
        });

        ws.send(
          JSON.stringify({
            type: "callbackResult",
            requestId,
            status: resp.status,
          }),
        );
      } catch (err) {
        ws.send(
          JSON.stringify({
            type: "callbackResult",
            requestId,
            status: 0,
            error:
              err instanceof Error ? err.message : "Unknown error",
          }),
        );
      }
    } else {
      ws.send(
        JSON.stringify({
          type: "error",
          message: "Unsupported message type",
        }),
      );
    }
  });
});

const PORT = Number(process.env.PORT ?? 3000);

server.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(
    `External auth webapp listening on http://localhost:${PORT}`,
  );
  // eslint-disable-next-line no-console
  console.log(
    `Expecting acl-proxy callbacks at ${CALLBACK_URL}`,
  );
});
