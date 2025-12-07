import http from "http";
import express from "express";

type MacroDescriptor = {
  name: string;
  label?: string | null;
  required?: boolean;
  secret?: boolean;
};

type PendingWebhookEvent = {
  requestId: string;
  profile: string;
  ruleIndex: number;
  url: string;
  method?: string | null;
  clientIp?: string | null;
  callbackUrl?: string | null;
  macros: MacroDescriptor[];
};

type StatusEvent = {
  requestId: string;
  status: string;
  terminal?: boolean;
  reason?: string | null;
};

type AclProxyWebhookBody = {
  requestId?: string;
  profile?: string;
  ruleIndex?: number;
  url?: string;
  method?: string;
  clientIp?: string;
  callbackUrl?: string;
  status?: string;
  reason?: string;
  ruleId?: string;
  timestamp?: string;
  elapsedMs?: number;
  terminal?: boolean;
  eventId?: string;
  failureKind?: string;
  httpStatus?: number;
  macros?: MacroDescriptor[];
};

type TermStationNotificationAction = {
  key: string;
  label: string;
  style?: "primary" | "secondary" | "danger";
  requires_inputs?: string[];
};

type TermStationNotificationInput = {
  id: string;
  label: string;
  type: "string" | "secret";
  required: boolean;
  placeholder?: string;
  max_length?: number;
};

type TermStationNotificationPayload = {
  type?: "info" | "warning" | "error" | "success";
  title: string;
  message: string;
  sound?: boolean;
  session_id?: string | null;
  actions?: TermStationNotificationAction[];
  inputs?: TermStationNotificationInput[];
  callback_url?: string;
  callback_method?: "POST" | "PUT" | "PATCH";
  callback_headers?: Record<string, string>;
};

type TermStationCallbackBody = {
  notification_id?: string;
  user?: string;
  action?: string;
  action_label?: string | null;
  inputs?: Record<string, unknown>;
  session_id?: string | null;
  title?: string;
  message?: string;
  timestamp?: string;
};

type PendingRequestState = {
  callbackUrl: string;
  macros: MacroDescriptor[];
  notificationId?: string | null;
};

const app = express();
app.use(express.json());

const server = http.createServer(app);

// Base URL that TermStation should use when calling back into this adapter.
// Defaults to http://localhost:${PORT}
const PORT = Number(process.env.PORT ?? 3000);
const ADAPTER_PUBLIC_BASE_URL =
  process.env.ADAPTER_PUBLIC_BASE_URL ?? `http://localhost:${PORT}`;

// TermStation notifications endpoint and auth
const TERMSTATION_NOTIFICATIONS_URL =
  process.env.TERMSTATION_NOTIFICATIONS_URL ??
  "http://localhost:6624/api/notifications";
const TERMSTATION_BASIC_USER =
  process.env.TERMSTATION_BASIC_USER ?? "webhooks";
const TERMSTATION_BASIC_PASS =
  process.env.TERMSTATION_BASIC_PASS ?? "webhoooks";

// In-memory map of pending approvals keyed by requestId.
const pendingRequests = new Map<string, PendingRequestState>();

function basicAuthHeader(username: string, password: string): string {
  const token = Buffer.from(`${username}:${password}`, "utf8").toString(
    "base64",
  );
  return `Basic ${token}`;
}

function normalizePendingWebhook(body: AclProxyWebhookBody): PendingWebhookEvent {
  const {
    requestId,
    profile,
    ruleIndex,
    url,
    method,
    clientIp,
    callbackUrl,
    macros,
  } = body;

  if (
    !requestId ||
    typeof requestId !== "string" ||
    !url ||
    typeof url !== "string" ||
    typeof ruleIndex !== "number"
  ) {
    throw new Error(
      "Missing or invalid requestId, url, or ruleIndex in webhook payload",
    );
  }

  const normalized: PendingWebhookEvent = {
    requestId,
    profile: profile ?? "",
    ruleIndex,
    url,
    method: method ?? null,
    clientIp: clientIp ?? null,
    callbackUrl: callbackUrl ?? null,
    macros: Array.isArray(macros) ? macros : [],
  };

  return normalized;
}

function normalizeStatusEvent(body: AclProxyWebhookBody): StatusEvent {
  const { requestId, status, terminal, reason } = body;
  if (!requestId || typeof requestId !== "string" || !status) {
    throw new Error(
      "Missing requestId or status in lifecycle webhook payload",
    );
  }
  return {
    requestId,
    status,
    terminal,
    reason: reason ?? null,
  };
}

type TermStationNotificationObject = {
  id?: string;
};

type TermStationNotificationCreateResponse = {
  ok?: boolean;
  notification?: TermStationNotificationObject;
} & TermStationNotificationObject;

function extractNotificationIdFromCreateResponse(
  body: unknown,
): string | null {
  if (!body || typeof body !== "object") {
    return null;
  }

  const topLevel = body as TermStationNotificationCreateResponse;
  if (topLevel.notification && typeof topLevel.notification.id === "string") {
    return topLevel.notification.id;
  }

  if (typeof topLevel.id === "string") {
    return topLevel.id;
  }

  return null;
}

function buildTermStationCancelUrl(notificationId: string): string {
  const base = TERMSTATION_NOTIFICATIONS_URL.replace(/\/+$/, "");
  return `${base}/${encodeURIComponent(notificationId)}/cancel`;
}

function selectGithubTokenMacro(macros: MacroDescriptor[]): MacroDescriptor | null {
  if (!Array.isArray(macros) || macros.length === 0) {
    return null;
  }
  const byName = macros.find((m) => m && m.name === "github_token");
  if (byName) return byName;
  return macros[0];
}

async function createTermStationNotification(
  ev: PendingWebhookEvent,
): Promise<string | null> {
  const tokenMacro = selectGithubTokenMacro(ev.macros);

  // Build interactive metadata for TermStation:
  // - When a macro is present (e.g., github_token), require it for Approve.
  // - When no macro is present, still allow Approve/Deny with no inputs.
  const inputs: TermStationNotificationInput[] = [];
  const actions: TermStationNotificationAction[] = [];

  let inputId: string | null = null;

  if (tokenMacro) {
    inputId = tokenMacro.name;
    inputs.push({
      id: inputId,
      label: "Token",
      type: tokenMacro.secret ? "secret" : "secret",
      required: false,
    });
  }

  const allowAction: TermStationNotificationAction = {
    key: "allow",
    label: "Approve",
    style: "primary",
  };
  if (inputId) {
    allowAction.requires_inputs = [inputId];
  }
  actions.push(allowAction);

  actions.push({
    key: "deny",
    label: "Deny",
    style: "secondary",
  });

  const method = ev.method ?? "GET";
  const title = "Agent needs your permission";
  const message = `${method.toUpperCase()} ${ev.url}`;

  const callbackUrl = `${ADAPTER_PUBLIC_BASE_URL.replace(
    /\/+$/,
    "",
  )}/termstation/callback/${encodeURIComponent(ev.requestId)}`;

  const payload: TermStationNotificationPayload = {
    type: "info",
    title,
    message,
    sound: true,
    actions,
    inputs: inputs.length > 0 ? inputs : undefined,
    callback_url: callbackUrl,
    callback_method: "POST",
  };

  // Log the outgoing interactive notification payload for debugging.
  // eslint-disable-next-line no-console
  console.log(
    "[termstation] notifications payload",
    JSON.stringify(payload),
  );

  const headers: Record<string, string> = {
    "content-type": "application/json; charset=utf-8",
    authorization: basicAuthHeader(TERMSTATION_BASIC_USER, TERMSTATION_BASIC_PASS),
  };

  const resp = await fetch(TERMSTATION_NOTIFICATIONS_URL, {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    // eslint-disable-next-line no-console
    console.error(
      "[termstation] failed to create notification",
      resp.status,
      text,
    );
    throw new Error(
      `TermStation /api/notifications returned status ${resp.status}`,
    );
  }

  let notificationId: string | null = null;
  try {
    const json = (await resp.json()) as unknown;
    notificationId = extractNotificationIdFromCreateResponse(json);
    if (!notificationId) {
      // eslint-disable-next-line no-console
      console.warn(
        "[termstation] create notification response missing id field",
        JSON.stringify(json),
      );
    } else {
      // eslint-disable-next-line no-console
      console.log(
        "[termstation] created notification with id",
        notificationId,
      );
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn(
      "[termstation] failed to parse create notification response body",
      err instanceof Error ? err.message : err,
    );
  }

  return notificationId;
}

async function cancelTermStationNotification(
  notificationId: string,
  reason?: string | null,
): Promise<void> {
  const url = buildTermStationCancelUrl(notificationId);

  const headers: Record<string, string> = {
    "content-type": "application/json; charset=utf-8",
    authorization: basicAuthHeader(TERMSTATION_BASIC_USER, TERMSTATION_BASIC_PASS),
  };

  const body: { reason?: string } = {};
  if (reason && reason.trim().length > 0) {
    body.reason = reason;
  }

  // Log the outgoing cancel payload for debugging.
  // eslint-disable-next-line no-console
  console.log(
    "[termstation] cancel payload",
    JSON.stringify({ url, body }),
  );

  const resp = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    // eslint-disable-next-line no-console
    console.error(
      "[termstation] failed to cancel notification",
      resp.status,
      text,
    );
    throw new Error(
      `TermStation /api/notifications/{id}/cancel returned status ${resp.status}`,
    );
  }
}

// Webhook endpoint that acl-proxy calls when an approval-required rule matches.
app.post("/webhook", async (req, res) => {
  const eventTypeHeader =
    (req.header("x-acl-proxy-event") ?? "").toLowerCase();

  const body = req.body as AclProxyWebhookBody;

  try {
    if (eventTypeHeader === "status") {
      const statusEvent = normalizeStatusEvent(body);

      // eslint-disable-next-line no-console
      console.log("[webhook] status", statusEvent);

      // Clean up any cached state when we see a terminal lifecycle event.
      const isTerminal =
        statusEvent.terminal === true ||
        statusEvent.status === "timed_out" ||
        statusEvent.status === "error" ||
        statusEvent.status === "webhook_failed" ||
        statusEvent.status === "cancelled";

      if (isTerminal) {
        const state = pendingRequests.get(statusEvent.requestId);

        if (state && state.notificationId) {
          // Fire-and-forget; status webhooks are best-effort telemetry.
          void cancelTermStationNotification(
            state.notificationId,
            statusEvent.reason ?? undefined,
          ).catch((err) => {
            // eslint-disable-next-line no-console
            console.error(
              "[webhook] failed to cancel TermStation notification",
              err instanceof Error ? err.message : err,
            );
          });
        }

        pendingRequests.delete(statusEvent.requestId);
      }

      return res.json({ status: "accepted" });
    }

    const pendingEvent = normalizePendingWebhook(body);

    // eslint-disable-next-line no-console
    console.log("[webhook] pending", pendingEvent);

    // Require callbackUrl from acl-proxy webhook; this ensures the adapter
    // only runs when [external_auth].callback_url is configured.
    if (
      !pendingEvent.callbackUrl ||
      typeof pendingEvent.callbackUrl !== "string" ||
      !pendingEvent.callbackUrl.startsWith("http")
    ) {
      throw new Error(
        "Missing or invalid callbackUrl in webhook payload; ensure [external_auth].callback_url is configured in acl-proxy",
      );
    }

    const callbackUrl = pendingEvent.callbackUrl;

    pendingRequests.set(pendingEvent.requestId, {
      callbackUrl,
      macros: pendingEvent.macros,
    });

    try {
      const notificationId = await createTermStationNotification(pendingEvent);

      if (notificationId) {
        const state = pendingRequests.get(pendingEvent.requestId);
        if (state) {
          state.notificationId = notificationId;
        }
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(
        "[webhook] failed to create TermStation notification",
        err instanceof Error ? err.message : err,
      );
      pendingRequests.delete(pendingEvent.requestId);
      return res.status(502).json({
        error: "NotificationError",
        message: "Failed to create TermStation notification",
      });
    }

    return res.json({ status: "accepted" });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(
      "[webhook] error handling webhook",
      err instanceof Error ? err.message : err,
    );
    return res.status(400).json({
      error: "InvalidWebhook",
      message:
        err instanceof Error ? err.message : "Invalid webhook payload",
    });
  }
});

// Callback endpoint that TermStation calls for interactive notification actions.
app.post("/termstation/callback/:requestId", async (req, res) => {
  const { requestId } = req.params;
  const body = req.body as TermStationCallbackBody;

  if (!requestId || typeof requestId !== "string") {
    return res.status(400).json({
      error: "InvalidRequestId",
      message: "Missing or invalid requestId in callback path",
    });
  }

  const state = pendingRequests.get(requestId);
  if (!state) {
    return res.status(404).json({
      error: "RequestNotFound",
      message: "No pending request for this requestId",
    });
  }

  const actionRaw = (body.action ?? "").toString().toLowerCase();
  if (!actionRaw) {
    return res.status(400).json({
      error: "InvalidCallback",
      message: "Missing action in TermStation callback payload",
    });
  }

  const decision = actionRaw === "allow" ? "allow" : "deny";

  const inputs = body.inputs && typeof body.inputs === "object"
    ? body.inputs
    : {};

  const macrosOut: Record<string, string> = {};

  if (decision === "allow" && Array.isArray(state.macros)) {
    for (const desc of state.macros) {
      const name = desc?.name;
      if (!name) continue;
      const rawVal = (inputs as Record<string, unknown>)[name];
      const value =
        rawVal == null ? "" : String(rawVal);
      if (desc.required !== false && !value) {
        return res.status(400).json({
          error: "MissingMacro",
          message: `Missing required macro value for '${name}'`,
        });
      }
      if (value) {
        macrosOut[name] = value;
      }
    }
  }

  const callbackBody: {
    requestId: string;
    decision: "allow" | "deny";
    macros?: Record<string, string>;
  } = {
    requestId,
    decision,
  };

  if (decision === "allow" && Object.keys(macrosOut).length > 0) {
    callbackBody.macros = macrosOut;
  }

  // eslint-disable-next-line no-console
  console.log("[callback] forwarding decision to acl-proxy", {
    requestId,
    decision,
    macroNames: Object.keys(callbackBody.macros ?? {}),
  });

  try {
    const resp = await fetch(state.callbackUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json; charset=utf-8",
      },
      body: JSON.stringify(callbackBody),
    });

    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      // eslint-disable-next-line no-console
      console.error(
        "[callback] acl-proxy callback failed",
        resp.status,
        text,
      );
      pendingRequests.delete(requestId);
      return res.status(502).json({
        error: "CallbackFailed",
        message: `acl-proxy callback returned status ${resp.status}`,
      });
    }

    pendingRequests.delete(requestId);
    return res.json({ status: "ok" });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(
      "[callback] acl-proxy callback error",
      err instanceof Error ? err.message : err,
    );
    pendingRequests.delete(requestId);
    return res.status(502).json({
      error: "CallbackError",
      message:
        err instanceof Error ? err.message : "Failed to call acl-proxy callback",
    });
  }
});

app.get("/healthz", (_req, res) => {
  res.json({ status: "ok" });
});

server.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(
    `TermStation adapter demo listening on http://localhost:${PORT}`,
  );
  // eslint-disable-next-line no-console
  console.log(
    `Expecting acl-proxy webhooks at /webhook and TermStation callbacks at ${ADAPTER_PUBLIC_BASE_URL.replace(
      /\/+$/,
      "",
    )}/termstation/callback/:requestId`,
  );
});
