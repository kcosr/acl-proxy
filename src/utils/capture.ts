import fs from 'fs';
import path from 'path';
import { logger } from './logger';

export type CaptureDecision = 'allow' | 'deny';
export type CaptureKind = 'request' | 'response';
export type CaptureMode = 'http_proxy' | 'https_connect' | 'https_transparent';

export interface CaptureBodyInfo {
  encoding: 'base64';
  length: number;
  data: string;
   contentType?: string;
}

export interface CaptureEndpointInfo {
  address?: string;
  port?: number;
}

export interface CaptureRecord {
  timestamp: string;
  requestId: string;
  kind: CaptureKind;
  decision: CaptureDecision;
  mode: CaptureMode;
  url: string;
  method: string;
  statusCode?: number;
  statusMessage?: string;
  client: CaptureEndpointInfo;
  target?: CaptureEndpointInfo;
  httpVersion?: string;
  headers?: Record<string, unknown>;
  body?: CaptureBodyInfo;
}

export interface CaptureConfig {
  allowed_request?: boolean;
  allowed_response?: boolean;
  denied_request?: boolean;
  denied_response?: boolean;
  directory?: string;
  filename?: string; // optional template; defaults to per-request files
}

function getCaptureConfig(rootConfig: any): CaptureConfig {
  return (rootConfig && rootConfig.capture) || {};
}

export function shouldCapture(rootConfig: any, decision: CaptureDecision, kind: CaptureKind): boolean {
  const cfg = getCaptureConfig(rootConfig);
  const prefix = decision === 'allow' ? 'allowed' : 'denied';
  const key = `${prefix}_${kind}` as keyof CaptureConfig;
  return Boolean(cfg && cfg[key]);
}

export function buildCaptureRecord(options: {
  rootConfig: any;
  requestId: string;
  kind: CaptureKind;
  decision: CaptureDecision;
  mode: CaptureMode;
  url: string;
  method: string | undefined;
  client: CaptureEndpointInfo;
  target?: CaptureEndpointInfo;
  httpVersion?: string | undefined;
  headers?: Record<string, unknown> | undefined;
  statusCode?: number | undefined;
  statusMessage?: string | undefined;
  body?: Buffer | null;
}): CaptureRecord {
  const {
    requestId,
    kind,
    decision,
    mode,
    url,
    method,
    client,
    target,
    httpVersion,
    headers,
    statusCode,
    statusMessage,
    body
  } = options;

  let contentType: string | undefined;
  if (headers) {
    for (const [key, value] of Object.entries(headers)) {
      if (key.toLowerCase() === 'content-type') {
        if (typeof value === 'string') {
          contentType = value;
        } else if (Array.isArray(value) && value.length > 0 && typeof value[0] === 'string') {
          contentType = value[0];
        }
        break;
      }
    }
  }

  let bodyInfo: CaptureBodyInfo | undefined;
  if (body && body.length > 0) {
    bodyInfo = {
      encoding: 'base64',
      length: body.length,
      data: body.toString('base64'),
      contentType
    };
  }

  return {
    timestamp: new Date().toISOString(),
    requestId,
    kind,
    decision,
    mode,
    url,
    method: method || '',
    statusCode,
    statusMessage,
    client: client || {},
    target,
    httpVersion,
    headers,
    body: bodyInfo
  };
}

function resolveCaptureFile(rootConfig: any, record: CaptureRecord): string {
  const cfg = getCaptureConfig(rootConfig) as CaptureConfig;
  const loggingCfg = (rootConfig && rootConfig.logging) || {};

  let directory = cfg.directory || loggingCfg.directory || path.join(process.cwd(), 'logs');
  if (!path.isAbsolute(directory)) directory = path.join(process.cwd(), directory);

  // One file per request/response record by default
  const kindAbbrev = record.kind === 'request' ? 'req' : 'res';
  const defaultName = `${record.requestId}-${kindAbbrev}.json`;

  // Optional templating: {requestId}, {kind}, {suffix}
  const rawName = (cfg.filename && cfg.filename.trim()) || defaultName;
  const filename = rawName
    .replace(/\{requestId\}/g, record.requestId)
    .replace(/\{kind\}/g, record.kind)
    .replace(/\{suffix\}/g, kindAbbrev);

  return path.join(directory, filename);
}

export function writeCaptureRecord(rootConfig: any, record: CaptureRecord): void {
  try {
    const filePath = resolveCaptureFile(rootConfig, record);
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const line = JSON.stringify(record, null, 2) + '\n';
    fs.writeFile(filePath, line, (err) => {
      if (err) {
        try {
          logger?.warn?.('Failed to write capture record', { error: err.message, path: filePath });
        } catch {}
      }
    });
  } catch (err: any) {
    try {
      logger?.warn?.('Failed to resolve capture file', { error: err?.message });
    } catch {}
  }
}
