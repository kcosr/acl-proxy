const http = require('http');
const https = require('https');
const tls = require('tls');
const fs = require('fs');
const path = require('path');

const { setupLogger, logger } = require('./utils/logger');
const CertificateManager = require('./utils/cert-manager').default;
const HTTPParser = require('./utils/http-parser').default;
const { shouldCapture, buildCaptureRecord, writeCaptureRecord } = require('./utils/capture');

const DEFAULT_LOOP_PROTECTION_HEADER = 'x-acl-proxy-request-id';

// ----- Config -----
const DEFAULT_CONFIG_PATH = process.env.ACL_PROXY_CONFIG || path.join(__dirname, '../config/acl-proxy.json');

function ensureDefaultConfig(filePath) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(filePath)) {
    const defaultCfg = {
      proxy: {
        bindAddress: '0.0.0.0',
        port: parseInt(process.env.PROXY_PORT || '8881', 10),
        httpsBindAddress: '0.0.0.0',
        httpsPort: parseInt(process.env.PROXY_HTTPS_PORT || '8889', 10)
      },
      policy: {
        default: 'allow',
        rules: []
      },
      logging: {
        level: process.env.LOG_LEVEL || 'info',
        directory: path.join(process.cwd(), 'logs'),
        console: { enabled: true },
        file: { enabled: true }
      },
      capture: {
        allowed_request: false,
        allowed_response: false,
        denied_request: false,
        denied_response: false
      },
      loopProtection: {
        enabled: true,
        addHeader: true,
        headerName: DEFAULT_LOOP_PROTECTION_HEADER
      },
      certificates: {
        certsDir: path.join(process.cwd(), 'certs')
      }
    };
    fs.writeFileSync(filePath, JSON.stringify(defaultCfg, null, 2));
  }
}

function loadConfig(filePath = DEFAULT_CONFIG_PATH) {
  ensureDefaultConfig(filePath);
  const cfg = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  if (process.env.PROXY_PORT) cfg.proxy.port = parseInt(process.env.PROXY_PORT, 10);
  if (process.env.PROXY_HOST) cfg.proxy.bindAddress = process.env.PROXY_HOST;
  if (process.env.LOG_LEVEL) cfg.logging.level = process.env.LOG_LEVEL;
  return cfg;
}

// ----- URL Policy Matching -----
function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Normalize raw client IP values from Node sockets into a form suitable
// for subnet matching (e.g. strip IPv6-mapped IPv4 prefix).
function normalizeClientIp(raw: string | undefined | null): string | undefined {
  if (!raw) return undefined;
  let addr = String(raw);
  const percentIndex = addr.indexOf('%');
  if (percentIndex !== -1) addr = addr.slice(0, percentIndex);
  if (addr.startsWith('::ffff:')) {
    addr = addr.slice('::ffff:'.length);
  } else if (addr === '::1') {
    // Treat IPv6 loopback as IPv4 loopback for convenience
    addr = '127.0.0.1';
  }
  return addr;
}

export const normalizeClientIpForTests = normalizeClientIp;

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const v = parseInt(part, 10);
    if (v < 0 || v > 255) return null;
    n = (n << 8) | v;
  }
  return n >>> 0;
}

interface Ipv4SubnetMatcher {
  base: number;
  mask: number;
}

function buildIpv4SubnetMatchers(subnets: string[]): Ipv4SubnetMatcher[] {
  const out: Ipv4SubnetMatcher[] = [];
  for (const raw of subnets || []) {
    if (raw == null) continue;
    const s = String(raw).trim();
    if (!s) continue;
    const [ipPart, prefixStr] = s.split('/');
    const ipInt = ipv4ToInt(ipPart);
    if (ipInt == null) {
      throw new Error(`Invalid IPv4 subnet: ${s}`);
    }
    let prefix = typeof prefixStr === 'string' && prefixStr.length > 0 ? parseInt(prefixStr, 10) : 32;
    if (!Number.isFinite(prefix) || prefix < 0 || prefix > 32) {
      throw new Error(`Invalid IPv4 subnet prefix: ${s}`);
    }
    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    const base = (ipInt & mask) >>> 0;
    out.push({ base, mask });
  }
  return out;
}

function ipv4InSubnets(ip: string | undefined, matchers: Ipv4SubnetMatcher[]): boolean {
  if (!ip || !matchers || matchers.length === 0) return false;
  const ipInt = ipv4ToInt(ip);
  if (ipInt == null) return false;
  for (const { base, mask } of matchers) {
    if (((ipInt & mask) >>> 0) === base) return true;
  }
  return false;
}

// Simple template interpolation supporting only {var}
export function interpolateTemplate(input, vars) {
  if (typeof input !== 'string') return input;
  return input.replace(/\{([a-zA-Z0-9_]+)\}/g, (_m, name) => {
    const val = vars && Object.prototype.hasOwnProperty.call(vars, name) ? vars[name] : '';
    return String(val ?? '');
  });
}

function cartesianProduct(objectOfArrays) {
  const entries = Object.entries(objectOfArrays || {});
  if (entries.length === 0) return [{}];
  let acc = [{}];
  for (const [key, arr] of entries) {
    const values = Array.isArray(arr) ? arr : [arr];
    const next = [];
    for (const combo of acc) {
      for (const v of values) {
        next.push({ ...combo, [key]: v });
      }
    }
    acc = next;
  }
  return acc;
}

export interface PolicyRuleTemplate { action: string; pattern: string; description?: string; subnets?: string[] }
export interface PolicyRulesets { [name: string]: PolicyRuleTemplate[] }
export type MacroValues = string | string[];
export interface PolicyIncludeRule {
  include: string;
  with?: { [name: string]: MacroValues };
  addUrlEncVariants?: boolean | string[];
}
export interface PolicyDirectRule {
  action: string;
  pattern: string;
  with?: { [name: string]: MacroValues };
  addUrlEncVariants?: boolean | string[];
  description?: string;
  subnets?: string[];
}
export interface PolicyConfig {
  default?: string;
  mode?: string;
  macros?: { [name: string]: MacroValues };
  rulesets?: PolicyRulesets;
  rules?: Array<PolicyIncludeRule | PolicyDirectRule>;
  allow?: string[]; // legacy
  deny?: string[]; // legacy
}

function expandPolicy(policyConfig: PolicyConfig) {
  const pc = policyConfig || {};
  const macros = pc.macros || {};
  const rulesets = pc.rulesets || {};
  const out = {
    default: (pc.default || pc.mode || 'deny'),
    rules: []
  } as any;

  const rules: any[] = Array.isArray(pc.rules) ? (pc.rules as any[]) : [];

  for (const r of rules) {
    if (!r) continue;

    const hasAction = !!(r as any).action;
    const hasPattern = typeof (r as any).pattern === 'string' && String((r as any).pattern).length > 0;
    const hasSubnets = Array.isArray((r as any).subnets) || (typeof (r as any).subnets === 'string' && String((r as any).subnets).length > 0);

    // Subnet-only direct rule (no URL pattern)
    if (hasAction && !hasPattern && hasSubnets) {
      out.rules.push({
        action: String((r as any).action).toLowerCase(),
        pattern: undefined,
        description: (r as any).description,
        subnets: (r as any).subnets
      });
      continue;
    }

    // Direct rule (with optional placeholder interpolation)
    if (hasAction && hasPattern) {
      const patternStr = String(r.pattern);
       const subnets = (r as any).subnets;
      const placeholderRe = /\{([a-zA-Z0-9_]+)\}/g;
      const used = new Set<string>();
      let m;
      while ((m = placeholderRe.exec(patternStr))) used.add(m[1]);

      if (used.size === 0) {
        out.rules.push({ action: String(r.action).toLowerCase(), pattern: r.pattern, description: (r as any).description, subnets });
        continue;
      }

      // Build variable sources: start from explicit mappings, fallback to macros by same name
      const varsSpec = (r.with || (r as any).vars || (r as any).values || {}) as any;
      const resolved = {} as any;
      for (const [k, v] of Object.entries(varsSpec)) {
        if (typeof v === 'string' && (v.startsWith('@') || v.startsWith('$'))) {
          const macroName = v.slice(1);
          if (typeof macros[macroName] === 'undefined') {
            throw new Error(`Policy macro not found: ${macroName} (referenced in direct rule pattern ${patternStr})`);
          }
          resolved[k] = macros[macroName];
        } else {
          resolved[k] = v;
        }
      }
      for (const name of used) {
        if (!(name in resolved)) {
          if (typeof macros[name] === 'undefined') {
            throw new Error(`Policy macro not found: ${name} (required by pattern ${patternStr})`);
          }
          resolved[name] = macros[name];
        }
      }

      let combos = cartesianProduct(resolved);
      // Optional URL-encoded variants at rule level
      const addUrlenc = (r.addUrlEncVariants !== undefined) ? r.addUrlEncVariants : false;
      if (addUrlenc) {
        const keysToVary: string[] = Array.isArray(addUrlenc) ? addUrlenc as string[] : Array.from(used);
        const expanded: any[] = [];
        for (const base of combos) {
          let acc = [base];
          for (const key of keysToVary) {
            const next: any[] = [];
            for (const c of acc) {
              next.push(c);
              const val = c[key];
              const enc = (typeof val === 'string') ? encodeURIComponent(val) : val;
              next.push({ ...c, [key]: enc });
            }
            acc = next;
          }
          for (const c of acc) expanded.push(c);
        }
        combos = expanded;
      }

      for (const combo of combos) {
        const action = String(r.action).toLowerCase();
        const pattern = interpolateTemplate(patternStr, combo);
        const description = (r as any).description ? interpolateTemplate(String((r as any).description), combo) : undefined;
        out.rules.push({ action, pattern, description, subnets });
      }
      continue;
    }

    // Include/ruleset expansion
    const includeName = r && (r.include || (r as any).ruleset || (r as any).use || (r as any).useRuleset);
    if (includeName && rulesets && rulesets[includeName]) {
      const templates = Array.isArray(rulesets[includeName]) ? rulesets[includeName] : [];
      const includeSubnets = (r as any).subnets;

      // Discover placeholders used in templates
      const placeholderRe = /\{([a-zA-Z0-9_]+)\}/g;
      const usedInTemplates = new Set<string>();
      for (const t of templates) {
        const p = t && t.pattern ? String(t.pattern) : '';
        let m;
        while ((m = placeholderRe.exec(p))) { usedInTemplates.add(m[1]); }
      }

      // Build variable sources: start from explicit mappings, fallback to macros by same name
      const varsSpec = (r.with || (r as any).vars || (r as any).values || {}) as any;
      const resolved = {} as any;
      for (const [k, v] of Object.entries(varsSpec)) {
        if (typeof v === 'string' && (v.startsWith('@') || v.startsWith('$'))) {
          const macroName = v.slice(1);
          if (typeof macros[macroName] === 'undefined') {
            throw new Error(`Policy macro not found: ${macroName} (referenced in include ${includeName})`);
          }
          resolved[k] = macros[macroName];
        } else {
          resolved[k] = v;
        }
      }
      // Auto-bind any missing placeholders to macros of the same name
      for (const name of usedInTemplates) {
        if (!(name in resolved)) {
          if (typeof macros[name] === 'undefined') {
            throw new Error(`Policy macro not found: ${name} (required by ruleset ${includeName})`);
          }
          resolved[name] = macros[name];
        }
      }

      let combos = cartesianProduct(resolved);

      // Optional: add URL-encoded variants per variable so templates can simply use {var}
      // r.addUrlEncVariants can be true (all placeholders used) or string[] (specific vars)
      const addUrlenc = (r.addUrlEncVariants !== undefined) ? r.addUrlEncVariants : false;
      if (addUrlenc) {
        const keysToVary: string[] = Array.isArray(addUrlenc)
          ? addUrlenc as string[]
          : Array.from(usedInTemplates);
        const expanded: any[] = [];
        for (const base of combos) {
          // Build 2^N variants across selected keys: raw and urlenc
          let acc = [base];
          for (const key of keysToVary) {
            const next: any[] = [];
            for (const c of acc) {
              next.push(c);
              const val = c[key];
              const enc = (typeof val === 'string') ? encodeURIComponent(val) : val;
              next.push({ ...c, [key]: enc });
            }
            acc = next;
          }
          for (const c of acc) expanded.push(c);
        }
        combos = expanded;
      }

      for (const combo of combos) {
        for (const t of templates) {
          if (t && t.action && t.pattern) {
            const action = String(t.action).toLowerCase();
            const pattern = interpolateTemplate(t.pattern, combo);
            const description = t.description ? interpolateTemplate(String(t.description), combo) : undefined;
            const ruleSubnets = includeSubnets ?? (t as any).subnets;
            out.rules.push({ action, pattern, description, subnets: ruleSubnets });
          }
        }
      }
      continue;
    }

    // Unknown item: skip
  }

  // Backward compat: allow/deny arrays with mode
  if (out.rules.length === 0) {
    const mode = (pc.mode || 'denylist').toLowerCase();
    const allow = (pc.allow || []).map((p) => ({ action: 'allow', pattern: p }));
    const deny = (pc.deny || []).map((p) => ({ action: 'deny', pattern: p }));
    if (mode === 'allowlist' || mode === 'whitelist') {
      out.default = 'deny';
      out.rules = [...deny, ...allow];
    } else {
      out.default = 'allow';
      out.rules = [...deny, ...allow];
    }
  }

  return out;
}

export function patternToRegex(pattern) {
  const raw = pattern.trim();
  const schemeMatch = raw.match(/^(https?):\/\//i);
  const hasScheme = !!schemeMatch;

  // For historical compatibility, patterns are protocol-agnostic:
  // both http and https are allowed via https?://
  const schemeRegex = 'https?:\\/\\/';

  // Strip scheme (if present) or leading slashes for host-only patterns
  let rest = hasScheme ? raw.slice(schemeMatch[0].length) : raw.replace(/^\/*/, '');

  // Determine if this is a host-only pattern (no path or only trailing slash)
  let pathPart = '';
  const slashIdx = rest.indexOf('/');
  if (slashIdx !== -1) {
    pathPart = rest.slice(slashIdx + 1);
  }
  const isHostOnly = !pathPart;

  // For host-only patterns, trim any trailing slashes before escaping
  if (isHostOnly) {
    rest = rest.replace(/\/+$/, '');
  }

  // Escape and expand wildcards in the remaining part
  let s = escapeRegex(rest)
    .replace(/\\\*\\\*/g, '.*')
    .replace(/\\\*/g, '[^/]*');

  // For host-only patterns, allow an optional trailing slash
  if (isHostOnly) {
    s += '\\/?';
  }

  return new RegExp('^' + schemeRegex + s + '$', 'i');
}

export class UrlPolicy {
  defaultAction: any;
  rules: any[];

  constructor(policyConfig: any) {
    const expanded = expandPolicy(policyConfig || {});
    this.defaultAction = String(expanded.default || 'deny').toLowerCase();
    this.rules = (expanded.rules || [])
      .map((r) => {
        if (!r || !r.action) return null;
        const action = String(r.action).toLowerCase();
        const pattern = (r as any).pattern;
        const description = (r as any).description;
        const rawSubnets = (r as any).subnets;
        const hasPattern = typeof pattern === 'string' && pattern.trim().length > 0;
        const subnetList = Array.isArray(rawSubnets)
          ? rawSubnets
          : (typeof rawSubnets === 'string' && rawSubnets.trim().length > 0 ? [rawSubnets] : []);
        const hasSubnets = subnetList.length > 0;

        if (!hasPattern && !hasSubnets) {
          throw new Error('Policy rule must define at least a pattern or subnets');
        }

        const compiled: any = {
          action,
          pattern: hasPattern ? pattern : undefined,
          description,
          subnets: hasSubnets ? subnetList : undefined
        };

        if (hasPattern) {
          compiled.re = patternToRegex(pattern);
        }
        if (hasSubnets) {
          compiled.subnetMatchers = buildIpv4SubnetMatchers(subnetList);
        }
        return compiled;
      })
      .filter((r) => r);
  }
  evaluate(urlStr: string, clientIp?: string) {
    try {
      const u = new URL(urlStr);
      const normalized = `${u.protocol}//${u.host}${u.pathname || ''}${u.search || ''}`;
      for (const rule of this.rules) {
        if (rule.re && !rule.re.test(normalized)) continue;
        if (rule.subnetMatchers && rule.subnetMatchers.length > 0) {
          if (!ipv4InSubnets(clientIp, rule.subnetMatchers)) continue;
        }
        return {
          allowed: rule.action === 'allow',
          matched: {
            action: rule.action,
            pattern: rule.pattern,
            description: (rule as any).description,
            subnets: (rule as any).subnets
          }
        };
      }
      return { allowed: this.defaultAction === 'allow', matched: null };
    } catch {
      return { allowed: false, matched: null };
    }
  }
  isAllowed(urlStr: string, clientIp?: string) {
    return this.evaluate(urlStr, clientIp).allowed;
  }
}

export class AclProxy {
  configPath: string;
  config: any;
  policy: UrlPolicy;
  certManager: any;
  server: any;
  httpsServer: any;
  reloadTimer: NodeJS.Timeout | null;
  configWatcher: any;
  requestIdCounter: number;

  constructor() {
    this.configPath = DEFAULT_CONFIG_PATH;
    this.config = loadConfig(this.configPath);
    this.requestIdCounter = 0;
    setupLogger(this.config.logging || {});
    this.policy = new UrlPolicy(this.config.policy || {});
    try {
      logger?.info?.('Compiled URL policy', { default: this.policy.defaultAction, rulesCount: this.policy.rules.length });
      try {
        const rulesPrintable = (this.policy.rules || []).map((r) => ({
          action: r.action,
          pattern: r.pattern,
          subnets: (r as any).subnets,
          description: (r as any).description
        }));
        logger?.debug?.('Compiled URL policy rules', { rules: rulesPrintable });
      } catch {}
    } catch {}
    this.certManager = new CertificateManager(this.config.certificates || {});
    this.server = http.createServer(this.handleHttp.bind(this));
    this.server.on('connect', this.handleConnect.bind(this));

    // Optional HTTPS listener
      const httpsPort = parseInt(this.config.proxy.httpsPort || 0, 10);
      if (httpsPort) {
      // Use localhost cert as default, SNI will override per-domain
      const defaultCreds = this.certManager.generateCertificateForDomain('localhost');
      const options = {
        key: defaultCreds.key,
        cert: defaultCreds.cert,
        SNICallback: (servername, cb) => {
          try {
            if (servername) {
              const sniCreds = this.certManager.generateCertificateForDomain(servername);
              return cb(null, require('tls').createSecureContext({ key: sniCreds.key, cert: sniCreds.cert }));
            }
          } catch {}
          return cb(null, require('tls').createSecureContext(defaultCreds));
        }
      };
    this.httpsServer = require('https').createServer(options, this.handleTransparentTLS.bind(this));
    }

    this.reloadTimer = null;
    this.setupConfigReloading();
  }
  generateRequestId() {
    this.requestIdCounter += 1;
    return `req-${Date.now().toString(36)}-${this.requestIdCounter.toString(36)}`;
  }
  getLoopProtectionConfig() {
    const raw = (this.config && (this.config as any).loopProtection) || {};
    let headerName = typeof raw.headerName === 'string' && raw.headerName.trim()
      ? raw.headerName.trim()
      : DEFAULT_LOOP_PROTECTION_HEADER;
    const enabled = raw.enabled !== false;
    const addHeader = enabled && raw.addHeader !== false;
    const headerNameLower = headerName.toLowerCase();
    return { enabled, addHeader, headerName, headerNameLower };
  }
  listen() {
    const host = this.config.proxy.bindAddress || '0.0.0.0';
    const port = parseInt(this.config.proxy.port || 8888, 10);
    this.server.listen(port, host, () => logger.info(`acl-proxy listening on ${host}:${port}`));
    if (this.httpsServer) {
      const hHost = this.config.proxy.httpsBindAddress || host;
      const hPort = parseInt(this.config.proxy.httpsPort, 10);
      this.httpsServer.listen(hPort, hHost, () => logger.info(`acl-proxy HTTPS transparent listener active on ${hHost}:${hPort}`));
    }
  }
  handleHttp(req, res) {
    try {
      const requestId = this.generateRequestId();
      const clientInfo = {
        address: req.socket?.remoteAddress,
        port: req.socket?.remotePort
      };
      const clientIpForPolicy = normalizeClientIp(clientInfo.address);
      const loopCfg = this.getLoopProtectionConfig();
      const loopHeaderName = loopCfg.headerNameLower;
      const incomingHeaders = (req.headers || {}) as any;
      const fullUrl = this.fullUrlFromReq(req, 'http');
      const hasLoopHeader = loopCfg.enabled && typeof incomingHeaders[loopHeaderName] !== 'undefined';

      if (hasLoopHeader) {
        const denyPayload = { error: 'LoopDetected', message: 'Proxy loop detected via loop protection header' };
        const denyBody = Buffer.from(JSON.stringify(denyPayload));

        if (shouldCapture(this.config, 'deny', 'request')) {
          const reqChunks: Buffer[] = [];
          req.on('data', (chunk) => { reqChunks.push(Buffer.from(chunk)); });
          req.on('end', () => {
            try {
              const bodyBuf = reqChunks.length ? Buffer.concat(reqChunks) : null;
              const record = buildCaptureRecord({
                rootConfig: this.config,
                requestId,
                kind: 'request',
                decision: 'deny',
                mode: 'http_proxy',
                url: fullUrl,
                method: req.method,
                client: clientInfo,
                target: undefined,
                httpVersion: `HTTP/${req.httpVersion}`,
                headers: req.headers as any,
                body: bodyBuf
              });
              writeCaptureRecord(this.config, record);
            } catch {}
          });
        }

        if (shouldCapture(this.config, 'deny', 'response')) {
          try {
            const record = buildCaptureRecord({
              rootConfig: this.config,
              requestId,
              kind: 'response',
              decision: 'deny',
              mode: 'http_proxy',
              url: fullUrl,
              method: req.method,
              client: clientInfo,
              target: undefined,
              httpVersion: 'HTTP/1.1',
              headers: {
                'content-type': 'application/json',
                'content-length': String(denyBody.length)
              } as any,
              statusCode: 508,
              statusMessage: 'Loop Detected',
              body: denyBody
            });
            writeCaptureRecord(this.config, record);
          } catch {}
        }

        res.writeHead(508, { 'Content-Type': 'application/json' });
        res.end(denyBody);
        return;
      }
      const decision = this.policy.evaluate(fullUrl, clientIpForPolicy);
      const decisionLabel = decision.allowed ? 'allow' : 'deny';

      if (!decision.allowed) {
        this.logPolicyDecision({
          allowed: false,
          url: fullUrl,
          method: req.method,
          clientIp: req.socket?.remoteAddress,
          matched: decision.matched,
          defaultAction: this.policy.defaultAction
        });
        if (shouldCapture(this.config, 'deny', 'request')) {
          const reqChunks: Buffer[] = [];
          req.on('data', (chunk) => { reqChunks.push(Buffer.from(chunk)); });
          req.on('end', () => {
            try {
              const bodyBuf = reqChunks.length ? Buffer.concat(reqChunks) : null;
              const record = buildCaptureRecord({
                rootConfig: this.config,
                requestId,
                kind: 'request',
                decision: 'deny',
                mode: 'http_proxy',
                url: fullUrl,
                method: req.method,
                client: clientInfo,
                target: undefined,
                httpVersion: `HTTP/${req.httpVersion}`,
                headers: req.headers as any,
                body: bodyBuf
              });
              writeCaptureRecord(this.config, record);
            } catch {}
          });
        }
        const denyPayload = { error: 'Forbidden', message: 'Blocked by URL policy' };
        const denyBody = Buffer.from(JSON.stringify(denyPayload));
        if (shouldCapture(this.config, 'deny', 'response')) {
          try {
            const record = buildCaptureRecord({
              rootConfig: this.config,
              requestId,
              kind: 'response',
              decision: 'deny',
              mode: 'http_proxy',
              url: fullUrl,
              method: req.method,
              client: clientInfo,
              target: undefined,
              httpVersion: 'HTTP/1.1',
              headers: {
                'content-type': 'application/json',
                'content-length': String(denyBody.length)
              } as any,
              statusCode: 403,
              statusMessage: 'Forbidden',
              body: denyBody
            });
            writeCaptureRecord(this.config, record);
          } catch {}
        }
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(denyBody);
        return;
      }
      this.logPolicyDecision({
        allowed: true,
        url: fullUrl,
        method: req.method,
        clientIp: req.socket?.remoteAddress,
        matched: decision.matched,
        defaultAction: this.policy.defaultAction
      });
      const u = new URL(fullUrl);
      const targetInfo = {
        address: u.hostname,
        port: Number(u.port || (u.protocol === 'https:' ? 443 : 80))
      };
      const opts = {
        protocol: u.protocol,
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        method: req.method,
        path: u.pathname + (u.search || ''),
        headers: { ...req.headers, host: u.host }
      };
      if (loopCfg.addHeader) {
        if (!opts.headers) opts.headers = {};
        if (typeof (opts.headers as any)[loopHeaderName] === 'undefined') {
          (opts.headers as any)[loopHeaderName] = requestId;
        }
      }
      if (shouldCapture(this.config, decisionLabel, 'request')) {
        const reqChunks: Buffer[] = [];
        req.on('data', (chunk) => { reqChunks.push(Buffer.from(chunk)); });
        req.on('end', () => {
          try {
            const bodyBuf = reqChunks.length ? Buffer.concat(reqChunks) : null;
            const record = buildCaptureRecord({
              rootConfig: this.config,
              requestId,
              kind: 'request',
              decision: decisionLabel,
              mode: 'http_proxy',
              url: fullUrl,
              method: req.method,
              client: clientInfo,
              target: targetInfo,
              httpVersion: `HTTP/${req.httpVersion}`,
              headers: req.headers as any,
              body: bodyBuf
            });
            writeCaptureRecord(this.config, record);
          } catch {}
        });
      }
      const up = (u.protocol === 'https:' ? https : http).request(opts, ur => {
        if (shouldCapture(this.config, decisionLabel, 'response')) {
          const resChunks: Buffer[] = [];
          ur.on('data', (chunk) => { resChunks.push(Buffer.from(chunk)); });
          ur.on('end', () => {
            try {
              const bodyBuf = resChunks.length ? Buffer.concat(resChunks) : null;
              const record = buildCaptureRecord({
                rootConfig: this.config,
                requestId,
                kind: 'response',
                decision: decisionLabel,
                mode: 'http_proxy',
                url: fullUrl,
                method: req.method,
                client: clientInfo,
                target: targetInfo,
                httpVersion: `HTTP/${ur.httpVersion}`,
                headers: ur.headers as any,
                statusCode: ur.statusCode,
                statusMessage: ur.statusMessage || (typeof ur.statusCode === 'number' ? http.STATUS_CODES[ur.statusCode] : ''),
                body: bodyBuf
              });
              writeCaptureRecord(this.config, record);
            } catch {}
          });
        }
        res.writeHead(ur.statusCode, ur.headers);
        ur.pipe(res);
      });
      up.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end('Bad Gateway'); });
      req.pipe(up);
    } catch (e) { if (!res.headersSent) res.writeHead(500); res.end('Internal Server Error'); }
  }
  fullUrlFromReq(req, defaultScheme) {
    if (/^https?:\/\//i.test(req.url)) return req.url;
    const host = req.headers?.host || '';
    const scheme = defaultScheme || (req.socket?.encrypted ? 'https' : 'http');
    const p = req.url.startsWith('/') ? req.url : '/' + req.url;
    return `${scheme}://${host}${p}`;
  }
  handleConnect(clientReq, clientSocket) {
    const loopCfg = this.getLoopProtectionConfig();
    const loopHeaderName = loopCfg.headerNameLower;
    const hasLoopHeader = loopCfg.enabled && clientReq.headers && typeof clientReq.headers[loopHeaderName] !== 'undefined';
    const [hostname, rawPort] = (clientReq.url || '').split(':');
    const port = rawPort ? parseInt(rawPort, 10) : 443;
    if (!hostname) { clientSocket.write('HTTP/1.1 400 Bad Request\r\n\r\n'); clientSocket.destroy(); return; }
    if (hasLoopHeader) {
      try {
        clientSocket.write('HTTP/1.1 508 Loop Detected\r\nContent-Length: 0\r\n\r\n');
      } catch {}
      try { clientSocket.destroy(); } catch {}
      return;
    }
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    const creds = this.certManager.generateCertificateForDomain(hostname);
    const tlsSock = new tls.TLSSocket(clientSocket, { isServer: true, secureContext: tls.createSecureContext({ key: creds.key, cert: creds.cert }) });
    const parser = new HTTPParser((request) => {
      const requestId = this.generateRequestId();
      const clientInfo = {
        address: clientSocket.remoteAddress,
        port: clientSocket.remotePort
      };
      const clientIpForPolicy = normalizeClientIp(clientInfo.address);
      const loopInnerCfg = this.getLoopProtectionConfig();
      const loopInnerHeaderName = loopInnerCfg.headerNameLower;
      const incomingHeaders = (request.headers || {}) as any;
      const fullUrl = `https://${hostname}${request.path}`;
      const hasInnerLoopHeader = loopInnerCfg.enabled && typeof incomingHeaders[loopInnerHeaderName] !== 'undefined';

      if (hasInnerLoopHeader) {
        const denyBody = Buffer.from('Blocked by proxy loop');
        if (shouldCapture(this.config, 'deny', 'request')) {
          try {
            const bodyBuf = Buffer.isBuffer(request.body)
              ? request.body
              : (request.body ? Buffer.from(String(request.body)) : Buffer.alloc(0));
            const record = buildCaptureRecord({
              rootConfig: this.config,
              requestId,
              kind: 'request',
              decision: 'deny',
              mode: 'https_connect',
              url: fullUrl,
              method: request.method || 'GET',
              client: clientInfo,
              target: { address: hostname, port },
              httpVersion: request.protocol,
              headers: request.headers as any,
              body: bodyBuf
            });
            writeCaptureRecord(this.config, record);
          } catch {}
        }
        if (shouldCapture(this.config, 'deny', 'response')) {
          try {
            const record = buildCaptureRecord({
              rootConfig: this.config,
              requestId,
              kind: 'response',
              decision: 'deny',
              mode: 'https_connect',
              url: fullUrl,
              method: request.method || 'GET',
              client: clientInfo,
              target: { address: hostname, port },
              httpVersion: 'HTTP/1.1',
              headers: {
                'content-type': 'text/plain',
                'content-length': String(denyBody.length)
              } as any,
              statusCode: 508,
              statusMessage: 'Loop Detected',
              body: denyBody
            });
            writeCaptureRecord(this.config, record);
          } catch {}
        }
        try {
          tlsSock.write(`HTTP/1.1 508 Loop Detected\r\nContent-Type: text/plain\r\nContent-Length: ${denyBody.length}\r\n\r\n`);
          tlsSock.write(denyBody);
        } catch {}
        return;
      }

      const decision = this.policy.evaluate(fullUrl, clientIpForPolicy);
      const decisionLabel = decision.allowed ? 'allow' : 'deny';

      if (!decision.allowed) {
        this.logPolicyDecision({
          allowed: false,
          url: fullUrl,
          method: request.method || 'GET',
          clientIp: clientSocket.remoteAddress,
          matched: decision.matched,
          defaultAction: this.policy.defaultAction
        });
        if (shouldCapture(this.config, 'deny', 'request')) {
          try {
            const bodyBuf = Buffer.isBuffer(request.body)
              ? request.body
              : (request.body ? Buffer.from(String(request.body)) : Buffer.alloc(0));
            const record = buildCaptureRecord({
              rootConfig: this.config,
              requestId,
              kind: 'request',
              decision: 'deny',
              mode: 'https_connect',
              url: fullUrl,
              method: request.method || 'GET',
              client: clientInfo,
              target: { address: hostname, port },
              httpVersion: request.protocol,
              headers: request.headers as any,
              body: bodyBuf
            });
            writeCaptureRecord(this.config, record);
          } catch {}
        }
        const denyBody = Buffer.from('Blocked by URL policy');
        if (shouldCapture(this.config, 'deny', 'response')) {
          try {
            const record = buildCaptureRecord({
              rootConfig: this.config,
              requestId,
              kind: 'response',
              decision: 'deny',
              mode: 'https_connect',
              url: fullUrl,
              method: request.method || 'GET',
              client: clientInfo,
              target: { address: hostname, port },
              httpVersion: 'HTTP/1.1',
              headers: {
                'content-type': 'text/plain',
                'content-length': String(denyBody.length)
              } as any,
              statusCode: 403,
              statusMessage: 'Forbidden',
              body: denyBody
            });
            writeCaptureRecord(this.config, record);
          } catch {}
        }
        try { tlsSock.write('HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 23\r\n\r\nBlocked by URL policy'); } catch {}
        return;
      }
      this.logPolicyDecision({
        allowed: true,
        url: fullUrl,
        method: request.method || 'GET',
        clientIp: clientSocket.remoteAddress,
        matched: decision.matched,
        defaultAction: this.policy.defaultAction
      });
      if (shouldCapture(this.config, decisionLabel, 'request')) {
        try {
          const bodyBuf = Buffer.isBuffer(request.body)
            ? request.body
            : (request.body ? Buffer.from(String(request.body)) : Buffer.alloc(0));
          const record = buildCaptureRecord({
            rootConfig: this.config,
            requestId,
            kind: 'request',
            decision: decisionLabel,
            mode: 'https_connect',
            url: fullUrl,
            method: request.method || 'GET',
            client: clientInfo,
            target: { address: hostname, port },
            httpVersion: request.protocol,
            headers: request.headers as any,
            body: bodyBuf
          });
          writeCaptureRecord(this.config, record);
        } catch {}
      }
      this.forwardHttps({ hostname, port, request, tlsSock, requestId, decisionLabel, clientInfo, fullUrl });
    });
    tlsSock.on('data', (c) => parser.parse(c));
    tlsSock.on('error', () => { try { clientSocket.destroy(); } catch {} });
  }
  forwardHttps({ hostname, port, request, tlsSock, requestId, decisionLabel, clientInfo, fullUrl }) {
    const loopCfg = this.getLoopProtectionConfig();
    const headers = { ...request.headers, host: hostname };
    const loopHeaderName = loopCfg.headerNameLower;
    if (loopCfg.addHeader && typeof headers[loopHeaderName] === 'undefined') {
      headers[loopHeaderName] = requestId;
    }
    const chunked = typeof headers['transfer-encoding'] === 'string' && /chunked/i.test(headers['transfer-encoding']);
    const body = Buffer.isBuffer(request.body) ? request.body : (request.body ? Buffer.from(String(request.body)) : Buffer.alloc(0));
    if (chunked) delete headers['content-length']; else headers['content-length'] = String(body.length);
    delete headers['transfer-encoding'];
    const opts = { hostname, port, path: request.path, method: request.method, headers, rejectUnauthorized: false };
    const up = https.request(opts, (ur) => {
      if (shouldCapture(this.config, decisionLabel, 'response')) {
        const resChunks: Buffer[] = [];
        ur.on('data', (chunk) => { resChunks.push(Buffer.from(chunk)); });
        ur.on('end', () => {
          try {
            const bodyBuf = resChunks.length ? Buffer.concat(resChunks) : null;
            const record = buildCaptureRecord({
              rootConfig: this.config,
              requestId,
              kind: 'response',
              decision: decisionLabel,
              mode: 'https_connect',
              url: fullUrl,
              method: request.method || 'GET',
              client: clientInfo,
              target: { address: hostname, port },
              httpVersion: `HTTP/${ur.httpVersion}`,
              headers: ur.headers as any,
              statusCode: ur.statusCode,
              statusMessage: ur.statusMessage || (typeof ur.statusCode === 'number' ? http.STATUS_CODES[ur.statusCode] : ''),
              body: bodyBuf
            });
            writeCaptureRecord(this.config, record);
          } catch {}
        });
      }
      tlsSock.write(`HTTP/1.1 ${ur.statusCode} ${http.STATUS_CODES[ur.statusCode] || ''}\r\n`);
      for (const [k, v] of Object.entries(ur.headers)) {
        if (Array.isArray(v)) v.forEach(vv => tlsSock.write(`${k}: ${vv}\r\n`));
        else if (typeof v !== 'undefined') tlsSock.write(`${k}: ${v}\r\n`);
      }
      tlsSock.write('\r\n');
      ur.pipe(tlsSock, { end: false });
    });
    up.on('error', () => { try { tlsSock.write('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n'); } catch {} });
    if (body.length > 0) up.write(body);
    up.end();
  }

  handleTransparentTLS(req, res) {
    try {
      const hostHeader = req.headers.host || req.socket?.servername || '';
      if (!hostHeader) { res.writeHead(400); res.end('Bad Request: Missing Host'); return; }
      const [hostname, portStr] = hostHeader.split(':');
      const port = portStr ? parseInt(portStr, 10) : 443;
      const fullUrl = `https://${hostname}${req.url.startsWith('/') ? req.url : '/' + req.url}`;
      const requestId = this.generateRequestId();
      const loopCfg = this.getLoopProtectionConfig();
      const loopHeaderName = loopCfg.headerNameLower;
      const clientInfo = {
        address: req.socket?.remoteAddress,
        port: req.socket?.remotePort
      };
      const clientIpForPolicy = normalizeClientIp(clientInfo.address);
      const hasLoopHeader = loopCfg.enabled && typeof (req.headers || {})[loopHeaderName] !== 'undefined';

      if (hasLoopHeader) {
        const denyPayload = { error: 'LoopDetected', message: 'Proxy loop detected via loop protection header' };
        const denyBody = Buffer.from(JSON.stringify(denyPayload));

        if (shouldCapture(this.config, 'deny', 'request')) {
          const reqChunks: Buffer[] = [];
          req.on('data', (chunk) => { reqChunks.push(Buffer.from(chunk)); });
          req.on('end', () => {
            try {
              const bodyBuf = reqChunks.length ? Buffer.concat(reqChunks) : null;
              const record = buildCaptureRecord({
                rootConfig: this.config,
                requestId,
                kind: 'request',
                decision: 'deny',
                mode: 'https_transparent',
                url: fullUrl,
                method: req.method,
                client: clientInfo,
                target: { address: hostname, port },
                httpVersion: `HTTP/${req.httpVersion}`,
                headers: req.headers as any,
                body: bodyBuf
              });
              writeCaptureRecord(this.config, record);
            } catch {}
          });
        }

        if (shouldCapture(this.config, 'deny', 'response')) {
          try {
            const record = buildCaptureRecord({
              rootConfig: this.config,
              requestId,
              kind: 'response',
              decision: 'deny',
              mode: 'https_transparent',
              url: fullUrl,
              method: req.method,
              client: clientInfo,
              target: { address: hostname, port },
              httpVersion: 'HTTP/1.1',
              headers: {
                'content-type': 'application/json',
                'content-length': String(denyBody.length)
              } as any,
              statusCode: 508,
              statusMessage: 'Loop Detected',
              body: denyBody
            });
            writeCaptureRecord(this.config, record);
          } catch {}
        }

        res.writeHead(508, { 'Content-Type': 'application/json' });
        res.end(denyBody);
        return;
      }
      const decision = this.policy.evaluate(fullUrl, clientIpForPolicy);
      const decisionLabel = decision.allowed ? 'allow' : 'deny';

      if (!decision.allowed) {
        this.logPolicyDecision({
          allowed: false,
          url: fullUrl,
          method: req.method,
          clientIp: req.socket?.remoteAddress,
          matched: decision.matched,
          defaultAction: this.policy.defaultAction
        });
        if (shouldCapture(this.config, 'deny', 'request')) {
          const reqChunks: Buffer[] = [];
          req.on('data', (chunk) => { reqChunks.push(Buffer.from(chunk)); });
          req.on('end', () => {
            try {
              const bodyBuf = reqChunks.length ? Buffer.concat(reqChunks) : null;
              const record = buildCaptureRecord({
                rootConfig: this.config,
                requestId,
                kind: 'request',
                decision: 'deny',
                mode: 'https_transparent',
                url: fullUrl,
                method: req.method,
                client: clientInfo,
                target: { address: hostname, port },
                httpVersion: `HTTP/${req.httpVersion}`,
                headers: req.headers as any,
                body: bodyBuf
              });
              writeCaptureRecord(this.config, record);
            } catch {}
          });
        }
        const denyPayload = { error: 'Forbidden', message: 'Blocked by URL policy' };
        const denyBody = Buffer.from(JSON.stringify(denyPayload));
        if (shouldCapture(this.config, 'deny', 'response')) {
          try {
            const record = buildCaptureRecord({
              rootConfig: this.config,
              requestId,
              kind: 'response',
              decision: 'deny',
              mode: 'https_transparent',
              url: fullUrl,
              method: req.method,
              client: clientInfo,
              target: { address: hostname, port },
              httpVersion: 'HTTP/1.1',
              headers: {
                'content-type': 'application/json',
                'content-length': String(denyBody.length)
              } as any,
              statusCode: 403,
              statusMessage: 'Forbidden',
              body: denyBody
            });
            writeCaptureRecord(this.config, record);
          } catch {}
        }
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(denyBody);
        return;
      }
      this.logPolicyDecision({
        allowed: true,
        url: fullUrl,
        method: req.method,
        clientIp: req.socket?.remoteAddress,
        matched: decision.matched,
        defaultAction: this.policy.defaultAction
      });
      const u = new URL(fullUrl);
      const opts = { protocol: 'https:', hostname: u.hostname, port, method: req.method, path: u.pathname + (u.search || ''), headers: { ...req.headers, host: u.host }, rejectUnauthorized: false };
      if (loopCfg.addHeader) {
        const headers: any = opts.headers as any;
        if (typeof headers[loopHeaderName] === 'undefined') {
          headers[loopHeaderName] = requestId;
        }
      }
      if (shouldCapture(this.config, decisionLabel, 'request')) {
        const reqChunks: Buffer[] = [];
        req.on('data', (chunk) => { reqChunks.push(Buffer.from(chunk)); });
        req.on('end', () => {
          try {
            const bodyBuf = reqChunks.length ? Buffer.concat(reqChunks) : null;
            const record = buildCaptureRecord({
              rootConfig: this.config,
              requestId,
              kind: 'request',
              decision: decisionLabel,
              mode: 'https_transparent',
              url: fullUrl,
              method: req.method,
              client: clientInfo,
              target: { address: hostname, port },
              httpVersion: `HTTP/${req.httpVersion}`,
              headers: req.headers as any,
              body: bodyBuf
            });
            writeCaptureRecord(this.config, record);
          } catch {}
        });
      }
      const up = require('https').request(opts, (ur) => {
        if (shouldCapture(this.config, decisionLabel, 'response')) {
          const resChunks: Buffer[] = [];
          ur.on('data', (chunk) => { resChunks.push(Buffer.from(chunk)); });
          ur.on('end', () => {
            try {
              const bodyBuf = resChunks.length ? Buffer.concat(resChunks) : null;
              const record = buildCaptureRecord({
                rootConfig: this.config,
                requestId,
                kind: 'response',
                decision: decisionLabel,
                mode: 'https_transparent',
                url: fullUrl,
                method: req.method,
                client: clientInfo,
                target: { address: hostname, port },
                httpVersion: `HTTP/${ur.httpVersion}`,
                headers: ur.headers as any,
                statusCode: ur.statusCode,
                statusMessage: ur.statusMessage || (typeof ur.statusCode === 'number' ? http.STATUS_CODES[ur.statusCode] : ''),
                body: bodyBuf
              });
              writeCaptureRecord(this.config, record);
            } catch {}
          });
        }
        res.writeHead(ur.statusCode, ur.headers);
        ur.pipe(res);
      });
      up.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end('Bad Gateway'); });
      req.pipe(up);
    } catch { if (!res.headersSent) res.writeHead(500); res.end('Internal Server Error'); }
  }

  logPolicyDecision({ allowed, url, method, clientIp, matched, defaultAction }) {
    try {
      const cfg = (this.config.logging && this.config.logging.policyDecisions) || {};
      const logAllows = cfg.logAllows === true;
      const logDenies = cfg.logDenies !== false; // default true
      const levelAllows = cfg.levelAllows || 'info';
      const levelDenies = cfg.levelDenies || 'warn';

      const payload = {
        decision: allowed ? 'allow' : 'deny',
        url,
        method,
        clientIp,
        matched,
        defaultAction
      };

      if (allowed) {
        if (!logAllows) return;
        (logger[levelAllows] || logger.info).call(logger, 'URL policy decision', payload);
      } else {
        if (!logDenies) return;
        (logger[levelDenies] || logger.warn).call(logger, 'URL policy decision', payload);
      }
    } catch {}
  }

  setupConfigReloading() {
    try {
      process.on('SIGHUP', () => {
        this.scheduleConfigReload('SIGHUP');
      });
    } catch {}
    try {
      if (this.configPath) {
        this.configWatcher = fs.watch(this.configPath, (eventType) => {
          if (eventType === 'change' || eventType === 'rename') {
            this.scheduleConfigReload('file');
          }
        });
      }
    } catch (err) {
      try {
        logger?.warn?.('Failed to watch config file for changes', { path: this.configPath, error: err.message });
      } catch {}
    }
  }

  scheduleConfigReload(source) {
    if (this.reloadTimer) clearTimeout(this.reloadTimer);
    this.reloadTimer = setTimeout(() => {
      this.reloadTimer = null;
      this.reloadConfig(source);
    }, 200);
  }

  reloadConfig(source) {
    let newCfg;
    try {
      newCfg = loadConfig(this.configPath);
    } catch (err) {
      try {
        logger?.error?.('Failed to reload config', { path: this.configPath, error: err.message, source });
      } catch {}
      return;
    }

    const prevLogging = JSON.stringify(this.config.logging || {});
    const prevPolicy = JSON.stringify(this.config.policy || {});
    const prevCapture = JSON.stringify(this.config.capture || {});
    const prevLoopProtection = JSON.stringify((this.config as any).loopProtection || {});
    const nextLogging = newCfg.logging || {};
    const nextPolicy = newCfg.policy || {};
    const nextCapture = newCfg.capture || {};
    const nextLoopProtection = (newCfg as any).loopProtection || {};

    const loggingChanged = JSON.stringify(nextLogging) !== prevLogging;
    const policyChanged = JSON.stringify(nextPolicy) !== prevPolicy;
    const captureChanged = JSON.stringify(nextCapture) !== prevCapture;
    const loopProtectionChanged = JSON.stringify(nextLoopProtection) !== prevLoopProtection;

    // Apply logging first
    if (loggingChanged) {
      this.config = { ...this.config, logging: nextLogging };
      setupLogger(nextLogging);
      try { logger?.info?.('Reloaded logging configuration', { source }); } catch {}
    }

    // Apply policy only if it successfully constructs
    if (policyChanged) {
      try {
        const newPolicy = new UrlPolicy(nextPolicy);
        this.policy = newPolicy;
        this.config = { ...this.config, policy: nextPolicy };
        try {
          logger?.info?.('Reloaded policy configuration', { source });
          logger?.info?.('Compiled URL policy', { default: this.policy.defaultAction, rulesCount: this.policy.rules.length });
          try {
            const rulesPrintable = (this.policy.rules || []).map((r) => ({
              action: r.action,
              pattern: r.pattern,
              subnets: (r as any).subnets,
              description: (r as any).description
            }));
            logger?.debug?.('Compiled URL policy rules', { rules: rulesPrintable });
          } catch {}
        } catch {}
      } catch (err) {
        try {
          logger?.error?.('Failed to apply policy configuration (keeping previous policy)', { error: err?.message, source });
        } catch {}
      }
    }

    if (captureChanged) {
      this.config = { ...this.config, capture: nextCapture };
      try {
        logger?.info?.('Reloaded capture configuration', { source });
      } catch {}
    }
    if (loopProtectionChanged) {
      this.config = { ...this.config, loopProtection: nextLoopProtection };
      try {
        logger?.info?.('Reloaded loop protection configuration', { source });
      } catch {}
    }
  }
}

if (require.main === module) {
  new AclProxy().listen();
}

// Exports for tests and programmatic usage
module.exports = {
  AclProxy,
  UrlPolicy,
  patternToRegex,
  interpolateTemplate,
  normalizeClientIpForTests,
  // escapeRegex intentionally not exported
};
