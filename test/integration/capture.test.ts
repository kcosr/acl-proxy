/**
 * Integration tests for HTTP request/response capture
 */

import * as path from 'path';
import * as http from 'http';
import * as fs from 'fs';
import axios, { AxiosInstance } from 'axios';
import { spawn, ChildProcess } from 'child_process';

const TEST_CONFIG_PATH = path.join(__dirname, '../../config/test-capture-config.json');
const HTTP_PORT = 8891;
const PROXY_HOST = '127.0.0.1';
const TARGET_PORT = 18080;
const CAPTURE_DIR = path.join(__dirname, '../../logs-capture');

describe('HTTP capture logging', () => {
  let proxyProcess: ChildProcess;
  let targetServer: http.Server;
  let httpClient: AxiosInstance;

  beforeAll(async () => {
    try { fs.rmSync(CAPTURE_DIR, { recursive: true, force: true }); } catch {}

    await startTargetServer();
    await startProxyServer();

    httpClient = axios.create({
      proxy: {
        host: PROXY_HOST,
        port: HTTP_PORT,
        protocol: 'http'
      },
      timeout: 10000,
      validateStatus: () => true
    });
  });

  afterAll(async () => {
    await stopProxyServer();
    await stopTargetServer();
  });

  test('captures allowed and denied HTTP traffic', async () => {
    const allowedBody = 'capture-body';
    const allowedUrl = `http://127.0.0.1:${TARGET_PORT}/echo`;
    const deniedUrl = 'http://denied.example.com/blocked';

    const allowedResponse = await httpClient.post(allowedUrl, allowedBody, {
      headers: { 'X-Test-Header': 'capture' }
    });
    expect(allowedResponse.status).toBe(200);

    const deniedResponse = await httpClient.get(deniedUrl);
    expect(deniedResponse.status).toBe(403);

    await new Promise((resolve) => setTimeout(resolve, 500));

    const files = fs.readdirSync(CAPTURE_DIR).filter((f) => f.endsWith('.json'));
    expect(files.length).toBeGreaterThanOrEqual(4);
    const records = files.map((f) => JSON.parse(fs.readFileSync(path.join(CAPTURE_DIR, f), 'utf8')));

    const allowedRequest = records.find(
      (r: any) => r.decision === 'allow' && r.kind === 'request' && r.url === allowedUrl
    );
    expect(allowedRequest).toBeDefined();
    expect(allowedRequest.method).toBe('POST');
    expect(allowedRequest.mode).toBe('http_proxy');
    expect(allowedRequest.client).toBeDefined();
    expect(typeof allowedRequest.client.port).toBe('number');
    expect(allowedRequest.body).toBeDefined();
    expect(allowedRequest.body.encoding).toBe('base64');
    expect(typeof allowedRequest.body.contentType).toBe('string');
    const allowedReqBody = Buffer.from(allowedRequest.body.data, 'base64').toString('utf8');
    expect(allowedReqBody).toBe(allowedBody);

    const allowedResponseRec = records.find(
      (r: any) => r.decision === 'allow' && r.kind === 'response' && r.url === allowedUrl
    );
    expect(allowedResponseRec).toBeDefined();
    expect(allowedResponseRec.statusCode).toBe(200);
    expect(allowedResponseRec.body).toBeDefined();
    expect(allowedResponseRec.body.contentType).toBe('text/plain');

    const deniedResponseRec = records.find(
      (r: any) => r.decision === 'deny' && r.kind === 'response' && r.url === deniedUrl
    );
    expect(deniedResponseRec).toBeDefined();
    expect(deniedResponseRec.statusCode).toBe(403);
    expect(deniedResponseRec.mode).toBe('http_proxy');
    expect(deniedResponseRec.body).toBeDefined();
    const deniedBody = Buffer.from(deniedResponseRec.body.data, 'base64').toString('utf8');
    expect(deniedBody).toContain('Blocked by URL policy');
    expect(deniedResponseRec.body.contentType).toBe('application/json');
  });

  async function startTargetServer(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        targetServer = http.createServer((req, res) => {
          const chunks: Buffer[] = [];
          req.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
          req.on('end', () => {
            const body = Buffer.concat(chunks).toString('utf8');
            res.statusCode = 200;
            res.setHeader('Content-Type', 'text/plain');
            res.end(`echo:${body}`);
          });
        });
        targetServer.listen(TARGET_PORT, PROXY_HOST, () => resolve());
        targetServer.on('error', (err) => reject(err));
      } catch (err) {
        reject(err);
      }
    });
  }

  async function stopTargetServer(): Promise<void> {
    return new Promise((resolve) => {
      if (!targetServer) {
        resolve();
        return;
      }
      targetServer.close(() => resolve());
    });
  }

  async function startProxyServer(): Promise<void> {
    return new Promise((resolve, reject) => {
      const env = {
        ...process.env,
        ACL_PROXY_CONFIG: TEST_CONFIG_PATH,
        NODE_ENV: 'test'
      };

      proxyProcess = spawn('node', ['dist/index.js'], {
        env,
        cwd: path.join(__dirname, '../..'),
        stdio: ['ignore', 'pipe', 'pipe']
      });

      let output = '';

      const onData = (data: Buffer) => {
        output += data.toString();
        if (output.includes('acl-proxy listening on')) {
          cleanup();
          resolve();
        }
      };

      const onError = (error: Error) => {
        cleanup();
        reject(new Error(`Failed to start proxy: ${error.message}`));
      };

      const onExit = (code: number) => {
        cleanup();
        if (code !== 0) {
          reject(new Error(`Proxy exited with code ${code}. Output: ${output}`));
        }
      };

      let timeoutId: NodeJS.Timeout | null = null;

      const cleanup = () => {
        proxyProcess.stdout?.off('data', onData);
        proxyProcess.stderr?.off('data', onData);
        proxyProcess.off('error', onError);
        proxyProcess.off('exit', onExit);
        if (timeoutId) { clearTimeout(timeoutId); timeoutId = null; }
      };

      proxyProcess.stdout?.on('data', onData);
      proxyProcess.stderr?.on('data', onData);
      proxyProcess.on('error', onError);
      proxyProcess.on('exit', onExit);

      timeoutId = setTimeout(() => {
        cleanup();
        reject(new Error(`Timeout waiting for proxy to start. Output: ${output}`));
      }, 10000);
    });
  }

  async function stopProxyServer(): Promise<void> {
    return new Promise((resolve) => {
      if (!proxyProcess) {
        resolve();
        return;
      }

      let killTimer: NodeJS.Timeout | null = null;
      const onExit = () => {
        if (killTimer) { clearTimeout(killTimer); killTimer = null; }
        try { proxyProcess.stdout?.removeAllListeners(); } catch {}
        try { proxyProcess.stderr?.removeAllListeners(); } catch {}
        try { proxyProcess.removeAllListeners(); } catch {}
        resolve();
      };
      proxyProcess.once('exit', onExit);

      proxyProcess.kill('SIGTERM');

      killTimer = setTimeout(() => {
        if (proxyProcess && !proxyProcess.killed) {
          proxyProcess.kill('SIGKILL');
        }
        onExit();
      }, 5000);
    });
  }
});
