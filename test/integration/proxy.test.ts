/**
 * Integration tests for ACL Proxy
 * Tests actual proxy behavior by starting the server and making requests
 */

import * as path from 'path';
import * as https from 'https';
import * as http from 'http';
import axios, { AxiosInstance } from 'axios';
import { spawn, ChildProcess } from 'child_process';

const TEST_CONFIG_PATH = path.join(__dirname, '../../config/test-config.json');
const HTTP_PORT = 8881;
const HTTPS_PORT = 8889;
const PROXY_HOST = '127.0.0.1';

describe('ACL Proxy Integration Tests', () => {
  let proxyProcess: ChildProcess;
  let httpClient: AxiosInstance;
  let httpsClient: AxiosInstance;
  let httpAgent: http.Agent;
  let httpsAgent: https.Agent;

  beforeAll(async () => {
    // Start the proxy server
    await startProxyServer();

    // Create HTTP client configured to use the proxy
    httpAgent = new http.Agent({ keepAlive: false });
    httpsAgent = new https.Agent({ keepAlive: false, rejectUnauthorized: false });
    httpClient = axios.create({
      proxy: {
        host: PROXY_HOST,
        port: HTTP_PORT,
        protocol: 'http'
      },
      httpAgent,
      httpsAgent,
      timeout: 10000,
      validateStatus: () => true // Don't throw on any status code
    });

    // Create HTTPS client for transparent HTTPS testing
    httpsClient = axios.create({
      httpsAgent,
      timeout: 10000,
      validateStatus: () => true
    });
  });

  afterAll(async () => {
    await stopProxyServer();
    try { httpAgent?.destroy(); } catch {}
    try { httpsAgent?.destroy(); } catch {}
  });

  describe('HTTP Proxy Mode', () => {
    test('should allow requests matching allow rules', async () => {
      const response = await httpClient.get('https://www.google.com/');
      expect(response.status).toBe(200);
    });

    test('should block requests not matching any allow rule (default deny)', async () => {
      const response = await httpClient.get('https://www.blocked-site.com/');
      expect(response.status).toBe(403);
      expect(response.data).toMatchObject({
        error: 'Forbidden',
        message: 'Blocked by URL policy'
      });
    });

    test('should allow requests matching wildcard patterns', async () => {
      // Use a stable path to avoid slow 404s
      const response = await httpClient.get('https://example.com/');
      // Ensure proxy policy allows; upstream may 200/301/302
      expect([200, 301, 302]).toContain(response.status);
    });

    test('should allow requests with query parameters', async () => {
      const response = await httpClient.get('https://httpbin.org/get?param=value');
      expect(response.status).toBe(200);
    });

    test('should block explicitly denied URLs', async () => {
      const response = await httpClient.get('https://blocked.com/anything');
      expect(response.status).toBe(403);
    });

    test('should match host wildcard patterns', async () => {
      const response = await httpClient.get('https://subdomain.allowed.test/path');
      // Domain may not resolve; ensure proxy policy does not block
      expect(response.status).not.toBe(403);
    });

    test('should match path wildcard patterns', async () => {
      const response = await httpClient.get('https://api.github.com/repos/test-org/readme');
      // Resource may not exist; assert not blocked by policy
      expect(response.status).not.toBe(403);
    });

    test('should be protocol-agnostic (http vs https)', async () => {
      // Pattern is https:// but should match http:// too
      const response = await httpClient.get('http://example.com/test');
      // Upstream may return 404; ensure not blocked by policy
      expect(response.status).not.toBe(403);
    });
  });

  describe('Transparent HTTPS Mode', () => {
    test('should allow HTTPS requests through transparent listener', async () => {
      const response = await httpsClient.get(`https://${PROXY_HOST}:${HTTPS_PORT}/`, {
        headers: {
          'Host': 'www.google.com'
        }
      });

      // Should either succeed (200) or be allowed through proxy
      // The exact status depends on whether the upstream is reachable
      expect([200, 301, 302]).toContain(response.status);
    });

    test('should block denied requests through transparent listener', async () => {
      const response = await httpsClient.get(`https://${PROXY_HOST}:${HTTPS_PORT}/`, {
        headers: {
          'Host': 'blocked.com'
        }
      });

      expect(response.status).toBe(403);
    });

    test('should handle Host header with port', async () => {
      const response = await httpsClient.get(`https://${PROXY_HOST}:${HTTPS_PORT}/`, {
        headers: {
          'Host': 'example.com:443'
        }
      });

      expect([200, 301, 302]).toContain(response.status);
    });
  });

  describe('Edge Cases', () => {
    test('should handle URLs with special characters', async () => {
      const response = await httpClient.get('https://httpbin.org/anything/%E2%9C%93');
      expect(response.status).toBe(200);
    });

    test('should handle URLs with fragments (fragments are not sent to server)', async () => {
      const response = await httpClient.get('https://httpbin.org/anything#fragment');
      expect(response.status).toBe(200);
    });

    test('should handle missing Host header gracefully', async () => {
      // Direct HTTP request without proper proxy setup
      try {
        const response = await axios.get(`http://${PROXY_HOST}:${HTTP_PORT}/`, {
          headers: {
            'Host': '' // Empty host
          },
          timeout: 5000,
          validateStatus: () => true
        });

        // Should return 400 or 500 for malformed request
        expect(response.status).toBeGreaterThanOrEqual(400);
      } catch (error) {
        // Connection errors are also acceptable
        expect(error).toBeDefined();
      }
    });
  });

  describe('Policy Decision Logging', () => {
    test('should log allowed requests', async () => {
      // This test verifies the request goes through
      // Actual log verification would require log file parsing
      const response = await httpClient.get('https://www.google.com/');
      expect(response.status).toBe(200);
    });

    test('should log denied requests', async () => {
      const response = await httpClient.get('https://denied-site.com/');
      expect(response.status).toBe(403);
    });
  });

  // Helper functions
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
        // Wait for both listeners to be ready
        if (output.includes('listening on') && output.includes('transparent listener active')) {
          cleanup();
          // Give it a moment to fully initialize
          resolveDelay = setTimeout(resolve, 500);
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
      let resolveDelay: NodeJS.Timeout | null = null;

      const cleanup = () => {
        proxyProcess.stdout?.off('data', onData);
        proxyProcess.stderr?.off('data', onData);
        proxyProcess.off('error', onError);
        proxyProcess.off('exit', onExit);
        if (timeoutId) { clearTimeout(timeoutId); timeoutId = null; }
        if (resolveDelay) { clearTimeout(resolveDelay); resolveDelay = null; }
      };

      proxyProcess.stdout?.on('data', onData);
      proxyProcess.stderr?.on('data', onData);
      proxyProcess.on('error', onError);
      proxyProcess.on('exit', onExit);

      // Timeout after 10 seconds
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

      // Force kill after 5 seconds
      killTimer = setTimeout(() => {
        if (proxyProcess && !proxyProcess.killed) {
          proxyProcess.kill('SIGKILL');
        }
        onExit();
      }, 5000);
    });
  }
});
