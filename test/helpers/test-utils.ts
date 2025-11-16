/**
 * Test helper utilities for ACL Proxy tests
 */

import * as http from 'http';
import * as https from 'https';
import * as path from 'path';
import * as fs from 'fs';
import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';
import { spawn, ChildProcess } from 'child_process';

export interface ProxyTestConfig {
  httpPort: number;
  httpsPort: number;
  host: string;
  configPath: string;
}

export interface TestResponse {
  status: number;
  data: any;
  headers: any;
}

/**
 * Proxy server instance for testing
 */
export class ProxyTestServer {
  private process: ChildProcess | null = null;
  private config: ProxyTestConfig;

  constructor(config: Partial<ProxyTestConfig> = {}) {
    this.config = {
      httpPort: config.httpPort || 18881,
      httpsPort: config.httpsPort || 18889,
      host: config.host || '127.0.0.1',
      configPath: config.configPath || path.join(__dirname, '../../config/test-config.json')
    };
  }

  /**
   * Start the proxy server
   */
  async start(): Promise<void> {
    if (this.process) {
      throw new Error('Proxy server is already running');
    }

    return new Promise((resolve, reject) => {
      const env = {
        ...process.env,
        ACL_PROXY_CONFIG: this.config.configPath,
        NODE_ENV: 'test'
      };

      this.process = spawn('node', ['dist/index.js'], {
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
          setTimeout(resolve, 500);
        }
      };

      const onError = (error: Error) => {
        cleanup();
        reject(new Error(`Failed to start proxy: ${error.message}`));
      };

      const onExit = (code: number | null) => {
        cleanup();
        if (code !== null && code !== 0) {
          reject(new Error(`Proxy exited with code ${code}. Output: ${output}`));
        }
      };

      const cleanup = () => {
        this.process?.stdout?.off('data', onData);
        this.process?.stderr?.off('data', onData);
        this.process?.off('error', onError);
        this.process?.off('exit', onExit);
      };

      this.process.stdout?.on('data', onData);
      this.process.stderr?.on('data', onData);
      this.process.on('error', onError);
      this.process.on('exit', onExit);

      // Timeout after 10 seconds
      setTimeout(() => {
        cleanup();
        reject(new Error(`Timeout waiting for proxy to start. Output: ${output}`));
      }, 10000);
    });
  }

  /**
   * Stop the proxy server
   */
  async stop(): Promise<void> {
    if (!this.process) {
      return;
    }

    return new Promise((resolve) => {
      const proc = this.process!;

      proc.on('exit', () => {
        this.process = null;
        resolve();
      });

      proc.kill('SIGTERM');

      // Force kill after 5 seconds
      setTimeout(() => {
        if (proc && !proc.killed) {
          proc.kill('SIGKILL');
        }
        this.process = null;
        resolve();
      }, 5000);
    });
  }

  /**
   * Create an HTTP client configured to use this proxy
   */
  createHttpClient(): AxiosInstance {
    return axios.create({
      proxy: {
        host: this.config.host,
        port: this.config.httpPort,
        protocol: 'http'
      },
      timeout: 10000,
      validateStatus: () => true // Don't throw on any status code
    });
  }

  /**
   * Create an HTTPS client for transparent HTTPS testing
   */
  createHttpsClient(): AxiosInstance {
    return axios.create({
      httpsAgent: new https.Agent({
        rejectUnauthorized: false // Accept self-signed certs
      }),
      timeout: 10000,
      validateStatus: () => true
    });
  }

  /**
   * Make a request through the HTTP proxy
   */
  async requestViaProxy(url: string, config: AxiosRequestConfig = {}): Promise<TestResponse> {
    const client = this.createHttpClient();
    const response = await client.get(url, config);
    return {
      status: response.status,
      data: response.data,
      headers: response.headers
    };
  }

  /**
   * Make a request through the transparent HTTPS listener
   */
  async requestViaTransparentHttps(host: string, path: string = '/', config: AxiosRequestConfig = {}): Promise<TestResponse> {
    const client = this.createHttpsClient();
    const url = `https://${this.config.host}:${this.config.httpsPort}${path}`;

    const response = await client.get(url, {
      ...config,
      headers: {
        ...config.headers,
        'Host': host
      }
    });

    return {
      status: response.status,
      data: response.data,
      headers: response.headers
    };
  }

  getConfig(): ProxyTestConfig {
    return { ...this.config };
  }
}

/**
 * Helper to create test configuration files
 */
export function createTestConfig(config: any, filename: string = 'test-config.json'): string {
  const configPath = path.join(__dirname, '../../config', filename);
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  return configPath;
}

/**
 * Helper to wait for a condition
 */
export async function waitFor(
  condition: () => boolean | Promise<boolean>,
  timeout: number = 5000,
  interval: number = 100
): Promise<void> {
  const startTime = Date.now();

  while (Date.now() - startTime < timeout) {
    if (await condition()) {
      return;
    }
    await sleep(interval);
  }

  throw new Error(`Timeout waiting for condition after ${timeout}ms`);
}

/**
 * Helper to sleep for a duration
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Helper to check if a port is in use
 */
export async function isPortInUse(port: number, host: string = '127.0.0.1'): Promise<boolean> {
  return new Promise((resolve) => {
    const server = http.createServer();

    server.once('error', (err: any) => {
      if (err.code === 'EADDRINUSE') {
        resolve(true);
      } else {
        resolve(false);
      }
    });

    server.once('listening', () => {
      server.close();
      resolve(false);
    });

    server.listen(port, host);
  });
}

/**
 * Helper to clean up test certificates and logs
 */
export async function cleanupTestArtifacts(): Promise<void> {
  const certsDir = path.join(__dirname, '../../certs/test');
  const logsDir = path.join(__dirname, '../../logs/test');

  const rmdir = (dir: string) => {
    if (fs.existsSync(dir)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  };

  rmdir(certsDir);
  rmdir(logsDir);
}

/**
 * Mock external server for testing
 */
export class MockServer {
  private server: http.Server | null = null;
  private port: number;

  constructor(port: number = 19999) {
    this.port = port;
  }

  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          method: req.method,
          url: req.url,
          headers: req.headers
        }));
      });

      this.server.listen(this.port, () => {
        resolve();
      });

      this.server.on('error', reject);
    });
  }

  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.server) {
        resolve();
        return;
      }

      this.server.close(() => {
        this.server = null;
        resolve();
      });
    });
  }

  getPort(): number {
    return this.port;
  }
}
