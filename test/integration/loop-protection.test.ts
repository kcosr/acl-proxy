/**
 * Integration tests for loop protection behavior.
 *
 * Verifies that:
 * - The proxy adds a loop-protection header to outbound requests.
 * - Requests that already carry this header are rejected with a loop error.
 * - Loop protection also applies to the transparent HTTPS listener.
 */

import { ProxyTestServer, MockServer, createTestConfig } from '../helpers/test-utils';

const LOOP_TEST_HTTP_PORT = 18881;
const LOOP_TEST_HTTPS_PORT = 18889;

describe('Loop protection', () => {
  let proxy: ProxyTestServer;
  let mock: MockServer;

  beforeAll(async () => {
    mock = new MockServer(19999);
    await mock.start();

    const loopTestConfig = {
      proxy: {
        bindAddress: '127.0.0.1',
        port: LOOP_TEST_HTTP_PORT,
        httpsBindAddress: '127.0.0.1',
        httpsPort: LOOP_TEST_HTTPS_PORT
      },
      policy: {
        default: 'allow',
        rules: []
      },
      logging: {
        level: 'debug',
        directory: 'logs',
        console: { enabled: true },
        file: { enabled: false },
        policyDecisions: {
          logAllows: true,
          logDenies: true,
          levelAllows: 'debug',
          levelDenies: 'warn'
        }
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
        headerName: 'x-acl-proxy-request-id'
      },
      certificates: {
        certsDir: 'certs'
      }
    };

    const configPath = createTestConfig(loopTestConfig, 'test-loop-config.json');

    proxy = new ProxyTestServer({
      httpPort: LOOP_TEST_HTTP_PORT,
      httpsPort: LOOP_TEST_HTTPS_PORT,
      configPath
    });
    await proxy.start();
  });

  afterAll(async () => {
    await proxy.stop();
    await mock.stop();
  });

  test('adds loop-protection header on outbound HTTP requests', async () => {
    const url = `http://127.0.0.1:${mock.getPort()}/loop-header`;

    const response = await proxy.requestViaProxy(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    const headers = response.data.headers as Record<string, unknown>;

    const headerValue = headers['x-acl-proxy-request-id'];
    expect(headerValue).toBeDefined();
    expect(typeof headerValue).toBe('string');
    expect((headerValue as string).length).toBeGreaterThan(0);
  });

  test('rejects HTTP requests that already carry the loop-protection header', async () => {
    const url = `http://127.0.0.1:${mock.getPort()}/loop-detected`;

    const response = await proxy.requestViaProxy(url, {
      headers: {
        'x-acl-proxy-request-id': 'client-supplied-loop-id'
      }
    });

    expect(response.status).toBe(508);
    expect(response.data).toMatchObject({
      error: 'LoopDetected'
    });
  });

  test('rejects transparent HTTPS requests that carry the loop-protection header', async () => {
    const response = await proxy.requestViaTransparentHttps('example.com', '/', {
      headers: {
        'x-acl-proxy-request-id': 'client-supplied-loop-id'
      }
    });

    expect(response.status).toBe(508);
    expect(response.data).toMatchObject({
      error: 'LoopDetected'
    });
  });

  test('rejects CONNECT MITM requests that carry the loop-protection header', async () => {
    const url = 'https://example.com/loop-connect';

    const response = await proxy.requestViaProxy(url, {
      headers: {
        'x-acl-proxy-request-id': 'client-supplied-loop-id'
      }
    });

    expect(response.status).toBe(508);
    expect(response.data).toMatchObject({
      error: 'LoopDetected'
    });
  });
});
