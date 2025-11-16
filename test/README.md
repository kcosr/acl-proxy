# ACL Proxy Test Suite

This directory contains the test suite for the ACL Proxy application.

## Test Structure

```
test/
├── unit/                      # Unit tests
│   └── simple-pattern.test.ts # Pattern matching logic tests
├── integration/               # Integration tests
│   └── proxy.test.ts          # End-to-end proxy behavior tests
├── helpers/                   # Test utilities
│   └── test-utils.ts          # Shared test helpers
├── manual-test.sh             # Shell script for manual testing
└── README.md                  # This file
```

## Running Tests

### All Tests

```bash
npm test
```

### Unit Tests Only

```bash
npm run test:unit
```

### Integration Tests Only

```bash
npm run test:integration
```

### Watch Mode (re-run on file changes)

```bash
npm run test:watch
```

### Coverage Report

```bash
npm run test:coverage
```

## Test Configuration

Tests use a separate configuration file located at `config/test-config.json`:

- **HTTP Proxy Port**: 18881 (instead of 8881)
- **HTTPS Proxy Port**: 18889 (instead of 8889)
- **Bind Address**: 127.0.0.1 (localhost only)
- **Logging**: Minimal (errors only, no console/file output)

This prevents tests from interfering with a running development proxy instance.

## Unit Tests

Unit tests verify the core pattern matching and URL normalization logic without starting the actual proxy server.

### What's Tested

- URL normalization (protocol, host, path, query parameters)
- Pattern matching with wildcards (`*` and `**`)
- Host-only patterns with optional trailing slashes
- Protocol-agnostic matching (http/https)
- Policy evaluation logic (first-match-wins, default actions)
- Edge cases (invalid URLs, special characters, etc.)

### Running Unit Tests

```bash
npm run test:unit
```

Unit tests are fast and don't require network access.

## Integration Tests

Integration tests start an actual proxy server and make HTTP/HTTPS requests through it to verify end-to-end behavior.

### What's Tested

- HTTP proxy mode (CONNECT tunneling)
- Transparent HTTPS mode (direct HTTPS listener)
- Allow/deny policy enforcement
- Wildcard pattern matching in real requests
- Protocol-agnostic behavior
- Edge cases (special characters, query parameters, etc.)

### Requirements

- Internet access (tests make requests to google.com, example.com, httpbin.org)
- Ports 18881 and 18889 must be available
- Node.js and npm installed

### Running Integration Tests

```bash
npm run test:integration
```

**Note**: Integration tests may take 30+ seconds to complete as they:
1. Build the project
2. Start the proxy server
3. Make actual HTTP/HTTPS requests
4. Stop the proxy server

## Manual Testing

For manual testing and debugging, use the shell script:

```bash
./test/manual-test.sh
```

This script:
1. Builds the project
2. Starts the proxy with test configuration
3. Runs a series of curl commands to test various URLs
4. Reports pass/fail for each test
5. Stops the proxy and shows results

### Example Output

```
ACL Proxy Test Suite
====================

Building project...
Starting proxy with config: config/test-config.json
Waiting for proxy to start...

Running HTTP Proxy Tests
------------------------
Testing: Allowed URL (www.google.com)... ✓ PASS (HTTP 200)
Testing: Allowed URL with path (example.com)... ✓ PASS (HTTP 200)
Testing: Explicitly denied URL... ✓ PASS (HTTP 403)
...

Test Results
====================
Passed: 8
Failed: 0

All tests passed! ✓
```

## Testing Your Own Proxy

To test the proxy with your own configuration:

1. Start the proxy with your config:
   ```bash
   ACL_PROXY_CONFIG=config/your-config.json npm start
   ```

2. Test with curl:
   ```bash
   # Test via HTTP proxy
   curl -k -x http://127.0.0.1:8881 https://www.google.com/

   # Test via transparent HTTPS listener
   curl -k -H "Host: www.google.com" https://127.0.0.1:8889/
   ```

3. Check the logs:
   ```bash
   tail -f logs/proxy-combined.log
   ```

## Writing New Tests

### Adding Unit Tests

Create a new file in `test/unit/`:

```typescript
describe('My Feature', () => {
  test('should do something', () => {
    expect(result).toBe(expected);
  });
});
```

### Adding Integration Tests

Use the `ProxyTestServer` helper from `test/helpers/test-utils.ts`:

```typescript
import { ProxyTestServer } from '../helpers/test-utils';

describe('My Integration Test', () => {
  let server: ProxyTestServer;

  beforeAll(async () => {
    server = new ProxyTestServer();
    await server.start();
  });

  afterAll(async () => {
    await server.stop();
  });

  test('should allow requests', async () => {
    const response = await server.requestViaProxy('https://example.com/');
    expect(response.status).toBe(200);
  });
});
```

## Test Patterns

### Testing URL Patterns

The test suite includes comprehensive tests for URL pattern matching:

| Pattern | Matches | Doesn't Match |
|---------|---------|---------------|
| `https://example.com/**` | `https://example.com/any/path` | `https://other.com/path` |
| `https://example.com/api/*/resource` | `https://example.com/api/v1/resource` | `https://example.com/api/v1/v2/resource` |
| `https://*.example.com/**` | `https://api.example.com/path` | `https://example.com/path` |
| `https://example.com` | `https://example.com/` | `https://example.com/path` |

### Testing Policy Actions

```typescript
// Default deny with specific allows
{
  "default": "deny",
  "rules": [
    { "action": "allow", "pattern": "https://safe-site.com/**" }
  ]
}

// Default allow with specific denies
{
  "default": "allow",
  "rules": [
    { "action": "deny", "pattern": "https://blocked-site.com/**" }
  ]
}
```

## Troubleshooting

### Tests Fail with "Port in use"

Make sure no other proxy instance is running:
```bash
pkill -f "node dist/index.js"
```

Or use different ports in `config/test-config.json`.

### Tests Fail with "Cannot resolve host"

Integration tests require internet access. If testing in an isolated environment, use unit tests instead:
```bash
npm run test:unit
```

### Tests Timeout

Increase the Jest timeout in `jest.config.js`:
```javascript
testTimeout: 60000, // 60 seconds
```

### Certificate Errors

The proxy generates self-signed certificates. Tests use `-k` flag for curl and `rejectUnauthorized: false` for axios to accept them.

In production, you should:
1. Import the CA certificate from `certs/ca-cert.pem`
2. Add it to your system's trusted certificates
3. Configure clients to trust it

## CI/CD Integration

For continuous integration:

```yaml
# Example GitHub Actions workflow
- name: Run tests
  run: |
    npm install
    npm run build
    npm run test:unit
    # Skip integration tests if no internet access
```

For full integration testing in CI:
```yaml
- name: Run all tests
  run: |
    npm install
    npm test
```

## Performance

- **Unit tests**: ~1 second
- **Integration tests**: ~30 seconds (depends on network)
- **Manual test script**: ~10 seconds (depends on network)

## License

Same as the main project.
