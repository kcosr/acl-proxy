/**
 * Simple pattern matching tests
 * Tests URL normalization and basic pattern concepts
 */

describe('URL Pattern Concepts', () => {
  test('URL normalization includes protocol, host, and path', () => {
    const url = new URL('https://example.com/path?query=value');
    const normalized = `${url.protocol}//${url.host}${url.pathname}${url.search}`;
    expect(normalized).toBe('https://example.com/path?query=value');
  });

  test('URLs with trailing slashes are normalized', () => {
    const url1 = new URL('https://example.com/');
    const url2 = new URL('https://example.com');

    expect(url1.pathname).toBe('/');
    expect(url2.pathname).toBe('/');
  });

  test('Query parameters are preserved in normalization', () => {
    const url = new URL('https://example.com/path?a=1&b=2');
    expect(url.search).toBe('?a=1&b=2');
  });

  test('Fragments are not sent to proxy', () => {
    const url = new URL('https://example.com/path#fragment');
    const normalized = `${url.protocol}//${url.host}${url.pathname}${url.search}`;
    expect(normalized).toBe('https://example.com/path');
    expect(url.hash).toBe('#fragment'); // Fragment exists but not in normalized form
  });

  test('Case sensitivity in URLs', () => {
    const url1 = new URL('https://Example.Com/Path');
    expect(url1.host).toBe('example.com'); // Host is lowercased
    expect(url1.pathname).toBe('/Path'); // Path is case-sensitive
  });

  describe('RegExp pattern matching', () => {
    test('** wildcard pattern (matches any characters)', () => {
      const pattern = /^https?:\/\/example\.com\/.*$/i;

      expect(pattern.test('https://example.com/')).toBe(true);
      expect(pattern.test('https://example.com/path')).toBe(true);
      expect(pattern.test('https://example.com/path/to/resource')).toBe(true);
      expect(pattern.test('http://example.com/path')).toBe(true); // Protocol-agnostic
      expect(pattern.test('https://other.com/path')).toBe(false);
    });

    test('* wildcard pattern (matches characters except /)', () => {
      const pattern = /^https?:\/\/example\.com\/api\/[^/]*\/resource$/i;

      expect(pattern.test('https://example.com/api/v1/resource')).toBe(true);
      expect(pattern.test('https://example.com/api/v2/resource')).toBe(true);
      expect(pattern.test('https://example.com/api/v1/v2/resource')).toBe(false); // * doesn't match /
    });

    test('Host-only pattern with optional trailing slash', () => {
      const pattern = /^https?:\/\/example\.com\/?$/i;

      expect(pattern.test('https://example.com')).toBe(true);
      expect(pattern.test('https://example.com/')).toBe(true);
      expect(pattern.test('https://example.com/path')).toBe(false);
    });

    test('Subdomain wildcard pattern', () => {
      const pattern = /^https?:\/\/[^/]*\.example\.com\/.*$/i;

      expect(pattern.test('https://api.example.com/path')).toBe(true);
      expect(pattern.test('https://www.example.com/path')).toBe(true);
      expect(pattern.test('https://example.com/path')).toBe(false); // * requires characters
    });

    test('Escaped special characters in patterns', () => {
      // Pattern: https://api.github.com/repos/owner/repo
      const pattern = /^https?:\/\/api\.github\.com\/repos\/[^/]*\/readme$/i;

      expect(pattern.test('https://api.github.com/repos/owner/readme')).toBe(true);
      expect(pattern.test('https://api.github.com/repos/test-org/readme')).toBe(true);
      expect(pattern.test('https://api.github.com/repos/owner/repo/readme')).toBe(false);
    });
  });

  describe('Policy evaluation logic', () => {
    test('First matching rule wins', () => {
      const rules = [
        { pattern: /^https?:\/\/example\.com\/admin\/.*$/, action: 'deny' },
        { pattern: /^https?:\/\/example\.com\/.*$/, action: 'allow' }
      ];

      const evaluate = (url: string) => {
        for (const rule of rules) {
          if (rule.pattern.test(url)) {
            return rule.action;
          }
        }
        return 'deny'; // default
      };

      expect(evaluate('https://example.com/public')).toBe('allow');
      expect(evaluate('https://example.com/admin/panel')).toBe('deny'); // First rule matched
    });

    test('Default action when no rule matches', () => {
      const rules: any[] = [];
      const defaultAction = 'deny';

      const evaluate = (url: string) => {
        for (const rule of rules) {
          if (rule.pattern.test(url)) {
            return rule.action;
          }
        }
        return defaultAction;
      };

      expect(evaluate('https://anything.com/path')).toBe('deny');
    });

    test('Invalid URLs should be denied', () => {
      const isValidUrl = (urlString: string) => {
        try {
          new URL(urlString);
          return true;
        } catch {
          return false;
        }
      };

      expect(isValidUrl('https://example.com/path')).toBe(true);
      expect(isValidUrl('not-a-url')).toBe(false);
      expect(isValidUrl('')).toBe(false);
      expect(isValidUrl('javascript:alert(1)')).toBe(true); // Valid URL, but shouldn't match http patterns
    });
  });
});
