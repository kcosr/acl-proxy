import { UrlPolicy, normalizeClientIpForTests } from '../../src/index';

describe('Policy client subnet rules', () => {
  test('rule with pattern and subnets requires both to match', () => {
    const policyConfig: any = {
      default: 'deny',
      rules: [
        { action: 'allow', pattern: 'https://example.com/**', subnets: ['10.0.0.0/8'] }
      ]
    };
    const policy = new UrlPolicy(policyConfig);

    // URL and client subnet both match
    expect(policy.isAllowed('https://example.com/path', '10.1.2.3')).toBe(true);

    // URL matches but client is outside subnet
    expect(policy.isAllowed('https://example.com/path', '192.168.1.1')).toBe(false);

    // Client subnet matches but URL does not
    expect(policy.isAllowed('https://other.com/', '10.1.2.3')).toBe(false);
  });

  test('subnet-only rules work without a URL pattern', () => {
    const policyConfig: any = {
      default: 'deny',
      rules: [
        { action: 'allow', subnets: ['192.168.0.0/16'] }
      ]
    };
    const policy = new UrlPolicy(policyConfig);

    expect(policy.isAllowed('https://example.com/', '192.168.1.10')).toBe(true);
    expect(policy.isAllowed('https://other.com/any', '192.168.2.3')).toBe(true);
    expect(policy.isAllowed('https://example.com/', '10.0.0.1')).toBe(false);
  });

  test('invalid IPv4 subnets fail policy construction', () => {
    const policyConfig: any = {
      default: 'deny',
      rules: [
        { action: 'allow', subnets: ['not-an-ip'] }
      ]
    };
    expect(() => new UrlPolicy(policyConfig)).toThrow(/Invalid IPv4 subnet/);
  });

  test('deny rules with subnets override default allow', () => {
    const policyConfig: any = {
      default: 'allow',
      rules: [
        { action: 'deny', subnets: ['10.0.0.0/8'] }
      ]
    };
    const policy = new UrlPolicy(policyConfig);

    expect(policy.isAllowed('https://example.com/', '10.1.2.3')).toBe(false);
    expect(policy.isAllowed('https://example.com/', '192.168.1.1')).toBe(true);
  });

  test('supports multiple subnets on a single rule', () => {
    const policyConfig: any = {
      default: 'deny',
      rules: [
        { action: 'allow', subnets: ['10.0.0.0/8', '192.168.0.0/16'] }
      ]
    };
    const policy = new UrlPolicy(policyConfig);

    expect(policy.isAllowed('https://example.com/', '10.1.2.3')).toBe(true);
    expect(policy.isAllowed('https://example.com/', '192.168.1.5')).toBe(true);
    expect(policy.isAllowed('https://example.com/', '172.16.0.1')).toBe(false);
  });

  test('respects different CIDR prefix lengths', () => {
    const policyConfig: any = {
      default: 'deny',
      rules: [
        { action: 'allow', subnets: ['10.1.2.3/32', '192.168.0.0/24'] }
      ]
    };
    const policy = new UrlPolicy(policyConfig);

    expect(policy.isAllowed('https://example.com/', '10.1.2.3')).toBe(true);
    expect(policy.isAllowed('https://example.com/', '10.1.2.4')).toBe(false);
    expect(policy.isAllowed('https://example.com/', '192.168.0.10')).toBe(true);
    expect(policy.isAllowed('https://example.com/', '192.168.1.10')).toBe(false);
  });

  test('normalizes IPv6-mapped and loopback addresses for subnet checks', () => {
    expect(normalizeClientIpForTests('::ffff:10.1.2.3')).toBe('10.1.2.3');
    expect(normalizeClientIpForTests('::1')).toBe('127.0.0.1');
    expect(normalizeClientIpForTests('2001:db8::1')).toBe('2001:db8::1');
  });
});
