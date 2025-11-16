/**
 * Macro and ruleset expansion tests
 */
import { UrlPolicy } from '../../src/index';

describe('Policy macros and rulesets', () => {
  test('expands rulesets with macro lists and urlenc variants via include flag', () => {
    const policyConfig: any = {
      default: 'deny',
      macros: {
        repo: ['user/ts-test-1', 'user/ts-test-2']
      },
      rulesets: {
        gitlabRepo: [
          { action: 'allow', pattern: 'https://gitlab.internal/api/v4/projects/{repo}?**' },
          { action: 'allow', pattern: 'https://gitlab.internal/api/v4/projects/{repo}/**' },
          { action: 'allow', pattern: 'https://gitlab.internal/api/v4/projects/{repo}' },
          { action: 'allow', pattern: 'https://gitlab.internal/{repo}/**' },
          { action: 'allow', pattern: 'https://gitlab.internal/{repo}.git/**' }
        ]
      },
      rules: [
        // Auto-binds {repo} to macros.repo; also generate URL-encoded variants
        { include: 'gitlabRepo', addUrlEncVariants: true }
      ]
    };

    const policy = new UrlPolicy(policyConfig);

    // Allowed URLs for repo 1 (encoded + raw forms)
    expect(policy.isAllowed('https://gitlab.internal/api/v4/projects/user%2Fts-test-1?stats=true')).toBe(true);
    expect(policy.isAllowed('https://gitlab.internal/api/v4/projects/user%2Fts-test-1')).toBe(true);
    expect(policy.isAllowed('https://gitlab.internal/user/ts-test-1/any/path')).toBe(true);
    expect(policy.isAllowed('https://gitlab.internal/user/ts-test-1.git/info/refs')).toBe(true);

    // Allowed URLs for repo 2 as well (macro list expansion)
    expect(policy.isAllowed('https://gitlab.internal/api/v4/projects/user%2Fts-test-2?stats=true')).toBe(true);
    expect(policy.isAllowed('https://gitlab.internal/user/ts-test-2/any/path')).toBe(true);

    // Not allowed for other repos
    expect(policy.isAllowed('https://gitlab.internal/other/repo/any')).toBe(false);
    expect(policy.isAllowed('https://gitlab.internal/api/v4/projects/other%2Frepo?foo=1')).toBe(false);
  });

  test('scoped urlenc variants only for specified placeholders', () => {
    const policyConfig: any = {
      default: 'deny',
      macros: {
        repo: ['user/ts-test-1'],
        other: ['x/y']
      },
      rulesets: {
        repoAndOther: [
          { action: 'allow', pattern: 'https://gitlab.internal/api/v4/projects/{repo}?name={other}' }
        ]
      },
      rules: [
        { include: 'repoAndOther', addUrlEncVariants: ['repo'] }
      ]
    };
    const policy = new UrlPolicy(policyConfig);
    // Encoded variant for repo should be allowed; other remains raw
    expect(policy.isAllowed('https://gitlab.internal/api/v4/projects/user%2Fts-test-1?name=x/y')).toBe(true);
    // If 'other' were encoded as well, it should not match
    expect(policy.isAllowed('https://gitlab.internal/api/v4/projects/user%2Fts-test-1?name=x%2Fy')).toBe(false);
  });

  test('explicit with override value, plus urlenc variants', () => {
    const policyConfig: any = {
      default: 'deny',
      macros: {
        repo: ['user/ts-test-1']
      },
      rulesets: {
        gitlabRepo: [
          { action: 'allow', pattern: 'https://gitlab.internal/api/v4/projects/{repo}?**' }
        ]
      },
      rules: [
        { include: 'gitlabRepo', with: { repo: 'user/override' }, addUrlEncVariants: true }
      ]
    };
    const policy = new UrlPolicy(policyConfig);
    expect(policy.isAllowed('https://gitlab.internal/api/v4/projects/user%2Foverride?stats=true')).toBe(true);
    // A repo from macros that isn't included by override should not be allowed
    expect(policy.isAllowed('https://gitlab.internal/api/v4/projects/user%2Fts-test-1?stats=true')).toBe(false);
  });

  test('legacy {repo|urlenc} placeholders are not supported', () => {
    const policyConfig: any = {
      default: 'deny',
      macros: {
        repo: ['user/ts-test-1']
      },
      rulesets: {
        legacy: [
          { action: 'allow', pattern: 'https://gitlab.internal/api/v4/projects/{repo|urlenc}?**' }
        ]
      },
      rules: [
        { include: 'legacy', addUrlEncVariants: true }
      ]
    };
    const policy = new UrlPolicy(policyConfig);
    // With legacy placeholders, the pattern won't interpolate, so it shouldn't match
    expect(policy.isAllowed('https://gitlab.internal/api/v4/projects/user%2Fts-test-1?stats=true')).toBe(false);
  });

  test('direct rule interpolation with single-value and list macros', () => {
    const policyConfig: any = {
      default: 'deny',
      macros: {
        gitlab_prefix: 'https://gitlab.internal',
        repo: ['user/ts-test-1', 'user/ts-test-2']
      },
      rules: [
        { action: 'allow', pattern: '{gitlab_prefix}/api/v4/projects/{repo}?**', addUrlEncVariants: ['repo'] },
        { action: 'allow', pattern: '{gitlab_prefix}/{repo}.git/**' }
      ]
    };
    const policy = new UrlPolicy(policyConfig);
    // Encoded API endpoint allowed for repo 1 and 2
    expect(policy.isAllowed('https://gitlab.internal/api/v4/projects/user%2Fts-test-1?stats=true')).toBe(true);
    expect(policy.isAllowed('https://gitlab.internal/api/v4/projects/user%2Fts-test-2?stats=true')).toBe(true);
    // Raw git endpoints allowed
    expect(policy.isAllowed('https://gitlab.internal/user/ts-test-1.git/info/refs')).toBe(true);
    expect(policy.isAllowed('https://gitlab.internal/user/ts-test-2.git/info/refs')).toBe(true);
    // Not allowed for other repos
    expect(policy.isAllowed('https://gitlab.internal/api/v4/projects/other%2Frepo?stats=true')).toBe(false);
  });

  test('throws when ruleset placeholder macro is missing', () => {
    const policyConfig: any = {
      default: 'deny',
      // No macros provided
      rulesets: {
        needsRepo: [
          { action: 'allow', pattern: 'https://gitlab.internal/api/v4/projects/{repo}?**' }
        ]
      },
      rules: [
        { include: 'needsRepo', addUrlEncVariants: true }
      ]
    };
    expect(() => new UrlPolicy(policyConfig)).toThrow(/Policy macro not found: repo/);
  });

  test('throws when direct rule placeholder macro is missing', () => {
    const policyConfig: any = {
      default: 'deny',
      rules: [
        { action: 'allow', pattern: 'https://gitlab.internal/api/v4/projects/{repo}?**', addUrlEncVariants: true }
      ]
    };
    expect(() => new UrlPolicy(policyConfig)).toThrow(/Policy macro not found: repo/);
  });
});
