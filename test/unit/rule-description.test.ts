import { UrlPolicy } from '../../src/index';

describe('Rule descriptions', () => {
  test('description is carried to matched rule for direct rules', () => {
    const policyConfig: any = {
      default: 'deny',
      macros: {
        gitlab_prefix: 'https://gitlab.internal',
        repo: ['user/ts-test-1']
      },
      rules: [
        { action: 'allow', pattern: '{gitlab_prefix}/api/v4/projects/{repo}', addUrlEncVariants: ['repo'], description: 'GitLab API for {repo}' }
      ]
    };
    const policy = new UrlPolicy(policyConfig);
    const res = policy.evaluate('https://gitlab.internal/api/v4/projects/user%2Fts-test-1');
    expect(res.allowed).toBe(true);
    expect(res.matched?.description).toBe('GitLab API for user%2Fts-test-1');
  });

  test('description interpolates in ruleset templates', () => {
    const policyConfig: any = {
      default: 'deny',
      macros: { repo: ['user/ts-test-1'] },
      rulesets: {
        rs: [ { action: 'allow', pattern: 'https://gitlab.internal/{repo}.git/**', description: 'Repo git for {repo}' } ]
      },
      rules: [ { include: 'rs' } ]
    };
    const policy = new UrlPolicy(policyConfig);
    const res = policy.evaluate('https://gitlab.internal/user/ts-test-1.git/info/refs');
    expect(res.allowed).toBe(true);
    expect(res.matched?.description).toBe('Repo git for user/ts-test-1');
  });
});
