// Quick test to debug pattern matching

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function patternToRegex(pattern) {
  const raw = pattern.trim();
  const schemeMatch = raw.match(/^(https?):\/\//i);
  const hasScheme = !!schemeMatch;
  const schemeRegex = 'https?:\\/\\/';

  let rest = hasScheme ? raw.slice(schemeMatch[0].length) : raw.replace(/^\/*/, '');

  let pathPart = '';
  const slashIdx = rest.indexOf('/');
  if (slashIdx !== -1) {
    pathPart = rest.slice(slashIdx + 1);
  }
  const isHostOnly = !pathPart;

  if (isHostOnly) {
    rest = rest.replace(/\/+$/, '');
  }

  let s = escapeRegex(rest)
    .replace(/\\\*\\\*/g, '.*')
    .replace(/\\\*/g, '[^/]*');

  if (isHostOnly) {
    s += '\\/?';
  }

  return new RegExp('^' + schemeRegex + s + '$', 'i');
}

function normalizeUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    return `${u.protocol}//${u.host}${u.pathname || ''}${u.search || ''}`;
  } catch {
    return null;
  }
}

// Test multiple URLs to check for false matches
const testUrls = [
  'https://gitlab.internal/api/v4/projects/user%2Fts-test-1?license=true',
  'https://gitlab.internal/api/v4/projects/user%2Fts-test-10?license=true',
  'https://gitlab.internal/api/v4/projects/user%2Fts-test-1',
  'https://gitlab.internal/api/v4/projects/user%2Fts-test-1/issues',
];

// Test different patterns
const patterns = [
  'https://gitlab.internal/api/v4/projects/user%2Fts-test-1**',
  'https://gitlab.internal/api/v4/projects/user%2Fts-test-1?**',
];

patterns.forEach(pattern => {
  const regex = patternToRegex(pattern);
  console.log(`Pattern: ${pattern}`);
  console.log(`Regex: ${regex}`);
  console.log('');
  testUrls.forEach(url => {
    const normalized = normalizeUrl(url);
    const matches = regex.test(normalized);
    console.log(`  ${matches ? '✓ MATCH' : '✗ NO   '} - ${url}`);
  });
  console.log('');
  console.log('---');
  console.log('');
});
