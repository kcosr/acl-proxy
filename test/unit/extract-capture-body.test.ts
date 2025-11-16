import { extractBodiesFromContent } from '../../src/cli/extract-capture-body';

describe('extractBodiesFromContent (single JSON file)', () => {
  test('extracts and decodes a base64 body from a single JSON', () => {
    const bodyText = 'ok';
    const base64 = Buffer.from(bodyText, 'utf8').toString('base64');
    const json = JSON.stringify({ body: { encoding: 'base64', data: base64 } });
    const result = extractBodiesFromContent(json);
    expect(result).toHaveLength(1);
    expect(result[0].toString('utf8')).toBe(bodyText);
  });

  test('returns empty when body is missing', () => {
    const json = JSON.stringify({});
    const result = extractBodiesFromContent(json);
    expect(result).toHaveLength(0);
  });

  test('returns empty when encoding is not base64', () => {
    const json = JSON.stringify({ body: { encoding: 'utf8', data: 'plain' } });
    const result = extractBodiesFromContent(json);
    expect(result).toHaveLength(0);
  });

  test('returns empty and logs for invalid JSON', () => {
    const result = extractBodiesFromContent('{invalid json');
    expect(result).toHaveLength(0);
  });
});
