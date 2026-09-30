const { normalizeString, parseUrlSafe } = require('../../src/utils/decoder');

describe('decoder', () => {
  test.each([
    ['%3Cscript%3Ealert(1)%3C/script%3E', '<script>alert(1)</script>'],
    ['%253Cscript%253Ealert(1)%253C%252Fscript%253E', '<script>alert(1)</script>']
  ])('decodes URL-encoded payload %s', (input, expected) => {
    expect(normalizeString(input)).toBe(expected);
  });

  test('decodes hexadecimal and decimal HTML entities', () => {
    expect(normalizeString('&#x3C;img src=x onerror=alert(1)&#x3E;')).toBe('<img src=x onerror=alert(1)>');
    expect(normalizeString('&#60;script&#62;')).toBe('<script>');
  });

  test('decodes Unicode and hexadecimal escape sequences', () => {
    expect(normalizeString('\\u003cscript\\u003e')).toBe('<script>');
    expect(normalizeString('\\u003cscript\\x3e')).toBe('<script>');
  });

  test.each(['ordinary text', 'john_doe', 'Hello world!', 'only one online option'])('preserves clean text: %s', (input) => {
    expect(normalizeString(input)).toBe(input);
  });

  test('removes null bytes', () => {
    expect(normalizeString('%00java%00script%00:')).toBe('javascript:');
  });
  test('stops after configured passes', () => {
    const input = '%252525253Cscript%252525253E';
    expect(normalizeString(input, { maxPasses: 1 })).not.toContain('<script>');
    expect(normalizeString(input, { maxPasses: 5 })).toContain('<script>');
  });

  test('parses relative URLs with the WHATWG URL API', () => {
    const parsed = parseUrlSafe('/search?q=x');
    expect(parsed.pathname).toBe('/search');
    expect(parsed.searchParams.get('q')).toBe('x');
  });

  test('returns null for invalid URL input', () => {
    expect(parseUrlSafe(null)).toBeNull();
    expect(parseUrlSafe('http://[invalid')).toBeNull();
  });
});
