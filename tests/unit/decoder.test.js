const { normalizeString } = require('../../src/utils/decoder');

describe('decoder', () => {
  test('decodes HTML decimal, hex and named entities', () => {
    expect(normalizeString('&#60;script&#62;&lt;img&gt;')).toBe('<script><img>');
  });
  test('decodes double URL encoding', () => {
    expect(normalizeString('%253Cscript%253E')).toBe('<script>');
  });
  test('decodes unicode and hexadecimal escapes', () => {
    expect(normalizeString('\\u003cscript\\x3e')).toBe('<script>');
  });
  test('removes null bytes', () => {
    expect(normalizeString('%00java%00script%00:')).toBe('javascript:');
  });
  test('stops after configured passes', () => {
    const input = '%252525253Cscript%252525253E';
    expect(normalizeString(input, { maxPasses: 1 })).not.toContain('<script>');
    expect(normalizeString(input, { maxPasses: 5 })).toContain('<script>');
  });
});
