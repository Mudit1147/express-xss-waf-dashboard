const { scanObject, scanString } = require('../../src/utils/scanner');

describe('scanner', () => {
  test('detects nested object and array payloads', () => {
    const findings = scanObject({ user: { bio: ['hello', '<script>alert(1)</script>'] } });
    expect(findings).toHaveLength(1);
    expect(findings[0].targetField).toBe('user.bio[1]');
    expect(findings[0].matches.some((m) => m.id === 'XSS_TAG_SCRIPT')).toBe(true);
  });
  test('detects encoded payload after normalization', () => {
    const result = scanString('%253Cscript%253Ealert(1)%253C%252Fscript%253E');
    expect(result.matches.map((m) => m.id)).toContain('XSS_TAG_SCRIPT');
    expect(result.threatScore).toBeGreaterThanOrEqual(10);
  });
  test('does not recurse forever on cyclic objects', () => {
    const obj = { name: 'safe' };
    obj.self = obj;
    expect(() => scanObject(obj)).not.toThrow();
  });
  test('supports exact path whitelist', () => {
    const findings = scanObject({ safe: '<script>x</script>', bad: '<script>x</script>' }, { whiteList: ['safe'] });
    expect(findings.map((x) => x.targetField)).toEqual(['bad']);
  });
});
