const { scanString } = require('../../src/utils/scanner');

describe('rules', () => {
  test.each([
    ['<script>alert(1)</script>', 'XSS_TAG_SCRIPT'],
    ['<iframe src="x">', 'XSS_TAG_IFRAME'],
    ['<svg onload=alert(1)>', 'XSS_TAG_SVG'],
    ['<img src=x onerror = alert(1)>', 'XSS_EVENT_HANDLER'],
    ['javascript:alert(1)', 'XSS_PSEUDO_PROTOCOL'],
    ['href="vbscript:msgbox(1)"', 'XSS_PSEUDO_PROTOCOL'],
    ['data:text/html,<script>alert(1)</script>', 'XSS_DATA_HTML']
  ])('detects %s', (payload, ruleId) => {
    expect(scanString(payload).matches.map((m) => m.id)).toContain(ruleId);
  });

  test.each([
    ['<script>alert(1)</script>', 'XSS_TAG_SCRIPT', 10],
    ['javascript:alert(1)', 'XSS_PSEUDO_PROTOCOL', 9],
    ['<img src=x onerror=alert(1)>', 'XSS_EVENT_HANDLER', 8]
  ])('assigns score %i to %s', (payload, ruleId, score) => {
    const match = scanString(payload).matches.find((rule) => rule.id === ruleId);
    expect(match.severity).toBe(score);
  });

  test.each(['only one option', 'online learning', 'a < b', '## harmless markdown'])('does not flag benign text: %s', (text) => {
    expect(scanString(text).matches).toHaveLength(0);
  });
});
