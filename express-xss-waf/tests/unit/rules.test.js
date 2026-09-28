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
});
