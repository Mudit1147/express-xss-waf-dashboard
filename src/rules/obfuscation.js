'use strict';

module.exports = [
  {
    id: 'XSS_PSEUDO_PROTOCOL',
    description: 'Executable or HTML data URI scheme',
    severity: 10,
    pattern: /(?:^|[\s"'=(])(?:javascript|vbscript)\s*:/i
  },
  {
    id: 'XSS_DATA_HTML',
    description: 'HTML data URI scheme',
    severity: 10,
    pattern: /(?:^|[\s"'=(])data\s*:\s*text\/html(?:[;,]|$)/i
  },
  {
    id: 'XSS_OBFUSCATED_ENCODING',
    description: 'Repeated percent or escape encoding anomaly',
    severity: 5,
    pattern: /(?:%25(?:25|3c|3e|22|27)|%u[0-9a-f]{4}|\\x[0-9a-f]{2}|\\u[0-9a-f]{4})/i
  },
  {
    id: 'XSS_SUSPICIOUS_CHAR_DISTRIBUTION',
    description: 'Suspicious concentration of markup/control characters',
    severity: 4,
    match(value) {
      if (value.length < 32) return false;
      const suspicious = (value.match(/[<>'"`%\\]/g) || []).length;
      return suspicious / value.length >= 0.25;
    }
  }
];
