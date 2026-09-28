# express-xss-waf

A lightweight, configurable XSS-focused Web Application Firewall middleware for Express.js. It recursively inspects request query parameters, bodies, route parameters and selected headers; normalizes common obfuscation; scores matched signatures; blocks or sanitizes requests; and emits structured SIEM-friendly events.

> **Security scope:** This package is an XSS-focused WAF layer, not a complete application security solution. Use output encoding, CSP, secure cookies, CSRF protection, input validation and dependency/security monitoring as additional controls.

## Requirements

- Node.js 18+
- Express 4.18+ or 5.x

## Installation

```bash
npm install express-xss-waf
```

## Basic usage

```js
const express = require('express');
const createXssWaf = require('express-xss-waf');

const app = express();
app.use(express.json());

app.use(createXssWaf({
  mode: 'block',
  threshold: 10,
  inspectHeaders: ['user-agent', 'referer']
}));

app.post('/profile', (req, res) => {
  res.json({ received: req.body });
});

app.listen(3000);
```

Place the middleware **after body parsers** (`express.json()`, `express.urlencoded()`) if you want it to inspect parsed request bodies.

## Configuration

| Option | Default | Description |
|---|---|---|
| `mode` | `block` | `block` returns 403 when a finding meets the threshold. `sanitize` mutates parsed inputs and calls `next()`. |
| `threshold` | `10` | Minimum per-field threat score required to trigger mitigation. |
| `maxDecodePasses` | `4` | Maximum normalization passes. Bounded to prevent unbounded decoding work. |
| `inspectHeaders` | `['user-agent','referer','x-forwarded-for']` | `false`, `true`, or an array of header names. |
| `customLogger` | `null` | Function receiving a structured event object. |
| `whiteList` | `[]` | Exact field paths, regular expressions, or predicate functions. |
| `maxDepth` | `20` | Maximum recursive object depth. |
| `maxStringLength` | `100000` | Maximum characters scanned from a single string. |
| `logger` | `true` | Enables the default JSON logger when no custom logger is supplied. |
| `failClosedOnError` | `true` | Returns 500 if WAF processing itself fails. Set false to pass the error to Express. |

## Detection model

The engine normalizes strings through bounded passes of URL decoding, HTML entity decoding, JavaScript Unicode/hex escape decoding, and null-byte removal. It then applies modular signatures for:

- `<script>`, `<iframe>`, `<object>`, `<embed>`, `<applet>`, `<svg>`, and `<base>` tags
- inline event handlers such as `onerror=`, `onclick=`, and `onload=`
- `javascript:`, `vbscript:` and `data:text/html` pseudo-protocols
- repeated encoding / escape anomalies and suspicious character distributions

Each matched rule contributes a severity score. Multiple rules on the same field are additive.

## SIEM event shape

A blocked or sanitized finding produces an event like:

```json
{
  "timestamp": "2026-09-28T08:15:30.000Z",
  "ip": "127.0.0.1",
  "method": "POST",
  "path": "/profile",
  "detectedRules": [
    { "id": "XSS_TAG_SCRIPT", "description": "Script element" }
  ],
  "threatScore": 10,
  "actionTaken": "BLOCKED",
  "targetField": "body.bio"
}
```

The default logger serializes this event as one JSON line through `console.info()`.

## Sanitization mode

`sanitize` is deliberately conservative and removes executable constructs rather than attempting to turn arbitrary HTML into a safe HTML subset. It normalizes parsed query/body/params first, then strips dangerous tags, inline handlers and executable URI schemes.

For applications that intentionally accept rich HTML, use a dedicated HTML sanitizer with a narrowly defined allowlist and continue to apply contextual output encoding. Do not treat this package as a substitute for browser-side CSP or server-side validation.

## Whitelisting

Exact paths can be excluded:

```js
createXssWaf({
  whiteList: ['body.markdown', 'query.search']
});
```

Regular expressions and predicates are also supported by the scanner:

```js
whiteList: [/^body\.trusted_/],
// or
whiteList: [(path) => path === 'body.signedPayload']
```

Only whitelist fields that are independently trusted or protected by another validation boundary. A whitelist bypasses this WAF's inspection; it does not make content safe.

## Testing

```bash
npm test
npm run test:watch
npm run test:coverage
```

The test suite covers decoder normalization, recursive arrays/objects, cycles, rule matching, whitelisting, Express blocking, encoded XSS, sanitization, headers, and structured logging.

## Production hardening notes

- Keep `express-xss-waf` behind normal Express request-size limits (`express.json({ limit: '100kb' })`, etc.).
- Keep the decoder pass count bounded.
- Use a restrictive Content Security Policy as a browser-side defense-in-depth control.
- Prefer context-aware output encoding over input filtering for preventing XSS.
- Do not log raw malicious payloads; this package's event format records rule metadata and target fields rather than the original input.
- Forward structured events to your SIEM through your existing logging pipeline.
- Test rules against your application's actual content types before deploying a blocking threshold.
