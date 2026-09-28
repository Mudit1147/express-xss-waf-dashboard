'use strict';

const { validateConfig } = require('./config');
const { scanObject } = require('./utils/scanner');
const { normalize } = require('./utils/decoder');
const { createLogEvent, logEvent } = require('./utils/logger');

function headerSource(req, inspectHeaders) {
  if (inspectHeaders === false) return {};
  const keys = inspectHeaders === true ? Object.keys(req.headers) : inspectHeaders;
  return Object.fromEntries(keys.map((key) => [key, req.get(key) ?? '']).filter(([, value]) => value !== ''));
}

function sanitizeValue(value) {
  if (typeof value !== 'string') return value;
  // Conservative sanitizer: remove executable constructs, not ordinary text.
  let output = value;
  output = output.replace(/<\s*(script|iframe|object|embed|applet|svg|base)\b[^>]*>[\s\S]*?<\s*\/\s*\1\s*>/gi, '');
  output = output.replace(/<\s*\/?\s*(script|iframe|object|embed|applet|svg|base)\b[^>]*>/gi, '');
  output = output.replace(/\bon(?:load|error|click|mouseover|mouseenter|mouseleave|focus|blur|change|submit|input|keydown|keyup|keypress|dblclick|contextmenu|animationstart|animationend|transitionend|pointerdown|pointerup)\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '');
  output = output.replace(/(?:javascript|vbscript)\s*:/gi, '');
  output = output.replace(/data\s*:\s*text\/html(?:[^\s"'>]*)/gi, '');
  return output;
}

function sanitizeObject(value, seen = new WeakSet()) {
  if (typeof value === 'string') return sanitizeValue(value);
  if (!value || typeof value !== 'object') return value;
  if (seen.has(value)) return value;
  seen.add(value);
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) value[i] = sanitizeObject(value[i], seen);
  } else {
    for (const key of Object.keys(value)) value[key] = sanitizeObject(value[key], seen);
  }
  return value;
}

function replaceNormalizedObject(value, options = {}, seen = new WeakSet()) {
  if (typeof value === 'string') return normalize(value, options);
  if (!value || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) value[i] = replaceNormalizedObject(value[i], options, seen);
  } else {
    for (const key of Object.keys(value)) value[key] = replaceNormalizedObject(value[key], options, seen);
  }
  return value;
}

function createXssWaf(options = {}) {
  const config = validateConfig(options);

  return function xssWaf(req, res, next) {
    try {
      const sources = {
        query: req.query || {},
        body: req.body || {},
        params: req.params || {},
        headers: headerSource(req, config.inspectHeaders)
      };

      const findings = [];
      for (const [source, value] of Object.entries(sources)) {
        findings.push(...scanObject(value, {
          maxDepth: config.maxDepth,
          maxStringLength: config.maxStringLength,
          maxDecodePasses: config.maxDecodePasses,
          whiteList: config.whiteList.map((entry) => {
            if (typeof entry === 'string' && !entry.startsWith(source)) return `${source}.${entry}`;
            return entry;
          })
        }).map((finding) => ({ ...finding, targetField: `${source}${finding.targetField ? `.${finding.targetField}` : ''}` })));
      }

      const breached = findings.filter((finding) => finding.threatScore >= config.threshold);
      if (!breached.length) return next();

      if (config.mode === 'block') {
        for (const finding of breached) {
          const event = createLogEvent(req, finding, 'BLOCKED');
          if (config.customLogger) config.customLogger(event);
          else if (config.logger) logEvent(event);
        }
        return res.status(403).json({ error: 'Forbidden', message: 'Request blocked by XSS WAF.' });
      }

      // Normalize first so double-encoded threats are represented in the request object,
      // then strip executable constructs in-place.
      for (const key of ['query', 'body', 'params']) replaceNormalizedObject(req[key], { maxPasses: config.maxDecodePasses, maxLength: config.maxStringLength });
      sanitizeObject(req.query);
      sanitizeObject(req.body);
      sanitizeObject(req.params);
      if (req.headers && config.inspectHeaders !== false) {
        const headerKeys = config.inspectHeaders === true ? Object.keys(req.headers) : config.inspectHeaders.map((key) => key.toLowerCase());
        for (const key of headerKeys) {
          if (typeof req.headers[key] === 'string') req.headers[key] = sanitizeValue(req.headers[key]);
        }
      }

      for (const finding of breached) {
        const event = createLogEvent(req, finding, 'SANITIZED');
        if (config.customLogger) config.customLogger(event);
        else if (config.logger) logEvent(event);
      }
      return next();
    } catch (error) {
      if (config.failClosedOnError) {
        return res.status(500).json({ error: 'Internal Server Error', message: 'WAF processing failed.' });
      }
      return next(error);
    }
  };
}

module.exports = createXssWaf;
module.exports.createXssWaf = createXssWaf;
module.exports.sanitizeValue = sanitizeValue;
