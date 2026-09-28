'use strict';

const tagRules = require('../rules/tags');
const eventRules = require('../rules/eventHandlers');
const obfuscationRules = require('../rules/obfuscation');
const { normalizeString } = require('./decoder');

const RULES = [...tagRules, ...eventRules, ...obfuscationRules];

function scanString(value, options = {}) {
  const matches = [];
  const normalized = normalizeString(value, {
    maxPasses: options.maxDecodePasses ?? 4,
    maxLength: options.maxStringLength ?? 100_000
  });
  for (const rule of RULES) {
    let matched = false;
    try {
      matched = typeof rule.match === 'function' ? rule.match(normalized) : rule.pattern.test(normalized);
    } catch {
      matched = false;
    }
    if (matched) matches.push({ id: rule.id, description: rule.description, severity: rule.severity });
  }
  return { normalized, matches, threatScore: matches.reduce((sum, rule) => sum + rule.severity, 0) };
}

function shouldSkipPath(path, whiteList = []) {
  return whiteList.some((entry) => {
    if (typeof entry === 'function') return entry(path);
    if (entry instanceof RegExp) return entry.test(path);
    return typeof entry === 'string' && entry === path;
  });
}

function scanObject(root, options = {}) {
  const maxDepth = options.maxDepth ?? 20;
  const maxStringLength = options.maxStringLength ?? 100_000;
  const whiteList = options.whiteList ?? [];
  const findings = [];
  const seen = new WeakSet();

  function visit(value, path, depth) {
    if (shouldSkipPath(path, whiteList)) return;
    if (depth > maxDepth) return;

    if (typeof value === 'string') {
      const bounded = value.length > maxStringLength ? value.slice(0, maxStringLength) : value;
      const result = scanString(bounded, { maxDecodePasses: options.maxDecodePasses, maxStringLength });
      if (result.matches.length) findings.push({ targetField: path, originalValue: value, ...result });
      return;
    }
    if (value === null || typeof value !== 'object') return;
    if (seen.has(value)) return;
    seen.add(value);

    if (Array.isArray(value)) {
      value.forEach((item, index) => visit(item, `${path}[${index}]`, depth + 1));
      return;
    }
    for (const [key, item] of Object.entries(value)) visit(item, path ? `${path}.${key}` : key, depth + 1);
  }

  visit(root, '', 0);
  return findings;
}

module.exports = { scanString, scanObject, RULES };
