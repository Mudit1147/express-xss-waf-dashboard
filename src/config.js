'use strict';

const DEFAULT_CONFIG = Object.freeze({
  mode: 'block',
  threshold: 8,
  maxDecodePasses: 4,
  inspectHeaders: ['user-agent', 'referer', 'x-forwarded-for'],
  whiteList: [],
  whiteListPaths: [],
  logger: true,
  customLogger: null,
  maxDepth: 20,
  maxStringLength: 100_000,
  failClosedOnError: true
});

function validateConfig(options = {}) {
  const config = { ...DEFAULT_CONFIG, ...options };

  if (!['block', 'sanitize'].includes(config.mode)) {
    throw new TypeError("express-xss-waf: 'mode' must be 'block' or 'sanitize'.");
  }
  if (!Number.isInteger(config.threshold) || config.threshold < 0) {
    throw new TypeError("express-xss-waf: 'threshold' must be a non-negative integer.");
  }
  if (!Number.isInteger(config.maxDecodePasses) || config.maxDecodePasses < 1 || config.maxDecodePasses > 10) {
    throw new TypeError("express-xss-waf: 'maxDecodePasses' must be an integer between 1 and 10.");
  }
  if (!Number.isInteger(config.maxDepth) || config.maxDepth < 1 || config.maxDepth > 100) {
    throw new TypeError("express-xss-waf: 'maxDepth' must be an integer between 1 and 100.");
  }
  if (!Number.isInteger(config.maxStringLength) || config.maxStringLength < 256) {
    throw new TypeError("express-xss-waf: 'maxStringLength' must be at least 256.");
  }
  if (!(config.inspectHeaders === false || config.inspectHeaders === true || Array.isArray(config.inspectHeaders))) {
    throw new TypeError("express-xss-waf: 'inspectHeaders' must be a boolean or an array.");
  }
  if (!Array.isArray(config.whiteList)) {
    throw new TypeError("express-xss-waf: 'whiteList' must be an array.");
  }
  if (!Array.isArray(config.whiteListPaths) || config.whiteListPaths.some((path) => typeof path !== 'string')) {
    throw new TypeError("express-xss-waf: 'whiteListPaths' must be an array of path strings.");
  }
  if (config.customLogger !== null && typeof config.customLogger !== 'function') {
    throw new TypeError("express-xss-waf: 'customLogger' must be a function or null.");
  }

  return config;
}

module.exports = { DEFAULT_CONFIG, validateConfig };
