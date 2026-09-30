'use strict';

const HTML_ENTITIES = Object.freeze({
  '&lt;': '<',
  '&gt;': '>',
  '&quot;': '"',
  '&apos;': "'",
  '&amp;': '&',
  '&colon;': ':',
  '&sol;': '/',
  '&tab;': '\t'
});

/**
 * Safely parses a URL string using the modern WHATWG URL API instead of deprecated url.parse().
 * @param {string} inputUrl - The URL or path to parse.
 * @param {string} [baseUrl='http://localhost'] - Fallback base URL for relative paths.
 * @returns {URL|null} The parsed WHATWG URL object or null if parsing fails.
 */
function parseUrlSafe(inputUrl, baseUrl = 'http://localhost') {
  if (typeof inputUrl !== 'string') return null;
  try {
    return new URL(inputUrl, baseUrl);
  } catch {
    return null;
  }
}

function decodeHtmlEntities(input) {
  return input
    .replace(/&#(x[0-9a-f]+|\d+);?/gi, (full, raw) => {
      const isHex = /^x/i.test(raw);
      const value = Number.parseInt(isHex ? raw.slice(1) : raw, isHex ? 16 : 10);
      if (!Number.isFinite(value) || value < 0 || value > 0x10ffff) return full;
      try {
        return String.fromCodePoint(value);
      } catch {
        return full;
      }
    })
    .replace(/&[a-z][a-z0-9]+;/gi, (entity) => HTML_ENTITIES[entity.toLowerCase()] ?? entity);
}

function decodeUnicodeEscapes(input) {
  return input
    .replace(/\\u\{([0-9a-f]{1,6})\}/gi, (full, hex) => {
      const n = Number.parseInt(hex, 16);
      return n <= 0x10ffff ? String.fromCodePoint(n) : full;
    })
    .replace(/\\u([0-9a-f]{4})/gi, (full, hex) => String.fromCharCode(Number.parseInt(hex, 16)))
    .replace(/\\x([0-9a-f]{2})/gi, (full, hex) => String.fromCharCode(Number.parseInt(hex, 16)));
}

function decodeUrl(input) {
  if (typeof input !== 'string') return input;
  let output = input;
  try {
    output = decodeURIComponent(output.replace(/\+/g, '%20'));
  } catch {
    // Decode valid percent triplets while preserving malformed sequences.
    output = output.replace(/%([0-9a-f]{2})/gi, (full, hex) =>
      String.fromCharCode(Number.parseInt(hex, 16))
    );
  }
  return output;
}

function normalizeString(value, options = {}) {
  const maxPasses = Number.isInteger(options.maxPasses) ? options.maxPasses : 4;
  const maxLength = Number.isInteger(options.maxLength) ? options.maxLength : 100_000;
  let current = String(value).replace(/\0/g, '');
  if (current.length > maxLength) current = current.slice(0, maxLength);

  for (let pass = 0; pass < maxPasses; pass += 1) {
    const previous = current;
    current = decodeUnicodeEscapes(current);
    current = decodeHtmlEntities(current);
    current = decodeUrl(current);
    current = current.replace(/\0/g, '');
    if (current.length > maxLength) current = current.slice(0, maxLength);
    if (current === previous) break;
  }

  return current;
}

function normalize(value, options = {}) {
  if (typeof value === 'string') return normalizeString(value, options);
  if (Array.isArray(value)) return value.map((item) => normalize(item, options));
  if (value && typeof value === 'object') {
    const output = {};
    for (const [key, item] of Object.entries(value)) {
      output[key] = normalize(item, options);
    }
    return output;
  }
  return value;
}

module.exports = {
  normalizeString,
  normalize,
  decodeHtmlEntities,
  decodeUnicodeEscapes,
  decodeUrl,
  parseUrlSafe
};