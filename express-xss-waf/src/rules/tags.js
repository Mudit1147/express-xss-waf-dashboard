'use strict';

module.exports = [
  {
    id: 'XSS_TAG_SCRIPT',
    description: 'Script element',
    severity: 10,
    pattern: /<\s*script\b[^>]*>/i
  },
  {
    id: 'XSS_TAG_IFRAME',
    description: 'Iframe element',
    severity: 8,
    pattern: /<\s*iframe\b[^>]*>/i
  },
  {
    id: 'XSS_TAG_OBJECT',
    description: 'Object element',
    severity: 7,
    pattern: /<\s*object\b[^>]*>/i
  },
  {
    id: 'XSS_TAG_EMBED',
    description: 'Embed element',
    severity: 7,
    pattern: /<\s*embed\b[^>]*>/i
  },
  {
    id: 'XSS_TAG_APPLET',
    description: 'Applet element',
    severity: 7,
    pattern: /<\s*applet\b[^>]*>/i
  },
  {
    id: 'XSS_TAG_SVG',
    description: 'SVG element',
    severity: 7,
    pattern: /<\s*svg\b[^>]*>/i
  },
  {
    id: 'XSS_TAG_BASE',
    description: 'Base element',
    severity: 6,
    pattern: /<\s*base\b[^>]*>/i
  }
];
