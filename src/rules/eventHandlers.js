'use strict';

module.exports = [
  {
    id: 'XSS_EVENT_HANDLER',
    description: 'Inline event handler attribute',
    severity: 8,
    pattern: /\bon[a-z]+\s*=/i
  }
];
