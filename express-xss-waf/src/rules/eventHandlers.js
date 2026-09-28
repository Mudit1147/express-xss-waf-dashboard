'use strict';

const HANDLERS = [
  'onload', 'onerror', 'onclick', 'onmouseover', 'onmouseenter', 'onmouseleave',
  'onfocus', 'onblur', 'onchange', 'onsubmit', 'oninput', 'onkeydown', 'onkeyup',
  'onkeypress', 'ondblclick', 'oncontextmenu', 'onanimationstart', 'onanimationend',
  'ontransitionend', 'onpointerdown', 'onpointerup'
];

module.exports = [
  {
    id: 'XSS_EVENT_HANDLER',
    description: 'Inline event handler attribute',
    severity: 9,
    pattern: new RegExp(`\\b(?:${HANDLERS.join('|')})\\s*=`, 'i')
  }
];
