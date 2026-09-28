'use strict';

const ANSI = Object.freeze({
  reset: '\x1b[0m',
  dim: '\x1b[2m',
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  white: '\x1b[37m'
});

function createLogEvent(req, finding, actionTaken) {
  return {
    timestamp: new Date().toISOString(),
    ip: req.ip || req.socket?.remoteAddress || null,
    method: req.method,
    path: req.originalUrl || req.path || req.url,
    detectedRules: finding.matches.map(({ id, description }) => ({ id, description })),
    threatScore: finding.threatScore,
    actionTaken,
    targetField: finding.targetField
  };
}

function actionColor(action) {
  if (action === 'BLOCKED') return ANSI.red;
  if (action === 'SANITIZED') return ANSI.yellow;
  return ANSI.green;
}

function formatLogEvent(event, color = process.stdout.isTTY) {
  const json = JSON.stringify(event, null, 2);
  if (!color) return json;
  const colorCode = actionColor(event.actionTaken);
  return `${ANSI.dim}┌─ XSS WAF / SIEM EVENT${ANSI.reset}\n${colorCode}${json}${ANSI.reset}\n${ANSI.dim}└────────────────────────${ANSI.reset}`;
}

function logEvent(event, logger = console) {
  const output = formatLogEvent(event);
  if (logger && typeof logger.info === 'function') logger.info(output);
  else if (logger && typeof logger.log === 'function') logger.log(output);
}

module.exports = { createLogEvent, formatLogEvent, logEvent };
