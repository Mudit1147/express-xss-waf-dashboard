'use strict';

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

function logEvent(event, logger = console) {
  const serialized = JSON.stringify(event);
  if (logger && typeof logger.info === 'function') logger.info(serialized);
  else if (logger && typeof logger.log === 'function') logger.log(serialized);
}

module.exports = { createLogEvent, logEvent };
