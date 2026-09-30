'use strict';

const MAX_EVENTS = 100;
const events = [];
const totals = {
  totalRequestsScanned: 0,
  totalBlocked: 0,
  totalSanitized: 0,
  riskTiers: { LOW: 0, MEDIUM: 0, HIGH: 0 }
};

function recordScannedRequest(riskScore) {
  totals.totalRequestsScanned += 1;
  const tier = riskScore >= 8 ? 'HIGH' : riskScore >= 4 ? 'MEDIUM' : 'LOW';
  totals.riskTiers[tier] += 1;
}

function recordAction(action) {
  if (action === 'BLOCKED') totals.totalBlocked += 1;
  if (action === 'SANITIZED') totals.totalSanitized += 1;
}

function recordEvent(event) {
  events.push(event);
  if (events.length > MAX_EVENTS) events.shift();
}

function getSummary() {
  return {
    ...totals,
    riskTiers: { ...totals.riskTiers }
  };
}

function getRecentBlockedLogs() {
  return events
    .filter((event) => event.actionTaken === 'BLOCKED')
    .slice()
    .reverse()
    .map((event) => ({
      timestamp: event.timestamp,
      ip: event.ip,
      method: event.method,
      path: event.path,
      riskScore: event.threatScore,
      triggeredRules: [...new Set(event.detectedRules.map((rule) => rule.id))]
    }));
}

module.exports = { recordScannedRequest, recordAction, recordEvent, getSummary, getRecentBlockedLogs };