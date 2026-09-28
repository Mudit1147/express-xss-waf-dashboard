'use strict';

const express = require('express');
const path = require('path');
const { createXssWaf } = require('./src');
const { logEvent } = require('./src/utils/logger');

const app = express();
const PORT = Number(process.env.PORT) || 3000;

// The dashboard can switch between the two supported mitigation modes per request.
// Each middleware instance is immutable, which avoids mutating shared configuration.
const siemEvents = [];
let eventSequence = 0;

function captureEvent(event) {
  const record = { sequence: ++eventSequence, ...event };
  siemEvents.push(record);
  logEvent(event);
  if (siemEvents.length > 100) siemEvents.shift();
}

const blockWaf = createXssWaf({
  mode: 'block',
  threshold: 10,
  inspectHeaders: ['user-agent', 'referer', 'x-forwarded-for'],
  customLogger: captureEvent
});

const sanitizeWaf = createXssWaf({
  mode: 'sanitize',
  threshold: 10,
  inspectHeaders: ['user-agent', 'referer', 'x-forwarded-for'],
  customLogger: captureEvent
});

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// Select the WAF mode using the X-WAF-Mode request header. The UI sends either
// "block" or "sanitize". Unknown values safely fall back to block mode.
app.use((req, res, next) => {
  const mode = String(req.get('x-waf-mode') || 'block').toLowerCase();
  return (mode === 'sanitize' ? sanitizeWaf : blockWaf)(req, res, next);
});

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/status', (req, res) => {
  res.json({ status: 'running' });
});

app.get('/api/logs', (req, res) => {
  const after = Number.parseInt(req.query.after, 10) || 0;
  const events = siemEvents.filter((event) => event.sequence > after);
  res.json({ events, latestSequence: eventSequence });
});

app.post('/api/test', (req, res) => {
  res.json({
    status: 'passed',
    message: 'Request reached the Express route.',
    received: req.body
  });
});

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  console.error('[DEMO ERROR]', error);
  return res.status(400).json({
    error: 'Bad Request',
    message: error.message || 'Unable to process request.'
  });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n  express-xss-waf live dashboard`);
    console.log(`  Local:  http://localhost:${PORT}`);
    console.log(`  API:    http://localhost:${PORT}/api/status`);
    console.log(`  Logs:   http://localhost:${PORT}/api/logs\n`);
  });
}

module.exports = app;
