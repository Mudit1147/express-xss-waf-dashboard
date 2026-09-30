'use strict';

const express = require('express');
const { getSummary, getRecentBlockedLogs } = require('./eventStore');

const router = express.Router();

router.get('/summary', (req, res) => res.json(getSummary()));
router.get('/logs', (req, res) => res.json({ logs: getRecentBlockedLogs() }));

module.exports = router;