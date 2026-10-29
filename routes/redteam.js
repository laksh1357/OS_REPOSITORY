/* Warden Red Team API Routes
 *
 * GET  /api/v1/redteam           — Execute the full 10-point Red Team Attack Suite
 * GET  /api/v1/redteam/scenarios — List scenario definitions and attack vectors
 * GET  /api/v1/redteam/status    — Return cached results from the last red team run
 */

'use strict';

const express = require('express');
const router = express.Router();
const { runRedTeamSuite, REDTEAM_SCENARIOS } = require('../engine/redteam');

let _lastRedTeamReport = null;
let _isRunning = false;

// GET /api/v1/redteam — trigger full red team attack run
router.get('/', async (req, res, next) => {
  if (_isRunning) {
    return res.status(429).json({
      error: 'Red Team Attack Suite is currently running. Please wait for completion.',
    });
  }
  try {
    _isRunning = true;
    const report = await runRedTeamSuite();
    _lastRedTeamReport = report;
    res.json(report);
  } catch (err) {
    next(err);
  } finally {
    _isRunning = false;
  }
});

// GET /api/v1/redteam/scenarios — list all attack scenarios without executing
router.get('/scenarios', (req, res) => {
  res.json({
    total: REDTEAM_SCENARIOS.length,
    scenarios: REDTEAM_SCENARIOS.map(s => ({
      id: s.id,
      name: s.name,
      category: s.category,
      severity: s.severity,
      vector: s.vector,
      expected: s.expected,
      remediation: s.remediation,
    })),
  });
});

// GET /api/v1/redteam/status — return cached report
router.get('/status', (req, res) => {
  if (!_lastRedTeamReport) {
    return res.json({
      message: 'No Red Team run executed yet. Call GET /api/v1/redteam to execute.',
      totalScenarios: REDTEAM_SCENARIOS.length,
    });
  }
  res.json(_lastRedTeamReport);
});

module.exports = router;
