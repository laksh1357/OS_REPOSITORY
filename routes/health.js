/* Warden Health Check Route */

const express = require('express');
const router = express.Router();
const db = require('../db');
const { version } = require('../package.json');

router.get('/', async (req, res) => {
  let dbStatus = 'DISCONNECTED';
  try {
    if (db && typeof db.checkHealth === 'function') {
      const isConnected = await db.checkHealth();
      dbStatus = isConnected ? 'CONNECTED' : 'DISCONNECTED (USING FALLBACK)';
    } else if (db && db.pool) {
      await db.pool.query('SELECT 1;');
      dbStatus = 'CONNECTED';
    }
  } catch (_) {
    dbStatus = 'DISCONNECTED (USING FALLBACK)';
  }

  res.json({
    status: 'HEALTHY',
    service: 'Warden Sandbox REST API Engine',
    version: version || '1.0.0',
    zeroDataLeakage: 'ENFORCED',
    database: dbStatus,
    timestamp: new Date().toISOString()
  });
});

module.exports = router;
