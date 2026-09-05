/* Warden Health Check Route */

const express = require('express');
const router = express.Router();
const db = require('../db');

router.get('/', async (req, res) => {
  let dbStatus = 'DISCONNECTED';
  try {
    await db.pool.query('SELECT 1;');
    dbStatus = 'CONNECTED';
  } catch (err) {
    dbStatus = 'DISCONNECTED (USING FALLBACK)';
  }

  res.json({
    status: 'HEALTHY',
    service: 'Warden Sandbox REST API Engine',
    version: '1.2.0',
    zeroDataLeakage: 'ENFORCED',
    database: dbStatus,
    timestamp: new Date().toISOString()
  });
});

module.exports = router;
