/* Warden Audit Log Route
 *
 * GET  /api/v1/audit         — Recent audit entries (newest first)
 * GET  /api/v1/audit/chain   — Chain integrity status
 * GET  /api/v1/audit/verify  — Verify full chain integrity
 */

'use strict';

const express = require('express');
const router = express.Router();
const { getRecentEntries, getChainStatus, verifyChain } = require('../engine/audit-chain');
const db = require('../db');

// GET /api/v1/audit
router.get('/', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const memEntries = getRecentEntries(limit);

  // Also try DB entries
  let dbEntries = [];
  try {
    const q = await db.pool.query(
      `SELECT run_id, status, is_violated, violation_type, execution_time_ms, created_at, snippet_hash
       FROM sandbox_audit_logs ORDER BY created_at DESC LIMIT $1`,
      [limit]
    );
    dbEntries = q.rows;
  } catch (_) {}

  res.json({
    chainEntries: memEntries,
    dbEntries,
    chainStatus: getChainStatus(),
  });
});

// GET /api/v1/audit/chain
router.get('/chain', (req, res) => {
  res.json(getChainStatus());
});

// GET /api/v1/audit/verify
router.get('/verify', (req, res) => {
  const result = verifyChain();
  res.json({
    ...result,
    message: result.valid
      ? 'Audit chain integrity verified — no tampering detected'
      : `Chain broken at sequence ${result.firstBrokenAt}`,
  });
});

module.exports = router;
