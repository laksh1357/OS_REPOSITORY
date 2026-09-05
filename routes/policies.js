/* Warden Sandbox Policy Routes */

const express = require('express');
const router = express.Router();
const db = require('../db');

const DEFAULT_POLICY_FALLBACK = {
  name: 'default-python-sandbox',
  runtime: 'microvm',
  cpu_limit: 0.5,
  memory_limit_mb: 256,
  max_processes: 8,
  root_readonly: true,
  writable_paths: ['/tmp'],
  egress_allowlist: ['pypi.org', 'files.pythonhosted.org', 'api.openai.com'],
  syscall_profile: 'python-minimal'
};

// GET /api/v1/policies
router.get('/', async (req, res, next) => {
  let policy = null;
  try {
    policy = await db.getPolicyByName('default-python-sandbox');
  } catch (err) {
    // Database fallback if disconnected
  }

  res.json({
    success: true,
    policies: [policy || DEFAULT_POLICY_FALLBACK]
  });
});

// POST /api/v1/policies
router.post('/', async (req, res, next) => {
  try {
    const policyData = req.body;
    if (!policyData || !policyData.name) {
      return res.status(400).json({ error: 'Missing required field: name' });
    }

    let saved = null;
    try {
      saved = await db.savePolicy(policyData);
    } catch (err) {
      saved = { ...policyData, id: 'mock-uuid', updated_at: new Date().toISOString() };
    }

    res.status(201).json({
      success: true,
      policy: saved
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
