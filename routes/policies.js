/* Warden Sandbox Policy Routes
 *
 * REST Endpoints:
 *   GET  /api/v1/policies          — List available policies
 *   POST /api/v1/policies          — Save or create a policy
 *   POST /api/v1/policies/validate — Validate candidate policy against rules & host capabilities
 *   POST /api/v1/policies/activate — Set the active policy used for execution pipeline
 *   GET  /api/v1/policies/active   — Retrieve the currently active sandbox policy
 *   POST /api/v1/policies/compare  — Compare candidate policy against active policy & host capabilities
 */

'use strict';

const express = require('express');
const router = express.Router();
const db = require('../db');
const { validatePolicy } = require('../engine/policy-validator');
const { comparePolicies } = require('../engine/policy-comparator');
const { getActivePolicy, setActivePolicy } = require('../engine/policy-enforcer');
const { appendEvent } = require('../engine/audit-chain');

const DEFAULT_POLICY_FALLBACK = {
  name: 'default-python-sandbox',
  runtime: 'process',
  cpu_limit: 0.5,
  memory_limit_mb: 256,
  max_processes: 8,
  timeoutMs: 10000,
  root_readonly: true,
  writable_paths: ['/tmp'],
  egress_allowlist: ['pypi.org', 'files.pythonhosted.org', 'api.openai.com'],
  syscall_profile: 'python-minimal',
  failClosed: false,
};

// GET /api/v1/policies — List policies
router.get('/', async (req, res, next) => {
  let policy = null;
  try {
    policy = await db.getPolicyByName('default-python-sandbox');
  } catch (err) {
    // Database fallback if disconnected
  }

  res.json({
    success: true,
    policies: [policy || getActivePolicy() || DEFAULT_POLICY_FALLBACK]
  });
});

// GET /api/v1/policies/active — Get current active policy
router.get('/active', (req, res) => {
  const active = getActivePolicy();
  res.json({
    success: true,
    activePolicy: active,
  });
});

// POST /api/v1/policies/validate — Validate candidate policy
router.post('/validate', (req, res) => {
  const policyData = req.body || {};
  const report = validatePolicy(policyData);

  // Record validation audit event
  try {
    appendEvent({
      eventType: 'POLICY_VALIDATED',
      policyName: policyData.name || 'unnamed',
      severity: report.severity,
      status: report.valid ? 'VALID' : 'INVALID',
      decisionReason: report.valid
        ? `Policy validated successfully (${report.warnings.length} warnings)`
        : `Policy validation failed with ${report.errors.length} errors: ${report.errors[0]?.message}`,
      metadata: {
        errorsCount: report.errors.length,
        warningsCount: report.warnings.length,
        unsupportedCount: report.unsupportedControls.length,
        enforceabilityScore: report.enforceabilityScore,
      },
    });
  } catch (_) {}

  res.json({
    success: true,
    validation: report,
  });
});

// POST /api/v1/policies/activate — Set policy as active sandbox policy
router.post('/activate', (req, res) => {
  const policyData = req.body || {};
  const validation = validatePolicy(policyData);

  if (!validation.valid) {
    return res.status(400).json({
      success: false,
      error: 'Cannot activate invalid policy',
      validation,
    });
  }

  const activated = setActivePolicy(validation.normalizedPolicy);

  // Record activation audit event
  try {
    appendEvent({
      eventType: 'POLICY_ACTIVATED',
      policyName: activated.name,
      severity: 'INFO',
      status: 'ACTIVATED',
      decisionReason: `Policy "${activated.name}" activated for sandbox execution`,
      metadata: {
        cpu_limit: activated.cpu_limit,
        memory_limit_mb: activated.memory_limit_mb,
        max_processes: activated.max_processes,
        writable_paths: activated.writable_paths,
        egress_allowlist: activated.egress_allowlist,
        enforceabilityScore: validation.enforceabilityScore,
      },
    });
  } catch (_) {}

  res.json({
    success: true,
    message: `Policy "${activated.name}" is now the active sandbox policy`,
    activePolicy: activated,
    validation,
  });
});

// POST /api/v1/policies/compare — Compare candidate policy against active policy
router.post('/compare', (req, res) => {
  const requested = req.body?.requested || req.body?.candidate || req.body || {};
  const active = req.body?.active || getActivePolicy();

  const comparison = comparePolicies(requested, active);

  res.json({
    success: true,
    comparison,
  });
});

// POST /api/v1/policies — Save policy (backward compatibility)
router.post('/', async (req, res, next) => {
  try {
    const policyData = req.body;
    if (!policyData || !policyData.name) {
      return res.status(400).json({ error: 'Missing required field: name' });
    }

    const validation = validatePolicy(policyData);

    let saved = null;
    try {
      saved = await db.savePolicy(validation.normalizedPolicy || policyData);
    } catch (err) {
      saved = { ...(validation.normalizedPolicy || policyData), id: 'mock-uuid', updated_at: new Date().toISOString() };
    }

    try {
      appendEvent({
        eventType: 'POLICY_CREATED',
        policyName: policyData.name,
        severity: 'INFO',
        status: 'STORED',
        decisionReason: `Policy "${policyData.name}" created and saved`,
      });
    } catch (_) {}

    res.status(201).json({
      success: true,
      policy: saved,
      validation,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
