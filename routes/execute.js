/* Warden Execute Route — Real Python Execution Endpoint
 *
 * POST /api/v1/execute
 * Body: { code: string, policy?: object }
 *
 * Unlike /api/v1/sandbox/run (pattern simulation), this endpoint
 * ACTUALLY executes the Python code in a subprocess with:
 *   - Timeout enforcement (SIGKILL)
 *   - Output byte limits
 *   - DLP redaction on all output
 *   - Python-level FS write guard
 *   - Python-level network egress guard
 *   - Real exit codes and execution timing
 */

'use strict';

const express = require('express');
const router = express.Router();
const { executeCode, HOST_CAPABILITIES } = require('../engine/executor');
const { appendEvent, buildExecutionEvent } = require('../engine/audit-chain');
const { evaluatePolicy } = require('../engine/policy-enforcer');
const db = require('../db');

// POST /api/v1/execute
router.post('/', async (req, res, next) => {
  try {
    const { code, policy: policyInput } = req.body;

    if (!code || typeof code !== 'string') {
      return res.status(400).json({ error: 'Missing required string parameter: code' });
    }

    // Build effective policy from request + defaults
    const policy = {
      name: policyInput?.name || 'default-python-sandbox',
      timeoutMs: Math.min(Number(policyInput?.timeoutMs) || 10000, 30000),
      memoryMb: Math.min(Number(policyInput?.memoryMb) || 256, 2048),
      maxProcesses: Math.min(Number(policyInput?.maxProcesses) || 8, 64),
      writablePaths: Array.isArray(policyInput?.writablePaths) ? policyInput.writablePaths : ['/tmp'],
      egressAllowlist: Array.isArray(policyInput?.egressAllowlist) ? policyInput.egressAllowlist : [],
    };

    // Run the actual execution
    const result = await executeCode(code, policy);

    // Build audit event + append to chain
    const auditEvent = buildExecutionEvent(result, policy.name);
    const chainEntry = appendEvent(auditEvent);

    // Persist to DB (non-blocking, graceful fallback)
    db.recordSandboxRun({
      runId: result.runId,
      policyId: null,
      codeSnippet: code.slice(0, 4096),
      snippetHash: result.snippetHash,
      status: auditEvent.status,
      isViolated: result.violations.length > 0,
      violationType: result.violations[0]?.type || null,
      violationDetails: {
        violations: result.violations,
        exitCode: result.exitCode,
        timedOut: result.timedOut,
        outputLimitHit: result.outputLimitHit,
      },
      executionTimeMs: result.executionMs,
    }).catch(() => {}); // non-fatal

    res.json({
      runId: result.runId,
      timestamp: result.timestamp,
      status: auditEvent.status,
      exitCode: result.exitCode,
      signal: result.signal,
      executionMs: result.executionMs,
      timedOut: result.timedOut,
      outputLimitHit: result.outputLimitHit,
      stdout: result.stdout,
      stderr: result.stderr,
      stdoutBytes: result.stdoutBytes,
      stderrBytes: result.stderrBytes,
      violations: result.violations,
      dlpRedacted: result.dlpRedacted,
      snippetHash: result.snippetHash,
      chainHash: chainEntry.chainHash.slice(0, 32),
      platform: result.platform,
      capabilities: {
        timeout: HOST_CAPABILITIES.timeout,
        outputLimit: HOST_CAPABILITIES.outputLimit,
        dlpRedaction: HOST_CAPABILITIES.dlpRedaction,
        nonRootExec: HOST_CAPABILITIES.nonRootExec,
        seccomp: HOST_CAPABILITIES.seccomp,
        cgroups: HOST_CAPABILITIES.cgroups,
        namespaces: HOST_CAPABILITIES.namespaces,
      },
      policy: {
        name: policy.name,
        timeoutMs: policy.timeoutMs,
        memoryMb: policy.memoryMb,
        maxProcesses: policy.maxProcesses,
        writablePaths: policy.writablePaths,
        egressAllowlist: policy.egressAllowlist,
      },
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/v1/execute/capabilities
router.get('/capabilities', (req, res) => {
  res.json({
    platform: HOST_CAPABILITIES.platform,
    capabilities: HOST_CAPABILITIES,
    note: 'Features marked false are UNSUPPORTED on this platform and must not be claimed as enforced.',
  });
});

// GET /api/v1/execute/policy-manifest
router.get('/policy-manifest', (req, res) => {
  const policy = {
    name: 'default-python-sandbox',
    timeoutMs: 10000,
    memoryMb: 256,
    maxProcesses: 8,
    writablePaths: ['/tmp'],
    egressAllowlist: [],
  };
  const manifest = evaluatePolicy(policy);
  res.json(manifest);
});

module.exports = router;
