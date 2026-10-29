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
const { getActivePolicy, evaluatePolicy } = require('../engine/policy-enforcer');
const db = require('../db');

// POST /api/v1/execute
router.post('/', async (req, res, next) => {
  try {
    const { code, policy: policyInput } = req.body;

    if (!code || typeof code !== 'string') {
      return res.status(400).json({ error: 'Missing required string parameter: code' });
    }

    // Default to currently active policy if no custom policy supplied
    const active = getActivePolicy();
    const effectiveName = policyInput?.name || active.name || 'default-python-sandbox';

    const policy = {
      name: effectiveName,
      runtime: policyInput?.runtime || active.runtime || 'process',
      timeoutMs: Math.min(Number(policyInput?.timeoutMs || policyInput?.timeout ? Number(policyInput?.timeout) * 1000 : active.timeoutMs) || 10000, 30000),
      memoryMb: Math.min(Number(policyInput?.memoryMb || policyInput?.memory_limit_mb || active.memory_limit_mb) || 256, 2048),
      maxProcesses: Math.min(Number(policyInput?.maxProcesses || policyInput?.max_processes || active.max_processes) || 8, 64),
      writablePaths: Array.isArray(policyInput?.writablePaths || policyInput?.writable_paths)
        ? (policyInput.writablePaths || policyInput.writable_paths)
        : (active.writable_paths || ['/tmp']),
      egressAllowlist: Array.isArray(policyInput?.egressAllowlist || policyInput?.egress_allowlist)
        ? (policyInput.egressAllowlist || policyInput.egress_allowlist)
        : (active.egress_allowlist || []),
      failClosed: Boolean(policyInput?.failClosed ?? active.failClosed),
    };

    // Record sandbox execution request in audit trail
    appendEvent({
      eventType: 'SANDBOX_EXECUTION_REQUEST',
      policyName: policy.name,
      severity: 'INFO',
      status: 'INITIATED',
      decisionReason: 'Sandbox execution requested for code snippet',
      metadata: {
        timeoutMs: policy.timeoutMs,
        memoryMb: policy.memoryMb,
        maxProcesses: policy.maxProcesses,
        writablePaths: policy.writablePaths,
        egressAllowlist: policy.egressAllowlist,
      },
    });

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
    if (err.code === 'SECURITY_ENFORCEMENT_FAILED') {
      try {
        appendEvent({
          eventType: 'SECURITY_ACTION_DENIED',
          severity: 'CRITICAL',
          status: 'FAIL_CLOSED',
          decisionReason: err.message,
          metadata: { unsupportedControls: err.unsupportedControls },
        });
      } catch (_) {}
      return res.status(403).json({
        success: false,
        error: 'SECURITY_ENFORCEMENT_FAILED',
        message: err.message,
        unsupportedControls: err.unsupportedControls || [],
      });
    }
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
  const active = getActivePolicy();
  const manifest = evaluatePolicy(active);
  res.json(manifest);
});

module.exports = router;
