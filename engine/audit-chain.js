/* Warden Tamper-Evident Security Audit Trail
 *
 * Implements cryptographic SHA-256 hash chaining over all sandbox security events:
 *   - POLICY_CREATED, POLICY_VALIDATED, POLICY_MODIFIED, POLICY_ACTIVATED
 *   - SANDBOX_EXECUTION_REQUEST, SECURITY_CONTROL_INITIALIZED, SECURITY_CONTROL_VERIFIED
 *   - SECURITY_ACTION_ALLOWED, SECURITY_ACTION_DENIED
 *   - RESOURCE_LIMIT_VIOLATION, SANDBOX_TERMINATED
 *   - REDTEAM_TEST_COMPLETED
 *
 * Every entry stores:
 *   seq, chainHash, previousHash, auditedAt, eventType, runId, policyName,
 *   observed (true = direct OS/kernel observation, false = inferred/unmonitorable),
 *   severity, decisionReason, and sanitized payload (DLP applied).
 */

'use strict';

const crypto = require('crypto');
const dlp = require('../security/dlp-node');

// In-memory circular ring buffer (retains up to 1,000 security audit events)
const RING_BUFFER_MAX = 1000;
const _chain = [];
let _lastHash = '0'.repeat(64); // Genesis hash

/**
 * Deeply sanitize sensitive tokens/secrets in event data before audit chaining.
 */
function sanitizeEventData(obj) {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') {
    return dlp.sanitizeCode(obj);
  }
  if (Array.isArray(obj)) {
    return obj.map(sanitizeEventData);
  }
  if (typeof obj === 'object') {
    const clean = {};
    for (const [k, v] of Object.entries(obj)) {
      clean[k] = sanitizeEventData(v);
    }
    return clean;
  }
  return obj;
}

/**
 * Compute the chain hash for a new entry.
 * chainHash = SHA-256(previousHash + canonicalJSON(sanitizedData))
 */
function computeChainHash(previousHash, data) {
  const canonical = JSON.stringify(data, Object.keys(data).sort());
  return crypto.createHash('sha256').update(previousHash + canonical).digest('hex');
}

/**
 * Add a new event to the audit chain.
 *
 * @param {object} rawEvent - Security event details
 * @returns {AuditEntry} Stored entry with cryptographic chain metadata
 */
function appendEvent(rawEvent = {}) {
  const sanitized = sanitizeEventData(rawEvent);

  const entryData = {
    eventType: sanitized.eventType || 'EXECUTION',
    runId: sanitized.runId || null,
    policyName: sanitized.policyName || sanitized.policyId || 'default',
    policyId: sanitized.policyId || sanitized.policyName || null,
    observed: sanitized.observed !== undefined ? Boolean(sanitized.observed) : true,
    severity: sanitized.severity || 'INFO',
    decisionReason: sanitized.decisionReason || sanitized.reason || null,
    status: sanitized.status || 'RECORDED',
    exitCode: sanitized.exitCode !== undefined ? sanitized.exitCode : null,
    executionMs: sanitized.executionMs || sanitized.executionDuration || null,
    violations: sanitized.violations || [],
    dlpRedacted: Boolean(sanitized.dlpRedacted),
    metadata: sanitized.metadata || {},
    auditedAt: new Date().toISOString(),
    seq: _chain.length + 1,
    ...sanitized,
  };

  const chainHash = computeChainHash(_lastHash, entryData);
  const entry = {
    seq: entryData.seq,
    chainHash,
    previousHash: _lastHash,
    data: entryData,
  };

  _lastHash = chainHash;

  if (_chain.length >= RING_BUFFER_MAX) {
    _chain.shift();
  }
  _chain.push(entry);

  return entry;
}

/**
 * Verify the cryptographic integrity of the entire audit chain.
 *
 * @returns {{ valid: boolean, firstBrokenAt: number|null, checkedCount: number }}
 */
function verifyChain() {
  if (_chain.length === 0) {
    return { valid: true, firstBrokenAt: null, checkedCount: 0 };
  }

  let prevHash = '0'.repeat(64);
  for (let i = 0; i < _chain.length; i++) {
    const entry = _chain[i];
    const expected = computeChainHash(prevHash, entry.data);
    if (expected !== entry.chainHash) {
      return { valid: false, firstBrokenAt: entry.seq, checkedCount: i + 1 };
    }
    prevHash = entry.chainHash;
  }
  return { valid: true, firstBrokenAt: null, checkedCount: _chain.length };
}

/**
 * Query audit entries with optional filtering.
 *
 * @param {object} filters - { eventType, severity, status, runId, limit }
 * @returns {Array<object>}
 */
function getRecentEntries(limit = 50, filters = {}) {
  let list = _chain.slice();

  if (filters.eventType) {
    const t = String(filters.eventType).toUpperCase();
    list = list.filter(e => e.data.eventType?.toUpperCase() === t);
  }
  if (filters.severity) {
    const s = String(filters.severity).toUpperCase();
    list = list.filter(e => e.data.severity?.toUpperCase() === s);
  }
  if (filters.status) {
    const st = String(filters.status).toUpperCase();
    list = list.filter(e => e.data.status?.toUpperCase() === st);
  }
  if (filters.runId) {
    list = list.filter(e => e.data.runId === filters.runId);
  }

  return list
    .slice(-limit)
    .reverse()
    .map(e => ({
      seq: e.seq,
      chainHash: e.chainHash.slice(0, 16) + '…',
      fullChainHash: e.chainHash,
      previousHash: e.previousHash.slice(0, 16) + '…',
      runId: e.data.runId,
      eventType: e.data.eventType,
      policyName: e.data.policyName,
      status: e.data.status,
      observed: e.data.observed,
      severity: e.data.severity,
      decisionReason: e.data.decisionReason,
      exitCode: e.data.exitCode,
      executionMs: e.data.executionMs,
      violations: e.data.violations || [],
      dlpRedacted: e.data.dlpRedacted,
      timestamp: e.data.auditedAt,
    }));
}

/**
 * Get full chain integrity status and summary metrics.
 */
function getChainStatus() {
  const integrity = verifyChain();
  return {
    length: _chain.length,
    lastHash: _lastHash.slice(0, 32) + '…',
    fullLastHash: _lastHash,
    ...integrity,
  };
}

/**
 * Build an execution event from an executor result.
 */
function buildExecutionEvent(executorResult, policyName) {
  const status = deriveStatus(executorResult);
  return {
    eventType: 'EXECUTION',
    runId: executorResult.runId,
    policyName: policyName || executorResult.policy?.name || 'default',
    status,
    observed: true,
    severity: status === 'CONTAINED' || status === 'ERROR' ? 'HIGH' : (status === 'DETECTED' ? 'MEDIUM' : 'INFO'),
    decisionReason: status === 'CLEAN' ? 'Normal execution within policy bounds' : (executorResult.violations[0]?.evidence || 'Resource or execution boundary violation'),
    exitCode: executorResult.exitCode,
    executionMs: executorResult.executionMs,
    timedOut: executorResult.timedOut,
    outputLimitHit: executorResult.outputLimitHit,
    dlpRedacted: executorResult.dlpRedacted,
    violations: executorResult.violations || [],
    snippetHash: executorResult.snippetHash,
    platform: executorResult.platform,
  };
}

function deriveStatus(result) {
  if (result.violations && result.violations.some(v => v.enforced)) return 'CONTAINED';
  if (result.violations && result.violations.length > 0) return 'DETECTED';
  if (result.timedOut) return 'TIMEOUT';
  if (result.exitCode === 0) return 'CLEAN';
  return 'ERROR';
}

module.exports = {
  appendEvent,
  verifyChain,
  getRecentEntries,
  getChainStatus,
  buildExecutionEvent,
  deriveStatus,
};
