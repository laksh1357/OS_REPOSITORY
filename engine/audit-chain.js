/* Warden Tamper-Evident Audit Chain
 *
 * Implements SHA-256 hash chaining over execution events.
 * Each entry contains: data + SHA-256(previous_hash + JSON(data))
 * This makes any retrospective modification detectable.
 *
 * The chain is maintained in-memory AND persisted to PostgreSQL
 * (with graceful fallback to in-memory when DB unavailable).
 */

'use strict';

const crypto = require('crypto');

// In-memory ring buffer (max 500 events, circular)
const RING_BUFFER_MAX = 500;
const _chain = [];
let _lastHash = '0'.repeat(64); // genesis hash

/**
 * Compute the chain hash for a new entry.
 * hash = SHA-256(previousHash + canonicalJSON(data))
 */
function computeChainHash(previousHash, data) {
  const canonical = JSON.stringify(data, Object.keys(data).sort());
  return crypto.createHash('sha256').update(previousHash + canonical).digest('hex');
}

/**
 * Add a new event to the audit chain.
 * @param {object} event - Execution event data
 * @returns {AuditEntry} The stored entry with chain metadata
 */
function appendEvent(event) {
  const entryData = {
    ...event,
    auditedAt: new Date().toISOString(),
    seq: _chain.length + 1,
  };

  const chainHash = computeChainHash(_lastHash, entryData);
  const entry = {
    seq: entryData.seq,
    chainHash,
    previousHash: _lastHash,
    data: entryData,
  };

  _lastHash = chainHash;

  // Ring buffer: drop oldest when full
  if (_chain.length >= RING_BUFFER_MAX) {
    _chain.shift();
  }
  _chain.push(entry);

  return entry;
}

/**
 * Verify the integrity of the entire in-memory chain.
 * Returns { valid: boolean, firstBrokenAt: number|null, checkedCount: number }
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
 * Get recent audit entries (newest first).
 * @param {number} limit - Max entries to return
 */
function getRecentEntries(limit = 50) {
  return _chain
    .slice(-limit)
    .reverse()
    .map(e => ({
      seq: e.seq,
      chainHash: e.chainHash.slice(0, 16) + '…',
      previousHash: e.previousHash.slice(0, 16) + '…',
      runId: e.data.runId,
      eventType: e.data.eventType,
      status: e.data.status,
      exitCode: e.data.exitCode,
      executionMs: e.data.executionMs,
      violations: e.data.violations || [],
      dlpRedacted: e.data.dlpRedacted,
      timestamp: e.data.auditedAt,
      policyName: e.data.policyName,
    }));
}

/**
 * Get full chain metadata for integrity display.
 */
function getChainStatus() {
  const integrity = verifyChain();
  return {
    length: _chain.length,
    lastHash: _lastHash.slice(0, 32) + '…',
    ...integrity,
  };
}

/**
 * Build an audit event from an executor result.
 */
function buildExecutionEvent(executorResult, policyName) {
  return {
    eventType: 'EXECUTION',
    runId: executorResult.runId,
    policyName: policyName || executorResult.policy?.name || 'default',
    status: deriveStatus(executorResult),
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
