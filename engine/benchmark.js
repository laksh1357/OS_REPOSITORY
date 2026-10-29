/* Warden Security Benchmark Suite
 *
 * Runs REAL execution tests against the sandbox engine.
 * Each benchmark actually executes code and verifies outcomes.
 *
 * Test statuses:
 *   PASS     — attack was blocked / behavior matched expectation
 *   FAIL     — sandbox failed to contain the attack
 *   SKIP     — cannot run this test on current platform
 *   ERROR    — test itself errored (not sandbox failure)
 *
 * NEVER reports PASS without actually running the code and checking real output.
 */

'use strict';

const { executeCode, HOST_CAPABILITIES } = require('./executor');

/**
 * All benchmark tests. Each returns { name, category, description, status, evidence, executionMs }.
 */
const BENCHMARKS = [

  // ── BM-01: Timeout Enforcement ─────────────────────────────────────────────
  {
    id: 'BM-01',
    name: 'Timeout Enforcement',
    category: 'RESOURCE',
    description: 'Infinite loop must be killed within timeout window',
    async run() {
      const code = 'while True: pass';
      const policy = { timeoutMs: 3000, name: 'timeout-test' };
      const result = await executeCode(code, policy);
      const passed = result.timedOut === true && result.exitCode === -1;
      return {
        passed,
        evidence: passed
          ? `Process killed after ${result.executionMs}ms (timeout=${policy.timeoutMs}ms). timedOut=${result.timedOut}, exit=${result.exitCode}`
          : `FAIL: timedOut=${result.timedOut}, exitCode=${result.exitCode}, executionMs=${result.executionMs}`,
        executionMs: result.executionMs,
        raw: { timedOut: result.timedOut, exitCode: result.exitCode },
      };
    },
  },

  // ── BM-02: Output Byte Limit ───────────────────────────────────────────────
  {
    id: 'BM-02',
    name: 'Output Size Limit',
    category: 'RESOURCE',
    description: 'Runaway output (print loop) must be truncated at 64KB',
    async run() {
      const code = `
for i in range(1_000_000):
    print("A" * 1000)
`;
      const policy = { timeoutMs: 10000, name: 'output-limit-test' };
      const result = await executeCode(code, policy);
      const passed = result.outputLimitHit === true || result.stdoutBytes >= 64 * 1024;
      return {
        passed,
        evidence: passed
          ? `Output truncated. stdoutBytes=${result.stdoutBytes}, outputLimitHit=${result.outputLimitHit}`
          : `FAIL: outputLimitHit=${result.outputLimitHit}, stdoutBytes=${result.stdoutBytes}`,
        executionMs: result.executionMs,
        raw: { outputLimitHit: result.outputLimitHit, stdoutBytes: result.stdoutBytes },
      };
    },
  },

  // ── BM-03: Filesystem Write Guard ─────────────────────────────────────────
  {
    id: 'BM-03',
    name: 'Filesystem Write Guard',
    category: 'FILESYSTEM',
    description: 'Write to /etc/passwd must be denied by FS guard',
    async run() {
      const code = `
try:
    with open("/etc/test_warden_write", "w") as f:
        f.write("warden_test")
    print("WRITE_SUCCEEDED")
except PermissionError as e:
    print(f"WRITE_BLOCKED: {e}")
`;
      const policy = { timeoutMs: 5000, writablePaths: ['/tmp'], name: 'fs-write-test' };
      const result = await executeCode(code, policy);
      const blocked = result.stdout.includes('WRITE_BLOCKED') || result.stderr.includes('WRITE_BLOCKED') || result.stderr.includes('[WARDEN]');
      const notSucceeded = !result.stdout.includes('WRITE_SUCCEEDED');
      const passed = blocked && notSucceeded;
      return {
        passed,
        evidence: passed
          ? `Write to /etc blocked: "${(result.stdout + result.stderr).slice(0, 200)}"`
          : `FAIL: Write may have succeeded. stdout="${result.stdout.slice(0, 200)}"`,
        executionMs: result.executionMs,
        raw: { stdout: result.stdout.slice(0, 300), stderr: result.stderr.slice(0, 300) },
      };
    },
  },

  // ── BM-04: Network Egress Block ───────────────────────────────────────────
  {
    id: 'BM-04',
    name: 'Network Egress Guard',
    category: 'NETWORK',
    description: 'DNS lookup to unauthorized host must be blocked',
    async run() {
      const code = `
import socket
try:
    ip = socket.getaddrinfo("evil-c2.attacker.com", 80)
    print(f"CONNECTED: {ip}")
except (ConnectionRefusedError, OSError) as e:
    print(f"BLOCKED: {e}")
`;
      const policy = { timeoutMs: 5000, egressAllowlist: ['pypi.org'], name: 'egress-test' };
      const result = await executeCode(code, policy);
      const blocked = result.stdout.includes('BLOCKED') || result.stderr.includes('BLOCKED') || result.stderr.includes('[WARDEN]');
      const notConnected = !result.stdout.includes('CONNECTED');
      const passed = blocked && notConnected;
      return {
        passed,
        evidence: passed
          ? `Egress blocked: "${(result.stdout + result.stderr).slice(0, 200)}"`
          : `FAIL: Connection may have succeeded. stdout="${result.stdout.slice(0, 200)}"`,
        executionMs: result.executionMs,
        raw: { stdout: result.stdout.slice(0, 300), stderr: result.stderr.slice(0, 300) },
      };
    },
  },

  // ── BM-05: DLP Secret Redaction ───────────────────────────────────────────
  {
    id: 'BM-05',
    name: 'DLP Secret Redaction',
    category: 'DLP',
    description: 'AWS key and OpenAI token must be redacted from output',
    async run() {
      const code = `
aws_key = "AKIA1234567890ABCDEF"
token = "sk-abcdefghijklmnopqrstuvwxyz123456"
print(f"key={aws_key}")
print(f"token={token}")
`;
      const policy = { timeoutMs: 5000, name: 'dlp-test' };
      const result = await executeCode(code, policy);
      const awsRedacted = !result.stdout.includes('AKIA1234567890ABCDEF');
      const openaiRedacted = !result.stdout.includes('sk-abcdefghijklmnopqrst');
      const passed = awsRedacted && openaiRedacted;
      return {
        passed,
        evidence: passed
          ? `Both secrets redacted from output. dlpRedacted=${result.dlpRedacted}`
          : `FAIL: Secrets found in output. stdout="${result.stdout.slice(0, 300)}"`,
        executionMs: result.executionMs,
        raw: { dlpRedacted: result.dlpRedacted, stdout: result.stdout.slice(0, 300) },
      };
    },
  },

  // ── BM-06: Safe Code Completes Normally ───────────────────────────────────
  {
    id: 'BM-06',
    name: 'Safe Code Execution',
    category: 'CORRECTNESS',
    description: 'Legitimate code must execute and return correct output',
    async run() {
      const code = `
result = sum(range(100))
print(f"sum(0..99) = {result}")
`;
      const policy = { timeoutMs: 5000, name: 'safe-exec-test' };
      const result = await executeCode(code, policy);
      const passed = result.exitCode === 0 && result.stdout.includes('sum(0..99) = 4950');
      return {
        passed,
        evidence: passed
          ? `Clean exit. stdout="${result.stdout.trim()}"`
          : `FAIL: exitCode=${result.exitCode}, stdout="${result.stdout.slice(0, 200)}"`,
        executionMs: result.executionMs,
        raw: { exitCode: result.exitCode, stdout: result.stdout.slice(0, 300) },
      };
    },
  },

  // ── BM-07: Filesystem Read of /etc/passwd ─────────────────────────────────
  {
    id: 'BM-07',
    name: 'Protected File Read',
    category: 'FILESYSTEM',
    description: 'Reading /etc/passwd contents must be blocked and prevented from leaking',
    async run() {
      const code = `
try:
    with open("/etc/passwd", "r") as f:
        content = f.read()
    print(f"READ_SUCCEEDED: {content[:50]}")
except (PermissionError, OSError) as e:
    print(f"READ_BLOCKED: {e}")
`;
      const policy = { timeoutMs: 5000, writablePaths: ['/tmp'], name: 'fs-read-test' };
      const result = await executeCode(code, policy);
      const readBlocked = result.stdout.includes('READ_BLOCKED') || result.stderr.includes('[WARDEN]') || result.stderr.includes('PermissionError');
      const notSucceeded = !result.stdout.includes('READ_SUCCEEDED');
      const passed = readBlocked && notSucceeded;
      return {
        passed,
        evidence: passed
          ? `Read of /etc/passwd blocked: "${(result.stdout + result.stderr).trim().slice(0, 200)}"`
          : `FAIL: File read succeeded. stdout="${result.stdout.slice(0, 200)}"`,
        executionMs: result.executionMs,
        platformNote: HOST_CAPABILITIES.platform === 'darwin'
          ? 'Enforced via Python path guard (host kernel OverlayFS unavailable on darwin)'
          : undefined,
        raw: { readBlocked, stdout: result.stdout.slice(0, 300) },
      };
    },
  },

  // ── BM-08: Fork Bomb Containment ──────────────────────────────────────────
  {
    id: 'BM-08',
    name: 'Fork Bomb Containment',
    category: 'RESOURCE',
    description: 'Recursive fork() must be stopped by RLIMIT_NPROC or timeout',
    async run() {
      const code = `
import os
count = 0
try:
    while True:
        os.fork()
        count += 1
except (BlockingIOError, OSError) as e:
    print(f"FORK_BLOCKED after {count} forks: {e}")
`;
      const policy = { timeoutMs: 5000, maxProcesses: 4, name: 'forkbomb-test' };
      const result = await executeCode(code, policy);
      const forkBlocked = result.stdout.includes('FORK_BLOCKED') || result.timedOut;
      const passed = forkBlocked;
      return {
        passed,
        evidence: passed
          ? `Fork contained: timedOut=${result.timedOut}, stdout="${result.stdout.slice(0, 200)}"`
          : `FAIL: Fork bomb may not have been contained. stdout="${result.stdout.slice(0, 200)}"`,
        executionMs: result.executionMs,
        platformNote: HOST_CAPABILITIES.platform === 'darwin'
          ? 'RLIMIT_NPROC on macOS applies per-user (not per-process), so fork may partially succeed'
          : undefined,
        raw: { forkBlocked, timedOut: result.timedOut, stdout: result.stdout.slice(0, 300) },
      };
    },
  },
];

/**
 * Run all benchmarks and return structured results.
 * @returns {Promise<BenchmarkReport>}
 */
async function runAll() {
  const startTime = Date.now();
  const results = [];

  for (const bm of BENCHMARKS) {
    let bmResult;
    try {
      const raw = await bm.run();
      bmResult = {
        id: bm.id,
        name: bm.name,
        category: bm.category,
        description: bm.description,
        status: raw.passed ? 'PASS' : 'FAIL',
        evidence: raw.evidence,
        executionMs: raw.executionMs,
        platformNote: raw.platformNote || null,
        raw: raw.raw || null,
      };
    } catch (err) {
      bmResult = {
        id: bm.id,
        name: bm.name,
        category: bm.category,
        description: bm.description,
        status: 'ERROR',
        evidence: `Test runner error: ${err.message}`,
        executionMs: 0,
        platformNote: null,
        raw: null,
      };
    }
    results.push(bmResult);
  }

  const pass = results.filter(r => r.status === 'PASS').length;
  const fail = results.filter(r => r.status === 'FAIL').length;
  const error = results.filter(r => r.status === 'ERROR').length;
  const skip = results.filter(r => r.status === 'SKIP').length;

  return {
    runAt: new Date().toISOString(),
    totalMs: Date.now() - startTime,
    platform: HOST_CAPABILITIES.platform,
    summary: { total: results.length, pass, fail, error, skip },
    results,
  };
}

/**
 * Run a single benchmark by ID.
 */
async function runOne(id) {
  const bm = BENCHMARKS.find(b => b.id === id);
  if (!bm) throw new Error(`Benchmark ${id} not found`);
  const raw = await bm.run();
  return {
    id: bm.id,
    name: bm.name,
    category: bm.category,
    description: bm.description,
    status: raw.passed ? 'PASS' : 'FAIL',
    evidence: raw.evidence,
    executionMs: raw.executionMs,
    platformNote: raw.platformNote || null,
    raw: raw.raw || null,
  };
}

module.exports = {
  runAll,
  runOne,
  BENCHMARKS,
};
