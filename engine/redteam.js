/* Warden Red Team Testing Suite
 *
 * Simulates safe, controlled, non-destructive attacks against the sandbox
 * to verify whether security policies and containment boundaries are actually enforced.
 *
 * Each attack records:
 *   - Scenario ID & Category
 *   - Attack Vector & Harmless Test Payload
 *   - Severity Level (CRITICAL, HIGH, MEDIUM, LOW)
 *   - Expected vs Actual Result
 *   - Status: PASS (contained), FAIL (escaped/uncontained), UNVERIFIED (platform limit)
 *   - Concrete Evidence (stdout, stderr, exit code, timing)
 *   - Actionable Remediation Guidance
 */

'use strict';

const { executeCode, HOST_CAPABILITIES } = require('./executor');
const { appendEvent } = require('./audit-chain');

const REDTEAM_SCENARIOS = [
  // ── RT-FS-01: Path Traversal Read ──────────────────────────────────────────
  {
    id: 'RT-FS-01',
    name: 'Directory Path Traversal Escape',
    category: 'FILESYSTEM',
    severity: 'CRITICAL',
    vector: 'Attempt reading system credentials via relative path traversal (../../../../etc/passwd).',
    expected: 'Read attempt outside sandbox scratchpad must be blocked with PermissionError or SIGSYS.',
    remediation: 'Enforce strict VFS mount namespace, OverlayFS upperdir isolation, and canonical path sanitization before file descriptor allocation.',
    code: `
try:
    with open("../../../../etc/passwd", "r") as f:
        data = f.read(64)
    print(f"BREACH: Read {len(data)} bytes via traversal: {data[:20]}")
except Exception as e:
    print(f"BLOCKED: {type(e).__name__} - {e}")
`,
    async evaluate(result) {
      const isBlocked = result.stdout.includes('BLOCKED:') || result.stderr.includes('[WARDEN]') || result.violations.some(v => v.type === 'FS_READ_BLOCKED');
      const hasBreach = result.stdout.includes('BREACH:');
      const pass = isBlocked && !hasBreach;
      return {
        status: pass ? 'PASS' : 'FAIL',
        actual: pass
          ? 'Path traversal access blocked cleanly by filesystem boundary.'
          : 'Path traversal succeeded; file content read without restriction.',
        evidence: (result.stdout + ' ' + result.stderr).trim().slice(0, 240) || `Exit code: ${result.exitCode}`,
      };
    },
  },

  // ── RT-FS-02: Root Filesystem Unauthorized Write ──────────────────────────
  {
    id: 'RT-FS-02',
    name: 'Root Filesystem Modification',
    category: 'FILESYSTEM',
    severity: 'HIGH',
    vector: 'Attempt creating file outside writable temporary paths (/etc/warden_rt_test.tmp).',
    expected: 'Write attempt must be denied by read-only root mount or filesystem guard.',
    remediation: 'Mount root container filesystem as MS_RDONLY and whitelist only ephemeral tmpfs scratch directories.',
    code: `
try:
    with open("/etc/warden_rt_test.tmp", "w") as f:
        f.write("redteam_probe")
    print("BREACH: Successfully wrote file to /etc")
except Exception as e:
    print(f"BLOCKED: {type(e).__name__} - {e}")
`,
    async evaluate(result) {
      const isBlocked = result.stdout.includes('BLOCKED:') || result.stderr.includes('[WARDEN]') || result.violations.some(v => v.type === 'FS_WRITE_BLOCKED');
      const hasBreach = result.stdout.includes('BREACH:');
      const pass = isBlocked && !hasBreach;
      return {
        status: pass ? 'PASS' : 'FAIL',
        actual: pass
          ? 'Write to /etc denied by filesystem guard.'
          : 'Write to /etc succeeded without error.',
        evidence: (result.stdout + ' ' + result.stderr).trim().slice(0, 240) || `Exit code: ${result.exitCode}`,
      };
    },
  },

  // ── RT-FS-03: Sensitive Credential Dotfile Discovery ───────────────────────
  {
    id: 'RT-FS-03',
    name: 'Host Credential Dotfile Harvesting',
    category: 'FILESYSTEM',
    severity: 'CRITICAL',
    vector: 'Attempt harvesting AWS credentials (~/.aws/credentials) or SSH keys (~/.ssh/id_rsa).',
    expected: 'User home directory dotfiles must be inaccessible or sanitized from isolated environment.',
    remediation: 'Provide isolated ephemeral HOME directory ($TMPDIR/sandbox_home) and scrub host dotfiles from container mounts.',
    code: `
import os
home = os.path.expanduser("~")
targets = [os.path.join(home, ".aws/credentials"), os.path.join(home, ".ssh/id_rsa")]
found = []
for p in targets:
    try:
        with open(p, "r") as f:
            found.append(p)
    except Exception:
        pass
if found:
    print(f"BREACH: Exposed host credential files: {found}")
else:
    print("BLOCKED: Host credential dotfiles unreachable")
`,
    async evaluate(result) {
      const hasBreach = result.stdout.includes('BREACH:');
      const isBlocked = result.stdout.includes('BLOCKED:') || !hasBreach;
      const pass = isBlocked && !hasBreach;
      return {
        status: pass ? 'PASS' : 'FAIL',
        actual: pass
          ? 'Host credentials isolated; dotfiles inaccessible to worker.'
          : 'Host credentials discovered and readable in worker environment.',
        evidence: (result.stdout + ' ' + result.stderr).trim().slice(0, 240) || `Exit code: ${result.exitCode}`,
      };
    },
  },

  // ── RT-NET-01: Direct Outbound C2 Socket Connection ────────────────────────
  {
    id: 'RT-NET-01',
    name: 'Outbound TCP C2 Connection Probe',
    category: 'NETWORK',
    severity: 'CRITICAL',
    vector: 'Attempt opening outbound TCP socket to unauthorized external IP (198.51.100.1:4444).',
    expected: 'Outbound socket connection must be dropped or rejected by default-deny egress policy.',
    remediation: 'Apply network namespace with loopback-only configuration (NET_NS) or eBPF socket connect filter.',
    code: `
import socket
try:
    s = socket.create_connection(("198.51.100.1", 4444), timeout=1.0)
    print("BREACH: Established connection to external C2 IP")
except Exception as e:
    print(f"BLOCKED: {type(e).__name__} - {e}")
`,
    async evaluate(result) {
      const hasBreach = result.stdout.includes('BREACH:');
      const isBlocked = result.stdout.includes('BLOCKED:') || result.stderr.includes('[WARDEN]') || result.violations.some(v => v.type === 'EGRESS_DENIED');
      const pass = isBlocked && !hasBreach;
      return {
        status: pass ? 'PASS' : 'FAIL',
        actual: pass
          ? 'Outbound connection rejected by network isolation guard.'
          : 'Outbound TCP connection established without restriction.',
        evidence: (result.stdout + ' ' + result.stderr).trim().slice(0, 240) || `Exit code: ${result.exitCode}`,
      };
    },
  },

  // ── RT-NET-02: Covert DNS Exfiltration Probe ───────────────────────────────
  {
    id: 'RT-NET-02',
    name: 'Covert DNS Exfiltration Channel',
    category: 'NETWORK',
    severity: 'HIGH',
    vector: 'Attempt resolving unauthorized external domain for DNS-based covert exfiltration.',
    expected: 'DNS lookups for unapproved domains must fail or be blocked by domain allowlist.',
    remediation: 'Bind isolated resolver rejecting queries for domains outside declarative policy egress_allowlist.',
    code: `
import socket
try:
    res = socket.getaddrinfo("unauthorized-beacon.evil-c2.net", 80)
    print(f"BREACH: Resolved unauthorized domain: {res}")
except Exception as e:
    print(f"BLOCKED: DNS resolution denied: {type(e).__name__} - {e}")
`,
    async evaluate(result) {
      const hasBreach = result.stdout.includes('BREACH:');
      const isBlocked = result.stdout.includes('BLOCKED:') || result.stderr.includes('[WARDEN]') || result.violations.some(v => v.type === 'EGRESS_DENIED');
      const pass = isBlocked && !hasBreach;
      return {
        status: pass ? 'PASS' : 'FAIL',
        actual: pass
          ? 'DNS lookup for unapproved host blocked by socket allowlist guard.'
          : 'DNS lookup succeeded without domain restriction.',
        evidence: (result.stdout + ' ' + result.stderr).trim().slice(0, 240) || `Exit code: ${result.exitCode}`,
      };
    },
  },

  // ── RT-PRIV-01: Privilege Escalation Resistance ────────────────────────────
  {
    id: 'RT-PRIV-01',
    name: 'Kernel Privilege Escalation (setuid)',
    category: 'PRIVILEGE',
    severity: 'CRITICAL',
    vector: 'Attempt invoking os.setuid(0) to acquire root privileges.',
    expected: 'Process must run unprivileged (non-root) and setuid(0) must fail with PermissionError or EPERM.',
    remediation: 'Drop all Linux capabilities (CAP_SETUID, CAP_SYS_ADMIN), set PR_SET_NO_NEW_PRIVS, and map to unprivileged user namespace UID.',
    code: `
import os
uid = os.getuid() if hasattr(os, 'getuid') else None
try:
    if hasattr(os, 'setuid'):
        os.setuid(0)
    print(f"BREACH: Escalated to root UID=0 (Initial UID={uid})")
except Exception as e:
    print(f"BLOCKED: {type(e).__name__} - {e} (Active UID={uid})")
`,
    async evaluate(result) {
      const hasBreach = result.stdout.includes('BREACH:');
      const isBlocked = result.stdout.includes('BLOCKED:') || !hasBreach;
      const pass = isBlocked && !hasBreach;
      return {
        status: pass ? 'PASS' : 'FAIL',
        actual: pass
          ? 'Privilege escalation rejected; worker runs under non-root permissions.'
          : 'setuid(0) succeeded; worker acquired root privileges.',
        evidence: (result.stdout + ' ' + result.stderr).trim().slice(0, 240) || `Exit code: ${result.exitCode}`,
      };
    },
  },

  // ── RT-RES-01: Bounded Fork Bomb Process Table Saturation ──────────────────
  {
    id: 'RT-RES-01',
    name: 'Process Table Saturation (Fork Bomb)',
    category: 'RESOURCE',
    severity: 'HIGH',
    vector: 'Attempt spawning recursive child processes beyond policy max_processes limit.',
    expected: 'Process multiplication must be halted by cgroups v2 pids.max or RLIMIT_NPROC ceiling.',
    remediation: 'Apply cgroups v2 pids.max=8 controller to isolate process trees from host OS.',
    code: `
import os, time
count = 0
try:
    for _ in range(16):
        pid = os.fork()
        if pid == 0:
            time.sleep(0.3)
            os._exit(0)
        count += 1
    print(f"BREACH: Created {count} child processes exceeding limit")
except Exception as e:
    print(f"BLOCKED: Fork stopped after {count} processes: {type(e).__name__}")
`,
    async evaluate(result) {
      const hasBreach = result.stdout.includes('BREACH:');
      const isContained = result.stdout.includes('BLOCKED:') || result.timedOut || result.violations.some(v => v.type === 'FORK_BLOCKED');
      const pass = isContained && !hasBreach;
      return {
        status: pass ? 'PASS' : 'FAIL',
        actual: pass
          ? 'Process multiplication halted by PID ceiling / timeout containment.'
          : 'Fork explosion unrestricted; exceeded safe PID quota.',
        evidence: (result.stdout + ' ' + result.stderr).trim().slice(0, 240) || `Exit code: ${result.exitCode}`,
      };
    },
  },

  // ── RT-RES-02: Output Buffer Flooding ──────────────────────────────────────
  {
    id: 'RT-RES-02',
    name: 'Terminal Output Buffer Flooding',
    category: 'RESOURCE',
    severity: 'MEDIUM',
    vector: 'Attempt flooding stdout with high-volume repetitive stream chunks to exhaust buffer memory.',
    expected: 'Output stream must be truncated at 64KB ceiling without server memory exhaustion.',
    remediation: 'Implement bounded stream listener capping stdout/stderr buffer to 64KB per execution.',
    code: `
try:
    for i in range(20000):
        print("STREAM_FLOOD_LINE_" + "A" * 200)
    print("STREAM_FINISHED")
except Exception as e:
    print(f"STREAM_HALTED: {e}")
`,
    async evaluate(result) {
      const isTruncated = result.outputLimitHit === true || result.stdoutBytes >= 64 * 1024;
      const pass = isTruncated;
      return {
        status: pass ? 'PASS' : 'FAIL',
        actual: pass
          ? `Stream output capped at ${result.stdoutBytes} bytes (limit hit: ${result.outputLimitHit}).`
          : 'Output stream was unbounded; permitted continuous flooding.',
        evidence: `stdoutBytes=${result.stdoutBytes}, outputLimitHit=${result.outputLimitHit}`,
      };
    },
  },

  // ── RT-RES-03: CPU Starvation & Timeout Enforcement ────────────────────────
  {
    id: 'RT-RES-03',
    name: 'Infinite Execution & CPU Starvation',
    category: 'RESOURCE',
    severity: 'HIGH',
    vector: 'Execute infinite CPU spin loop to monopolize processor cores.',
    expected: 'Worker process must be killed with SIGKILL upon reaching hard timeout limit.',
    remediation: 'Bind hardware execution watchdog enforcing asynchronous SIGKILL upon timeout expiration.',
    code: `
import time
t0 = time.time()
while True:
    if time.time() - t0 > 12:
        break
print("BREACH: Ran past deadline")
`,
    async evaluate(result) {
      const pass = result.timedOut === true;
      return {
        status: pass ? 'PASS' : 'FAIL',
        actual: pass
          ? `Infinite loop killed by SIGKILL at ${result.executionMs}ms.`
          : 'Execution failed to terminate within designated timeout window.',
        evidence: `timedOut=${result.timedOut}, exitCode=${result.exitCode}, executionMs=${result.executionMs}`,
      };
    },
  },

  // ── RT-SEC-01: Hardcoded Secret Exfiltration & Leakage ─────────────────────
  {
    id: 'RT-SEC-01',
    name: 'Hardcoded Cloud Credentials Leakage',
    category: 'DLP',
    severity: 'CRITICAL',
    vector: 'Attempt printing active AWS Access Key and OpenAI API key to standard output streams.',
    expected: 'Secret strings must be intercepted and masked with DLP redaction placeholders.',
    remediation: 'Deploy Data Loss Prevention (DLP) regex filter intercepting process output buffers prior to serialization.',
    code: `
key1 = "AKIA" + "1122334455667788"
key2 = "sk-" + "abcdef1234567890abcdef1234567890"
print(f"EXFILTRATE_AWS: {key1}")
print(f"EXFILTRATE_OPENAI: {key2}")
`,
    async evaluate(result) {
      const leaksAws = result.stdout.includes('AKIA1122334455667788');
      const leaksOpenai = result.stdout.includes('sk-abcdef1234567890abcdef');
      const hasMasks = result.stdout.includes('[REDACTED_AWS_ACCESS_KEY]') || result.stdout.includes('[REDACTED_OPENAI_API_KEY]');
      const pass = !leaksAws && !leaksOpenai && (hasMasks || result.dlpRedacted);
      return {
        status: pass ? 'PASS' : 'FAIL',
        actual: pass
          ? 'Cloud secrets intercepted and replaced with DLP redaction placeholders.'
          : 'Plaintext credentials leaked directly to execution output stream.',
        evidence: `leaksAws=${leaksAws}, leaksOpenai=${leaksOpenai}, dlpRedacted=${result.dlpRedacted}`,
      };
    },
  },
];

/**
 * Run the entire Red Team Attack Suite.
 * Executes each safe, bounded scenario inside a disposable worker environment.
 * @returns {Promise<RedTeamReport>}
 */
async function runRedTeamSuite() {
  const startTime = Date.now();
  const scenarioResults = [];

  for (const scenario of REDTEAM_SCENARIOS) {
    const policy = {
      name: `redteam-${scenario.id.toLowerCase()}`,
      timeoutMs: scenario.id === 'RT-RES-03' ? 2500 : 4000,
      memoryMb: 128,
      maxProcesses: 4,
      writablePaths: ['/tmp'],
      egressAllowlist: ['pypi.org'],
    };

    let result;
    let evalOutput;
    try {
      result = await executeCode(scenario.code, policy);
      evalOutput = await scenario.evaluate(result);
    } catch (err) {
      evalOutput = {
        status: 'UNVERIFIED',
        actual: `Runner encounter: ${err.message}`,
        evidence: `Execution error: ${err.message}`,
      };
      result = { executionMs: 0, runId: 'err_' + scenario.id.toLowerCase() };
    }

    const entry = {
      id: scenario.id,
      name: scenario.name,
      category: scenario.category,
      severity: scenario.severity,
      vector: scenario.vector,
      expected: scenario.expected,
      actual: evalOutput.actual,
      status: evalOutput.status,
      evidence: evalOutput.evidence,
      remediation: scenario.remediation,
      executionMs: result.executionMs || 0,
      runId: result.runId || null,
    };

    scenarioResults.push(entry);

    // Record into tamper-evident audit chain
    try {
      appendEvent({
        eventType: 'REDTEAM_ATTACK',
        scenarioId: scenario.id,
        severity: scenario.severity,
        status: evalOutput.status,
        executionMs: result.executionMs || 0,
        runId: result.runId || 'rt_probe',
      });
    } catch (_) {}
  }

  const passCount = scenarioResults.filter(s => s.status === 'PASS').length;
  const failCount = scenarioResults.filter(s => s.status === 'FAIL').length;
  const unverifiedCount = scenarioResults.filter(s => s.status === 'UNVERIFIED').length;

  const vulnerabilities = scenarioResults.filter(s => s.status === 'FAIL').map(s => ({
    id: s.id,
    title: s.name,
    severity: s.severity,
    evidence: s.evidence,
    remediation: s.remediation,
  }));

  return {
    suite: 'Warden Red Team Testing Engine',
    version: '1.0.0',
    executedAt: new Date().toISOString(),
    totalDurationMs: Date.now() - startTime,
    platform: HOST_CAPABILITIES.platform,
    summary: {
      total: scenarioResults.length,
      passed: passCount,
      failed: failCount,
      unverified: unverifiedCount,
      vulnerabilitiesCount: vulnerabilities.length,
      defenseScore: Math.round((passCount / scenarioResults.length) * 100),
    },
    vulnerabilities,
    scenarios: scenarioResults,
  };
}

module.exports = {
  runRedTeamSuite,
  REDTEAM_SCENARIOS,
};
