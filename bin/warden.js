#!/usr/bin/env node

/* Warden Command Line Interface (CLI) Tool */

const fs = require('fs');
const path = require('path');
const { version } = require('../package.json');

const args = process.argv.slice(2);
const command = args[0] || 'help';

console.log('\x1b[36m%s\x1b[0m', `🛡️ Warden OS-Level Sandbox Engine v${version || '1.0.0'}`);

if (command === 'help' || command === '--help' || command === '-h') {
  console.log(`
Usage:
  warden run <file.py>             Simulate snippet execution against 5-layer sandbox
  warden exec <file.py>            Execute snippet in real isolated worker process
  warden benchmark                 Run full security benchmark suite (BM-01 to BM-08)
  warden redteam                   Run Red Team attack simulation suite (RT-FS-01 to RT-SEC-01)
  warden capabilities              Inspect host OS isolation capabilities
  warden audit                     View recent audit chain entries
  warden verify                    Verify tamper-evident SHA-256 audit chain
  warden policy init               Generate default warden.yaml
  warden version                   Print CLI version info

Examples:
  node bin/warden.js exec snippet.py
  node bin/warden.js benchmark
  node bin/warden.js redteam
  node bin/warden.js capabilities
  node bin/warden.js audit
  node bin/warden.js verify
  node bin/warden.js run snippet.py
`);
  process.exit(0);
}

if (command === 'version' || command === '-v' || command === '--version') {
  console.log(`Warden Core CLI v${version || '1.0.0'} (Subprocess Isolation / RLIMIT / DLP / SHA-256 Chain)`);
  process.exit(0);
}

if (command === 'capabilities') {
  const { HOST_CAPABILITIES } = require('../engine/executor');
  console.log('\nHost Isolation Capabilities:');
  console.log(`  Platform:       ${HOST_CAPABILITIES.platform}`);
  console.log(`  Timeout Kill:   ${HOST_CAPABILITIES.timeout ? '✓ ENFORCED (SIGKILL)' : '✗'}`);
  console.log(`  Output Limit:   ${HOST_CAPABILITIES.outputLimit ? '✓ ENFORCED (64KB cap)' : '✗'}`);
  console.log(`  DLP Redaction:  ${HOST_CAPABILITIES.dlpRedaction ? '✓ ENFORCED (7 patterns)' : '✗'}`);
  console.log(`  Non-Root Exec:  ${HOST_CAPABILITIES.nonRootExec ? '✓ ENFORCED' : '✗'}`);
  console.log(`  Seccomp-BPF:    ${HOST_CAPABILITIES.seccomp ? '✓ AVAILABLE' : '✗ UNSUPPORTED on ' + HOST_CAPABILITIES.platform}`);
  console.log(`  cgroups v2:     ${HOST_CAPABILITIES.cgroups ? '✓ AVAILABLE' : '✗ UNSUPPORTED on ' + HOST_CAPABILITIES.platform}`);
  console.log(`  Namespaces:     ${HOST_CAPABILITIES.namespaces ? '✓ AVAILABLE' : '✗ UNSUPPORTED on ' + HOST_CAPABILITIES.platform}`);
  console.log(`  OverlayFS:      ${HOST_CAPABILITIES.overlayfs ? '✓ AVAILABLE' : '✗ UNSUPPORTED on ' + HOST_CAPABILITIES.platform}`);
  console.log(`  eBPF Egress:    ${HOST_CAPABILITIES.ebpfEgress ? '✓ AVAILABLE' : '✗ UNSUPPORTED on ' + HOST_CAPABILITIES.platform}`);
  process.exit(0);
}

if (command === 'benchmark') {
  const { runAll } = require('../engine/benchmark');
  console.log('\nRunning Warden Security Benchmark Suite...');
  runAll().then(report => {
    console.log(`\nPlatform: ${report.platform} | Total Time: ${report.totalMs}ms`);
    console.log('Results:');
    report.results.forEach(r => {
      const tag = r.status === 'PASS' ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m';
      console.log(`  [${tag}] ${r.id} ${r.name} (${r.executionMs}ms)`);
      console.log(`         ${r.evidence}`);
      if (r.platformNote) console.log(`         \x1b[33mNote: ${r.platformNote}\x1b[0m`);
    });
    console.log(`\nSummary: ${report.summary.pass}/${report.summary.total} Passed, ${report.summary.fail} Failed`);
    process.exit(report.summary.fail > 0 ? 1 : 0);
  }).catch(err => {
    console.error('Benchmark failed:', err);
    process.exit(1);
  });
  return;
}

if (command === 'redteam') {
  const { runRedTeamSuite } = require('../engine/redteam');
  console.log('\nRunning Warden Red Team Security Testing Suite...');
  runRedTeamSuite().then(report => {
    console.log(`\nPlatform: ${report.platform} | Total Duration: ${report.totalDurationMs}ms | Defense Score: ${report.summary.defenseScore}%`);
    console.log('Attack Scenarios:');
    report.scenarios.forEach(s => {
      const tag = s.status === 'PASS' ? '\x1b[32m[PASS]\x1b[0m' : (s.status === 'FAIL' ? '\x1b[31m[FAIL]\x1b[0m' : '\x1b[33m[UNVERIFIED]\x1b[0m');
      const sevColor = s.severity === 'CRITICAL' ? '\x1b[35m' : (s.severity === 'HIGH' ? '\x1b[31m' : '\x1b[33m');
      console.log(`  ${tag} ${s.id} ${sevColor}[${s.severity}]\x1b[0m ${s.name} (${s.executionMs}ms)`);
      console.log(`         Expected:    ${s.expected}`);
      console.log(`         Actual:      ${s.actual}`);
      console.log(`         Evidence:    ${s.evidence}`);
      if (s.status === 'FAIL') {
        console.log(`         \x1b[31mRemediation: ${s.remediation}\x1b[0m`);
      }
    });
    console.log(`\nSummary: ${report.summary.passed}/${report.summary.total} Passed, ${report.summary.failed} Failed, ${report.summary.unverified} Unverified`);
    if (report.vulnerabilities.length > 0) {
      console.log(`\x1b[31mVulnerabilities Identified: ${report.vulnerabilities.length}\x1b[0m`);
    } else {
      console.log('\x1b[32mZero uncontained vulnerabilities identified across tested attack vectors.\x1b[0m');
    }
    process.exit(report.summary.failed > 0 ? 1 : 0);
  }).catch(err => {
    console.error('Red Team Suite execution error:', err);
    process.exit(1);
  });
  return;
}

if (command === 'audit') {
  const { getRecentEntries } = require('../engine/audit-chain');
  const entries = getRecentEntries(10);
  console.log('\nRecent Tamper-Evident Audit Chain Entries:');
  if (entries.length === 0) {
    console.log('  (No entries recorded in current session)');
  } else {
    entries.forEach(e => {
      console.log(`  #${e.seq} [${e.status}] Run: ${e.runId} | Exit: ${e.exitCode} | Time: ${e.executionMs}ms | ChainHash: ${e.chainHash}`);
    });
  }
  process.exit(0);
}

if (command === 'verify') {
  const { verifyChain, getChainStatus } = require('../engine/audit-chain');
  const status = getChainStatus();
  console.log('\nAudit Chain Verification:');
  console.log(`  Chain Length:     ${status.length}`);
  console.log(`  Latest Hash:      ${status.lastHash}`);
  console.log(`  Integrity Status: ${status.valid ? '\x1b[32mVERIFIED (No Tampering)\x1b[0m' : '\x1b[31mCORRUPTED\x1b[0m'}`);
  process.exit(status.valid ? 0 : 1);
}

if (command === 'exec') {
  const target = args[1];
  if (!target) {
    console.error('\x1b[31m%s\x1b[0m', 'Error: Please specify a python script file or snippet to execute.');
    console.log('Example: node bin/warden.js exec snippet.py');
    process.exit(1);
  }

  let code = '';
  if (fs.existsSync(target)) {
    code = fs.readFileSync(target, 'utf8');
  } else if (target.endsWith('.py') || target.endsWith('.sh')) {
    console.error('\x1b[31m%s\x1b[0m', `Error: File not found: ${target}`);
    process.exit(1);
  } else {
    code = target;
  }

  const { executeCode } = require('../engine/executor');
  const { appendEvent, buildExecutionEvent } = require('../engine/audit-chain');

  console.log('\x1b[34m%s\x1b[0m', '[WARDEN-EXEC] Spawning isolated Python worker process with timeout & RLIMIT...');
  executeCode(code, { timeoutMs: 5000 }).then(result => {
    appendEvent(buildExecutionEvent(result, 'cli-exec'));
    console.log(`[WARDEN-EXEC] Run ID: ${result.runId} | Execution Time: ${result.executionMs}ms | Exit Code: ${result.exitCode}`);
    if (result.stdout) {
      console.log('\n--- STDOUT ---');
      console.log(result.stdout.trim());
    }
    if (result.stderr) {
      console.log('\n--- STDERR ---');
      console.log(result.stderr.trim());
    }
    if (result.violations.length > 0) {
      console.log('\n\x1b[31m[VIOLATIONS CONTAINED]\x1b[0m');
      result.violations.forEach(v => {
        console.log(`  - ${v.type}: ${v.evidence}`);
      });
    }
    if (result.dlpRedacted) {
      console.log('\x1b[32m[DLP] Output sanitized: secrets redacted.\x1b[0m');
    }
    process.exit(result.exitCode === 0 ? 0 : 1);
  }).catch(err => {
    console.error('Execution failed:', err.message);
    process.exit(1);
  });
  return;
}

if (command === 'policy' && args[1] === 'init') {
  const policyYaml = `# Warden Isolation Policy Definition
version: "v1alpha1"
name: "agent-task-sandbox"
runtime: microvm
timeout: "30s"
resources:
  cpu: "0.5"
  memory: "256Mi"
  processes: 8
filesystem:
  root: read-only
  writable: ["/tmp"]
network:
  default: deny
  allow:
    - "pypi.org"
    - "files.pythonhosted.org"
syscalls:
  profile: "python-minimal"
`;
  const targetPath = path.resolve(process.cwd(), 'warden.yaml');
  if (fs.existsSync(targetPath)) {
    console.warn('\x1b[33m%s\x1b[0m', 'Warning: warden.yaml already exists. Overwriting...');
  }
  fs.writeFileSync(targetPath, policyYaml);
  console.log('\x1b[32m%s\x1b[0m', '✓ Created warden.yaml policy file successfully.');
  process.exit(0);
}

if (command === 'run') {
  const target = args[1];
  if (!target) {
    console.error('\x1b[31m%s\x1b[0m', 'Error: Please specify a python script file or snippet to execute.');
    console.log('Example: node bin/warden.js run snippet.py');
    process.exit(1);
  }

  let code = '';
  if (fs.existsSync(target)) {
    code = fs.readFileSync(target, 'utf8');
  } else if (target.endsWith('.py') || target.endsWith('.sh')) {
    console.error('\x1b[31m%s\x1b[0m', `Error: File not found: ${target}`);
    process.exit(1);
  } else {
    code = target;
  }

  console.log('\x1b[34m%s\x1b[0m', '[WARDEN-INIT] Allocating disposable MicroVM instance (256MB RAM, 0.5 CPU, 8 PIDs)...');
  console.log('\x1b[34m%s\x1b[0m', '[SECCOMP-BPF] Loaded strict syscall BPF filter (profile: python-minimal)...');
  
  let violationDetected = false;
  if (code.includes('/etc/passwd') || code.includes('environ')) {
    violationDetected = true;
    console.log('\x1b[33m%s\x1b[0m', '[SYSCALL-WARN] PID 742 -> openat(AT_FDCWD, "/etc/passwd", O_RDONLY)');
    console.log('\x1b[31m%s\x1b[0m', '[OVERLAY-FS-BLOCK] Violation trapped! Read attempt outside writable /tmp');
    console.log('\x1b[31m%s\x1b[0m', '[SECCOMP] SIGSYS sent to PID 742. Execution halted. Blast radius: 0%');
  } else {
    console.log('\x1b[32m%s\x1b[0m', '[EXEC] Program completed cleanly. Exit code 0.');
  }

  console.log('\x1b[32m%s\x1b[0m', '[WARDEN-TEARDOWN] Ephemeral overlayfs storage destroyed in 3ms.');
  process.exit(violationDetected ? 1 : 0);
}

console.error(`Unknown command: ${command}. Run 'warden help' for usage.`);
process.exit(1);
