/* Warden Policy Comparison Engine
 *
 * Compares:
 *   1. Requested / Generated Policy (from Policy Builder)
 *   2. Active Sandbox Policy (currently loaded policy)
 *   3. Actual Runtime Enforced Configuration (OS kernel capabilities)
 *
 * Highlights:
 *   - Added / removed permissions (writable dirs)
 *   - Tightened / loosened resource limits (CPU, RAM, timeout, PIDs)
 *   - Newly allowed or restricted network domains
 *   - Security controls requested but missing from runtime enforcement
 *   - Potential security regressions
 *   - Overall risk level & remediation advice
 */

'use strict';

const { HOST_CAPABILITIES } = require('./executor');

/**
 * Compare two policy configurations and evaluate the runtime enforcement gap.
 *
 * @param {object} requested - The candidate or newly generated policy
 * @param {object} active - The currently active policy in the engine
 * @param {object} capabilities - Host capabilities (defaults to HOST_CAPABILITIES)
 * @returns {ComparisonReport}
 */
function comparePolicies(requested = {}, active = {}, capabilities = HOST_CAPABILITIES) {
  const req = normalizeForComparison(requested);
  const act = normalizeForComparison(active);

  const diffs = [];
  const regressions = [];
  const enforcementGaps = [];
  let riskScore = 0; // 0 (safe/identical) to 100 (critical regression)

  // ── 1. Resource Limits Comparison ─────────────────────────────────────────
  // CPU
  if (req.cpu_limit !== act.cpu_limit) {
    const loosened = req.cpu_limit > act.cpu_limit;
    diffs.push({
      parameter: 'cpu_limit',
      activeValue: `${act.cpu_limit} cores`,
      requestedValue: `${req.cpu_limit} cores`,
      changeType: loosened ? 'LOOSENED' : 'TIGHTENED',
      details: loosened
        ? `CPU quota increased by ${(req.cpu_limit - act.cpu_limit).toFixed(1)} cores.`
        : `CPU quota reduced by ${(act.cpu_limit - req.cpu_limit).toFixed(1)} cores.`,
    });
    if (loosened && req.cpu_limit > 2.0) {
      regressions.push({
        severity: 'MEDIUM',
        message: `High CPU allocation (${req.cpu_limit} cores) increases exposure to processor core starvation.`,
        remediation: 'Cap CPU quota to <= 2.0 cores for untrusted AI workflows.',
      });
      riskScore += 15;
    }
  }

  // Memory
  if (req.memory_limit_mb !== act.memory_limit_mb) {
    const loosened = req.memory_limit_mb > act.memory_limit_mb;
    diffs.push({
      parameter: 'memory_limit_mb',
      activeValue: `${act.memory_limit_mb} MiB`,
      requestedValue: `${req.memory_limit_mb} MiB`,
      changeType: loosened ? 'LOOSENED' : 'TIGHTENED',
      details: loosened
        ? `Memory ceiling expanded by ${req.memory_limit_mb - act.memory_limit_mb} MiB.`
        : `Memory ceiling tightened by ${act.memory_limit_mb - req.memory_limit_mb} MiB.`,
    });
    if (loosened && req.memory_limit_mb > 1024) {
      regressions.push({
        severity: 'MEDIUM',
        message: `Memory limit increased to ${req.memory_limit_mb} MiB. Risk of host RAM pressure.`,
        remediation: 'Keep memory limit <= 1024 MiB unless processing large payloads.',
      });
      riskScore += 15;
    }
  }

  // Max Processes (PIDs)
  if (req.max_processes !== act.max_processes) {
    const loosened = req.max_processes > act.max_processes;
    diffs.push({
      parameter: 'max_processes',
      activeValue: `${act.max_processes} PIDs`,
      requestedValue: `${req.max_processes} PIDs`,
      changeType: loosened ? 'LOOSENED' : 'TIGHTENED',
      details: loosened
        ? `Process ceiling increased by ${req.max_processes - act.max_processes} child PIDs.`
        : `Process ceiling lowered by ${act.max_processes - req.max_processes} child PIDs.`,
    });
    if (loosened && req.max_processes > 16) {
      regressions.push({
        severity: 'HIGH',
        message: `Process limit increased to ${req.max_processes}. Increases risk of fork-bomb host degradation.`,
        remediation: 'Keep max_processes <= 16 to contain process table saturation.',
      });
      riskScore += 25;
    }
  }

  // Timeout
  if (req.timeoutMs !== act.timeoutMs) {
    const loosened = req.timeoutMs > act.timeoutMs;
    diffs.push({
      parameter: 'timeoutMs',
      activeValue: `${act.timeoutMs}ms`,
      requestedValue: `${req.timeoutMs}ms`,
      changeType: loosened ? 'LOOSENED' : 'TIGHTENED',
      details: loosened
        ? `Execution deadline extended by ${((req.timeoutMs - act.timeoutMs) / 1000).toFixed(1)}s.`
        : `Execution deadline tightened by ${((act.timeoutMs - req.timeoutMs) / 1000).toFixed(1)}s.`,
    });
    if (loosened && req.timeoutMs > 20000) {
      regressions.push({
        severity: 'LOW',
        message: `Execution timeout increased to ${req.timeoutMs / 1000}s.`,
        remediation: 'Ensure workers that hang or spin loop are killed within 15-20s.',
      });
      riskScore += 10;
    }
  }

  // ── 2. Filesystem Permissions Comparison ──────────────────────────────────
  const actWritable = new Set(act.writable_paths);
  const reqWritable = new Set(req.writable_paths);

  const addedPaths = req.writable_paths.filter(p => !actWritable.has(p));
  const removedPaths = act.writable_paths.filter(p => !reqWritable.has(p));

  if (addedPaths.length > 0) {
    diffs.push({
      parameter: 'writable_paths:added',
      activeValue: '—',
      requestedValue: addedPaths.join(', '),
      changeType: 'PERMISSION_EXPANDED',
      details: `New writable directory paths granted: ${addedPaths.join(', ')}`,
    });
    // Check if added path is outside /tmp
    const riskyPaths = addedPaths.filter(p => !p.startsWith('/tmp'));
    if (riskyPaths.length > 0) {
      regressions.push({
        severity: 'CRITICAL',
        message: `Expanded writable permissions to non-standard path: ${riskyPaths.join(', ')}.`,
        remediation: 'Restrict write permissions strictly to ephemeral scratch directories under /tmp.',
      });
      riskScore += 40;
    } else {
      riskScore += 10;
    }
  }

  if (removedPaths.length > 0) {
    diffs.push({
      parameter: 'writable_paths:removed',
      activeValue: removedPaths.join(', '),
      requestedValue: '—',
      changeType: 'PERMISSION_REVOKED',
      details: `Writable directory access revoked: ${removedPaths.join(', ')}`,
    });
  }

  // ── 3. Network Egress Domains Comparison ──────────────────────────────────
  const actEgress = new Set(act.egress_allowlist);
  const reqEgress = new Set(req.egress_allowlist);

  const addedDomains = req.egress_allowlist.filter(d => !actEgress.has(d));
  const removedDomains = act.egress_allowlist.filter(d => !reqEgress.has(d));

  if (addedDomains.length > 0) {
    diffs.push({
      parameter: 'egress_allowlist:added',
      activeValue: '—',
      requestedValue: addedDomains.join(', '),
      changeType: 'EGRESS_EXPANDED',
      details: `Newly permitted external egress domains: ${addedDomains.join(', ')}`,
    });
    regressions.push({
      severity: addedDomains.length > 3 ? 'HIGH' : 'MEDIUM',
      message: `Outbound network egress expanded with ${addedDomains.length} new domains (${addedDomains.join(', ')}).`,
      remediation: 'Verify each external domain is strictly necessary for worker tasks.',
    });
    riskScore += Math.min(30, addedDomains.length * 10);
  }

  if (removedDomains.length > 0) {
    diffs.push({
      parameter: 'egress_allowlist:removed',
      activeValue: removedDomains.join(', '),
      requestedValue: '—',
      changeType: 'EGRESS_RESTRICTED',
      details: `Egress domains revoked: ${removedDomains.join(', ')}`,
    });
  }

  // ── 4. Runtime Enforcement Gap (Requested vs Enforceable) ─────────────────
  // Compare requested policy features against what host capabilities can genuinely enforce
  if (req.runtime === 'microvm' && capabilities.platform !== 'linux') {
    enforcementGaps.push({
      control: 'Hardware MicroVM Isolation (KVM)',
      requestedInPolicy: 'runtime: microvm',
      actualEnforcement: 'Worker process with RLIMITs and Python builtins sandbox',
      platform: capabilities.platform,
      enforced: false,
      severity: 'HIGH',
      impact: `Hardware virtualization boundary is not present on ${capabilities.platform}. Process-level fallback active.`,
    });
    riskScore += 20;
  }

  if (req.syscall_profile !== 'none' && !capabilities.seccomp) {
    enforcementGaps.push({
      control: 'Seccomp-BPF System Call Filtering',
      requestedInPolicy: `syscall_profile: ${req.syscall_profile}`,
      actualEnforcement: 'Python builtins and socket wrapper interception (No kernel syscall drop)',
      platform: capabilities.platform,
      enforced: false,
      severity: 'MEDIUM',
      impact: `Kernel-level syscall table filtering is not available on ${capabilities.platform}. C-extensions bypassing Python builtins cannot be blocked.`,
    });
    riskScore += 15;
  }

  if (req.max_processes > 0 && !capabilities.cgroups) {
    enforcementGaps.push({
      control: 'cgroups v2 Process Ceiling (pids.max)',
      requestedInPolicy: `max_processes: ${req.max_processes}`,
      actualEnforcement: 'resource.setrlimit(RLIMIT_NPROC)',
      platform: capabilities.platform,
      enforced: false,
      severity: 'MEDIUM',
      impact: 'RLIMIT_NPROC limits per-user processes rather than container cgroup hierarchy.',
    });
  }

  if (req.egress_allowlist.length > 0 && !capabilities.ebpfEgress) {
    enforcementGaps.push({
      control: 'Kernel eBPF TC Packet Egress Filtering',
      requestedInPolicy: `egress_allowlist: ${req.egress_allowlist.length} domains`,
      actualEnforcement: 'socket.getaddrinfo and socket.connect Python interception',
      platform: capabilities.platform,
      enforced: false,
      severity: 'LOW',
      impact: 'Egress filtering is enforced at userspace Python runtime. Raw AF_INET sockets via C extensions are unmonitored at kernel level.',
    });
  }

  // ── 5. Compute Risk Level ─────────────────────────────────────────────────
  let riskLevel = 'NEUTRAL';
  if (riskScore >= 60 || regressions.some(r => r.severity === 'CRITICAL')) {
    riskLevel = 'CRITICAL';
  } else if (riskScore >= 40 || regressions.some(r => r.severity === 'HIGH')) {
    riskLevel = 'HIGH';
  } else if (riskScore >= 20 || regressions.some(r => r.severity === 'MEDIUM')) {
    riskLevel = 'MEDIUM';
  } else if (diffs.length > 0) {
    riskLevel = 'LOW';
  }

  return {
    comparedAt: new Date().toISOString(),
    platform: capabilities.platform,
    requestedName: req.name,
    activeName: act.name,
    summary: {
      diffsCount: diffs.length,
      regressionsCount: regressions.length,
      enforcementGapsCount: enforcementGaps.length,
      riskScore: Math.min(100, riskScore),
      riskLevel,
    },
    diffs,
    regressions,
    enforcementGaps,
    recommendations: generateRecommendations(diffs, regressions, enforcementGaps),
  };
}

function normalizeForComparison(p = {}) {
  return {
    name: p.name || 'default',
    runtime: (p.runtime || 'microvm').toLowerCase(),
    cpu_limit: Number(p.cpu_limit ?? p.cpu ?? 0.5),
    memory_limit_mb: Number(p.memory_limit_mb ?? p.memoryMb ?? p.memory ?? 256),
    max_processes: parseInt(p.max_processes ?? p.pids ?? 8, 10),
    timeoutMs: Number(p.timeoutMs ?? (p.timeout ? Number(p.timeout) * 1000 : 10000)),
    root_readonly: Boolean(p.root_readonly ?? (p.rootFs === 'read-only') ?? true),
    writable_paths: Array.isArray(p.writable_paths ?? p.writableDirs ?? p.writablePaths)
      ? (p.writable_paths ?? p.writableDirs ?? p.writablePaths).map(s => String(s).trim())
      : ['/tmp'],
    egress_allowlist: Array.isArray(p.egress_allowlist ?? p.egressDomains ?? p.egressAllowlist)
      ? (p.egress_allowlist ?? p.egressDomains ?? p.egressAllowlist).map(s => String(s).trim().toLowerCase())
      : [],
    syscall_profile: p.syscall_profile || p.syscallProfile || 'python-minimal',
  };
}

function generateRecommendations(diffs, regressions, gaps) {
  const recs = [];
  if (regressions.length === 0 && gaps.length === 0 && diffs.length === 0) {
    recs.push('Policies are identical. No configuration change detected.');
    return recs;
  }

  if (gaps.some(g => g.severity === 'HIGH')) {
    recs.push('Platform Capability Alert: The host OS does not support hardware microVMs or kernel namespaces. For mission-critical isolation, deploy Warden on a Linux KVM host.');
  }

  if (regressions.some(r => r.severity === 'CRITICAL')) {
    recs.push('Critical Regression Alert: Review added writable filesystem paths. Granting write access outside /tmp allows untrusted code to mutate system state.');
  }

  if (diffs.some(d => d.changeType === 'EGRESS_EXPANDED')) {
    recs.push('Egress Expansion: Newly allowed external domains create potential data exfiltration paths. Ensure egress domains are pinned to specific vendor APIs.');
  }

  if (recs.length === 0) {
    recs.push('Policy update looks balanced. Proceed to verification testing before production deployment.');
  }

  return recs;
}

module.exports = {
  comparePolicies,
  normalizeForComparison,
};
