/* Warden Policy Validation Engine
 *
 * Validates sandbox security policies against strict safety constraints,
 * platform capability boundaries, and conflict matrices.
 *
 * Checks:
 *   1. Schema & Required Fields (name, runtime, resource limits)
 *   2. Resource Boundaries (CPU 0.1-4.0, RAM 64-2048MB, PIDs 1-64, Timeout 1-60s)
 *   3. Unsafe Writable Paths (/, /etc, /usr, /bin, /dev, /proc, traversal '..', null bytes)
 *   4. Network Egress Allowlists (reject wildcards, loopback 127.0.0.1, cloud metadata 169.254.169.254, RFC1918)
 *   5. Duplicate and Conflicting Rules
 *   6. Overly Permissive Configurations
 *   7. Platform Enforceability & Capabilities (macOS vs Linux namespaces/seccomp/cgroups)
 *   8. Diff between requested and genuinely enforceable controls
 */

'use strict';

const { HOST_CAPABILITIES } = require('./executor');

const FORBIDDEN_WRITABLE_ROOTS = [
  '/',
  '/etc',
  '/usr',
  '/bin',
  '/sbin',
  '/lib',
  '/lib64',
  '/var',
  '/dev',
  '/proc',
  '/sys',
  '/boot',
  '/root',
  '/home',
];

const DANGEROUS_IPS = [
  '127.0.0.1',
  'localhost',
  '0.0.0.0',
  '::1',
  '169.254.169.254', // AWS/GCP/Azure link-local metadata service
  'metadata.google.internal',
  '100.100.100.200', // Alibaba metadata
];

const DOMAIN_REGEX = /^(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}$/;

/**
 * Validate a candidate policy against security best practices and host capability.
 *
 * @param {object} policy - Raw policy object
 * @returns {ValidationResult}
 */
function validatePolicy(policy) {
  const errors = [];
  const warnings = [];
  const unsupportedControls = [];
  const conflicts = [];

  if (!policy || typeof policy !== 'object') {
    return {
      valid: false,
      severity: 'CRITICAL',
      errors: [{
        field: 'policy',
        code: 'INVALID_PAYLOAD',
        message: 'Policy definition must be a non-null JSON object.',
        remediation: 'Provide a valid JSON policy with at least a unique name and resource bounds.'
      }],
      warnings: [],
      unsupportedControls: [],
      enforceabilityScore: 0,
      normalizedPolicy: null,
    };
  }

  // ── 1. Name & Metadata ───────────────────────────────────────────────────
  const name = typeof policy.name === 'string' ? policy.name.trim() : '';
  if (!name) {
    errors.push({
      field: 'name',
      code: 'MISSING_NAME',
      message: 'Policy must specify a non-empty name identifier.',
      remediation: 'Set a descriptive identifier such as "python-agent-strict".'
    });
  } else if (!/^[a-zA-Z0-9_-]{3,64}$/.test(name)) {
    warnings.push({
      field: 'name',
      code: 'NAME_FORMAT',
      severity: 'LOW',
      message: `Policy name "${name}" contains unusual characters. Recommend alphanumeric, hyphen, underscore (3-64 chars).`,
      remediation: 'Use kebab-case or snake_case without spaces or special symbols.'
    });
  }

  // ── 2. Runtime Selection ──────────────────────────────────────────────────
  const runtime = (policy.runtime || 'microvm').toLowerCase();
  const validRuntimes = ['microvm', 'container', 'process'];
  if (!validRuntimes.includes(runtime)) {
    errors.push({
      field: 'runtime',
      code: 'INVALID_RUNTIME',
      message: `Runtime "${policy.runtime}" is unrecognized. Must be one of: ${validRuntimes.join(', ')}.`,
      remediation: 'Select "microvm" for maximum isolation, or "process" for lightweight environments.'
    });
  }

  // Check if requested runtime is enforceable on host
  if (runtime === 'microvm' && HOST_CAPABILITIES.platform !== 'linux') {
    unsupportedControls.push({
      mechanism: 'MICROVM_HYPERVISOR',
      requested: 'microvm (Firecracker/Cloud-Hypervisor /dev/kvm)',
      platform: HOST_CAPABILITIES.platform,
      status: 'UNSUPPORTED',
      severity: 'HIGH',
      alternative: 'Fallback to process isolation with RLIMIT ceilings and Python builtins sandbox.',
      message: `KVM hardware-assisted microVM hypervisor is unavailable on ${HOST_CAPABILITIES.platform}. Warden will fall back to isolated worker processes.`
    });
    warnings.push({
      field: 'runtime',
      code: 'UNSUPPORTED_MICROVM',
      severity: 'HIGH',
      message: `Requested runtime "microvm" requires Linux KVM. Running on ${HOST_CAPABILITIES.platform}; operating in worker process mode.`,
      remediation: 'Deploy on a Linux KVM host for genuine microVM isolation, or accept process-level containment.'
    });
  } else if (runtime === 'container' && !HOST_CAPABILITIES.namespaces) {
    unsupportedControls.push({
      mechanism: 'CONTAINER_NAMESPACES',
      requested: 'container (Linux mount/pid/user namespaces)',
      platform: HOST_CAPABILITIES.platform,
      status: 'UNSUPPORTED',
      severity: 'HIGH',
      alternative: 'Fallback to process-level isolation.',
      message: `Linux user and mount namespaces are unavailable on ${HOST_CAPABILITIES.platform}.`
    });
  }

  // ── 3. Resource Bounds ────────────────────────────────────────────────────
  // CPU Limit
  const rawCpu = policy.cpu_limit ?? policy.cpu ?? 0.5;
  const cpu = Number(rawCpu);
  if (isNaN(cpu) || cpu <= 0) {
    errors.push({
      field: 'cpu_limit',
      code: 'INVALID_CPU',
      message: `CPU quota ceiling must be a positive number. Got: ${rawCpu}`,
      remediation: 'Specify CPU between 0.1 and 4.0 cores.'
    });
  } else if (cpu > 4.0) {
    warnings.push({
      field: 'cpu_limit',
      code: 'HIGH_CPU_ALLOCATION',
      severity: 'MEDIUM',
      message: `CPU quota ${cpu} cores is unusually high for an untrusted worker.`,
      remediation: 'Cap CPU quota to 1.0 or 2.0 cores to prevent noisy-neighbor core starvation.'
    });
  }

  // Memory Limit
  const rawMem = policy.memory_limit_mb ?? policy.memoryMb ?? policy.memory ?? 256;
  const mem = Number(rawMem);
  if (isNaN(mem) || mem < 32) {
    errors.push({
      field: 'memory_limit_mb',
      code: 'INVALID_MEMORY',
      message: `Memory limit must be at least 32 MiB. Got: ${rawMem}`,
      remediation: 'Set memory between 64 and 2048 MiB.'
    });
  } else if (mem > 2048) {
    warnings.push({
      field: 'memory_limit_mb',
      code: 'HIGH_MEMORY_ALLOCATION',
      severity: 'MEDIUM',
      message: `Memory allocation ${mem} MiB exceeds 2048 MiB recommendation for untrusted tasks.`,
      remediation: 'Limit untrusted workers to <= 1024 MiB to mitigate memory exhaustion denial-of-service.'
    });
  }

  // Process / PID Limit
  const rawPids = policy.max_processes ?? policy.pids ?? 8;
  const pids = parseInt(rawPids, 10);
  if (isNaN(pids) || pids < 1) {
    errors.push({
      field: 'max_processes',
      code: 'INVALID_PIDS',
      message: `Max child processes must be at least 1. Got: ${rawPids}`,
      remediation: 'Set max_processes between 1 and 64.'
    });
  } else if (pids > 64) {
    warnings.push({
      field: 'max_processes',
      code: 'HIGH_PID_LIMIT',
      severity: 'HIGH',
      message: `Max processes ${pids} is overly permissive and increases fork-bomb risk.`,
      remediation: 'Cap process limit to <= 16 to contain process table saturation.'
    });
  }

  // Execution Timeout
  const rawTimeout = policy.timeoutMs ?? (policy.timeout ? Number(policy.timeout) * 1000 : 10000);
  const timeoutMs = Number(rawTimeout);
  if (isNaN(timeoutMs) || timeoutMs < 1000 || timeoutMs > 60000) {
    errors.push({
      field: 'timeoutMs',
      code: 'INVALID_TIMEOUT',
      message: `Execution timeout must be between 1,000ms (1s) and 60,000ms (60s). Got: ${rawTimeout}`,
      remediation: 'Set timeout between 1000 and 30000 ms.'
    });
  }

  // ── 4. Filesystem Boundaries ──────────────────────────────────────────────
  const rawWritable = policy.writable_paths ?? policy.writableDirs ?? policy.writablePaths ?? ['/tmp'];
  const writablePaths = Array.isArray(rawWritable) ? rawWritable : [String(rawWritable)];

  writablePaths.forEach((wPath, idx) => {
    if (typeof wPath !== 'string' || !wPath.trim()) {
      errors.push({
        field: `writable_paths[${idx}]`,
        code: 'EMPTY_PATH',
        message: 'Writable path entry cannot be empty.',
        remediation: 'Provide an absolute path such as "/tmp".'
      });
      return;
    }

    const cleanPath = wPath.trim();

    // Check null bytes
    if (cleanPath.includes('\0')) {
      errors.push({
        field: `writable_paths[${idx}]`,
        code: 'NULL_BYTE_INJECTION',
        message: `Writable path contains null byte injection: ${JSON.stringify(cleanPath)}`,
        remediation: 'Remove null bytes from path string.'
      });
      return;
    }

    // Check path traversal
    if (cleanPath.includes('..') || cleanPath.includes('./')) {
      errors.push({
        field: `writable_paths[${idx}]`,
        code: 'PATH_TRAVERSAL_DETECTED',
        message: `Writable path contains relative directory traversal sequence: "${cleanPath}"`,
        remediation: 'Specify canonical absolute paths without ".." or "."'
      });
      return;
    }

    // Check absolute path
    if (!cleanPath.startsWith('/')) {
      errors.push({
        field: `writable_paths[${idx}]`,
        code: 'NON_ABSOLUTE_PATH',
        message: `Writable path must be an absolute path starting with "/". Got: "${cleanPath}"`,
        remediation: `Use "/tmp/${cleanPath}" instead.`
      });
      return;
    }

    // Check forbidden system root directories
    const normalized = cleanPath.replace(/\/+$/, '') || '/';
    if (FORBIDDEN_WRITABLE_ROOTS.includes(normalized)) {
      errors.push({
        field: `writable_paths[${idx}]`,
        code: 'UNSAFE_WRITABLE_PATH',
        message: `Path "${cleanPath}" is a critical system directory and cannot be granted writable permissions.`,
        remediation: 'Restrict writable storage strictly to ephemeral scratch directories such as "/tmp" or "/tmp/sandbox".'
      });
    } else if (normalized.startsWith('/etc') || normalized.startsWith('/sys') || normalized.startsWith('/dev') || normalized.startsWith('/proc')) {
      errors.push({
        field: `writable_paths[${idx}]`,
        code: 'CRITICAL_SYSTEM_PATH',
        message: `Path "${cleanPath}" targets sensitive host OS subsystem. Write permissions denied.`,
        remediation: 'Use "/tmp" for ephemeral file writes.'
      });
    }
  });

  // Duplicate writable paths check
  const uniqueWritable = new Set(writablePaths.map(p => (typeof p === 'string' ? p.trim() : '')));
  if (uniqueWritable.size < writablePaths.length) {
    warnings.push({
      field: 'writable_paths',
      code: 'DUPLICATE_WRITABLE_PATHS',
      severity: 'LOW',
      message: 'Writable paths list contains duplicate entries.',
      remediation: 'Remove duplicate paths to simplify policy configuration.'
    });
  }

  // ── 5. Network Egress Allowlists ──────────────────────────────────────────
  const rawEgress = policy.egress_allowlist ?? policy.egressDomains ?? policy.egressAllowlist ?? [];
  const egressList = Array.isArray(rawEgress) ? rawEgress : [String(rawEgress)];

  if (egressList.length === 0) {
    // Note: Empty allowlist is secure, it means default-deny!
    warnings.push({
      field: 'egress_allowlist',
      code: 'DEFAULT_DENY_EGRESS',
      severity: 'LOW',
      message: 'Egress allowlist is empty. Sandbox will enforce strict DENY-ALL on all outbound network traffic.',
      remediation: 'Add approved API domains (e.g. "api.openai.com") if worker requires legitimate external network egress.'
    });
  }

  const seenDomains = new Set();
  egressList.forEach((entry, idx) => {
    if (typeof entry !== 'string') {
      errors.push({
        field: `egress_allowlist[${idx}]`,
        code: 'INVALID_ENTRY',
        message: 'Egress allowlist entry must be a string.',
        remediation: 'Specify a valid domain string.'
      });
      return;
    }

    const domain = entry.trim().toLowerCase();

    // Check duplicate
    if (seenDomains.has(domain)) {
      conflicts.push({
        type: 'DUPLICATE_EGRESS_DOMAIN',
        message: `Duplicate egress domain entry: "${domain}"`,
        field: `egress_allowlist[${idx}]`
      });
    }
    seenDomains.add(domain);

    // Check wildcards
    if (domain === '*' || domain.startsWith('*.')) {
      errors.push({
        field: `egress_allowlist[${idx}]`,
        code: 'WILDCARD_EGRESS_FORBIDDEN',
        message: `Wildcard egress domain "${domain}" undermines network containment boundary.`,
        remediation: 'Specify exact, fully qualified domain names (FQDN) rather than wildcards.'
      });
      return;
    }

    // Check dangerous/local/cloud metadata IPs
    if (DANGEROUS_IPS.includes(domain)) {
      errors.push({
        field: `egress_allowlist[${idx}]`,
        code: 'DANGEROUS_EGRESS_TARGET',
        message: `Egress to loopback/link-local/metadata address "${domain}" is strictly prohibited.`,
        remediation: 'Remove internal/metadata endpoints from egress allowlist.'
      });
      return;
    }

    // Check RFC1918 Private IP subnets
    if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain) ||
        /^192\.168\.\d{1,3}\.\d{1,3}$/.test(domain) ||
        /^172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(domain)) {
      errors.push({
        field: `egress_allowlist[${idx}]`,
        code: 'INTERNAL_SUBNET_EXPOSURE',
        message: `Egress target "${domain}" belongs to private RFC1918 intranet address space.`,
        remediation: 'Do not expose internal private network hosts to untrusted AI code.'
      });
      return;
    }

    // Check domain syntax
    if (!DOMAIN_REGEX.test(domain) && !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
      warnings.push({
        field: `egress_allowlist[${idx}]`,
        code: 'SUSPICIOUS_DOMAIN_SYNTAX',
        severity: 'MEDIUM',
        message: `Egress entry "${domain}" does not match standard FQDN format.`,
        remediation: 'Ensure domain is a valid hostname like "api.github.com".'
      });
    }
  });

  // ── 6. Platform Capability vs Policy Requirements ─────────────────────────
  if (!HOST_CAPABILITIES.cgroups && pids > 16) {
    unsupportedControls.push({
      mechanism: 'CGROUPS_PIDS_CEILING',
      requested: `max_processes=${pids}`,
      platform: HOST_CAPABILITIES.platform,
      status: 'UNVERIFIED',
      severity: 'MEDIUM',
      alternative: 'RLIMIT_NPROC inside Python process.',
      message: `cgroups v2 pids.max controller is unavailable on ${HOST_CAPABILITIES.platform}. High PID limit (${pids}) increases denial-of-service risk.`
    });
  }

  if (!HOST_CAPABILITIES.seccomp) {
    unsupportedControls.push({
      mechanism: 'SECCOMP_BPF',
      requested: policy.syscall_profile || policy.syscallProfile || 'python-minimal',
      platform: HOST_CAPABILITIES.platform,
      status: 'UNSUPPORTED',
      severity: 'MEDIUM',
      alternative: 'Python builtins and socket interception.',
      message: `Seccomp-BPF system call filtering is not supported natively by the ${HOST_CAPABILITIES.platform} kernel.`
    });
  }

  if (!HOST_CAPABILITIES.ebpfEgress && egressList.length > 0) {
    unsupportedControls.push({
      mechanism: 'EBPF_NETWORK_FILTER',
      requested: 'Kernel-level TC eBPF egress drop',
      platform: HOST_CAPABILITIES.platform,
      status: 'UNSUPPORTED',
      severity: 'LOW',
      alternative: 'Python socket.getaddrinfo and socket.connect interception.',
      message: `eBPF TC egress filtering requires Linux kernel with CAP_NET_ADMIN. Operating at socket wrapper layer on ${HOST_CAPABILITIES.platform}.`
    });
  }

  // ── 7. Fail Closed Check ─────────────────────────────────────────────────
  if (policy.failClosed === true && unsupportedControls.some(c => c.severity === 'HIGH')) {
    errors.push({
      field: 'failClosed',
      code: 'FAIL_CLOSED_BLOCKED',
      message: 'Policy demands fail-closed enforcement, but critical isolation controls are unsupported on this platform.',
      remediation: 'Execute on a fully supported Linux container/KVM host, or set failClosed: false to permit fallback containment.'
    });
  }

  // ── 8. Calculate Enforceability & Severity ─────────────────────────────────
  const valid = errors.length === 0;

  let severity = 'CLEAN';
  if (errors.length > 0) {
    severity = errors.some(e => e.code.includes('CRITICAL') || e.code.includes('UNSAFE') || e.code.includes('INJECTION'))
      ? 'CRITICAL'
      : 'HIGH';
  } else if (warnings.some(w => w.severity === 'HIGH')) {
    severity = 'HIGH';
  } else if (warnings.some(w => w.severity === 'MEDIUM')) {
    severity = 'MEDIUM';
  } else if (warnings.length > 0 || unsupportedControls.length > 0) {
    severity = 'LOW';
  }

  // Enforceability score: 100 base, penalize for unsupported controls and warnings
  let score = 100;
  if (!HOST_CAPABILITIES.seccomp) score -= 15;
  if (!HOST_CAPABILITIES.cgroups) score -= 15;
  if (!HOST_CAPABILITIES.namespaces) score -= 10;
  if (runtime === 'microvm' && HOST_CAPABILITIES.platform !== 'linux') score -= 20;
  score -= warnings.filter(w => w.severity === 'HIGH').length * 10;
  score -= warnings.filter(w => w.severity === 'MEDIUM').length * 5;
  score = Math.max(0, Math.min(100, score));

  // Normalized Policy
  const normalizedPolicy = {
    name,
    runtime,
    cpu_limit: cpu,
    memory_limit_mb: mem,
    max_processes: pids,
    timeoutMs,
    root_readonly: policy.root_readonly ?? policy.rootFs === 'read-only' ?? true,
    writable_paths: Array.from(uniqueWritable),
    egress_allowlist: Array.from(seenDomains),
    syscall_profile: policy.syscall_profile || policy.syscallProfile || 'python-minimal',
    failClosed: Boolean(policy.failClosed),
  };

  return {
    valid,
    severity,
    errors,
    warnings,
    conflicts,
    unsupportedControls,
    enforceabilityScore: score,
    normalizedPolicy: valid ? normalizedPolicy : null,
    validatedAt: new Date().toISOString(),
    platform: HOST_CAPABILITIES.platform,
  };
}

module.exports = {
  validatePolicy,
  FORBIDDEN_WRITABLE_ROOTS,
  DANGEROUS_IPS,
};
