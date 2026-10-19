/* Warden View Module - Interactive Sandbox Playground */

import { SandboxEngine, PRESET_SNIPPETS } from '../sandbox-engine.js';

export function initPlayground(auditFeed) {
  const pgConsole = document.getElementById("pg-console");
  const pgStatus = document.getElementById("pg-status");
  const pgSummary = document.getElementById("pg-summary");
  const pgCodeArea = document.getElementById("pg-code-editor");
  const pgRunBtn = document.getElementById("pg-run-btn");
  const pgEnforceToggle = document.getElementById("pg-enforce-toggle");

  if (!pgConsole || !pgCodeArea || !pgRunBtn) return;

  const playgroundEngine = new SandboxEngine(pgConsole, pgStatus, pgSummary);
  let activePresetKey = "exfiltration";

  // Set initial code
  if (PRESET_SNIPPETS[activePresetKey]) {
    pgCodeArea.value = PRESET_SNIPPETS[activePresetKey].code;
  }

  // Preset button clicks
  document.querySelectorAll(".preset-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".preset-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      activePresetKey = btn.dataset.preset;
      if (PRESET_SNIPPETS[activePresetKey]) {
        pgCodeArea.value = PRESET_SNIPPETS[activePresetKey].code;
      }
    });
  });

  // Run Button Click
  pgRunBtn.addEventListener("click", async () => {
    const code = pgCodeArea.value;
    const isEnforced = pgEnforceToggle ? pgEnforceToggle.checked : true;
    await playgroundEngine.execute(code, isEnforced);

    if (auditFeed) {
      const runId = 'run_' + Math.random().toString(36).substring(2, 10);
      let action = 'COMPLETED (Exit 0)';
      const threat = PRESET_SNIPPETS[activePresetKey] 
        ? PRESET_SNIPPETS[activePresetKey].title 
        : 'Custom Script Execution';
      
      if (code.includes('/etc/passwd') || code.includes('environ') || code.includes('AKIA')) {
        action = isEnforced ? 'OVERLAY_FS_BLOCK (SIGSYS)' : 'UNCONTAINED_EXPOSURE';
      } else if (code.includes('203.0.113.88') || code.includes('198.51.100.44') || code.includes('socket.connect')) {
        action = isEnforced ? 'EGRESS_DENY (eBPF Drop)' : 'UNCONTAINED_EXPOSURE';
      } else if (code.includes('os.fork()')) {
        action = isEnforced ? 'CGROUP_CEILING (PID Limit)' : 'UNCONTAINED_EXPOSURE';
      }

      auditFeed.addEntry({
        runId,
        threat,
        action,
        dlp: isEnforced ? '0 Bytes Leaked (Sanitized)' : 'EXPOSED RISK',
        latency: '3.8ms',
        timestamp: 'Just now'
      });
    }
  });
}
