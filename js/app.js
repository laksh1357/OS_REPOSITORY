/* Warden Main Application Orchestrator */

import { SandboxEngine, PRESET_SNIPPETS } from './sandbox-engine.js';
import { PolicyBuilder } from './policy-builder.js';
import { ArchVisualizer } from './arch-visualizer.js';
import { renderAttackMatrix } from './attack-matrix.js';
import { AuditFeed } from './audit-feed.js';

document.addEventListener("DOMContentLoaded", () => {
  // 1. Initialize Navbar Scroll Behavior
  const navbar = document.getElementById("navbar");
  if (navbar) {
    window.addEventListener("scroll", () => {
      if (window.scrollY > 20) {
        navbar.classList.add("scrolled");
      } else {
        navbar.classList.remove("scrolled");
      }
    });
  }

  // 2. Initialize Audit Feed Stream Component
  const auditBodyEl = document.getElementById("audit-feed-body");
  const auditFeed = auditBodyEl ? new AuditFeed(auditBodyEl) : null;
  if (auditFeed) {
    auditFeed.init();
  }

  // 3. Initialize Hero Live Demo Terminal
  const heroConsole = document.getElementById("hero-terminal");
  const heroStatus = document.getElementById("hero-status");
  const heroSummary = document.getElementById("hero-summary");

  if (heroConsole && heroStatus) {
    const heroEngine = new SandboxEngine(heroConsole, heroStatus, heroSummary);
    // Auto-run initial demo
    heroEngine.execute(PRESET_SNIPPETS.exfiltration.code, true);

    const replayBtn = document.getElementById("replay-hero-btn");
    if (replayBtn) {
      replayBtn.addEventListener("click", () => {
        heroEngine.execute(PRESET_SNIPPETS.exfiltration.code, true);
      });
    }
  }

  // 4. Initialize Interactive Sandbox Playground
  const pgConsole = document.getElementById("pg-console");
  const pgStatus = document.getElementById("pg-status");
  const pgSummary = document.getElementById("pg-summary");
  const pgCodeArea = document.getElementById("pg-code-editor");
  const pgRunBtn = document.getElementById("pg-run-btn");
  const pgEnforceToggle = document.getElementById("pg-enforce-toggle");

  if (pgConsole && pgCodeArea && pgRunBtn) {
    const playgroundEngine = new SandboxEngine(pgConsole, pgStatus, pgSummary);
    let activePresetKey = "exfiltration";

    // Set initial code
    pgCodeArea.value = PRESET_SNIPPETS[activePresetKey].code;

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
        let threat = PRESET_SNIPPETS[activePresetKey] ? PRESET_SNIPPETS[activePresetKey].title : 'Custom Script Execution';
        
        if (code.includes('/etc/passwd') || code.includes('environ')) {
          action = isEnforced ? 'OVERLAY_FS_BLOCK (SIGSYS)' : 'UNCONTAINED_EXPOSURE';
        } else if (code.includes('203.0.113.88') || code.includes('socket.connect')) {
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

  // 5. Initialize Architecture Inspector (5 Layers)
  const archSvg = document.getElementById("arch-svg-container");
  const archList = document.getElementById("arch-layer-list");
  const archInfo = document.getElementById("arch-info-box");

  if (archSvg && archList && archInfo) {
    const archVis = new ArchVisualizer(archSvg, archList, archInfo);
    archVis.init();
  }

  // 6. Initialize Policy Builder
  const policy = new PolicyBuilder();
  const yamlOutput = document.getElementById("code-output-area");
  const cpuSlider = document.getElementById("slider-cpu");
  const cpuVal = document.getElementById("val-cpu");
  const memSlider = document.getElementById("slider-mem");
  const memVal = document.getElementById("val-mem");
  const pidSlider = document.getElementById("slider-pid");
  const pidVal = document.getElementById("val-pid");
  const domainInput = document.getElementById("input-domain");
  const addDomainBtn = document.getElementById("btn-add-domain");
  const chipsContainer = document.getElementById("domain-chips-container");

  let activeCodeTab = "yaml";

  const renderPolicyOutput = () => {
    if (!yamlOutput) return;
    if (activeCodeTab === "yaml") {
      yamlOutput.textContent = policy.generateYAML();
    } else if (activeCodeTab === "sql") {
      yamlOutput.textContent = policy.generateSQL();
    } else if (activeCodeTab === "python") {
      yamlOutput.textContent = policy.generatePythonSDK();
    } else if (activeCodeTab === "go") {
      yamlOutput.textContent = policy.generateGoSDK();
    } else if (activeCodeTab === "curl") {
      yamlOutput.textContent = policy.generateCurl();
    }
  };

  const renderDomainChips = () => {
    if (!chipsContainer) return;
    chipsContainer.innerHTML = policy.state.egressDomains.map(d => `
      <span class="chip">
        ${d}
        <button data-domain="${d}" aria-label="Remove domain ${d}">×</button>
      </span>
    `).join("");

    chipsContainer.querySelectorAll("button").forEach(btn => {
      btn.addEventListener("click", (e) => {
        const domain = e.currentTarget.dataset.domain;
        if (domain) {
          policy.removeDomain(domain);
          renderDomainChips();
          renderPolicyOutput();
        }
      });
    });
  };

  if (cpuSlider) {
    cpuSlider.addEventListener("input", (e) => {
      const val = e.target.value;
      if (cpuVal) cpuVal.textContent = `${val} Cores`;
      policy.update("cpu", val);
      renderPolicyOutput();
    });
  }

  if (memSlider) {
    memSlider.addEventListener("input", (e) => {
      const val = e.target.value;
      if (memVal) memVal.textContent = `${val} MiB`;
      policy.update("memory", parseInt(val));
      renderPolicyOutput();
    });
  }

  if (pidSlider) {
    pidSlider.addEventListener("input", (e) => {
      const val = e.target.value;
      if (pidVal) pidVal.textContent = val;
      policy.update("pids", parseInt(val));
      renderPolicyOutput();
    });
  }

  if (addDomainBtn && domainInput) {
    const handleAdd = () => {
      if (domainInput.value) {
        policy.addDomain(domainInput.value);
        domainInput.value = "";
        renderDomainChips();
        renderPolicyOutput();
      }
    };
    addDomainBtn.addEventListener("click", handleAdd);
    domainInput.addEventListener("keypress", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        handleAdd();
      }
    });
  }

  // Code Tab switching
  document.querySelectorAll(".code-tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".code-tab").forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      activeCodeTab = tab.dataset.lang;
      renderPolicyOutput();
    });
  });

  renderDomainChips();
  renderPolicyOutput();

  // 7. Initialize Attack Matrix
  const attackMatrixEl = document.getElementById("attack-matrix-container");
  if (attackMatrixEl) {
    renderAttackMatrix(attackMatrixEl);
  }

  // 8. Clipboard Copy Actions
  document.querySelectorAll(".copy-trigger").forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.dataset.copyTarget;
      let textToCopy = "";
      if (targetId) {
        const el = document.getElementById(targetId);
        textToCopy = el ? el.textContent || el.value : "";
      } else if (btn.dataset.copyText) {
        textToCopy = btn.dataset.copyText;
      }

      if (textToCopy) {
        navigator.clipboard.writeText(textToCopy);
        const originalText = btn.textContent;
        btn.textContent = "✓ Copied";
        setTimeout(() => {
          btn.textContent = originalText;
        }, 1500);
      }
    });
  });
});
