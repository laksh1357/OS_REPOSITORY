/* Warden View Module - Policy Builder UI */

import { PolicyBuilder } from '../policy-builder.js';

export function initPolicy() {
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

  // New action elements
  const btnValidate = document.getElementById("btn-validate-policy");
  const btnActivate = document.getElementById("btn-activate-policy");
  const btnCompare = document.getElementById("btn-compare-policy");
  const feedbackContainer = document.getElementById("policy-feedback-container");

  let activeCodeTab = "yaml";

  const esc = (s) => String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

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
    chipsContainer.innerHTML = "";

    policy.state.egressDomains.forEach(domain => {
      const chip = document.createElement("span");
      chip.className = "chip";
      
      const domainLabel = document.createTextNode(domain + " ");
      chip.appendChild(domainLabel);

      const removeBtn = document.createElement("button");
      removeBtn.setAttribute("aria-label", `Remove domain ${domain}`);
      removeBtn.textContent = "×";
      removeBtn.addEventListener("click", () => {
        policy.removeDomain(domain);
        renderDomainChips();
        renderPolicyOutput();
      });

      chip.appendChild(removeBtn);
      chipsContainer.appendChild(chip);
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
      policy.update("memory", parseInt(val, 10));
      renderPolicyOutput();
    });
  }

  if (pidSlider) {
    pidSlider.addEventListener("input", (e) => {
      const val = e.target.value;
      if (pidVal) pidVal.textContent = val;
      policy.update("pids", parseInt(val, 10));
      renderPolicyOutput();
    });
  }

  if (addDomainBtn && domainInput) {
    const handleAdd = () => {
      const val = domainInput.value.trim();
      if (val) {
        policy.addDomain(val);
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

  // ── 1. Policy Validation Handler ──────────────────────────────────────────
  if (btnValidate && feedbackContainer) {
    btnValidate.addEventListener("click", async () => {
      btnValidate.disabled = true;
      btnValidate.textContent = "Validating...";
      feedbackContainer.style.display = "block";
      feedbackContainer.innerHTML = `<div class="bench-placeholder">Evaluating policy boundaries and platform compatibility...</div>`;

      try {
        const payload = policy.toPolicyObject();
        const res = await fetch('/api/v1/policies/validate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        const v = data.validation || {};

        const statusClass = v.valid ? "bench-pass" : "bench-fail";
        const statusText = v.valid ? "POLICY VALID" : "VALIDATION FAILED";
        const sevClass = v.severity === 'CRITICAL' ? 'sev-critical' : (v.severity === 'HIGH' ? 'sev-high' : 'sev-low');

        let errorsHtml = "";
        if (v.errors && v.errors.length > 0) {
          errorsHtml = `
            <div style="margin-top:12px;">
              <strong style="color:var(--red); font-size:0.8rem;">🚨 Errors (${v.errors.length}):</strong>
              <div style="display:flex; flex-direction:column; gap:6px; margin-top:6px;">
                ${v.errors.map(err => `
                  <div style="background:rgba(224,70,70,0.1); border-left:3px solid var(--red); padding:6px 10px; font-size:0.75rem;">
                    <strong>[${esc(err.code)}]</strong> ${esc(err.message)}
                    <div style="color:var(--text-muted); margin-top:2px;">↳ Remediation: ${esc(err.remediation)}</div>
                  </div>
                `).join('')}
              </div>
            </div>`;
        }

        let warningsHtml = "";
        if (v.warnings && v.warnings.length > 0) {
          warningsHtml = `
            <div style="margin-top:12px;">
              <strong style="color:var(--amber); font-size:0.8rem;">⚠️ Warnings (${v.warnings.length}):</strong>
              <div style="display:flex; flex-direction:column; gap:6px; margin-top:6px;">
                ${v.warnings.map(w => `
                  <div style="background:rgba(252,161,48,0.1); border-left:3px solid var(--amber); padding:6px 10px; font-size:0.75rem;">
                    <strong>[${esc(w.code)}]</strong> ${esc(w.message)}
                    <div style="color:var(--text-muted); margin-top:2px;">↳ Remediation: ${esc(w.remediation)}</div>
                  </div>
                `).join('')}
              </div>
            </div>`;
        }

        let unsupportedHtml = "";
        if (v.unsupportedControls && v.unsupportedControls.length > 0) {
          unsupportedHtml = `
            <div style="margin-top:12px;">
              <strong style="color:#64a0f0; font-size:0.8rem;">ℹ️ Platform Fallback & Unsupported Controls (${v.unsupportedControls.length}):</strong>
              <div style="display:flex; flex-direction:column; gap:6px; margin-top:6px;">
                ${v.unsupportedControls.map(u => `
                  <div style="background:rgba(100,160,240,0.1); border-left:3px solid #64a0f0; padding:6px 10px; font-size:0.75rem;">
                    <strong>${esc(u.mechanism)}</strong>: ${esc(u.message)}
                    <div style="color:var(--text-dim); margin-top:2px;">↳ Active Alternative: ${esc(u.alternative)}</div>
                  </div>
                `).join('')}
              </div>
            </div>`;
        }

        feedbackContainer.innerHTML = `
          <div class="dash-panel" style="border-color:${v.valid ? 'rgba(78,205,196,0.3)' : 'rgba(224,70,70,0.3)'};">
            <div class="dash-panel-header">
              <div style="display:flex; align-items:center; gap:8px;">
                <span class="badge ${statusClass}">${statusText}</span>
                <span class="rt-sev-badge ${sevClass}">SEVERITY: ${esc(v.severity)}</span>
                <span style="font-size:0.78rem; color:var(--text-dim);">Enforceability Score: <strong>${v.enforceabilityScore}/100</strong></span>
              </div>
              <button class="btn-secondary btn-sm" id="btn-close-feedback" style="margin-left:auto;">✕ Close</button>
            </div>
            <div style="padding:14px;">
              <div style="font-size:0.82rem; color:var(--text-muted);">
                Validated on Host OS: <strong>${esc((v.platform || 'UNKNOWN').toUpperCase())}</strong>
              </div>
              ${errorsHtml}
              ${warningsHtml}
              ${unsupportedHtml}
            </div>
          </div>
        `;

        document.getElementById("btn-close-feedback")?.addEventListener("click", () => {
          feedbackContainer.style.display = "none";
        });
      } catch (err) {
        feedbackContainer.innerHTML = `<div style="color:var(--red); padding:12px;">Validation request failed: ${esc(err.message)}</div>`;
      } finally {
        btnValidate.disabled = false;
        btnValidate.textContent = "🛡️ Validate Policy";
      }
    });
  }

  // ── 2. Policy Activation Handler ──────────────────────────────────────────
  if (btnActivate && feedbackContainer) {
    btnActivate.addEventListener("click", async () => {
      btnActivate.disabled = true;
      btnActivate.textContent = "Activating...";
      feedbackContainer.style.display = "block";
      feedbackContainer.innerHTML = `<div class="bench-placeholder">Activating policy in Warden execution pipeline...</div>`;

      try {
        const payload = policy.toPolicyObject();
        const res = await fetch('/api/v1/policies/activate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await res.json();

        if (res.ok && data.success) {
          feedbackContainer.innerHTML = `
            <div class="dash-panel" style="border-color:rgba(78,205,196,0.4); background:rgba(78,205,196,0.04);">
              <div class="dash-panel-header">
                <span class="badge bench-pass">⚡ POLICY ACTIVATED</span>
                <span style="font-size:0.82rem; color:var(--accent);">Active Policy: <strong>${esc(data.activePolicy.name)}</strong></span>
                <button class="btn-secondary btn-sm" id="btn-close-feedback" style="margin-left:auto;">✕ Close</button>
              </div>
              <div style="padding:14px; font-size:0.8rem; color:var(--text-muted);">
                <p>This policy is now applied to all subsequent sandbox executions via <code>/api/v1/execute</code> and the interactive playground.</p>
                <div style="display:flex; gap:12px; margin-top:8px; font-family:var(--font-mono); font-size:0.75rem;">
                  <span>CPU: ${data.activePolicy.cpu_limit}</span>
                  <span>RAM: ${data.activePolicy.memory_limit_mb}MiB</span>
                  <span>PIDs: ${data.activePolicy.max_processes}</span>
                  <span>Timeout: ${data.activePolicy.timeoutMs / 1000}s</span>
                  <span>Egress: ${data.activePolicy.egress_allowlist?.length || 0} domains</span>
                </div>
              </div>
            </div>
          `;
          window.dispatchEvent(new CustomEvent('warden:policy-activated', { detail: data.activePolicy }));
        } else {
          feedbackContainer.innerHTML = `
            <div class="dash-panel" style="border-color:rgba(224,70,70,0.4);">
              <div class="dash-panel-header">
                <span class="badge bench-fail">ACTIVATION REJECTED</span>
                <button class="btn-secondary btn-sm" id="btn-close-feedback" style="margin-left:auto;">✕ Close</button>
              </div>
              <div style="padding:14px; color:var(--red); font-size:0.8rem;">
                ${esc(data.error || 'Policy contains blocking validation errors')}
              </div>
            </div>
          `;
        }

        document.getElementById("btn-close-feedback")?.addEventListener("click", () => {
          feedbackContainer.style.display = "none";
        });
      } catch (err) {
        feedbackContainer.innerHTML = `<div style="color:var(--red); padding:12px;">Activation failed: ${esc(err.message)}</div>`;
      } finally {
        btnActivate.disabled = false;
        btnActivate.textContent = "⚡ Activate Policy";
      }
    });
  }

  // ── 3. Policy vs Runtime Comparison Handler ───────────────────────────────
  if (btnCompare && feedbackContainer) {
    btnCompare.addEventListener("click", async () => {
      btnCompare.disabled = true;
      btnCompare.textContent = "Comparing...";
      feedbackContainer.style.display = "block";
      feedbackContainer.innerHTML = `<div class="bench-placeholder">Comparing requested policy against active sandbox and host OS capabilities...</div>`;

      try {
        const requested = policy.toPolicyObject();
        const res = await fetch('/api/v1/policies/compare', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ requested }),
        });
        const data = await res.json();
        const comp = data.comparison || {};
        const sum = comp.summary || {};

        const riskClass = sum.riskLevel === 'CRITICAL' ? 'sev-critical' : (sum.riskLevel === 'HIGH' ? 'sev-high' : (sum.riskLevel === 'MEDIUM' ? 'sev-medium' : 'sev-low'));

        let diffsHtml = "";
        if (comp.diffs && comp.diffs.length > 0) {
          diffsHtml = `
            <div style="margin-top:12px;">
              <strong style="font-size:0.8rem; color:var(--text);">Parameter Diffs (${comp.diffs.length}):</strong>
              <table class="audit-table" style="margin-top:6px; font-size:0.75rem;">
                <thead>
                  <tr>
                    <th>Parameter</th>
                    <th>Active Value</th>
                    <th>Requested Value</th>
                    <th>Change Type</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  ${comp.diffs.map(d => `
                    <tr>
                      <td><code>${esc(d.parameter)}</code></td>
                      <td>${esc(d.activeValue)}</td>
                      <td>${esc(d.requestedValue)}</td>
                      <td><span class="badge ${d.changeType.includes('LOOSEN') || d.changeType.includes('EXPAND') ? 'bench-fail' : 'bench-pass'}" style="font-size:0.65rem;">${esc(d.changeType)}</span></td>
                      <td style="color:var(--text-muted);">${esc(d.details)}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>`;
        } else {
          diffsHtml = `<div style="margin-top:8px; font-size:0.75rem; color:var(--text-dim);">No parameter differences detected against active policy.</div>`;
        }

        let gapsHtml = "";
        if (comp.enforcementGaps && comp.enforcementGaps.length > 0) {
          gapsHtml = `
            <div style="margin-top:14px;">
              <strong style="color:var(--amber); font-size:0.8rem;">⚠️ Runtime Enforcement Gaps (${comp.enforcementGaps.length}):</strong>
              <div style="display:flex; flex-direction:column; gap:6px; margin-top:6px;">
                ${comp.enforcementGaps.map(g => `
                  <div style="background:rgba(252,161,48,0.08); border-left:3px solid var(--amber); padding:6px 10px; font-size:0.75rem;">
                    <strong>${esc(g.control)}</strong>
                    <div style="color:var(--text-muted); margin-top:2px;">Requested: <code>${esc(g.requestedInPolicy)}</code> ➔ Host Enforcement: <em>${esc(g.actualEnforcement)}</em></div>
                    <div style="color:var(--text-dim); margin-top:2px;">↳ ${esc(g.impact)}</div>
                  </div>
                `).join('')}
              </div>
            </div>`;
        }

        let recsHtml = "";
        if (comp.recommendations && comp.recommendations.length > 0) {
          recsHtml = `
            <div style="margin-top:14px;">
              <strong style="color:var(--accent); font-size:0.8rem;">💡 Security Recommendations:</strong>
              <ul style="margin:6px 0 0 16px; font-size:0.75rem; color:var(--text-muted); line-height:1.5;">
                ${comp.recommendations.map(r => `<li>${esc(r)}</li>`).join('')}
              </ul>
            </div>`;
        }

        feedbackContainer.innerHTML = `
          <div class="dash-panel">
            <div class="dash-panel-header">
              <div style="display:flex; align-items:center; gap:8px;">
                <span class="rt-sev-badge ${riskClass}">RISK LEVEL: ${esc(sum.riskLevel)} (${sum.riskScore}/100)</span>
                <span style="font-size:0.78rem; color:var(--text-dim);">${sum.diffsCount} Diffs, ${sum.regressionsCount} Regressions, ${sum.enforcementGapsCount} Platform Gaps</span>
              </div>
              <button class="btn-secondary btn-sm" id="btn-close-feedback" style="margin-left:auto;">✕ Close</button>
            </div>
            <div style="padding:14px;">
              ${diffsHtml}
              ${gapsHtml}
              ${recsHtml}
            </div>
          </div>
        `;

        document.getElementById("btn-close-feedback")?.addEventListener("click", () => {
          feedbackContainer.style.display = "none";
        });
      } catch (err) {
        feedbackContainer.innerHTML = `<div style="color:var(--red); padding:12px;">Comparison request failed: ${esc(err.message)}</div>`;
      } finally {
        btnCompare.disabled = false;
        btnCompare.textContent = "🔍 Compare vs Runtime";
      }
    });
  }

  renderDomainChips();
  renderPolicyOutput();

  return policy;
}
