/* Warden Live Execution Telemetry Dashboard */

export function initDashboard() {
  const capBanner = document.getElementById('capability-banner');
  const benchBtn = document.getElementById('bench-run-btn');
  const benchBadge = document.getElementById('bench-status-badge');
  const benchContainer = document.getElementById('bench-results-container');
  const manifestBtn = document.getElementById('manifest-load-btn');
  const manifestContainer = document.getElementById('manifest-container');
  const auditRefreshBtn = document.getElementById('audit-refresh-btn');
  const liveAuditBody = document.getElementById('live-audit-body');
  const chainBadge = document.getElementById('chain-integrity-badge');

  // Red Team elements
  const redteamBtn = document.getElementById('redteam-run-btn');
  const redteamBadge = document.getElementById('redteam-status-badge');
  const redteamContainer = document.getElementById('redteam-results-container');

  // Metric elements
  const elTotalRuns = document.getElementById('dash-total-runs');
  const elContained = document.getElementById('dash-contained');
  const elAvgLatency = document.getElementById('dash-avg-latency');
  const elDlpRedactions = document.getElementById('dash-dlp-redactions');
  const elChainStatus = document.getElementById('dash-chain-status');

  // Audit filter elements
  const filterType = document.getElementById('audit-filter-type');
  const filterSeverity = document.getElementById('audit-filter-severity');

  // Escape helper for safe DOM insertion
  const esc = (s) => String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

  // 1. Fetch & render capabilities
  async function loadCapabilities() {
    if (!capBanner) return;
    try {
      const res = await fetch('/api/v1/execute/capabilities');
      if (!res.ok) throw new Error('Failed to fetch capabilities');
      const data = await res.json();
      const caps = data.capabilities || {};
      const platform = data.platform || 'unknown';

      const items = [
        { label: 'Timeout Kill', val: caps.timeout, os: 'All' },
        { label: 'Output Limit', val: caps.outputLimit, os: 'All' },
        { label: 'DLP Redaction', val: caps.dlpRedaction, os: 'All' },
        { label: 'Non-Root Exec', val: caps.nonRootExec, os: 'Unix' },
        { label: 'Seccomp-BPF', val: caps.seccomp, os: 'Linux Only' },
        { label: 'cgroups v2', val: caps.cgroups, os: 'Linux Only' },
        { label: 'Namespaces', val: caps.namespaces, os: 'Linux Only' },
        { label: 'OverlayFS', val: caps.overlayfs, os: 'Linux Only' },
        { label: 'eBPF Egress', val: caps.ebpfEgress, os: 'Linux Only' },
      ];

      capBanner.innerHTML = `
        <div class="cap-header">
          <div class="cap-platform">
            <span class="pulse-dot"></span>
            <span>Host OS: <strong>${esc(platform.toUpperCase())}</strong></span>
          </div>
          <div class="cap-status-pill ${platform === 'linux' ? 'cap-full' : 'cap-partial'}">
            ${platform === 'linux' ? '✓ FULL KERNEL ENFORCEMENT' : '⚠️ PROCESS RLIMIT ENFORCEMENT (Darwin)'}
          </div>
        </div>
        <div class="cap-grid">
          ${items.map(it => `
            <div class="cap-item ${it.val ? 'cap-supported' : 'cap-unsupported'}">
              <span class="cap-icon">${it.val ? '✓' : '✗'}</span>
              <div class="cap-info">
                <span class="cap-name">${esc(it.label)}</span>
                <span class="cap-tag">${esc(it.os)}</span>
              </div>
            </div>
          `).join('')}
        </div>
        ${platform !== 'linux' ? `
          <div class="cap-notice">
            <strong>Platform Limitation Notice:</strong> Running on <code>${esc(platform)}</code>.
            cgroups v2, seccomp-bpf, OverlayFS, and network namespaces require a Linux kernel.
            Warden enforces timeouts via <code>SIGKILL</code>, memory ceilings via <code>RLIMIT_AS</code>,
            and filesystem/egress guards via Python userspace wrappers.
          </div>
        ` : ''}
      `;
    } catch (err) {
      capBanner.innerHTML = `<div class="cap-error">Failed to load platform capabilities: ${esc(err.message)}</div>`;
    }
  }

  // 2. Fetch & render Audit / Telemetry metrics
  async function refreshTelemetry() {
    try {
      const typeVal = filterType ? filterType.value : '';
      const sevVal = filterSeverity ? filterSeverity.value : '';

      let url = '/api/v1/audit?limit=50';
      if (typeVal) url += `&type=${encodeURIComponent(typeVal)}`;
      if (sevVal) url += `&severity=${encodeURIComponent(sevVal)}`;

      const res = await fetch(url);
      if (!res.ok) return;
      const data = await res.json();
      const entries = data.chainEntries || [];
      const chainStatus = data.chainStatus || {};

      // Compute metrics
      const total = entries.length;
      let contained = 0;
      let totalTime = 0;
      let dlpCount = 0;

      entries.forEach(e => {
        if (e.status === 'CONTAINED' || (e.violations && e.violations.length > 0)) contained++;
        if (typeof e.executionMs === 'number') totalTime += e.executionMs;
        if (e.dlpRedacted) dlpCount++;
      });

      const avgTime = total > 0 ? (totalTime / total).toFixed(1) + 'ms' : '0.0ms';

      if (elTotalRuns) elTotalRuns.textContent = total;
      if (elContained) elContained.textContent = contained;
      if (elAvgLatency) elAvgLatency.textContent = avgTime;
      if (elDlpRedactions) elDlpRedactions.textContent = dlpCount;
      if (elChainStatus) {
        elChainStatus.textContent = chainStatus.valid ? 'VERIFIED' : 'TAMPERED';
        elChainStatus.style.color = chainStatus.valid ? 'var(--green)' : 'var(--red)';
      }

      if (chainBadge) {
        chainBadge.innerHTML = chainStatus.valid
          ? `<span class="pulse-dot"></span> SHA-256 CHAIN INTACT (${chainStatus.length || 0})`
          : `<span class="pulse-dot red"></span> CHAIN BROKEN AT #${chainStatus.firstBrokenAt}`;
      }

      // Render 10-column table
      if (liveAuditBody) {
        if (entries.length === 0) {
          liveAuditBody.innerHTML = `<tr><td colspan="10" style="text-align:center; color:var(--text-dim); padding:20px;">No audit events match current filters. Execute code in the Playground or run the Red Team Suite.</td></tr>`;
        } else {
          liveAuditBody.innerHTML = entries.map(it => {
            const statusClass = it.status === 'CONTAINED' || it.status === 'FAIL_CLOSED'
              ? 'badge-danger'
              : (it.status === 'CLEAN' || it.status === 'VALID' || it.status === 'ACTIVATED' ? 'badge-success' : 'badge-warning');

            const reason = it.decisionReason || (it.violations && it.violations[0]?.evidence) || 'Normal processing';
            const runOrTarget = it.runId || it.policyName || '—';
            const execTime = it.executionMs !== null ? `${it.executionMs}ms` : '—';
            const exit = it.exitCode !== null ? it.exitCode : '—';

            return `
              <tr class="audit-row">
                <td class="audit-cell-dim">#${esc(it.seq)}</td>
                <td><code style="font-size:0.7rem; color:var(--accent);">${esc(it.eventType || 'EXECUTION')}</code></td>
                <td class="audit-cell-id" style="font-size:0.75rem;">${esc(runOrTarget)}</td>
                <td><span class="status-pill ${statusClass}">${esc(it.status)}</span></td>
                <td class="audit-cell-dim">${esc(exit)}</td>
                <td class="audit-cell-dim">${esc(execTime)}</td>
                <td>${it.dlpRedacted ? '<span class="text-green" style="font-size:0.72rem;">Redacted</span>' : '<span class="text-dim" style="font-size:0.72rem;">None</span>'}</td>
                <td style="max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:0.72rem; color:var(--text-muted);" title="${esc(reason)}">
                  ${it.observed ? '<span title="Direct kernel/wrapper observation" style="color:var(--accent); margin-right:4px;">👁️</span>' : '<span title="Inferred event" style="color:var(--text-dim); margin-right:4px;">◌</span>'}
                  ${esc(reason)}
                </td>
                <td class="audit-cell-mono" style="font-size:0.7rem;">${esc(it.chainHash)}</td>
                <td class="audit-cell-dim" style="font-size:0.7rem;">${new Date(it.timestamp).toLocaleTimeString()}</td>
              </tr>
            `;
          }).join('');
        }
      }
    } catch (_) {}
  }

  // Filter change events
  if (filterType) filterType.addEventListener('change', () => refreshTelemetry());
  if (filterSeverity) filterSeverity.addEventListener('change', () => refreshTelemetry());

  // 3. Benchmark Runner
  if (benchBtn) {
    benchBtn.addEventListener('click', async () => {
      benchBtn.disabled = true;
      if (benchBadge) benchBadge.innerHTML = `<span class="pulse-dot"></span> RUNNING BENCHMARKS...`;
      if (benchContainer) {
        benchContainer.innerHTML = `<div class="bench-running"><span class="spinner"></span> Running real Python isolation benchmarks (BM-01 to BM-08)...</div>`;
      }

      try {
        const res = await fetch('/api/v1/benchmark');
        if (!res.ok) throw new Error(`Benchmark runner returned HTTP ${res.status}`);
        const data = await res.json();
        renderBenchmarkResults(data);
        if (benchBadge) {
          const pass = data.summary?.pass ?? 0;
          const total = data.summary?.total ?? 0;
          benchBadge.innerHTML = `<span class="pulse-dot"></span> PASSED ${pass}/${total}`;
        }
        refreshTelemetry();
      } catch (err) {
        if (benchContainer) {
          benchContainer.innerHTML = `<div class="bench-error">Benchmark execution failed: ${esc(err.message)}</div>`;
        }
        if (benchBadge) benchBadge.innerHTML = `<span class="pulse-dot red"></span> ERROR`;
      } finally {
        benchBtn.disabled = false;
      }
    });
  }

  function renderBenchmarkResults(data) {
    if (!benchContainer) return;
    const results = data.results || [];
    const summary = data.summary || {};

    benchContainer.innerHTML = `
      <div class="bench-summary-bar">
        <div class="bench-stat"><label>Total:</label> <span>${summary.total || 0}</span></div>
        <div class="bench-stat"><label>Passed:</label> <span class="text-green">${summary.pass || 0}</span></div>
        <div class="bench-stat"><label>Failed:</label> <span class="text-red">${summary.fail || 0}</span></div>
        <div class="bench-stat"><label>Duration:</label> <span>${data.totalMs || 0}ms</span></div>
      </div>
      <div class="bench-cards-grid">
        ${results.map(r => `
          <div class="bench-card ${r.status.toLowerCase()}">
            <div class="bench-card-head">
              <span class="bench-id">${esc(r.id)}</span>
              <span class="bench-status-tag ${r.status === 'PASS' ? 'pass' : 'fail'}">${esc(r.status)}</span>
            </div>
            <h4 class="bench-title">${esc(r.name)}</h4>
            <p class="bench-desc">${esc(r.description)}</p>
            <div class="bench-evidence">
              <strong>Evidence:</strong> ${esc(r.evidence)}
            </div>
            ${r.platformNote ? `<div class="bench-platform-note">⚠️ ${esc(r.platformNote)}</div>` : ''}
            <div class="bench-meta">
              <span>Category: <em>${esc(r.category)}</em></span>
              <span>${esc(r.executionMs)}ms</span>
            </div>
          </div>
        `).join('')}
      </div>
    `;
  }

  // 3b. Red Team Attack Suite Runner
  if (redteamBtn) {
    redteamBtn.addEventListener('click', async () => {
      redteamBtn.disabled = true;
      if (redteamBadge) redteamBadge.innerHTML = `<span class="pulse-dot"></span> SIMULATING ATTACKS...`;
      if (redteamContainer) {
        redteamContainer.innerHTML = `<div class="bench-running"><span class="spinner"></span> Simulating 15 safe, controlled attacks across filesystem, network, privileges, resource ceilings, bypass escapes, and false-positive checks...</div>`;
      }

      try {
        const res = await fetch('/api/v1/redteam');
        if (!res.ok) throw new Error(`Red Team runner returned HTTP ${res.status}`);
        const data = await res.json();
        renderRedTeamResults(data);
        if (redteamBadge) {
          const pass = data.summary?.passed ?? 0;
          const total = data.summary?.total ?? 0;
          const score = data.summary?.defenseScore ?? 0;
          redteamBadge.innerHTML = `<span class="pulse-dot"></span> SCORE ${score}% (${pass}/${total} DEFENDED)`;
        }
        refreshTelemetry();
      } catch (err) {
        if (redteamContainer) {
          redteamContainer.innerHTML = `<div class="bench-error">Red Team attack simulation error: ${esc(err.message)}</div>`;
        }
        if (redteamBadge) redteamBadge.innerHTML = `<span class="pulse-dot red"></span> ERROR`;
      } finally {
        redteamBtn.disabled = false;
      }
    });
  }

  function renderRedTeamResults(data) {
    if (!redteamContainer) return;
    const scenarios = data.scenarios || [];
    const summary = data.summary || {};
    const vulns = data.vulnerabilities || [];

    redteamContainer.innerHTML = `
      <div class="redteam-summary-bar">
        <div class="rt-stat-card defense-score">
          <label>Defense Score</label>
          <div class="rt-score-num ${summary.defenseScore === 100 ? 'text-green' : (summary.defenseScore >= 80 ? 'text-amber' : 'text-red')}">${summary.defenseScore ?? 0}%</div>
        </div>
        <div class="rt-stat-card">
          <label>Scenarios Tested</label>
          <div class="rt-stat-val">${summary.total || 0}</div>
        </div>
        <div class="rt-stat-card">
          <label>Attacks Defended</label>
          <div class="rt-stat-val text-green">${summary.passed || 0}</div>
        </div>
        <div class="rt-stat-card">
          <label>Unverified Controls</label>
          <div class="rt-stat-val text-blue">${summary.unverified || 0}</div>
        </div>
        <div class="rt-stat-card">
          <label>Uncontained Breaches</label>
          <div class="rt-stat-val ${summary.failed > 0 ? 'text-red' : 'text-dim'}">${summary.failed || 0}</div>
        </div>
        <div class="rt-stat-card">
          <label>Execution Time</label>
          <div class="rt-stat-val">${data.totalDurationMs || 0}ms</div>
        </div>
      </div>

      ${vulns.length > 0 ? `
        <div class="rt-vuln-alert">
          <div class="rt-vuln-alert-head">
            <span class="pulse-dot red"></span>
            <strong>Active Vulnerabilities Identified (${vulns.length})</strong>
          </div>
          <div class="rt-vuln-list">
            ${vulns.map(v => `
              <div class="rt-vuln-item">
                <span class="sev-tag sev-${v.severity.toLowerCase()}">${esc(v.severity)}</span>
                <div>
                  <strong>${esc(v.title)} (${esc(v.id)})</strong>
                  <p class="rt-vuln-desc">${esc(v.evidence)}</p>
                  <p class="rt-vuln-remed"><strong>Remediation:</strong> ${esc(v.remediation)}</p>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      ` : `
        <div class="rt-secure-banner">
          <span>🛡️</span> Zero uncontained vulnerabilities detected across all tested scenarios. Tested on <strong>${esc((data.platform || 'host').toUpperCase())}</strong>.
        </div>
      `}

      <div class="rt-cards-grid">
        ${scenarios.map(s => {
          const statusClass = s.status === 'PASS' ? 'pass' : (s.status === 'FAIL' ? 'fail' : 'unverified');
          const sevClass = `sev-${(s.severity || 'low').toLowerCase()}`;
          return `
            <div class="rt-scenario-card ${statusClass}">
              <div class="rt-card-header">
                <div style="display:flex; align-items:center; gap:8px;">
                  <span class="rt-id">${esc(s.id)}</span>
                  <span class="sev-tag ${sevClass}">${esc(s.severity)}</span>
                  <span class="badge ${s.blocked ? 'bench-pass' : (s.status === 'PASS' ? 'bench-pass' : 'bench-fail')}" style="font-size:0.65rem;">
                    ${s.category === 'FALSE_POSITIVE_CHECK' ? (s.status === 'PASS' ? 'CLEAN (0 FP)' : 'FALSE POSITIVE') : (s.blocked ? 'BLOCKED' : 'NOT BLOCKED')}
                  </span>
                </div>
                <span class="bench-status-tag ${statusClass}">${esc(s.status)}</span>
              </div>
              <h4 class="rt-title">${esc(s.testName || s.name)}</h4>
              <p class="rt-vector"><strong>Vector:</strong> ${esc(s.vector)}</p>
              
              <div class="rt-comparison-box">
                <div class="rt-cmp-line">
                  <span class="rt-cmp-lbl">Expected:</span>
                  <span class="rt-cmp-val">${esc(s.expectedResult || s.expected)}</span>
                </div>
                <div class="rt-cmp-line">
                  <span class="rt-cmp-lbl">Actual:</span>
                  <span class="rt-cmp-val ${statusClass === 'pass' ? 'text-green' : (statusClass === 'unverified' ? 'text-blue' : 'text-red')}">${esc(s.actualResult || s.actual)}</span>
                </div>
              </div>

              <div class="bench-evidence" style="margin-top:6px;">
                <strong>Evidence:</strong> ${esc(s.evidence)}
              </div>

              <details class="rt-remediation-details">
                <summary>Remediation Guidance</summary>
                <div class="rt-remediation-body">
                  ${esc(s.remediation)}
                </div>
              </details>

              <div class="bench-meta" style="margin-top:8px;">
                <span>Category: <em>${esc(s.threatCategory || s.category)}</em></span>
                <span>Audit ID: <code>${esc(s.auditEventId || '—')}</code></span>
                <span>${esc(s.executionDuration || s.executionMs)}ms</span>
              </div>
            </div>
          `;
        }).join('')}
      </div>
    `;
  }

  // 4. Policy Manifest Loader
  if (manifestBtn) {
    manifestBtn.addEventListener('click', async () => {
      manifestBtn.disabled = true;
      try {
        const res = await fetch('/api/v1/execute/policy-manifest');
        if (!res.ok) throw new Error('Failed to load policy manifest');
        const data = await res.json();
        renderManifest(data);
      } catch (err) {
        if (manifestContainer) {
          manifestContainer.innerHTML = `<div class="cap-error">Failed: ${esc(err.message)}</div>`;
        }
      } finally {
        manifestBtn.disabled = false;
      }
    });
  }

  function renderManifest(data) {
    if (!manifestContainer) return;
    const enforcements = data.enforcements || [];
    const summary = data.summary || {};

    manifestContainer.innerHTML = `
      <div class="manifest-summary-bar">
        <span>Active Policy: <strong>${esc(data.policyName)}</strong> (Platform: ${esc(data.platform)})</span>
        <div class="manifest-counts">
          <span class="tag-enforced">ENFORCED: ${summary.enforced || 0}</span>
          <span class="tag-unverified">UNVERIFIED: ${summary.unverified || 0}</span>
          <span class="tag-unsupported">UNSUPPORTED: ${summary.unsupported || 0}</span>
        </div>
      </div>
      <div class="manifest-table-wrapper">
        <table class="manifest-table">
          <thead>
            <tr>
              <th>Mechanism</th>
              <th>Status</th>
              <th>Target Restriction</th>
              <th>Evidence & Platform Boundary</th>
            </tr>
          </thead>
          <tbody>
            ${enforcements.map(e => `
              <tr class="manifest-row status-${e.status.toLowerCase()}">
                <td><strong>${esc(e.mechanism)}</strong></td>
                <td><span class="manifest-pill status-${e.status.toLowerCase()}">${esc(e.status)}</span></td>
                <td><code>${esc(e.limitValue || '—')}</code></td>
                <td>
                  <div>${esc(e.evidence)}</div>
                  ${e.note ? `<div class="manifest-note">ℹ️ ${esc(e.note)}</div>` : ''}
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  // 5. Refresh button
  if (auditRefreshBtn) {
    auditRefreshBtn.addEventListener('click', () => {
      refreshTelemetry();
    });
  }

  // Listen for execution and policy activation events
  window.addEventListener('warden:execution', () => {
    refreshTelemetry();
  });

  window.addEventListener('warden:policy-activated', () => {
    refreshTelemetry();
    if (manifestBtn) manifestBtn.click();
  });

  // Initial load
  loadCapabilities();
  refreshTelemetry();
}
