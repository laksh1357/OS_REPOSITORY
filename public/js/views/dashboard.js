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

  // Metric elements
  const elTotalRuns = document.getElementById('dash-total-runs');
  const elContained = document.getElementById('dash-contained');
  const elAvgLatency = document.getElementById('dash-avg-latency');
  const elDlpRedactions = document.getElementById('dash-dlp-redactions');
  const elChainStatus = document.getElementById('dash-chain-status');

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
          <span class="cap-legend">
            <span class="tag-enforced">● Enforced</span>
            <span class="tag-unsupported">○ Platform Unsupported</span>
          </span>
        </div>
        <div class="cap-grid">
          ${items.map(it => `
            <div class="cap-chip ${it.val ? 'active' : 'inactive'}">
              <span class="cap-indicator">${it.val ? '✓' : '✗'}</span>
              <span class="cap-name">${esc(it.label)}</span>
              <span class="cap-scope">${esc(it.os)}</span>
            </div>
          `).join('')}
        </div>
      `;
    } catch (err) {
      capBanner.innerHTML = `<div class="cap-error">Unable to query host capabilities: ${esc(err.message)}</div>`;
    }
  }

  // 2. Fetch & render Audit / Telemetry metrics
  async function refreshTelemetry() {
    try {
      const res = await fetch('/api/v1/audit?limit=25');
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

      // Render table
      if (liveAuditBody) {
        if (entries.length === 0) {
          liveAuditBody.innerHTML = `<tr><td colspan="9" style="text-align:center; color:var(--text-dim); padding:20px;">No executions logged yet. Execute code in the Playground or run the Benchmark Suite.</td></tr>`;
        } else {
          liveAuditBody.innerHTML = entries.map(it => {
            const statusClass = it.status === 'CONTAINED' ? 'badge-danger' : it.status === 'CLEAN' ? 'badge-success' : 'badge-warning';
            return `
              <tr class="audit-row">
                <td class="audit-cell-dim">#${esc(it.seq)}</td>
                <td class="audit-cell-id">${esc(it.runId)}</td>
                <td><span class="status-pill ${statusClass}">${esc(it.status)}</span></td>
                <td class="audit-cell-dim">${esc(it.exitCode)}</td>
                <td class="audit-cell-dim">${esc(it.executionMs)}ms</td>
                <td>${it.dlpRedacted ? '<span class="text-green">Redacted</span>' : '<span class="text-dim">None</span>'}</td>
                <td><span class="violation-count">${(it.violations || []).length}</span></td>
                <td class="audit-cell-mono">${esc(it.chainHash)}</td>
                <td class="audit-cell-dim">${new Date(it.timestamp).toLocaleTimeString()}</td>
              </tr>
            `;
          }).join('');
        }
      }
    } catch (_) {}
  }

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
        <span>Evaluated: <strong>${esc(data.policyName)}</strong> (${esc(data.platform)})</span>
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

  // Listen for execution events
  window.addEventListener('warden:execution', () => {
    refreshTelemetry();
  });

  // Initial load
  loadCapabilities();
  refreshTelemetry();
}
