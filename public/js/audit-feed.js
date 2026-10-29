/* Warden Real-Time Audit Log Stream Component */

export class AuditFeed {
  constructor(tableBodyElement) {
    this.tableBodyEl = tableBodyElement;
    this.history = [
      {
        runId: "run_8f3a9e1c",
        threat: "Filesystem Secret Theft (/etc/passwd)",
        action: "OVERLAY_FS_BLOCK (SIGSYS)",
        dlp: "0 Bytes Leaked (Sanitized)",
        latency: "3.8ms",
        timestamp: "Just now"
      },
      {
        runId: "run_7f2a1c44",
        threat: "Outbound C2 Socket (203.0.113.88)",
        action: "EGRESS_DENY (eBPF Drop)",
        dlp: "0 Bytes Leaked (Blocked)",
        latency: "4.1ms",
        timestamp: "2 mins ago"
      }
    ];
  }

  init() {
    this.render();
  }

  addEntry(entry) {
    this.history.unshift(entry);
    if (this.history.length > 10) this.history.pop();
    this.render();
  }

  render() {
    if (!this.tableBodyEl) return;
    // Helper to escape HTML and prevent XSS from injected audit data
    const esc = (str) => String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
    this.tableBodyEl.innerHTML = this.history.map(item => `
      <tr class="audit-row">
        <td class="audit-cell audit-cell-id">${esc(item.runId)}</td>
        <td class="audit-cell audit-cell-threat">${esc(item.threat)}</td>
        <td class="audit-cell"><span class="audit-action-badge">${esc(item.action)}</span></td>
        <td class="audit-cell audit-cell-dlp">${esc(item.dlp)}</td>
        <td class="audit-cell audit-cell-dim">${esc(item.latency)}</td>
        <td class="audit-cell audit-cell-dim">${esc(item.timestamp)}</td>
      </tr>
    `).join("");
  }
}
