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
    this.tableBodyEl.innerHTML = this.history.map(item => `
      <tr class="audit-row">
        <td class="audit-cell audit-cell-id">${item.runId}</td>
        <td class="audit-cell audit-cell-threat">${item.threat}</td>
        <td class="audit-cell"><span class="audit-action-badge">${item.action}</span></td>
        <td class="audit-cell audit-cell-dlp">${item.dlp}</td>
        <td class="audit-cell audit-cell-dim">${item.latency}</td>
        <td class="audit-cell audit-cell-dim">${item.timestamp}</td>
      </tr>
    `).join("");
  }
}
