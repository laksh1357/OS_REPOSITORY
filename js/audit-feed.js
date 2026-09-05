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
      <tr style="border-bottom:1px solid rgba(255,255,255,0.03); transition:var(--transition-fast);">
        <td style="padding:10px; color:var(--green); font-weight:600;">${item.runId}</td>
        <td style="padding:10px; color:var(--text);">${item.threat}</td>
        <td style="padding:10px;"><span style="background:rgba(255,197,107,0.15); color:var(--amber); padding:2px 6px; border-radius:4px; font-size:0.7rem;">${item.action}</span></td>
        <td style="padding:10px; color:var(--green);">${item.dlp}</td>
        <td style="padding:10px; color:var(--text-dim);">${item.latency}</td>
        <td style="padding:10px; color:var(--text-dim);">${item.timestamp}</td>
      </tr>
    `).join("");
  }
}
