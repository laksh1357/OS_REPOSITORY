/* Warden Attack Matrix & Security Comparison */

export const ATTACK_SCENARIOS = [
  {
    id: "fs-escape",
    tag: "01 · FS ESCAPE",
    title: "Filesystem & Secret Theft",
    vector: "Code attempts `open('/etc/passwd')` or reads `~/.aws/credentials` or dotfiles.",
    bareHost: "CRITICAL COMPROMISE. Stolen API keys, AWS tokens, or environment credentials exfiltrated.",
    warden: "CONTAINED. Read attempts outside `/tmp` return EACCES or trigger instant SIGSYS process termination."
  },
  {
    id: "net-malware",
    tag: "02 · NET MALWARE",
    title: "Unrestricted Outbound C2 Channel",
    vector: "Script opens TCP socket to arbitrary IP (`203.0.113.88:4444`) to establish reverse shell.",
    bareHost: "FULL ESCAPE. Attacker receives active root/user shell with direct host network privileges.",
    warden: "CONTAINED. Default-deny eBPF egress drops connection at socket layer. 0 packets leave container."
  },
  {
    id: "proc-forkbomb",
    tag: "03 · PROC BOMB",
    title: "Fork Bomb Resource Exhaustion",
    vector: "Infinite loop executing `os.fork()` to saturate system process table and exhaust RAM.",
    bareHost: "SYSTEM CRASH. Host becomes completely unresponsive, requiring hard hardware reboot.",
    warden: "CONTAINED. Hard cgroup ceiling (`max_pids=8`) stops process creation. Host CPU/RAM unaffected."
  },
  {
    id: "syscall-priv",
    tag: "04 · SYSCALL INJ",
    title: "Kernel PrivEsc & Module Injection",
    vector: "Snippet attempts `init_module()`, `bpf()`, or `ptrace()` to hijack kernel memory.",
    bareHost: "ROOT TAKEOVER. Kernel memory overwritten, granting persistent root privilege escalation.",
    warden: "CONTAINED. Seccomp-BPF filter traps prohibited syscall at ring 0, terminating process instantly."
  }
];

export function renderAttackMatrix(containerElement) {
  if (!containerElement) return;

  containerElement.innerHTML = ATTACK_SCENARIOS.map(sc => `
    <div class="attack-card">
      <div class="attack-header">
        <div class="attack-title">
          <span style="color:var(--green); font-family:var(--font-mono); font-weight:700;">🛡️</span>
          <h3>${sc.title}</h3>
        </div>
        <span class="attack-tag">${sc.tag}</span>
      </div>
      <p style="font-size:0.85rem; color:var(--text-muted); margin-bottom:14px;"><strong>Attack Vector:</strong> ${sc.vector}</p>

      <div class="attack-comparison">
        <div class="comparison-box bare-host">
          <label>Bare Host / Docker Default</label>
          <p style="color:var(--red); font-size:0.78rem;">${sc.bareHost}</p>
        </div>
        <div class="comparison-box warden">
          <label>Warden OS Sandbox</label>
          <p style="color:var(--green); font-size:0.78rem;">${sc.warden}</p>
        </div>
      </div>
    </div>
  `).join("");
}
