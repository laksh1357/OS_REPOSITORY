/* Warden Interactive 5-Layer Architecture Inspector */

export const LAYER_DETAILS = {
  5: {
    num: "01",
    title: "Syscall Filtering (Seccomp-BPF)",
    tech: "seccomp-bpf / kernel filter",
    desc: "Hooks kernel syscall dispatch vector. Uses BPF bytecode to filter all system calls against an explicit allowlist. Disallowed syscalls (e.g. ptrace, reboot, bpf, init_module) trigger immediate SIGSYS process termination before entering kernel handler routines.",
    specs: ["Default Action: SECCOMP_RET_ERRNO", "Profile: python-minimal", "Syscall Audit Log: Enabled"]
  },
  4: {
    num: "02",
    title: "Namespace Isolation",
    tech: "Linux Namespaces (PID, NET, MNT, IPC, USER)",
    desc: "Constructs virtualized OS environments. PID namespace hides host process tree; NET namespace provides loopback-only stack; MNT namespace creates clean VFS root; USER namespace maps container root to unprivileged host UID.",
    specs: ["PID Tree: Virtualized (PID 1)", "NetStack: Isolated Loopback", "User Mapping: UID 10001 -> 0"]
  },
  3: {
    num: "03",
    title: "Resource Ceilings (cgroups v2)",
    tech: "cgroups v2 unified hierarchy",
    desc: "Enforces deterministic resource boundaries via kernel cgroup controllers (`memory.max`, `cpu.max`, `pids.max`). Prevents memory exhaustion attacks, CPU starvation, and fork-bomb process multiplication.",
    specs: ["Memory High/Max: 256 MiB", "CPU Quota: 50,000 / 100,000 us", "PIDs Max: 8 processes"]
  },
  2: {
    num: "04",
    title: "Ephemeral Filesystem (OverlayFS)",
    tech: "OverlayFS / Read-Only VFS",
    desc: "Mounts base container filesystem image as read-only. All file writes, modifications, and temporary artifacts are redirected to an ephemeral in-memory upperdir scratchpad, which is completely erased on container exit.",
    specs: ["Base Mount: Read-Only Root", "Scratch Space: /tmp (tmpfs overlay)", "Persistence: 0 Bytes"]
  },
  1: {
    num: "05",
    title: "Network Egress Policy",
    tech: "eBPF TC Egress Filter",
    desc: "Intercepts all outgoing SKB packets at kernel network interface layer. Compares destination IP/domain against active policy allowlist. Non-matching egress packets are dropped at socket layer without DNS leakage.",
    specs: ["Default Egress: DENY ALL", "Allowlist: pypi.org, openai.com", "DNS Leak Protection: Enforced"]
  }
};

export class ArchVisualizer {
  constructor(svgElement, layerListElement, infoBoxElement) {
    this.svg = svgElement;
    this.listEl = layerListElement;
    this.infoEl = infoBoxElement;
    this.currentLayer = 5;
  }

  init() {
    this.renderSVG();
    this.bindEvents();
    this.selectLayer(5);
  }

  renderSVG() {
    this.svg.innerHTML = `
      <svg viewBox="0 0 520 430" role="img" aria-label="Warden 5-Layer Security Isolation Architecture">
        <defs>
          <linearGradient id="layerGlow" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stop-color="rgba(103,246,161,0.15)"/>
            <stop offset="100%" stop-color="rgba(110,182,255,0.05)"/>
          </linearGradient>
          <filter id="neonShadow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="6" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        <!-- HOST KERNEL BASE LAYER -->
        <rect class="svg-layer-box" data-layer="0" x="15" y="15" width="490" height="400" rx="14" fill="rgba(255,255,255,0.01)" stroke="#23303d" stroke-width="1.5"/>
        <text class="svg-layer-label" x="32" y="42" fill="#546272" font-family="JetBrains Mono" font-size="10" font-weight="600">UNTRUSTED HOST OPERATING SYSTEM & KERNEL</text>

        <!-- LAYER 05 - NETWORK EGRESS -->
        <rect class="svg-layer-box clickable" data-layer="1" x="48" y="60" width="424" height="335" rx="12" fill="rgba(110,182,255,0.015)" stroke="#2c3a4a" stroke-width="1.5"/>
        <text class="svg-layer-label" x="65" y="85" fill="#8896a6" font-family="JetBrains Mono" font-size="10" font-weight="600">05 · NETWORK EGRESS POLICY (eBPF DENY-DEFAULT)</text>

        <!-- LAYER 04 - EPHEMERAL FS -->
        <rect class="svg-layer-box clickable" data-layer="2" x="82" y="105" width="356" height="265" rx="10" fill="rgba(255,255,255,0.01)" stroke="#2c3a4a" stroke-width="1.5"/>
        <text class="svg-layer-label" x="99" y="130" fill="#8896a6" font-family="JetBrains Mono" font-size="10" font-weight="600">04 · EPHEMERAL FILESYSTEM (READ-ONLY OVERLAYFS)</text>

        <!-- LAYER 03 - RESOURCE CEILINGS -->
        <rect class="svg-layer-box clickable" data-layer="3" x="116" y="150" width="288" height="195" rx="9" fill="rgba(255,255,255,0.01)" stroke="#2c3a4a" stroke-width="1.5"/>
        <text class="svg-layer-label" x="133" y="175" fill="#8896a6" font-family="JetBrains Mono" font-size="10" font-weight="600">03 · RESOURCE CEILINGS (CGROUPS V2)</text>

        <!-- LAYER 02 - NAMESPACES -->
        <rect class="svg-layer-box clickable" data-layer="4" x="150" y="195" width="220" height="125" rx="8" fill="rgba(255,255,255,0.01)" stroke="#2c3a4a" stroke-width="1.5"/>
        <text class="svg-layer-label" x="167" y="220" fill="#8896a6" font-family="JetBrains Mono" font-size="10" font-weight="600">02 · NAMESPACES (PID/NET/USER)</text>

        <!-- LAYER 01 - SECCOMP (INNERMOST CORE) -->
        <rect class="svg-layer-box clickable active" data-layer="5" x="184" y="240" width="152" height="60" rx="7" fill="rgba(103,246,161,0.08)" stroke="#67f6a1" stroke-width="2" filter="url(#neonShadow)"/>
        <text class="svg-layer-label core-text" data-layer="5" x="260" y="275" fill="#67f6a1" font-family="Space Grotesk" font-size="11" font-weight="700" text-anchor="middle">01 · SECCOMP-BPF</text>
      </svg>
    `;
  }

  bindEvents() {
    this.listEl.querySelectorAll(".layer-card").forEach(card => {
      const layerNum = parseInt(card.dataset.layer);
      card.addEventListener("click", () => this.selectLayer(layerNum));
      card.addEventListener("mouseenter", () => this.highlightSVG(layerNum));
    });

    this.svg.querySelectorAll(".svg-layer-box.clickable").forEach(box => {
      const layerNum = parseInt(box.dataset.layer);
      box.addEventListener("click", () => this.selectLayer(layerNum));
      box.addEventListener("mouseenter", () => this.highlightSVG(layerNum));
    });
  }

  selectLayer(layerNum) {
    this.currentLayer = layerNum;
    const info = LAYER_DETAILS[layerNum];

    // Update list UI
    this.listEl.querySelectorAll(".layer-card").forEach(c => {
      c.classList.toggle("active", parseInt(c.dataset.layer) === layerNum);
    });

    // Update SVG UI
    this.highlightSVG(layerNum);

    // Update Detail Info Box
    if (this.infoEl) {
      this.infoEl.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
          <span style="font-family:var(--font-mono); font-size:0.75rem; color:var(--green); font-weight:700;">LAYER ${info.num}</span>
          <span class="layer-tech-badge">${info.tech}</span>
        </div>
        <h3 style="font-size:1.2rem; color:#fff; margin-bottom:10px;">${info.title}</h3>
        <p style="font-size:0.88rem; color:var(--text-muted); line-height:1.6; margin-bottom:16px;">${info.desc}</p>
        <div style="background:rgba(255,255,255,0.02); border:1px solid var(--panel-border); border-radius:var(--radius-s); padding:12px;">
          <div style="font-family:var(--font-mono); font-size:0.7rem; color:var(--text-dim); text-transform:uppercase; margin-bottom:6px;">Enforcement Specs:</div>
          ${info.specs.map(s => `<div style="font-family:var(--font-mono); font-size:0.76rem; color:var(--green); margin-top:4px;">✓ ${s}</div>`).join("")}
        </div>
      `;
    }
  }

  highlightSVG(layerNum) {
    this.svg.querySelectorAll(".svg-layer-box").forEach(box => {
      const num = parseInt(box.dataset.layer);
      if (num === layerNum) {
        box.setAttribute("stroke", "var(--green)");
        box.setAttribute("stroke-width", "2");
        box.setAttribute("fill", "rgba(103, 246, 161, 0.06)");
      } else if (num > 0) {
        box.setAttribute("stroke", "#2c3a4a");
        box.setAttribute("stroke-width", "1.5");
        box.setAttribute("fill", "rgba(255, 255, 255, 0.01)");
      }
    });
  }
}
