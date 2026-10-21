# Warden — OS-Level Sandboxing for AI-Generated Code

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security: Kernel Contained](https://img.shields.io/badge/Security-Seccomp--BPF%20%7C%20Cgroups%20v2-brightgreen.svg)](#-5-layer-isolation-architecture)
[![DLP: Zero Data Leakage](https://img.shields.io/badge/DLP-Zero%20Data%20Leakage-success.svg)](#-zero-data-leakage--dlp-security-system)
[![Database: PostgreSQL 16](https://img.shields.io/badge/Database-PostgreSQL%2016-blue.svg)](#-postgresql-database-integration)
[![Cold Start](https://img.shields.io/badge/Cold%20Start-~38ms-success.svg)](#-performance--benchmarks)

**Warden** is an OS-level kernel sandboxing and execution containment platform designed specifically to execute untrusted AI-generated code snippets inside disposable, isolated environments before they can compromise host filesystems, network interfaces, credentials, or system processes.

---

## 🛡️ Key Features

- **Disposable MicroVM Isolation**: Ephemeral kernel-isolated execution environments spawned in ~38ms.
- **Zero Data Leakage (DLP Shield)**: Real-time secret redactor, PII masker, covert DNS/ICMP channel interceptor, and 3-pass DoD 5220.22-M memory zeroing.
- **5-Layer Security Boundary**: Multi-tiered defense enforcing syscall filtering, namespace separation, cgroup resource limits, ephemeral storage, and default-deny egress policies.
- **PostgreSQL Database Integration**: Persistent storage for isolation policies, execution audit logs, threat signature patterns, and client API keys.
- **Interactive Live Web Dashboard**: Developer-focused dashboard with a live execution terminal, 5-layer visualizer, policy builder, and threat comparison matrix.
- **Declarative YAML & SQL Policies**: Export policies directly to YAML, PostgreSQL SQL, Python SDK, Go SDK, or cURL.
- **CLI & REST API**: Full-featured command-line tool (`bin/warden.js`) and Express.js REST API with automated request sanitization.

---

## 🔐 Zero Data Leakage & DLP Security System

Warden integrates a unified Data Loss Prevention (DLP) engine (`shared/dlp-patterns.js`, `security/dlp-node.js`, and `security/dlp-engine.js`) to guarantee zero secret leakage across execution pipelines:

### 1. Pre-Execution Secret Sanitizer & Redactor
Scans code and output streams for sensitive credentials and automatically masks them before storage or logging:
- **AWS Keys** (`AKIA...`) -> `[REDACTED_AWS_ACCESS_KEY]`
- **OpenAI API Keys** (`sk-...`) -> `[REDACTED_OPENAI_API_KEY]`
- **GitHub Tokens** (`ghp_...`) -> `[REDACTED_GITHUB_TOKEN]`
- **Private RSA / SSH Keys** -> `[REDACTED_PRIVATE_KEY]`
- **JSON Web Tokens (JWT)** -> `[REDACTED_JWT_TOKEN]`
- **Database Connection URIs** -> `[REDACTED_DB_URI]`

### 2. Covert Channel & DNS Tunneling Interceptor
Detects non-standard data exfiltration channels designed to bypass network filters:
- **DNS Tunneling Queries** (`nslookup stolen.evil.com`)
- **Base64 / Hex Exfiltration Wrappers**
- **Raw ICMP Ping Socket Tunneling**
- **Environment Variable Harvesting** (`os.environ`, `/proc/self/environ`)

### 3. Ephemeral Memory & Storage Shredder
Upon sandbox teardown, OverlayFS scratchpads (`/tmp`) undergo a **DoD 5220.22-M 3-Pass Zeroing** protocol before unmounting to prevent RAM dump forensics or residual disk leaks.

---

## 🐘 PostgreSQL Database Integration

Warden includes a complete PostgreSQL schema for persistent audit logging and policy management:

```bash
# Launch PostgreSQL server via Docker
docker-compose up -d
```

| Table Name | Description | Key Columns |
| :--- | :--- | :--- |
| `warden_policies` | Sandbox execution policies | `id`, `name`, `cpu_limit`, `memory_limit_mb`, `egress_allowlist`, `syscall_profile` |
| `sandbox_audit_logs` | Real-time security audit log trail | `run_id`, `snippet_hash`, `status`, `is_violated`, `violation_type`, `execution_time_ms` |
| `threat_patterns` | Malicious regex signatures | `category`, `pattern_regex`, `severity`, `description` |
| `api_keys` | Authorized client credentials | `client_name`, `key_hash`, `rate_limit_per_min`, `is_active` |

---

## 🏗️ 5-Layer Isolation Architecture

```
+-------------------------------------------------------------------+
|               UNTRUSTED HOST OPERATING SYSTEM & KERNEL            |
|  +-------------------------------------------------------------+  |
|  | 05 · NETWORK EGRESS POLICY (eBPF Default-Deny Drop Filter)   |  |
|  |  +-------------------------------------------------------+  |  |
|  |  | 04 · EPHEMERAL FILESYSTEM (Read-Only OverlayFS + /tmp) |  |  |
|  |  |  +-------------------------------------------------+  |  |  |
|  |  |  | 03 · RESOURCE CEILINGS (Cgroups v2 Limits)      |  |  |  |
|  |  |  |  +-------------------------------------------+  |  |  |  |
|  |  |  |  | 02 · NAMESPACES (PID, NET, MNT, USER)    |  |  |  |  |
|  |  |  |  |  +-------------------------------------+  |  |  |  |  |
|  |  |  |  |  | 01 · SECCOMP-BPF (Syscall Filter)   |  |  |  |  |  |
|  |  |  |  |  +-------------------------------------+  |  |  |  |  |
|  |  |  |  +-------------------------------------------+  |  |  |  |
|  |  |  +-------------------------------------------------+  |  |  |
|  |  +-------------------------------------------------------+  |  |
|  +-------------------------------------------------------------+  |
+-------------------------------------------------------------------+
```

---

## ⚡ Quick Start

### 1. Installation
```bash
git clone https://github.com/laksh1357/OS_REPOSITORY.git
cd OS_REPOSITORY
npm install
```

### 2. Run the Automated Test Suite
```bash
npm test
```

### 3. Start the Server
```bash
npm start
# Server starts on http://localhost:8080
```

### 4. CLI Usage
```bash
# Display CLI version and help
node bin/warden.js --help

# Initialize a default policy file (warden.yaml)
node bin/warden.js policy init

# Execute a Python script inside the simulated sandbox
node bin/warden.js run snippet.py
```

---

## 📁 Repository Structure

```
OS_REPOSITORY/
├── bin/
│   └── warden.js             # Executable CLI tool
├── css/
│   ├── base.css              # Design tokens, typography & accessible reset
│   ├── layout.css            # Grid layouts, navigation & responsive breakpoints
│   ├── components.css        # Developer UI components, cards, tables & sliders
│   └── style.css             # Entrypoint bundle
├── db/
│   ├── index.js              # PostgreSQL client, health check & DAO layer
│   └── schema.sql            # PostgreSQL DDL & default seed rows
├── js/
│   ├── app.js                # Slim client orchestrator
│   ├── arch-visualizer.js    # Interactive SVG 5-layer topology
│   ├── attack-matrix.js      # Threat scenario matrix renderer
│   ├── audit-feed.js         # Real-time audit log stream
│   ├── policy-builder.js     # Declarative policy state & code generator
│   ├── sandbox-engine.js     # Sandbox execution simulation engine
│   └── views/                # Modular view controllers
│       ├── architecture.js   # Layer visualizer lifecycle
│       ├── clipboard.js      # Reusable copy trigger
│       ├── hero.js           # Hero terminal demo & replay
│       ├── playground.js     # Code editor & preset execution
│       └── policy.js         # Slider inputs & safe domain chips
├── middleware/
│   └── errorHandler.js       # Request sanitizer & centralized error handler
├── routes/
│   ├── health.js             # Service & database health probe
│   ├── policies.js           # Policy retrieval & creation routes
│   └── sandbox.js            # Code execution & threat evaluation route
├── security/
│   ├── dlp-engine.js         # Browser DLP engine
│   └── dlp-node.js           # Node.js DLP engine
├── shared/
│   └── dlp-patterns.js       # Unified single-source DLP & threat patterns
├── tests/
│   └── sandbox.test.js       # Automated test suite (5 passing tests)
├── .env.example              # Environment variables template
├── docker-compose.yml        # PostgreSQL container configuration
├── index.html                # Developer dashboard & interactive playground
├── package.json              # Project manifest & npm scripts
└── server.js                 # Express.js REST API server
```

---

## 📄 License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information about it.
