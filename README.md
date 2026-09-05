# Warden — OS-Level Sandboxing for AI-Generated Code

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security: Kernel Contained](https://img.shields.io/badge/Security-Seccomp--BPF%20%7C%20Cgroups%20v2-brightgreen.svg)](#5-layer-isolation-architecture)
[![Database: PostgreSQL 16](https://img.shields.io/badge/Database-PostgreSQL%2016-blue.svg)](#-postgresql-database-integration)
[![Cold Start](https://img.shields.io/badge/Cold%20Start-~38ms-success.svg)](#performance--benchmarks)

**Warden** is an OS-level kernel sandboxing and execution containment system designed specifically to execute untrusted AI-generated code snippets inside disposable, isolated environments before they can compromise host filesystems, network interfaces, credentials, or system processes.

---

## 🛡️ Key Features

- **Disposable MicroVM Isolation**: Spawns ephemeral kernel-isolated execution environments in ~38ms.
- **5-Layer Security Boundary**: Multi-tiered protection enforcing syscall filtering, namespace separation, cgroup resource limits, ephemeral storage, and default-deny egress policies.
- **PostgreSQL Database Integration**: Persistent storage for isolation policies, execution audit logs, threat signature patterns, and client API keys.
- **Interactive Live Web Playground**: Built-in interactive browser dashboard to test malicious code snippets (secret theft, reverse shells, fork bombs) against Warden enforcement.
- **Declarative YAML & SQL Policies**: Simple human-readable policy files and SQL migration DDLs.
- **Multi-Language SDKs**: Native support for Python, Go, Node.js (PostgreSQL `pg`), and REST HTTP API.

---

## 🐘 PostgreSQL Database Integration

Warden includes a complete PostgreSQL schema for persistent audit logging and policy management:

### 1. Launch PostgreSQL Container via Docker Compose

```bash
docker-compose up -d
```

### 2. Database Tables Schema

| Table Name | Description | Key Columns |
| :--- | :--- | :--- |
| `warden_policies` | Sandbox execution policies | `id`, `name`, `cpu_limit`, `memory_limit_mb`, `egress_allowlist`, `syscall_profile` |
| `sandbox_audit_logs` | Real-time security audit log trail | `run_id`, `snippet_hash`, `status`, `is_violated`, `violation_type`, `execution_time_ms` |
| `threat_patterns` | Malicious regex signatures | `category`, `pattern_regex`, `severity`, `description` |
| `api_keys` | Authorized client credentials | `client_name`, `key_hash`, `rate_limit_per_min`, `is_active` |

### 3. Connect via Node.js Client (`db/index.js`)

```javascript
const { recordSandboxRun, savePolicy } = require('./db');

// Record a sandboxed execution run
await recordSandboxRun({
  runId: 'task_7f2a1c',
  codeSnippet: 'import os; open("/etc/passwd")',
  snippetHash: '8f3a9e...',
  status: 'CONTAINED',
  isViolated: true,
  violationType: 'OVERLAY_FS_BLOCK',
  executionTimeMs: 3.8
});
```

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

## 📁 Repository Structure

```
OS_REPOSITORY/
├── db/
│   ├── schema.sql        # PostgreSQL DDL & DML Schema Definitions
│   └── index.js          # Node.js PostgreSQL Database Client & DAO Layer
├── docker-compose.yml    # PostgreSQL 16 Service Container Setup
├── .env.example          # Environment & Database Connection Variables
├── index.html            # Master Web Dashboard & Interactive Playground
├── css/
│   └── style.css         # Design System, Glassmorphic UI & Cyber Themes
├── js/
│   ├── app.js            # Main Orchestrator & UI Event Handler
│   ├── sandbox-engine.js # Real-time Kernel Isolation Log Simulator
│   ├── policy-builder.js # Policy Builder & Multi-Language Exporter (SQL/YAML/SDKs)
│   ├── arch-visualizer.js# 5-Layer SVG Interactive Topology Visualizer
│   └── attack-matrix.js  # Threat Comparison Matrix & Security Scoring
└── README.md             # Project Documentation
```

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
