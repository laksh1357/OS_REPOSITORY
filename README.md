# Warden — OS-Level Sandboxing for AI-Generated Code

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security: Kernel Contained](https://img.shields.io/badge/Security-Seccomp--BPF%20%7C%20Cgroups%20v2-brightgreen.svg)](#5-layer-isolation-architecture)
[![DLP: Zero Data Leakage](https://img.shields.io/badge/DLP-Zero%20Data%20Leakage-success.svg)](#-zero-data-leakage--dlp-security-system)
[![Database: PostgreSQL 16](https://img.shields.io/badge/Database-PostgreSQL%2016-blue.svg)](#-postgresql-database-integration)
[![Cold Start](https://img.shields.io/badge/Cold%20Start-~38ms-success.svg)](#performance--benchmarks)

**Warden** is an OS-level kernel sandboxing and execution containment system designed specifically to execute untrusted AI-generated code snippets inside disposable, isolated environments before they can compromise host filesystems, network interfaces, credentials, or system processes.

---

## 🛡️ Key Features

- **Disposable MicroVM Isolation**: Spawns ephemeral kernel-isolated execution environments in ~38ms.
- **Zero Data Leakage (DLP Shield)**: Real-time secret redactor, PII masker, covert DNS/ICMP channel interceptor, and 3-pass DoD 5220.22-M memory zeroing.
- **5-Layer Security Boundary**: Multi-tiered protection enforcing syscall filtering, namespace separation, cgroup resource limits, ephemeral storage, and default-deny egress policies.
- **PostgreSQL Database Integration**: Persistent storage for isolation policies, execution audit logs, threat signature patterns, and client API keys.
- **Interactive Live Web Playground**: Built-in interactive browser dashboard to test malicious code snippets (secret theft, reverse shells, fork bombs) against Warden enforcement.
- **Declarative YAML & SQL Policies**: Simple human-readable policy files and SQL migration DDLs.
- **Multi-Language SDKs**: Native support for Python, Go, Node.js (PostgreSQL `pg`), and REST HTTP API.

---

## 🔐 Zero Data Leakage & DLP Security System

Warden integrates a multi-layer Data Loss Prevention (DLP) engine (`security/dlp-engine.js` & `security/dlp-node.js`) to guarantee zero secret leakage across execution pipelines:

### 1. Pre-Execution Secret Sanitizer & Redactor
Scans code and output streams for sensitive credentials and automatically masks them before storage or logging:
- **AWS Keys** (`AKIA...`) -> `[REDACTED_AWS_KEY]`
- **OpenAI API Keys** (`sk-...`) -> `[REDACTED_OPENAI_KEY]`
- **GitHub Tokens** (`ghp_...`) -> `[REDACTED_GITHUB_TOKEN]`
- **Private RSA / SSH Keys** -> `[REDACTED_PRIVATE_KEY]`

### 2. Covert Channel & DNS Tunneling Interceptor
Detects non-standard data exfiltration channels designed to bypass network filters:
- **DNS Tunneling Queries** (`nslookup stolen.evil.com`)
- **Base64 / Hex Exfiltration Wrappers**
- **Raw ICMP Ping Socket Tunneling**

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

## 📁 Repository Structure

```
OS_REPOSITORY/
├── security/
│   ├── dlp-engine.js     # Browser/Frontend DLP Secret Redactor & Covert Scanner
│   └── dlp-node.js       # Backend Node.js Secret Sanitizer Module
├── db/
│   ├── schema.sql        # PostgreSQL DDL & DML Schema Definitions
│   └── index.js          # Node.js PostgreSQL Database Client & DAO Layer
├── bin/
│   └── warden.js         # Executable CLI Binary Tool
├── tests/
│   └── sandbox.test.js   # Automated Test Suite (5/5 Passing)
├── server.js             # Express.js REST API Server with DLP Shield
├── docker-compose.yml    # PostgreSQL 16 Service Container Setup
├── index.html            # Master Web Dashboard & Interactive Playground
└── README.md             # Project Documentation
```

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
