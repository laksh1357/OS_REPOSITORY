-- Warden OS Sandbox Platform - PostgreSQL Database Schema
-- Version: v1.0.0

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. POLICIES TABLE
CREATE TABLE IF NOT EXISTS warden_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL UNIQUE,
    runtime VARCHAR(50) NOT NULL DEFAULT 'microvm',
    cpu_limit NUMERIC(3, 1) NOT NULL DEFAULT 0.5,
    memory_limit_mb INTEGER NOT NULL DEFAULT 256,
    max_processes INTEGER NOT NULL DEFAULT 8,
    root_readonly BOOLEAN NOT NULL DEFAULT TRUE,
    writable_paths JSONB NOT NULL DEFAULT '["/tmp"]'::jsonb,
    egress_allowlist JSONB NOT NULL DEFAULT '["pypi.org", "files.pythonhosted.org"]'::jsonb,
    syscall_profile VARCHAR(50) NOT NULL DEFAULT 'python-minimal',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. SANDBOX AUDIT LOGS TABLE
CREATE TABLE IF NOT EXISTS sandbox_audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    run_id VARCHAR(64) NOT NULL UNIQUE,
    policy_id UUID REFERENCES warden_policies(id) ON DELETE SET NULL,
    snippet_hash VARCHAR(64) NOT NULL,
    code_snippet TEXT NOT NULL,
    status VARCHAR(50) NOT NULL, -- 'CONTAINED', 'COMPLETED', 'EXPOSED'
    is_violated BOOLEAN NOT NULL DEFAULT FALSE,
    violation_type VARCHAR(100), -- 'SECCOMP_BLOCK', 'EGRESS_DENY', 'CGROUP_CEILING'
    violation_details JSONB,
    execution_time_ms NUMERIC(8, 2) NOT NULL,
    warm_teardown_ms NUMERIC(6, 2) DEFAULT 3.8,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. THREAT PATTERNS TABLE
CREATE TABLE IF NOT EXISTS threat_patterns (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    category VARCHAR(50) NOT NULL, -- 'CRED_THEFT', 'REVERSE_SHELL', 'FORK_BOMB'
    pattern_regex VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'CRITICAL',
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. API KEYS TABLE
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_name VARCHAR(100) NOT NULL,
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    rate_limit_per_min INTEGER DEFAULT 60,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- INDEXES FOR PERFORMANCE
CREATE INDEX IF NOT EXISTS idx_audit_logs_status ON sandbox_audit_logs(status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON sandbox_audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_policies_name ON warden_policies(name);

-- SAMPLE SEED DATA
INSERT INTO warden_policies (name, runtime, cpu_limit, memory_limit_mb, max_processes, egress_allowlist)
VALUES 
    ('default-python-sandbox', 'microvm', 0.5, 256, 8, '["pypi.org", "files.pythonhosted.org", "api.openai.com"]'::jsonb),
    ('strict-isolated-sandbox', 'microvm', 0.2, 128, 4, '[]'::jsonb)
ON CONFLICT (name) DO NOTHING;

INSERT INTO threat_patterns (category, pattern_regex, severity, description)
VALUES 
    ('CRED_THEFT', '(/etc/passwd|\.aws/credentials|os\.environ)', 'CRITICAL', 'Attempting unauthorized read of system or cloud credential files'),
    ('REVERSE_SHELL', '(socket\.connect|/bin/sh|subprocess\.call)', 'CRITICAL', 'Outbound TCP connection attempt for C2 reverse shell'),
    ('FORK_BOMB', '(os\.fork\(\)|while\s+True:\s+fork)', 'HIGH', 'Recursive child process spawner aimed at CPU/RAM exhaustion')
ON CONFLICT DO NOTHING;
