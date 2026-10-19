/* Warden PostgreSQL Connection & Database Access Layer */

const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://warden:warden_secret_pass@localhost:5432/warden_db',
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Handle idle client connection errors gracefully
pool.on('error', (err) => {
  console.error('[WARDEN DB POOL WARNING] Idle client connection error:', err.message);
});

/**
 * Health check ping for the pool
 */
async function checkHealth() {
  try {
    await pool.query('SELECT 1;');
    return true;
  } catch (_) {
    return false;
  }
}

/**
 * Record a sandbox execution run into PostgreSQL audit log table
 */
async function recordSandboxRun({ runId, policyId, codeSnippet, snippetHash, status, isViolated, violationType, violationDetails, executionTimeMs }) {
  const query = `
    INSERT INTO sandbox_audit_logs 
      (run_id, policy_id, code_snippet, snippet_hash, status, is_violated, violation_type, violation_details, execution_time_ms)
    VALUES 
      ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    RETURNING id, created_at;
  `;
  const values = [runId, policyId || null, codeSnippet, snippetHash, status, isViolated, violationType || null, JSON.stringify(violationDetails || {}), executionTimeMs];
  
  try {
    const res = await pool.query(query, values);
    return res.rows[0];
  } catch (err) {
    console.error('[WARDEN DB ERROR] Failed to record audit log:', err.message);
    throw err;
  }
}

/**
 * Fetch active policy by name from PostgreSQL
 */
async function getPolicyByName(name) {
  const query = 'SELECT * FROM warden_policies WHERE name = $1 AND is_active = TRUE LIMIT 1;';
  try {
    const res = await pool.query(query, [name]);
    return res.rows[0] || null;
  } catch (err) {
    console.error('[WARDEN DB ERROR] Failed to fetch policy:', err.message);
    throw err;
  }
}

/**
 * Create or update a policy in PostgreSQL
 */
async function savePolicy(policyData) {
  const query = `
    INSERT INTO warden_policies 
      (name, runtime, cpu_limit, memory_limit_mb, max_processes, root_readonly, writable_paths, egress_allowlist, syscall_profile)
    VALUES 
      ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    ON CONFLICT (name) DO UPDATE SET
      runtime = EXCLUDED.runtime,
      cpu_limit = EXCLUDED.cpu_limit,
      memory_limit_mb = EXCLUDED.memory_limit_mb,
      max_processes = EXCLUDED.max_processes,
      root_readonly = EXCLUDED.root_readonly,
      writable_paths = EXCLUDED.writable_paths,
      egress_allowlist = EXCLUDED.egress_allowlist,
      syscall_profile = EXCLUDED.syscall_profile,
      updated_at = CURRENT_TIMESTAMP
    RETURNING *;
  `;

  // Normalize property names to handle both snake_case (DB/API) and camelCase inputs
  const cpu = policyData.cpu_limit !== undefined ? policyData.cpu_limit : (policyData.cpu !== undefined ? policyData.cpu : 0.5);
  const memory = policyData.memory_limit_mb !== undefined ? policyData.memory_limit_mb : (policyData.memory !== undefined ? policyData.memory : 256);
  const pids = policyData.max_processes !== undefined ? policyData.max_processes : (policyData.pids !== undefined ? policyData.pids : 8);
  const rootReadonly = policyData.root_readonly !== undefined 
    ? Boolean(policyData.root_readonly) 
    : (policyData.rootFs === 'read-only' || true);
  const writablePaths = policyData.writable_paths || policyData.writableDirs || ['/tmp'];
  const egressAllowlist = policyData.egress_allowlist || policyData.egressDomains || [];
  const syscallProfile = policyData.syscall_profile || policyData.syscallProfile || 'python-minimal';

  const values = [
    policyData.name,
    policyData.runtime || 'microvm',
    cpu,
    memory,
    pids,
    rootReadonly,
    JSON.stringify(Array.isArray(writablePaths) ? writablePaths : [writablePaths]),
    JSON.stringify(Array.isArray(egressAllowlist) ? egressAllowlist : []),
    syscallProfile
  ];

  try {
    const res = await pool.query(query, values);
    return res.rows[0];
  } catch (err) {
    console.error('[WARDEN DB ERROR] Failed to save policy:', err.message);
    throw err;
  }
}

/**
 * Gracefully close the connection pool
 */
async function close() {
  try {
    await pool.end();
  } catch (err) {
    console.error('[WARDEN DB WARNING] Error closing connection pool:', err.message);
  }
}

module.exports = {
  pool,
  checkHealth,
  recordSandboxRun,
  getPolicyByName,
  savePolicy,
  close
};
