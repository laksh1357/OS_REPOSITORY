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
      cpu_limit = EXCLUDED.cpu_limit,
      memory_limit_mb = EXCLUDED.memory_limit_mb,
      max_processes = EXCLUDED.max_processes,
      egress_allowlist = EXCLUDED.egress_allowlist,
      updated_at = CURRENT_TIMESTAMP
    RETURNING *;
  `;
  const values = [
    policyData.name,
    policyData.runtime || 'microvm',
    policyData.cpu,
    policyData.memory,
    policyData.pids,
    policyData.rootFs === 'read-only',
    JSON.stringify(policyData.writableDirs || ['/tmp']),
    JSON.stringify(policyData.egressDomains || []),
    policyData.syscallProfile || 'python-minimal'
  ];

  try {
    const res = await pool.query(query, values);
    return res.rows[0];
  } catch (err) {
    console.error('[WARDEN DB ERROR] Failed to save policy:', err.message);
    throw err;
  }
}

module.exports = {
  pool,
  recordSandboxRun,
  getPolicyByName,
  savePolicy
};
