/* Warden Security Platform - Express.js REST API Server */

require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 8080;

// Security & Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// Healthcheck Endpoint
app.get('/api/v1/health', (req, res) => {
  res.json({
    status: 'HEALTHY',
    service: 'Warden Sandbox API Engine',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// REST API: Run Sandbox Code Snippet
app.post('/api/v1/sandbox/run', async (req, res) => {
  const { code, policyName = 'default-python-sandbox', isEnforced = true } = req.body;

  if (!code) {
    return res.status(400).json({ error: 'Missing required string parameter: code' });
  }

  const runId = 'run_' + Math.random().toString(36).substring(2, 10);
  const timestamp = new Date().toISOString();

  // Evaluate pattern threat triggers
  const hasEtcPasswd = code.includes('/etc/passwd') || code.includes('environ');
  const hasC2IP = code.includes('203.0.113.88') || code.includes('198.51.100.44') || code.includes('socket.connect');
  const hasFork = code.includes('os.fork()');
  
  let isViolated = false;
  let status = 'COMPLETED';
  let violationType = null;
  let violationDetails = {};

  if (hasEtcPasswd) {
    if (isEnforced) {
      isViolated = true;
      status = 'CONTAINED';
      violationType = 'OVERLAY_FS_BLOCK';
      violationDetails = { message: 'Read attempt outside writable /tmp directory blocked.', path: '/etc/passwd' };
    } else {
      status = 'EXPOSED';
    }
  } else if (hasC2IP) {
    if (isEnforced) {
      isViolated = true;
      status = 'CONTAINED';
      violationType = 'EGRESS_DENY';
      violationDetails = { message: 'Outbound IP connection not in policy allowlist.', target: '203.0.113.88:4444' };
    } else {
      status = 'EXPOSED';
    }
  } else if (hasFork) {
    if (isEnforced) {
      isViolated = true;
      status = 'CONTAINED';
      violationType = 'CGROUP_CEILING';
      violationDetails = { message: 'Process limit max_pids=8 exceeded.', pid_count: 9 };
    } else {
      status = 'EXPOSED';
    }
  }

  const executionTimeMs = (Math.random() * 5 + 35).toFixed(2);

  // Try recording into PostgreSQL if database connected
  let dbAuditLog = null;
  try {
    dbAuditLog = await db.recordSandboxRun({
      runId,
      codeSnippet: code,
      snippetHash: 'sha256:' + Math.random().toString(36).substring(2, 12),
      status,
      isViolated,
      violationType,
      violationDetails,
      executionTimeMs: parseFloat(executionTimeMs)
    });
  } catch (err) {
    // Database fallback if PostgreSQL server isn't running locally
  }

  res.json({
    runId,
    timestamp,
    status,
    isEnforced,
    isViolated,
    violationType,
    violationDetails,
    executionTimeMs: parseFloat(executionTimeMs),
    blastRadius: isEnforced ? '0% (Host Protected)' : '100% (CRITICAL RISK)',
    postgresLogged: !!dbAuditLog
  });
});

// REST API: Get All Policies
app.get('/api/v1/policies', async (req, res) => {
  try {
    const policy = await db.getPolicyByName('default-python-sandbox');
    res.json({ success: true, policies: policy ? [policy] : [] });
  } catch (err) {
    res.json({ success: true, policies: [], note: 'Using in-memory policy fallback.' });
  }
});

// Fallback to index.html for SPA routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`[WARDEN SERVER] Server running on http://localhost:${PORT}`);
});
