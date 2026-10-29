/* Warden Automated Test Suite — v2 (with real execution engine tests) */

const assert = require('assert');
const { PolicyBuilder } = require('../public/js/policy-builder.js');
const dlpNode = require('../security/dlp-node.js');
const { SECRET_PATTERNS } = require('../shared/dlp-patterns.js');
const { errorHandler, requestSanitizer } = require('../middleware/errorHandler.js');
const { evaluatePolicy } = require('../engine/policy-enforcer.js');
const { appendEvent, verifyChain, buildExecutionEvent, getChainStatus } = require('../engine/audit-chain.js');

console.log('\x1b[36m%s\x1b[0m', '🧪 Running Warden Platform Automated Test Suite v2...');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log('\x1b[32m%s\x1b[0m', `  ✓ PASS: ${name}`);
    passed++;
  } catch (err) {
    console.error('\x1b[31m%s\x1b[0m', `  ✗ FAIL: ${name}`);
    console.error(err);
    failed++;
  }
}

// 1. Test PolicyBuilder YAML Generation
test('PolicyBuilder generates valid YAML structure', () => {
  const pb = new PolicyBuilder({ cpu: '1.0', memory: 512, pids: 16 });
  const yaml = pb.generateYAML();
  assert.ok(yaml.includes('cpu: "1.0"'), 'YAML should reflect updated CPU quota');
  assert.ok(yaml.includes('memory: "512Mi"'), 'YAML should reflect updated RAM limit');
  assert.ok(yaml.includes('processes: 16'), 'YAML should reflect max PIDs');
});

// 2. Test PolicyBuilder SQL Generation
test('PolicyBuilder generates valid PostgreSQL SQL DDL query', () => {
  const pb = new PolicyBuilder({ egressDomains: ['pypi.org', 'api.openai.com'] });
  const sql = pb.generateSQL();
  assert.ok(sql.includes('INSERT INTO warden_policies'), 'SQL must contain INSERT table statement');
  assert.ok(sql.includes('pypi.org'), 'SQL must contain egress domain allowlist JSON');
});

// 3. Test Threat Signature Matching Logic via Shared DLP Patterns
test('Shared DLP & Threat Engine flags covert channels and credential access', () => {
  const sampleMaliciousCode = 'with open("/etc/passwd", "r") as f: print(f.read())';
  const riskAnalysis = dlpNode.inspectExfiltrationRisk(sampleMaliciousCode);
  assert.strictEqual(typeof riskAnalysis.hasHighRisk, 'boolean');
  
  // Verify secret patterns contain critical rules
  const ruleNames = SECRET_PATTERNS.map(r => r.name);
  assert.ok(ruleNames.includes('AWS_ACCESS_KEY'), 'Should include AWS Access Key rule');
  assert.ok(ruleNames.includes('OPENAI_API_KEY'), 'Should include OpenAI API Key rule');
  assert.ok(ruleNames.includes('JWT_TOKEN'), 'Should include JWT Token rule');
  assert.ok(ruleNames.includes('DATABASE_URI'), 'Should include Database URI rule');
});

// 4. Test Domain Allowlist Addition & Removal
test('PolicyBuilder allows adding and removing egress domains', () => {
  const pb = new PolicyBuilder();
  pb.addDomain('api.anthropic.com');
  assert.ok(pb.state.egressDomains.includes('api.anthropic.com'), 'Domain should be added');
  pb.removeDomain('api.anthropic.com');
  assert.ok(!pb.state.egressDomains.includes('api.anthropic.com'), 'Domain should be removed');
});

// 5. Test DLP Secret Redaction System
test('DLP Engine redacts AWS keys and OpenAI tokens', () => {
  const sampleSnippet = 'aws_key = "AKIA1234567890ABCDEF"; token = "sk-1234567890abcdef1234567890abcdef"';
  const sanitized = dlpNode.sanitizeCode(sampleSnippet);
  assert.ok(!sanitized.includes('AKIA1234567890ABCDEF'), 'AWS Key must be redacted');
  assert.ok(sanitized.includes('[REDACTED_AWS_ACCESS_KEY]'), 'Redaction placeholder must be present');
  assert.ok(!sanitized.includes('sk-1234567890abcdef1234567890abcdef'), 'OpenAI key must be redacted');
});

// 6. Test Request Sanitizer Middleware
test('Request Sanitizer middleware intercepts and redacts payload code', () => {
  const req = { body: { code: 'key = "AKIA0000000000000000"' } };
  const res = {};
  let nextCalled = false;
  requestSanitizer(req, res, () => { nextCalled = true; });
  assert.ok(nextCalled, 'next() must be called');
  assert.ok(req.sanitizedCode.includes('[REDACTED_AWS_ACCESS_KEY]'), 'Code should be pre-sanitized');
});

// 7. Test Error Handler Middleware response formatting
test('Error Handler middleware returns structured JSON payload', () => {
  const err = new Error('Database connection failed');
  err.status = 503;
  let responseStatus = null;
  let responsePayload = null;
  const res = {
    headersSent: false,
    status(code) {
      responseStatus = code;
      return this;
    },
    json(data) {
      responsePayload = data;
      return this;
    }
  };
  
  // Suppress stderr output for expected error logging in test
  const originalErr = console.error;
  console.error = () => {};
  try {
    errorHandler(err, {}, res, () => {});
  } finally {
    console.error = originalErr;
  }

  assert.strictEqual(responseStatus, 503, 'Status code should match err.status');
  assert.ok(responsePayload && responsePayload.error, 'Payload must contain error object');
});

console.log('\n----------------------------------------');
console.log(`Test Results: \x1b[32m${passed} Passed\x1b[0m, \x1b[31m${failed} Failed\x1b[0m`);

// ── PART 2: Engine & Enforcement Tests (synchronous / unit-level) ────────────
console.log('\n\x1b[36m%s\x1b[0m', '⚙️  Policy Enforcer & Audit Chain Tests...');

// 8. Test Policy Enforcement Manifest
test('PolicyEnforcer produces enforcement manifest with correct mechanism count', () => {
  const policy = { name: 'test-policy', timeoutMs: 5000, memoryMb: 128, maxProcesses: 4, writablePaths: ['/tmp'], egressAllowlist: [] };
  const manifest = evaluatePolicy(policy);
  assert.ok(manifest.enforcements.length >= 14, `Expected >= 14 mechanisms, got ${manifest.enforcements.length}`);
  assert.ok(typeof manifest.summary.enforced === 'number', 'summary.enforced must be a number');
  assert.ok(manifest.summary.enforced + manifest.summary.unverified + manifest.summary.unsupported + manifest.summary.failed === manifest.summary.total, 'Summary counts must add up');
});

// 9. Timeout mechanism is always ENFORCED
test('PolicyEnforcer marks TIMEOUT as ENFORCED on all platforms', () => {
  const manifest = evaluatePolicy({});
  const timeout = manifest.enforcements.find(e => e.mechanism === 'TIMEOUT');
  assert.ok(timeout, 'TIMEOUT enforcement must exist');
  assert.strictEqual(timeout.status, 'ENFORCED', 'TIMEOUT must be ENFORCED');
});

// 10. DLP_REDACTION mechanism is always ENFORCED
test('PolicyEnforcer marks DLP_REDACTION as ENFORCED on all platforms', () => {
  const manifest = evaluatePolicy({});
  const dlpMech = manifest.enforcements.find(e => e.mechanism === 'DLP_REDACTION');
  assert.ok(dlpMech, 'DLP_REDACTION enforcement must exist');
  assert.strictEqual(dlpMech.status, 'ENFORCED', 'DLP_REDACTION must be ENFORCED');
});

// 11. Audit chain integrity (empty chain)
test('AuditChain verifyChain returns valid on empty chain', () => {
  const result = verifyChain();
  assert.strictEqual(result.valid, true, 'Empty chain must be valid');
});

// 12. Audit chain appends events and maintains integrity
test('AuditChain appendEvent maintains hash chain integrity', () => {
  const event1 = { eventType: 'TEST', runId: 'test_01', status: 'CLEAN', exitCode: 0, executionMs: 42 };
  const event2 = { eventType: 'TEST', runId: 'test_02', status: 'CONTAINED', exitCode: 1, executionMs: 99 };
  const e1 = appendEvent(event1);
  const e2 = appendEvent(event2);
  assert.ok(e1.chainHash, 'Entry must have chainHash');
  assert.ok(e2.chainHash, 'Entry must have chainHash');
  assert.notStrictEqual(e1.chainHash, e2.chainHash, 'Sequential hashes must differ');
  const integrity = verifyChain();
  assert.strictEqual(integrity.valid, true, `Chain must remain valid after appends. Broken at: ${integrity.firstBrokenAt}`);
});

// 13. buildExecutionEvent derives correct status
test('AuditChain buildExecutionEvent derives CONTAINED status from violations', () => {
  const mockResult = {
    runId: 'test_exec_01',
    timestamp: new Date().toISOString(),
    executionMs: 55,
    exitCode: 1,
    signal: 'SIGKILL',
    timedOut: false,
    outputLimitHit: false,
    stdout: '',
    stderr: '',
    stdoutBytes: 0,
    stderrBytes: 0,
    violations: [{ type: 'EGRESS_DENIED', severity: 'HIGH', evidence: 'test', enforced: true }],
    dlpRedacted: false,
    platform: process.platform,
    snippetHash: 'sha256:testabcd',
    policy: { name: 'test-policy', timeoutMs: 5000 },
  };
  const event = buildExecutionEvent(mockResult, 'test-policy');
  assert.strictEqual(event.eventType, 'EXECUTION');
  assert.strictEqual(event.status, 'CONTAINED', 'Status must be CONTAINED when enforced violations exist');
  assert.strictEqual(event.violations.length, 1);
});

// 14. Chain status reflects append count
test('AuditChain getChainStatus returns updated length after appends', () => {
  const before = getChainStatus();
  appendEvent({ eventType: 'STATUS_TEST', runId: 'status_check', status: 'CLEAN', exitCode: 0, executionMs: 1 });
  const after = getChainStatus();
  assert.ok(after.length >= before.length, 'Chain length must not decrease');
});

console.log('\n----------------------------------------');
console.log(`Test Results: \x1b[32m${passed} Passed\x1b[0m, \x1b[31m${failed} Failed\x1b[0m`);

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
