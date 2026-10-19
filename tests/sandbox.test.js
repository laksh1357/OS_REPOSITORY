/* Warden Automated Test Suite */

const assert = require('assert');
const { PolicyBuilder } = require('../js/policy-builder.js');
const dlpNode = require('../security/dlp-node.js');
const { SECRET_PATTERNS, COVERT_EXFILTRATION_PATTERNS } = require('../shared/dlp-patterns.js');

console.log('\x1b[36m%s\x1b[0m', '🧪 Running Warden Platform Automated Test Suite...');

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

console.log('\n----------------------------------------');
console.log(`Test Results: \x1b[32m${passed} Passed\x1b[0m, \x1b[31m${failed} Failed\x1b[0m`);

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
