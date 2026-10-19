/* Warden Backend DLP & Secret Redactor for Node.js */

const { SECRET_PATTERNS, COVERT_EXFILTRATION_PATTERNS } = require('../shared/dlp-patterns');

function sanitizeCode(code) {
  if (!code || typeof code !== 'string') return code;
  let clean = code;
  SECRET_PATTERNS.forEach(pat => {
    // Reset regex index if global
    pat.regex.lastIndex = 0;
    clean = clean.replace(pat.regex, pat.mask);
  });
  return clean;
}

function inspectExfiltrationRisk(code) {
  if (!code || typeof code !== 'string') return { hasHighRisk: false, risks: [] };
  const detectedRisks = [];
  COVERT_EXFILTRATION_PATTERNS.forEach(pat => {
    pat.regex.lastIndex = 0;
    if (pat.regex.test(code)) {
      detectedRisks.push({
        name: pat.name,
        risk: pat.risk,
        description: pat.desc
      });
    }
  });
  return {
    hasHighRisk: detectedRisks.some(r => r.risk === "CRITICAL" || r.risk === "HIGH"),
    risks: detectedRisks
  };
}

module.exports = {
  sanitizeCode,
  inspectExfiltrationRisk,
  SECRET_PATTERNS,
  COVERT_EXFILTRATION_PATTERNS
};
