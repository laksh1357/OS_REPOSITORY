/* Warden Data Loss Prevention (DLP) & Zero Data Leakage Engine */

export const SECRET_PATTERNS = [
  { name: "AWS_ACCESS_KEY", regex: /AKIA[0-9A-Z]{16}/g, mask: "[REDACTED_AWS_KEY]" },
  { name: "AWS_SECRET_KEY", regex: /[0-9a-zA-Z/+]{40}/g, mask: "[REDACTED_AWS_SECRET]" },
  { name: "OPENAI_API_KEY", regex: /sk-[a-zA-Z0-9]{32,}/g, mask: "[REDACTED_OPENAI_KEY]" },
  { name: "GITHUB_TOKEN", regex: /gh[pousr]_[a-zA-Z0-9]{36,}/g, mask: "[REDACTED_GITHUB_TOKEN]" },
  { name: "PRIVATE_RSA_KEY", regex: /-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----[\s\S]*?-----END \1 PRIVATE KEY-----/g, mask: "[REDACTED_PRIVATE_KEY]" },
  { name: "JWT_TOKEN", regex: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g, mask: "[REDACTED_JWT_TOKEN]" },
  { name: "DATABASE_URI", regex: /(postgres|mysql|mongodb):\/\/[^:]+:[^@]+@[^/]+\/[^\s]+/g, mask: "[REDACTED_DB_URI]" }
];

export const COVERT_EXFILTRATION_PATTERNS = [
  { name: "DNS_TUNNELING", regex: /(nslookup|dig|socket\.gethostbyname).*\.(attacker|evil|c2)\./i, risk: "HIGH", desc: "DNS Tunneling exfiltration vector detected" },
  { name: "BASE64_ENCODING", regex: /(base64\.b64encode|b64encode\(|zlib\.compress)/i, risk: "MEDIUM", desc: "Encoded binary payload exfiltration wrapper detected" },
  { name: "ICMP_RAW_SOCKET", regex: /(SOCK_RAW|IPPROTO_ICMP)/i, risk: "CRITICAL", desc: "Raw ICMP socket creation for ping covert channel" },
  { name: "ENV_VAR_HARVEST", regex: /(os\.environ|process\.env|\/proc\/self\/environ)/i, risk: "CRITICAL", desc: "Process environment harvesting for cloud secrets" }
];

export class DLPEngine {
  constructor() {
    this.redactionCount = 0;
  }

  /**
   * Redact secrets, tokens, and credentials from text/code before logging or execution
   */
  sanitizeOutput(text) {
    if (!text || typeof text !== 'string') return text;
    let sanitized = text;

    SECRET_PATTERNS.forEach(pattern => {
      if (pattern.regex.test(sanitized)) {
        sanitized = sanitized.replace(pattern.regex, pattern.mask);
        this.redactionCount++;
      }
    });

    return sanitized;
  }

  /**
   * Scan code snippet for covert data exfiltration attempts and PII leakage
   */
  inspectExfiltrationRisk(code) {
    const detectedRisks = [];

    COVERT_EXFILTRATION_PATTERNS.forEach(pat => {
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

  /**
   * Ephemeral OverlayFS Shredding Protocol simulation
   */
  shredStorageBuffer() {
    return {
      passes: 3,
      protocol: "DoD 5220.22-M Zeroing",
      status: "SHREDDED_AND_UNMOUNTED",
      residueBytes: 0
    };
  }
}
