/* Warden Data Loss Prevention (DLP) & Zero Data Leakage Engine */

import { SECRET_PATTERNS, COVERT_EXFILTRATION_PATTERNS } from '../shared/dlp-patterns.js';

export { SECRET_PATTERNS, COVERT_EXFILTRATION_PATTERNS };

export class DLPEngine {
  constructor() {
    this.redactionCount = 0;
  }

  /**
   * Redact secrets, tokens, and credentials from text/code before logging or execution
   * @param {string} text - Untrusted output text to sanitize
   * @returns {string} Sanitized output
   */
  sanitizeOutput(text) {
    if (!text || typeof text !== 'string') return text;
    let sanitized = text;

    SECRET_PATTERNS.forEach(pattern => {
      pattern.regex.lastIndex = 0;
      const matches = sanitized.match(pattern.regex);
      if (matches) {
        this.redactionCount += matches.length;
      }
      sanitized = sanitized.replace(pattern.regex, pattern.mask);
    });

    return sanitized;
  }

  /**
   * Scan code snippet for covert data exfiltration attempts and PII leakage
   * @param {string} code - Source code to inspect
   * @returns {{ hasHighRisk: boolean, risks: Array<{ name: string, risk: string, description: string }> }}
   */
  inspectExfiltrationRisk(code) {
    if (!code || typeof code !== 'string') {
      return { hasHighRisk: false, risks: [] };
    }

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

  /**
   * Ephemeral OverlayFS Shredding Protocol simulation
   * @returns {{ passes: number, protocol: string, status: string, residueBytes: number }}
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
