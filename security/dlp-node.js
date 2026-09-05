/* Warden Backend DLP & Secret Redactor for Node.js */

const SECRET_PATTERNS = [
  { name: "AWS_ACCESS_KEY", regex: /AKIA[0-9A-Z]{16}/g, replacement: "[REDACTED_AWS_ACCESS_KEY]" },
  { name: "AWS_SECRET_KEY", regex: /(aws_secret_access_key|secret_key)\s*=\s*['"][0-9a-zA-Z/+]{40}['"]/gi, replacement: "$1 = '[REDACTED_AWS_SECRET_KEY]'" },
  { name: "OPENAI_API_KEY", regex: /sk-[a-zA-Z0-9]{32,}/g, replacement: "[REDACTED_OPENAI_API_KEY]" },
  { name: "GITHUB_TOKEN", regex: /gh[pousr]_[a-zA-Z0-9]{36,}/g, replacement: "[REDACTED_GITHUB_TOKEN]" },
  { name: "PRIVATE_KEY", regex: /-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----[\s\S]*?-----END \1 PRIVATE KEY-----/g, replacement: "[REDACTED_PRIVATE_KEY]" }
];

function sanitizeCode(code) {
  if (!code || typeof code !== 'string') return code;
  let clean = code;
  SECRET_PATTERNS.forEach(pat => {
    clean = clean.replace(pat.regex, pat.replacement);
  });
  return clean;
}

module.exports = {
  sanitizeCode,
  SECRET_PATTERNS
};
