import type { Rule, Finding } from '../types.js';

/**
 * Common placeholder patterns that should NOT be flagged as secrets
 */
const PLACEHOLDER_PATTERNS = [
  /your[_-]?api[_-]?key/i,
  /your[_-]?token/i,
  /your[_-]?secret/i,
  /^\*+$/,  // Redacted values like "****"
  /^x{4,}$/i,  // Placeholder like "XXXX" (4 or more X's only)
  /^example/i,  // Starts with "example"
  /placeholder/i,
  /replace[_-]?me/i,
  /^\$\{?\w+\}?$/,  // Variables like ${API_KEY} or $TOKEN (exact match)
];

/**
 * Check if a value looks like a placeholder rather than a real secret
 */
function isPlaceholder(value: string): boolean {
  return PLACEHOLDER_PATTERNS.some(pattern => pattern.test(value));
}

/**
 * Secret patterns to detect
 */
interface SecretPattern {
  name: string;
  pattern: RegExp;
  /** Minimum length to consider (helps avoid false positives) */
  minLength?: number;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: 'AWS Access Key',
    pattern: /AKIA[0-9A-Z]{16}/g,
  },
  {
    name: 'AWS Secret Key',
    pattern: /aws.{0,20}?(?:secret|access).{0,20}?['"]\s*([A-Za-z0-9/+=]{40})\s*['"]/gi,
    minLength: 40,
  },
  {
    name: 'Generic API Key',
    pattern: /api[_-]?key\s*[=:]\s*['"]\s*([A-Za-z0-9_\-]{20,})\s*['"]/gi,
    minLength: 20,
  },
  {
    name: 'JWT Token',
    pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_.\-+/]+/g,
  },
  {
    name: 'Private Key',
    pattern: /-----BEGIN\s+(RSA\s+|EC\s+)?PRIVATE\s+KEY-----/g,
  },
  {
    name: 'GitHub Token',
    pattern: /gh[ps]_[A-Za-z0-9_]{36,}/g,
  },
  {
    name: 'Generic Secret/Token',
    pattern: /(secret|token|password)\s*[=:]\s*['"]\s*([A-Za-z0-9_\-!@#$%^&*]{16,})\s*['"]/gi,
    minLength: 16,
  },
];

/**
 * Rule that detects hardcoded secrets in skill files
 */
export const secretsRule: Rule = {
  id: 'SECRET_EXPOSURE_001',
  name: 'Hardcoded Secrets',
  severity: 'CRITICAL',
  description: 'Detects hardcoded secrets such as API keys, tokens, and credentials',
  remediation: 'Remove hardcoded secrets and use environment variables or secure secret management',
  cwe: 'CWE-798',

  check(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const secretPattern of SECRET_PATTERNS) {
      // Reset regex state
      secretPattern.pattern.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = secretPattern.pattern.exec(content)) !== null) {
        const matchedValue = match[1] || match[0];

        // Skip if it looks like a placeholder
        if (isPlaceholder(matchedValue)) {
          continue;
        }

        // Check minimum length if specified
        if (secretPattern.minLength && matchedValue.length < secretPattern.minLength) {
          continue;
        }

        // Find line number
        const lineNumber = content.substring(0, match.index).split('\n').length - 1;
        const line = lines[lineNumber];

        findings.push({
          ruleId: 'SECRET_EXPOSURE_001',
          severity: 'CRITICAL',
          message: `Potential ${secretPattern.name} detected`,
          file: filePath,
          line: lineNumber,
          snippet: line.trim(),
          remediation: 'Remove hardcoded secrets and use environment variables or secure secret management',
          cwe: 'CWE-798',
        });
      }
    }

    return findings;
  },
};
