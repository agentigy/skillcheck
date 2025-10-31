import type { Rule, Finding } from '../types.js';

/**
 * Keywords that suggest proper redaction/filtering is being performed
 */
const REDACTION_KEYWORDS = [
  /redact/i,
  /filter/i,
  /sanitiz/i,
  /mask/i,
  /obfuscate/i,
  /strip/i,
  /remove[_-]?sensitive/i,
];

/**
 * Check if redaction code exists near the match
 */
function hasNearbyRedaction(content: string, matchIndex: number, contextLines: number = 3): boolean {
  const lines = content.split('\n');
  const matchLine = content.substring(0, matchIndex).split('\n').length - 1;

  const startLine = Math.max(0, matchLine - contextLines);
  const endLine = Math.min(lines.length - 1, matchLine + contextLines);

  const contextText = lines.slice(startLine, endLine + 1).join('\n');

  return REDACTION_KEYWORDS.some(pattern => pattern.test(contextText));
}

/**
 * Patterns that indicate potential information disclosure
 */
interface DisclosurePattern {
  name: string;
  pattern: RegExp;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  description: string;
}

const INFORMATION_DISCLOSURE_PATTERNS: DisclosurePattern[] = [
  {
    name: 'Environment variables exposure',
    pattern: /(?:\bprintenv\b|\benv\s*$|^env\s|\bexport\s*$|^export\s|\bprocess\.env\b|\bos\.environ\b|\bSystem\.getenv\b)/gim,
    severity: 'HIGH',
    description: 'Exposing environment variables (may contain secrets)',
  },
  {
    name: 'Reading /etc/passwd',
    pattern: /(?:read|cat|type|Get-Content)\s+(?:\/etc\/passwd|\/etc\/shadow)/gi,
    severity: 'HIGH',
    description: 'Reading system password files',
  },
  {
    name: 'SSH key access',
    pattern: /(?:read|cat|type|Get-Content)\s+.*?(?:\.ssh\/id_rsa|\.ssh\/id_ed25519|\.pem|authorized_keys)/gi,
    severity: 'CRITICAL',
    description: 'Accessing SSH private keys or authorized keys',
  },
  {
    name: 'AWS credentials access',
    pattern: /(?:read|cat|type|Get-Content)\s+.*?(?:\.aws\/credentials|\.aws\/config)/gi,
    severity: 'CRITICAL',
    description: 'Accessing AWS credential files',
  },
  {
    name: 'Sensitive environment file access',
    pattern: /(?:read|cat|type|Get-Content)\s+.*?\.env(?:\.local|\.production)?(?:\s|$|["'])/gi,
    severity: 'HIGH',
    description: 'Reading .env files containing sensitive configuration',
  },
  {
    name: 'Database dump exposure',
    pattern: /(?:mysqldump|pg_dump|mongodump|sqlite3\s+.*?\.dump)(?!\s+--.*?(?:redact|mask|anonymize))/gi,
    severity: 'HIGH',
    description: 'Database dump without apparent redaction',
  },
  {
    name: 'Private key in code',
    pattern: /(?:private[_-]?key|privateKey)\s*[=:]\s*['"]/gi,
    severity: 'CRITICAL',
    description: 'Private key assignment in code',
  },
  {
    name: 'System information disclosure',
    pattern: /(?:uname\s+-a|systeminfo|hostnamectl|cat\s+\/proc\/version|lsb_release)/gi,
    severity: 'MEDIUM',
    description: 'Exposing detailed system information',
  },
  {
    name: 'Network configuration exposure',
    pattern: /(?:ifconfig|ip\s+addr|ipconfig\s+\/all|netstat\s+-[rn])/gi,
    severity: 'MEDIUM',
    description: 'Exposing network configuration details',
  },
  {
    name: 'Browser history/cookies access',
    pattern: /(?:read|cat)\s+.*?(?:cookies|History|Bookmarks).*?(?:Chrome|Firefox|Safari|Edge)/gi,
    severity: 'HIGH',
    description: 'Accessing browser history or cookies',
  },
  {
    name: 'Git credentials exposure',
    pattern: /(?:read|cat|type|Get-Content)\s+.*?(?:\.git-credentials|\.netrc|\.gitconfig)/gi,
    severity: 'HIGH',
    description: 'Accessing Git credential files',
  },
  {
    name: 'Docker secrets access',
    pattern: /(?:read|cat|type|Get-Content)\s+\/run\/secrets\//gi,
    severity: 'HIGH',
    description: 'Accessing Docker secrets',
  },
  {
    name: 'Kubernetes secrets access',
    pattern: /kubectl\s+get\s+secret(?!s\s+--help)/gi,
    severity: 'HIGH',
    description: 'Accessing Kubernetes secrets',
  },
  {
    name: 'Connection strings in code',
    pattern: /(?:connection[_-]?string|connStr|connectionString)\s*[=:]\s*["'][^"']*(?:password|pwd)=[^"']*["']/gi,
    severity: 'CRITICAL',
    description: 'Connection string with embedded password',
  },
  {
    name: 'Process list exposure',
    pattern: /\b(?:ps\s+aux|Get-Process|tasklist)(?!\s*\|\s*grep)/gi,
    severity: 'MEDIUM',
    description: 'Full process list disclosure (may contain sensitive info in command lines)',
  },
  {
    name: 'Directory listing with sensitive paths',
    pattern: /\b(?:ls|dir|Get-ChildItem)\s+.*?(?:\/root|\/home\/.*?\/\.|C:\\Users\\.*?\\AppData)/gi,
    severity: 'MEDIUM',
    description: 'Listing contents of sensitive directories',
  },
];

/**
 * Rule that detects information disclosure vulnerabilities
 */
export const informationDisclosureRule: Rule = {
  id: 'INFO_DISCLOSURE_001',
  name: 'Information Disclosure',
  severity: 'HIGH',
  description: 'Detects patterns that could lead to unauthorized disclosure of sensitive information',
  remediation: 'Avoid exposing sensitive files, credentials, or system information. Implement proper access controls and redaction for sensitive data.',
  cwe: 'CWE-200',

  check(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const disclosurePattern of INFORMATION_DISCLOSURE_PATTERNS) {
      // Reset regex state
      disclosurePattern.pattern.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = disclosurePattern.pattern.exec(content)) !== null) {
        // Check if redaction exists nearby for patterns that might have legitimate uses
        if (disclosurePattern.name.includes('dump') || disclosurePattern.name.includes('exposure')) {
          if (hasNearbyRedaction(content, match.index)) {
            continue;
          }
        }

        // Find line number
        const lineNumber = content.substring(0, match.index).split('\n').length - 1;
        const line = lines[lineNumber];

        findings.push({
          ruleId: 'INFO_DISCLOSURE_001',
          severity: disclosurePattern.severity,
          message: `Potential information disclosure: ${disclosurePattern.description}`,
          file: filePath,
          line: lineNumber,
          snippet: line.trim(),
          remediation: 'Avoid exposing sensitive files, credentials, or system information. Implement proper access controls and redaction for sensitive data.',
          cwe: 'CWE-200',
        });
      }
    }

    return findings;
  },
};
