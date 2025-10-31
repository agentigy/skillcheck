import type { Rule, Finding } from '../types.js';

/**
 * Keywords that suggest proper authorization checks are being performed
 */
const AUTHORIZATION_KEYWORDS = [
  /authori[zs]ation/i,
  /permission/i,
  /access[_-]?control/i,
  /check[_-]?admin/i,
  /require[_-]?root/i,
  /verify[_-]?user/i,
];

/**
 * Check if authorization code exists near the match
 */
function hasNearbyAuthorization(content: string, matchIndex: number, contextLines: number = 3): boolean {
  const lines = content.split('\n');
  const matchLine = content.substring(0, matchIndex).split('\n').length - 1;

  const startLine = Math.max(0, matchLine - contextLines);
  const endLine = Math.min(lines.length - 1, matchLine + contextLines);

  const contextText = lines.slice(startLine, endLine + 1).join('\n');

  return AUTHORIZATION_KEYWORDS.some(pattern => pattern.test(contextText));
}

/**
 * Patterns that indicate potential privilege escalation
 */
interface PrivilegePattern {
  name: string;
  pattern: RegExp;
  severity: 'CRITICAL' | 'HIGH';
  description: string;
}

const PRIVILEGE_ESCALATION_PATTERNS: PrivilegePattern[] = [
  {
    name: 'sudo command',
    pattern: /\bsudo\s+(?!-[vklnA]\b)[^\n;|&]+/gi,
    severity: 'CRITICAL',
    description: 'Execution of commands with sudo (elevated privileges)',
  },
  {
    name: 'setuid/setgid',
    pattern: /\b(setuid|setgid|seteuid|setegid)\s*\(/gi,
    severity: 'CRITICAL',
    description: 'Setting user/group ID for privilege escalation',
  },
  {
    name: 'chmod with setuid/setgid bit',
    pattern: /chmod\s+[+]?[ugoa]*[s]+/gi,
    severity: 'HIGH',
    description: 'Setting setuid/setgid bit on files',
  },
  {
    name: 'chmod 777 or similar',
    pattern: /chmod\s+(-R\s+)?[0-7]*[4567][4567][4567]\b/gi,
    severity: 'HIGH',
    description: 'Overly permissive file permissions',
  },
  {
    name: 'su command',
    pattern: /\bsu\s+(-\s+)?(?:root|admin)/gi,
    severity: 'CRITICAL',
    description: 'Switching to root or admin user',
  },
  {
    name: 'pkexec command',
    pattern: /\bpkexec\s+[^\n;|&]+/gi,
    severity: 'CRITICAL',
    description: 'PolicyKit command execution with elevated privileges',
  },
  {
    name: 'doas command',
    pattern: /\bdoas\s+[^\n;|&]+/gi,
    severity: 'CRITICAL',
    description: 'OpenBSD doas command execution with elevated privileges',
  },
  {
    name: 'UAC bypass attempts',
    pattern: /RunAs\s+(Administrator|TrustedInstaller)/gi,
    severity: 'CRITICAL',
    description: 'Windows UAC bypass or privilege escalation',
  },
  {
    name: 'System file modification',
    pattern: /(?:write|edit|modify|append|>|>>)\s+(?:\/etc\/|\/sys\/|\/proc\/|\/boot\/|C:\\Windows\\)/gi,
    severity: 'CRITICAL',
    description: 'Direct modification of system directories',
  },
  {
    name: 'Kernel module loading',
    pattern: /\b(insmod|modprobe|kextload)\s+[^\n;|&]+/gi,
    severity: 'CRITICAL',
    description: 'Loading kernel modules (requires root)',
  },
  {
    name: 'Docker socket access',
    pattern: /\/var\/run\/docker\.sock/gi,
    severity: 'HIGH',
    description: 'Direct access to Docker socket (equivalent to root)',
  },
];

/**
 * Rule that detects privilege escalation vulnerabilities
 */
export const privilegeEscalationRule: Rule = {
  id: 'PRIV_ESCALATION_001',
  name: 'Privilege Escalation',
  severity: 'CRITICAL',
  description: 'Detects patterns that could lead to privilege escalation or unauthorized elevated access',
  remediation: 'Avoid running commands with elevated privileges. If required, implement proper authorization checks and use principle of least privilege.',
  cwe: 'CWE-250',

  check(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const privPattern of PRIVILEGE_ESCALATION_PATTERNS) {
      // Reset regex state
      privPattern.pattern.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = privPattern.pattern.exec(content)) !== null) {
        // Check if authorization exists nearby (unless it's a file permission issue)
        if (!privPattern.name.includes('chmod') && hasNearbyAuthorization(content, match.index)) {
          continue;
        }

        // Find line number
        const lineNumber = content.substring(0, match.index).split('\n').length - 1;
        const line = lines[lineNumber];

        findings.push({
          ruleId: 'PRIV_ESCALATION_001',
          severity: privPattern.severity,
          message: `Potential privilege escalation: ${privPattern.description}`,
          file: filePath,
          line: lineNumber,
          snippet: line.trim(),
          remediation: 'Avoid running commands with elevated privileges. If required, implement proper authorization checks and use principle of least privilege.',
          cwe: 'CWE-250',
        });
      }
    }

    return findings;
  },
};
