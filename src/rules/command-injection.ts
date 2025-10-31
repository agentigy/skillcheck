import type { Rule, Finding } from '../types.js';

/**
 * Keywords that suggest input validation is being performed
 */
const VALIDATION_KEYWORDS = [
  /validat/i,
  /sanitiz/i,
  /escape/i,
  /allow[_-]?list/i,
  /whitelist/i,
  /filter/i,
  /check/i,
];

/**
 * Check if validation code exists near the match
 * This helps reduce false positives
 */
function hasNearbyValidation(content: string, matchIndex: number, contextLines: number = 3): boolean {
  const lines = content.split('\n');
  const matchLine = content.substring(0, matchIndex).split('\n').length - 1;

  // Check lines before and after
  const startLine = Math.max(0, matchLine - contextLines);
  const endLine = Math.min(lines.length - 1, matchLine + contextLines);

  const contextText = lines.slice(startLine, endLine + 1).join('\n');

  return VALIDATION_KEYWORDS.some(pattern => pattern.test(contextText));
}

/**
 * Patterns that indicate potential command injection
 */
interface CommandPattern {
  name: string;
  pattern: RegExp;
  severity: 'CRITICAL' | 'HIGH';
  description: string;
}

const COMMAND_INJECTION_PATTERNS: CommandPattern[] = [
  {
    name: 'Bash with variable interpolation',
    pattern: /bash[^;{]*(?:command|cmd|c)[^;{]*['"]\s*.*?[\$\{][\w]+/gi,
    severity: 'CRITICAL',
    description: 'Shell command execution with variable interpolation',
  },
  {
    name: 'eval() with variables',
    pattern: /\beval\s*\([^)]*[\$\{][\w]+/gi,
    severity: 'CRITICAL',
    description: 'Dynamic code evaluation with variables',
  },
  {
    name: 'exec() with variables',
    pattern: /\bexec\s*\([^)]*[\$\{][\w]+/gi,
    severity: 'CRITICAL',
    description: 'Code execution with variables',
  },
  {
    name: 'subprocess with shell=True',
    pattern: /subprocess\.[^(]+\([^)]*shell\s*=\s*True/gi,
    severity: 'HIGH',
    description: 'Python subprocess with shell enabled',
  },
  {
    name: 'os.system with variables',
    pattern: /os\.system\s*\([^)]*[\$\{][\w]+/gi,
    severity: 'CRITICAL',
    description: 'Direct system command execution with variables',
  },
  {
    name: 'child_process.exec with variables',
    pattern: /child_process\.exec\s*\([^)]*[\$\{`][\w]+/gi,
    severity: 'HIGH',
    description: 'Node.js command execution with variables',
  },
  {
    name: 'Command parameter with user input',
    pattern: /<parameter name="command">[^<]*[\$\{](?:user|input|request|param)/gi,
    severity: 'HIGH',
    description: 'Bash tool command parameter with user input',
  },
];

/**
 * Rule that detects command injection vulnerabilities
 */
export const commandInjectionRule: Rule = {
  id: 'CMD_INJECTION_001',
  name: 'Command Injection',
  severity: 'CRITICAL',
  description: 'Detects potential command injection vulnerabilities in shell commands',
  remediation: 'Validate and sanitize all user inputs. Use parameterized commands or allowlists. Avoid shell=True.',
  cwe: 'CWE-78',

  check(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const cmdPattern of COMMAND_INJECTION_PATTERNS) {
      // Reset regex state
      cmdPattern.pattern.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = cmdPattern.pattern.exec(content)) !== null) {
        // Check if validation exists nearby
        if (hasNearbyValidation(content, match.index)) {
          continue;
        }

        // Find line number
        const lineNumber = content.substring(0, match.index).split('\n').length - 1;
        const line = lines[lineNumber];

        findings.push({
          ruleId: 'CMD_INJECTION_001',
          severity: cmdPattern.severity,
          message: `Potential command injection: ${cmdPattern.description}`,
          file: filePath,
          line: lineNumber,
          snippet: line.trim(),
          remediation: 'Validate and sanitize all user inputs. Use parameterized commands or allowlists. Avoid shell=True.',
          cwe: 'CWE-78',
        });
      }
    }

    return findings;
  },
};
