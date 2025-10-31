import type { Rule, Finding } from '../types.js';

/**
 * Keywords that suggest path validation is being performed
 */
const PATH_VALIDATION_KEYWORDS = [
  /path\.resolve/i,
  /path\.normalize/i,
  /validat.*path/i,
  /sanitiz.*path/i,
  /allow[_-]?list/i,
  /whitelist/i,
  /realpath/i,
];

/**
 * Check if path validation code exists near the match
 */
function hasNearbyPathValidation(content: string, matchIndex: number, contextLines: number = 3): boolean {
  const lines = content.split('\n');
  const matchLine = content.substring(0, matchIndex).split('\n').length - 1;

  const startLine = Math.max(0, matchLine - contextLines);
  const endLine = Math.min(lines.length - 1, matchLine + contextLines);

  const contextText = lines.slice(startLine, endLine + 1).join('\n');

  return PATH_VALIDATION_KEYWORDS.some(pattern => pattern.test(contextText));
}

/**
 * Patterns that indicate potential path traversal
 */
interface PathPattern {
  name: string;
  pattern: RegExp;
  severity: 'HIGH' | 'MEDIUM';
  description: string;
}

const PATH_TRAVERSAL_PATTERNS: PathPattern[] = [
  {
    name: 'Path traversal sequence',
    pattern: /\.\.[\/\\]/g,
    severity: 'HIGH',
    description: 'Path traversal sequence (../) detected',
  },
  {
    name: 'File path construction with user input',
    pattern: /(?:file_?path|path|filename)\s*=\s*f?["'][^"']*\{(?:user|input|request|param|filename)/gi,
    severity: 'HIGH',
    description: 'File path constructed with user input',
  },
  {
    name: 'Read tool with user input',
    pattern: /<parameter name="file_path">[^<]*[\$\{](?:user|input|request|param)/gi,
    severity: 'HIGH',
    description: 'Read tool file_path parameter with user input',
  },
  {
    name: 'Write tool with user input',
    pattern: /<parameter name="file_path">[^<]*[\$\{](?:user|input|request|param)/gi,
    severity: 'HIGH',
    description: 'Write tool file_path parameter with user input',
  },
  {
    name: 'Edit tool with user input',
    pattern: /<parameter name="file_path">[^<]*[\$\{](?:user|input|request|param)/gi,
    severity: 'HIGH',
    description: 'Edit tool file_path parameter with user input',
  },
  {
    name: 'File operation with variables',
    pattern: /(?:readFile|writeFile|appendFile)\s*\(\s*(?:[\$\{`][\w]+|(?:user|input|param|request)[\w]*)/gi,
    severity: 'HIGH',
    description: 'File system operation with variables',
  },
  {
    name: 'Python file open with variables',
    pattern: /\bopen\s*\([^)]*[\$\{][\w]+/gi,
    severity: 'MEDIUM',
    description: 'Python open() with variables',
  },
];

/**
 * Rule that detects path traversal vulnerabilities
 */
export const pathTraversalRule: Rule = {
  id: 'PATH_TRAVERSAL_001',
  name: 'Path Traversal',
  severity: 'HIGH',
  description: 'Detects potential path traversal vulnerabilities in file operations',
  remediation: 'Validate file paths using path.resolve() or path.normalize(). Use allowlists for permitted directories.',
  cwe: 'CWE-22',

  check(content: string, filePath: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const pathPattern of PATH_TRAVERSAL_PATTERNS) {
      // Reset regex state
      pathPattern.pattern.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = pathPattern.pattern.exec(content)) !== null) {
        // Check if path validation exists nearby
        if (hasNearbyPathValidation(content, match.index)) {
          continue;
        }

        // Find line number
        const lineNumber = content.substring(0, match.index).split('\n').length - 1;
        const line = lines[lineNumber];

        findings.push({
          ruleId: 'PATH_TRAVERSAL_001',
          severity: pathPattern.severity,
          message: `Potential path traversal: ${pathPattern.description}`,
          file: filePath,
          line: lineNumber,
          snippet: line.trim(),
          remediation: 'Validate file paths using path.resolve() or path.normalize(). Use allowlists for permitted directories.',
          cwe: 'CWE-22',
        });
      }
    }

    return findings;
  },
};
