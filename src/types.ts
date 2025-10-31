/**
 * Severity levels for security findings
 */
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

/**
 * A security finding detected in a skill file
 */
export interface Finding {
  /** Unique rule identifier */
  ruleId: string;
  /** Severity level */
  severity: Severity;
  /** Human-readable message describing the issue */
  message: string;
  /** File path where the issue was found */
  file: string;
  /** Line number (0-indexed) */
  line: number;
  /** Column number (0-indexed, optional) */
  column?: number;
  /** Code snippet showing the issue */
  snippet?: string;
  /** Suggested remediation */
  remediation: string;
  /** CWE identifier (optional) */
  cwe?: string;
}

/**
 * A security rule that can be applied to skill files
 */
export interface Rule {
  /** Unique identifier for this rule */
  id: string;
  /** Human-readable name */
  name: string;
  /** Severity level if this rule triggers */
  severity: Severity;
  /** Description of what this rule checks */
  description: string;
  /** How to fix issues found by this rule */
  remediation: string;
  /** CWE identifier (optional) */
  cwe?: string;
  /** Execute the rule against file content */
  check: (content: string, filePath: string) => Finding[];
}
