import type { ScanResult } from '../scanner.js';
import type { Finding } from '../types.js';

/**
 * ANSI color codes
 */
const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  green: '\x1b[32m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',
};

/**
 * Get color for severity level
 */
function getSeverityColor(severity: string): string {
  switch (severity) {
    case 'CRITICAL':
      return colors.red;
    case 'HIGH':
      return colors.red;
    case 'MEDIUM':
      return colors.yellow;
    case 'LOW':
      return colors.cyan;
    default:
      return colors.reset;
  }
}

/**
 * Format a finding for console output
 */
function formatFinding(finding: Finding, fileIndex: number): string {
  const color = getSeverityColor(finding.severity);
  const output: string[] = [];

  output.push(`\n${color}${colors.bold}[${finding.severity}]${colors.reset} ${finding.message}`);
  output.push(`  ${colors.gray}${finding.file}:${finding.line + 1}${colors.reset}`);

  if (finding.snippet) {
    output.push(`  ${colors.cyan}${finding.line + 1}:${colors.reset} ${finding.snippet}`);
  }

  output.push(`  ${colors.gray}Fix: ${finding.remediation}${colors.reset}`);

  if (finding.cwe) {
    output.push(`  ${colors.gray}Reference: ${finding.cwe}${colors.reset}`);
  }

  return output.join('\n');
}

/**
 * Console reporter that outputs results in a human-readable format
 */
export class ConsoleReporter {
  /**
   * Report scan results to the console
   */
  report(results: ScanResult[]): void {
    const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);
    const filesScanned = results.length;
    const filesWithIssues = results.filter(r => r.findings.length > 0).length;

    // Summary header
    console.log(`\n${colors.bold}Security Scan Results${colors.reset}`);
    console.log(`${'='.repeat(50)}\n`);
    console.log(`Files scanned: ${filesScanned}`);
    console.log(`Files with issues: ${filesWithIssues}`);
    console.log(`Total findings: ${totalFindings}\n`);

    if (totalFindings === 0) {
      console.log(`${colors.green}${colors.bold}✓ No security issues found!${colors.reset}\n`);
      return;
    }

    // Group findings by severity
    const criticalCount = results.reduce((sum, r) =>
      sum + r.findings.filter(f => f.severity === 'CRITICAL').length, 0);
    const highCount = results.reduce((sum, r) =>
      sum + r.findings.filter(f => f.severity === 'HIGH').length, 0);
    const mediumCount = results.reduce((sum, r) =>
      sum + r.findings.filter(f => f.severity === 'MEDIUM').length, 0);
    const lowCount = results.reduce((sum, r) =>
      sum + r.findings.filter(f => f.severity === 'LOW').length, 0);

    console.log('Findings by severity:');
    if (criticalCount > 0) console.log(`  ${colors.red}CRITICAL: ${criticalCount}${colors.reset}`);
    if (highCount > 0) console.log(`  ${colors.red}HIGH: ${highCount}${colors.reset}`);
    if (mediumCount > 0) console.log(`  ${colors.yellow}MEDIUM: ${mediumCount}${colors.reset}`);
    if (lowCount > 0) console.log(`  ${colors.cyan}LOW: ${lowCount}${colors.reset}`);

    // Output each finding
    console.log(`\n${colors.bold}Issues Found:${colors.reset}`);

    results.forEach((result, index) => {
      if (result.findings.length > 0) {
        console.log(`\n${colors.bold}${result.skill.name}${colors.reset}`);
        result.findings.forEach(finding => {
          console.log(formatFinding(finding, index));
        });
      }
    });

    // Exit code recommendation
    console.log(`\n${'='.repeat(50)}`);
    if (criticalCount > 0) {
      console.log(`${colors.red}${colors.bold}❌ Critical security issues found!${colors.reset}`);
    } else if (highCount > 0) {
      console.log(`${colors.yellow}${colors.bold}⚠️  High severity issues found!${colors.reset}`);
    }
    console.log();
  }
}
