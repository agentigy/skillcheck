import type { ScanResult } from '../scanner.js';
import type { Finding, Severity } from '../types.js';

/**
 * SARIF 2.1.0 Schema Types
 */
interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: SarifTool;
  results: SarifResult[];
  invocations?: SarifInvocation[];
}

interface SarifTool {
  driver: SarifToolComponent;
}

interface SarifToolComponent {
  name: string;
  informationUri: string;
  version: string;
  rules: SarifRule[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: {
    text: string;
  };
  fullDescription?: {
    text: string;
  };
  help?: {
    text: string;
  };
  properties?: {
    tags?: string[];
    'security-severity'?: string;
  };
}

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  message: {
    text: string;
  };
  locations: SarifLocation[];
  properties?: {
    cwe?: string;
  };
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: {
      uri: string;
    };
    region: {
      startLine: number;
      startColumn?: number;
      snippet?: {
        text: string;
      };
    };
  };
}

interface SarifInvocation {
  executionSuccessful: boolean;
  endTimeUtc: string;
}

/**
 * Convert severity to SARIF level
 */
function severityToSarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'CRITICAL':
      return 'error';
    case 'HIGH':
      return 'error';
    case 'MEDIUM':
      return 'warning';
    case 'LOW':
      return 'note';
  }
}

/**
 * Convert severity to numeric security severity (0-10)
 * Used by GitHub to determine display priority
 */
function severityToSecuritySeverity(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL':
      return '9.0';
    case 'HIGH':
      return '7.0';
    case 'MEDIUM':
      return '5.0';
    case 'LOW':
      return '3.0';
  }
}

/**
 * Convert a Finding to a SARIF result
 */
function findingToSarifResult(finding: Finding): SarifResult {
  const result: SarifResult = {
    ruleId: finding.ruleId,
    level: severityToSarifLevel(finding.severity),
    message: {
      text: finding.message,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: finding.file,
          },
          region: {
            startLine: finding.line + 1, // SARIF uses 1-indexed line numbers
            startColumn: finding.column !== undefined ? finding.column + 1 : undefined,
            snippet: finding.snippet ? {
              text: finding.snippet,
            } : undefined,
          },
        },
      },
    ],
  };

  if (finding.cwe) {
    result.properties = {
      cwe: finding.cwe,
    };
  }

  return result;
}

/**
 * Extract unique rules from scan results
 */
function extractRules(results: ScanResult[]): Map<string, SarifRule> {
  const rulesMap = new Map<string, SarifRule>();

  for (const result of results) {
    for (const finding of result.findings) {
      if (!rulesMap.has(finding.ruleId)) {
        rulesMap.set(finding.ruleId, {
          id: finding.ruleId,
          name: finding.ruleId,
          shortDescription: {
            text: finding.message,
          },
          fullDescription: {
            text: finding.remediation,
          },
          help: {
            text: `${finding.remediation}${finding.cwe ? `\n\nReference: ${finding.cwe}` : ''}`,
          },
          properties: {
            tags: ['security'],
            'security-severity': severityToSecuritySeverity(finding.severity),
          },
        });
      }
    }
  }

  return rulesMap;
}

/**
 * SARIF reporter that outputs results in SARIF 2.1.0 format
 * Compatible with GitHub Code Scanning
 */
export class SarifReporter {
  /**
   * Generate SARIF report and write to stdout
   */
  report(results: ScanResult[]): void {
    const sarifLog = this.generateSarif(results);
    console.log(JSON.stringify(sarifLog, null, 2));
  }

  /**
   * Generate SARIF log object from scan results
   */
  generateSarif(results: ScanResult[]): SarifLog {
    const rules = extractRules(results);
    const sarifResults: SarifResult[] = [];

    // Collect all findings
    for (const result of results) {
      for (const finding of result.findings) {
        sarifResults.push(findingToSarifResult(finding));
      }
    }

    const sarifLog: SarifLog = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'SkillCheck',
              informationUri: 'https://github.com/agentigy/skillcheck',
              version: '1.0.0',
              rules: Array.from(rules.values()),
            },
          },
          results: sarifResults,
          invocations: [
            {
              executionSuccessful: true,
              endTimeUtc: new Date().toISOString(),
            },
          ],
        },
      ],
    };

    return sarifLog;
  }
}
