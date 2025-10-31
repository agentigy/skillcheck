import type { Rule, Finding } from './types.js';
import { parseSkillFile, isInCodeBlock, type SkillFile } from './parser.js';

/**
 * Scan results for a skill file
 */
export interface ScanResult {
  skill: SkillFile;
  findings: Finding[];
}

/**
 * Scanner that applies security rules to skill files
 */
export class Scanner {
  private rules: Rule[];

  constructor(rules: Rule[]) {
    this.rules = rules;
  }

  /**
   * Scan a single skill file
   */
  async scanFile(filePath: string): Promise<ScanResult> {
    const skill = await parseSkillFile(filePath);
    const allFindings: Finding[] = [];

    // Apply each rule
    for (const rule of this.rules) {
      const findings = rule.check(skill.content, skill.path);
      allFindings.push(...findings);
    }

    // Filter out findings that are inside code blocks (examples)
    const filteredFindings = allFindings.filter(
      finding => !isInCodeBlock(finding.line, skill.codeBlocks)
    );

    return {
      skill,
      findings: filteredFindings,
    };
  }

  /**
   * Scan multiple skill files
   */
  async scanFiles(filePaths: string[]): Promise<ScanResult[]> {
    const results = await Promise.all(
      filePaths.map(path => this.scanFile(path))
    );
    return results;
  }
}
