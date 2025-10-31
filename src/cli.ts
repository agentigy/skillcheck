#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { Scanner } from './scanner.js';
import { ALL_RULES } from './rules/index.js';
import { findSkillFiles } from './discovery.js';
import { ConsoleReporter } from './reporters/console.js';
import { SarifReporter } from './reporters/sarif.js';

interface CliOptions {
  path: string;
  help: boolean;
  version: boolean;
  failOn: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  format: 'console' | 'sarif';
}

const USAGE = `
Usage: skillcheck [options] <path>

Scan Claude skill.md files for security vulnerabilities.

Arguments:
  path                    File or directory to scan

Options:
  --format <format>       Output format: console, sarif [default: console]
  --fail-on <severity>    Exit with error code if issues of this severity or higher are found
                          (CRITICAL, HIGH, MEDIUM, LOW) [default: CRITICAL]
  --help                  Show this help message
  --version               Show version

Examples:
  skillcheck .claude/skills/my-skill.md
  skillcheck .
  skillcheck --fail-on HIGH ./skills
  skillcheck --format sarif . > results.sarif
`;

async function main() {
  try {
    const { values, positionals } = parseArgs({
      options: {
        format: {
          type: 'string',
          default: 'console',
        },
        'fail-on': {
          type: 'string',
          default: 'CRITICAL',
        },
        help: {
          type: 'boolean',
          default: false,
        },
        version: {
          type: 'boolean',
          default: false,
        },
      },
      allowPositionals: true,
    });

    const options: CliOptions = {
      path: positionals[0] || '.',
      help: values.help as boolean,
      version: values.version as boolean,
      failOn: (values['fail-on'] as string).toUpperCase() as CliOptions['failOn'],
      format: (values.format as string).toLowerCase() as CliOptions['format'],
    };

    if (options.help) {
      console.log(USAGE);
      process.exit(0);
    }

    if (options.version) {
      console.log('@agentigy/skillcheck v1.0.0');
      process.exit(0);
    }

    if (!positionals[0]) {
      console.error('Error: No path specified\n');
      console.log(USAGE);
      process.exit(1);
    }

    // Validate format option
    const validFormats = ['console', 'sarif'];
    if (!validFormats.includes(options.format)) {
      console.error(`Error: Invalid --format value. Must be one of: ${validFormats.join(', ')}\n`);
      process.exit(1);
    }

    // Validate fail-on option
    const validSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    if (!validSeverities.includes(options.failOn)) {
      console.error(`Error: Invalid --fail-on value. Must be one of: ${validSeverities.join(', ')}\n`);
      process.exit(1);
    }

    // Find all skill files
    const files = await findSkillFiles(options.path);

    if (files.length === 0) {
      console.log('No .md files found to scan.');
      process.exit(0);
    }

    // Scan all files
    const scanner = new Scanner(ALL_RULES);
    const results = await scanner.scanFiles(files);

    // Report results
    if (options.format === 'sarif') {
      const reporter = new SarifReporter();
      reporter.report(results);
    } else {
      const reporter = new ConsoleReporter();
      reporter.report(results);
    }

    // Determine exit code based on findings
    const severityLevels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const failIndex = severityLevels.indexOf(options.failOn);

    for (const result of results) {
      for (const finding of result.findings) {
        const findingIndex = severityLevels.indexOf(finding.severity);
        if (findingIndex <= failIndex) {
          // Found an issue at or above the fail threshold
          process.exit(1);
        }
      }
    }

    process.exit(0);
  } catch (error) {
    console.error('Error:', (error as Error).message);
    process.exit(1);
  }
}

main();
