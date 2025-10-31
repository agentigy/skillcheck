import { describe, it, expect } from 'vitest';
import { Scanner } from '../src/scanner.js';
import { informationDisclosureRule } from '../src/rules/information-disclosure.js';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesPath = join(__dirname, 'fixtures');

describe('Information Disclosure Detection Rule', () => {
  const scanner = new Scanner([informationDisclosureRule]);

  it('should detect environment variable exposure', async () => {
    const filePath = join(fixturesPath, 'vulnerable-information-disclosure.md');
    const result = await scanner.scanFile(filePath);

    const envFindings = result.findings.filter(f =>
      f.message.includes('environment variables')
    );
    expect(envFindings.length).toBeGreaterThan(0);
  });

  it('should detect SSH key access', async () => {
    const filePath = join(fixturesPath, 'vulnerable-information-disclosure.md');
    const result = await scanner.scanFile(filePath);

    const sshFindings = result.findings.filter(f =>
      f.message.includes('SSH')
    );
    expect(sshFindings.length).toBeGreaterThan(0);
  });

  it('should detect sensitive file reads', async () => {
    const filePath = join(fixturesPath, 'vulnerable-information-disclosure.md');
    const result = await scanner.scanFile(filePath);

    const fileFindings = result.findings.filter(f =>
      f.message.includes('.env') || f.message.includes('password')
    );
    expect(fileFindings.length).toBeGreaterThan(0);
  });

  it('should detect AWS credentials access', async () => {
    const filePath = join(fixturesPath, 'vulnerable-information-disclosure.md');
    const result = await scanner.scanFile(filePath);

    const awsFindings = result.findings.filter(f =>
      f.message.includes('AWS')
    );
    expect(awsFindings.length).toBeGreaterThan(0);
  });

  it('should detect connection strings with passwords', async () => {
    const filePath = join(fixturesPath, 'vulnerable-information-disclosure.md');
    const result = await scanner.scanFile(filePath);

    const connStrFindings = result.findings.filter(f =>
      f.message.includes('Connection string')
    );
    expect(connStrFindings.length).toBeGreaterThan(0);
  });

  it('should include line numbers and severity in findings', async () => {
    const filePath = join(fixturesPath, 'vulnerable-information-disclosure.md');
    const result = await scanner.scanFile(filePath);

    expect(result.findings.length).toBeGreaterThan(0);
    for (const finding of result.findings) {
      expect(finding.line).toBeGreaterThanOrEqual(0);
      expect(finding.file).toBe(filePath);
      expect(['CRITICAL', 'HIGH', 'MEDIUM']).toContain(finding.severity);
    }
  });

  it('should provide remediation guidance', async () => {
    const filePath = join(fixturesPath, 'vulnerable-information-disclosure.md');
    const result = await scanner.scanFile(filePath);

    for (const finding of result.findings) {
      expect(finding.remediation).toBeTruthy();
      expect(finding.remediation).toContain('sensitive');
    }
  });

  it('should have correct CWE reference', async () => {
    const filePath = join(fixturesPath, 'vulnerable-information-disclosure.md');
    const result = await scanner.scanFile(filePath);

    for (const finding of result.findings) {
      expect(finding.cwe).toBe('CWE-200');
    }
  });
});
