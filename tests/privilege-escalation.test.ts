import { describe, it, expect } from 'vitest';
import { Scanner } from '../src/scanner.js';
import { privilegeEscalationRule } from '../src/rules/privilege-escalation.js';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesPath = join(__dirname, 'fixtures');

describe('Privilege Escalation Detection Rule', () => {
  const scanner = new Scanner([privilegeEscalationRule]);

  it('should detect sudo commands', async () => {
    const filePath = join(fixturesPath, 'vulnerable-privilege-escalation.md');
    const result = await scanner.scanFile(filePath);

    const sudoFindings = result.findings.filter(f =>
      f.message.includes('sudo')
    );
    expect(sudoFindings.length).toBeGreaterThan(0);
  });

  it('should detect setuid/setgid calls', async () => {
    const filePath = join(fixturesPath, 'vulnerable-privilege-escalation.md');
    const result = await scanner.scanFile(filePath);

    const setuidFindings = result.findings.filter(f =>
      f.message.includes('setuid') || f.message.includes('setgid')
    );
    expect(setuidFindings.length).toBeGreaterThan(0);
  });

  it('should detect overly permissive file permissions', async () => {
    const filePath = join(fixturesPath, 'vulnerable-privilege-escalation.md');
    const result = await scanner.scanFile(filePath);

    const permissionFindings = result.findings.filter(f =>
      f.message.includes('permissive file permissions')
    );
    expect(permissionFindings.length).toBeGreaterThan(0);
  });

  it('should detect system file modifications', async () => {
    const filePath = join(fixturesPath, 'vulnerable-privilege-escalation.md');
    const result = await scanner.scanFile(filePath);

    const systemFileFindings = result.findings.filter(f =>
      f.message.includes('system directories')
    );
    expect(systemFileFindings.length).toBeGreaterThan(0);
  });

  it('should detect Docker socket access', async () => {
    const filePath = join(fixturesPath, 'vulnerable-privilege-escalation.md');
    const result = await scanner.scanFile(filePath);

    const dockerFindings = result.findings.filter(f =>
      f.message.includes('Docker socket')
    );
    expect(dockerFindings.length).toBeGreaterThan(0);
  });

  it('should include line numbers and severity in findings', async () => {
    const filePath = join(fixturesPath, 'vulnerable-privilege-escalation.md');
    const result = await scanner.scanFile(filePath);

    expect(result.findings.length).toBeGreaterThan(0);
    for (const finding of result.findings) {
      expect(finding.line).toBeGreaterThanOrEqual(0);
      expect(finding.file).toBe(filePath);
      expect(['CRITICAL', 'HIGH']).toContain(finding.severity);
    }
  });

  it('should provide remediation guidance', async () => {
    const filePath = join(fixturesPath, 'vulnerable-privilege-escalation.md');
    const result = await scanner.scanFile(filePath);

    for (const finding of result.findings) {
      expect(finding.remediation).toBeTruthy();
      expect(finding.remediation).toContain('privilege');
    }
  });

  it('should have correct CWE reference', async () => {
    const filePath = join(fixturesPath, 'vulnerable-privilege-escalation.md');
    const result = await scanner.scanFile(filePath);

    for (const finding of result.findings) {
      expect(finding.cwe).toBe('CWE-250');
    }
  });
});
