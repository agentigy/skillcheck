import { describe, it, expect } from 'vitest';
import { Scanner } from '../src/scanner.js';
import { commandInjectionRule } from '../src/rules/command-injection.js';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesPath = join(__dirname, 'fixtures');

describe('Command Injection Detection Rule', () => {
  const scanner = new Scanner([commandInjectionRule]);

  it('should detect bash command with variable interpolation', async () => {
    const filePath = join(fixturesPath, 'vulnerable-command-injection.md');
    const result = await scanner.scanFile(filePath);

    const bashFindings = result.findings.filter(f =>
      f.message.toLowerCase().includes('bash') || f.message.toLowerCase().includes('shell command')
    );
    expect(bashFindings.length).toBeGreaterThan(0);
  });

  it('should detect os.system with variables', async () => {
    const filePath = join(fixturesPath, 'vulnerable-command-injection.md');
    const result = await scanner.scanFile(filePath);

    const osSystemFindings = result.findings.filter(f =>
      f.message.includes('system command')
    );
    expect(osSystemFindings.length).toBeGreaterThan(0);
  });

  it('should detect eval with variables', async () => {
    const filePath = join(fixturesPath, 'vulnerable-command-injection.md');
    const result = await scanner.scanFile(filePath);

    const evalFindings = result.findings.filter(f =>
      f.message.includes('eval')
    );
    expect(evalFindings.length).toBeGreaterThan(0);
  });

  it('should detect child_process.exec with variables', async () => {
    const filePath = join(fixturesPath, 'vulnerable-command-injection.md');
    const result = await scanner.scanFile(filePath);

    const nodeFindings = result.findings.filter(f =>
      f.message.includes('Node.js')
    );
    expect(nodeFindings.length).toBeGreaterThan(0);
  });

  it('should detect subprocess with shell=True', async () => {
    const filePath = join(fixturesPath, 'vulnerable-command-injection.md');
    const result = await scanner.scanFile(filePath);

    const subprocessFindings = result.findings.filter(f =>
      f.message.includes('subprocess')
    );
    expect(subprocessFindings.length).toBeGreaterThan(0);
  });

  it('should NOT flag commands with proper validation', async () => {
    const filePath = join(fixturesPath, 'secure-command-validation.md');
    const result = await scanner.scanFile(filePath);

    // Should have zero findings since validation is present
    expect(result.findings).toHaveLength(0);
  });

  it('should include correct severity levels', async () => {
    const filePath = join(fixturesPath, 'vulnerable-command-injection.md');
    const result = await scanner.scanFile(filePath);

    expect(result.findings.length).toBeGreaterThan(0);

    // All findings should be CRITICAL or HIGH
    for (const finding of result.findings) {
      expect(['CRITICAL', 'HIGH']).toContain(finding.severity);
    }
  });

  it('should provide CWE-78 reference', async () => {
    const filePath = join(fixturesPath, 'vulnerable-command-injection.md');
    const result = await scanner.scanFile(filePath);

    for (const finding of result.findings) {
      expect(finding.cwe).toBe('CWE-78');
    }
  });
});
