import { describe, it, expect } from 'vitest';
import { Scanner } from '../src/scanner.js';
import { secretsRule } from '../src/rules/secrets.js';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesPath = join(__dirname, 'fixtures');

describe('Secrets Detection Rule', () => {
  const scanner = new Scanner([secretsRule]);

  it('should detect hardcoded API keys', async () => {
    const filePath = join(fixturesPath, 'vulnerable-secrets.md');
    const result = await scanner.scanFile(filePath);

    // Should find the API key outside code block
    const apiKeyFindings = result.findings.filter(f =>
      f.message.includes('API Key') || f.message.includes('Generic Secret')
    );
    expect(apiKeyFindings.length).toBeGreaterThan(0);
  });

  it('should detect AWS access keys', async () => {
    const filePath = join(fixturesPath, 'vulnerable-secrets.md');
    const result = await scanner.scanFile(filePath);

    const awsFindings = result.findings.filter(f =>
      f.message.includes('AWS')
    );
    expect(awsFindings.length).toBeGreaterThan(0);
  });

  it('should detect JWT tokens', async () => {
    const filePath = join(fixturesPath, 'vulnerable-secrets.md');
    const result = await scanner.scanFile(filePath);

    const jwtFindings = result.findings.filter(f =>
      f.message.includes('JWT')
    );
    expect(jwtFindings.length).toBeGreaterThan(0);
  });

  it('should NOT flag placeholders', async () => {
    const filePath = join(fixturesPath, 'secure-placeholders.md');
    const result = await scanner.scanFile(filePath);

    // Should have zero findings since all are placeholders
    expect(result.findings).toHaveLength(0);
  });

  it('should NOT flag secrets in code blocks', async () => {
    const filePath = join(fixturesPath, 'vulnerable-secrets.md');
    const result = await scanner.scanFile(filePath);

    // The code block has "your_api_key_here" which should be filtered out
    const codeBlockFindings = result.findings.filter(f =>
      f.snippet?.includes('your_api_key_here')
    );
    expect(codeBlockFindings).toHaveLength(0);
  });

  it('should include line numbers in findings', async () => {
    const filePath = join(fixturesPath, 'vulnerable-secrets.md');
    const result = await scanner.scanFile(filePath);

    expect(result.findings.length).toBeGreaterThan(0);
    for (const finding of result.findings) {
      expect(finding.line).toBeGreaterThanOrEqual(0);
      expect(finding.file).toBe(filePath);
      expect(finding.severity).toBe('CRITICAL');
    }
  });

  it('should provide remediation guidance', async () => {
    const filePath = join(fixturesPath, 'vulnerable-secrets.md');
    const result = await scanner.scanFile(filePath);

    for (const finding of result.findings) {
      expect(finding.remediation).toBeTruthy();
      expect(finding.remediation).toContain('environment variables');
    }
  });
});
