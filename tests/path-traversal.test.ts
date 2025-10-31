import { describe, it, expect } from 'vitest';
import { Scanner } from '../src/scanner.js';
import { pathTraversalRule } from '../src/rules/path-traversal.js';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesPath = join(__dirname, 'fixtures');

describe('Path Traversal Detection Rule', () => {
  const scanner = new Scanner([pathTraversalRule]);

  it('should detect path traversal sequences', async () => {
    const filePath = join(fixturesPath, 'vulnerable-path-traversal.md');
    const result = await scanner.scanFile(filePath);

    const traversalFindings = result.findings.filter(f =>
      f.message.toLowerCase().includes('traversal sequence')
    );
    expect(traversalFindings.length).toBeGreaterThan(0);
  });

  it('should detect file_path parameter with user input', async () => {
    const filePath = join(fixturesPath, 'vulnerable-path-traversal.md');
    const result = await scanner.scanFile(filePath);

    const toolFindings = result.findings.filter(f =>
      f.message.toLowerCase().includes('file_path parameter')
    );
    expect(toolFindings.length).toBeGreaterThan(0);
  });

  it('should detect readFile with variables', async () => {
    const filePath = join(fixturesPath, 'vulnerable-path-traversal.md');
    const result = await scanner.scanFile(filePath);

    const readFileFindings = result.findings.filter(f =>
      f.message.toLowerCase().includes('file system operation')
    );
    expect(readFileFindings.length).toBeGreaterThan(0);
  });

  it('should detect Python open() with variables', async () => {
    const filePath = join(fixturesPath, 'vulnerable-path-traversal.md');
    const result = await scanner.scanFile(filePath);

    const pythonFindings = result.findings.filter(f =>
      f.message.toLowerCase().includes('python open')
    );
    expect(pythonFindings.length).toBeGreaterThan(0);
  });

  it('should NOT flag file operations with proper validation', async () => {
    const filePath = join(fixturesPath, 'secure-path-validation.md');
    const result = await scanner.scanFile(filePath);

    // Should have zero findings since validation is present
    expect(result.findings).toHaveLength(0);
  });

  it('should include correct severity levels', async () => {
    const filePath = join(fixturesPath, 'vulnerable-path-traversal.md');
    const result = await scanner.scanFile(filePath);

    expect(result.findings.length).toBeGreaterThan(0);

    // All findings should be HIGH or MEDIUM
    for (const finding of result.findings) {
      expect(['HIGH', 'MEDIUM']).toContain(finding.severity);
    }
  });

  it('should provide CWE-22 reference', async () => {
    const filePath = join(fixturesPath, 'vulnerable-path-traversal.md');
    const result = await scanner.scanFile(filePath);

    for (const finding of result.findings) {
      expect(finding.cwe).toBe('CWE-22');
    }
  });

  it('should detect writeFile with variables', async () => {
    const filePath = join(fixturesPath, 'vulnerable-path-traversal.md');
    const result = await scanner.scanFile(filePath);

    const writeFileFindings = result.findings.filter(f =>
      f.snippet && f.snippet.includes('writeFile')
    );
    expect(writeFileFindings.length).toBeGreaterThan(0);
  });
});
