import { describe, it, expect } from 'vitest';
import { parseSkillFile, isInCodeBlock } from '../src/parser.js';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesPath = join(__dirname, 'fixtures');

describe('parseSkillFile', () => {
  it('should parse a skill file and extract basic information', async () => {
    const filePath = join(fixturesPath, 'example-skill.md');
    const skill = await parseSkillFile(filePath);

    expect(skill.path).toBe(filePath);
    expect(skill.name).toBe('example-skill');
    expect(skill.content).toContain('Example Skill');
    expect(skill.content).toContain('validate all user input');
  });

  it('should extract code blocks from the content', async () => {
    const filePath = join(fixturesPath, 'example-skill.md');
    const skill = await parseSkillFile(filePath);

    expect(skill.codeBlocks).toHaveLength(1);
    expect(skill.codeBlocks[0].content).toContain('echo "Hello, World!"');
  });

  it('should track line numbers for code blocks', async () => {
    const filePath = join(fixturesPath, 'example-skill.md');
    const skill = await parseSkillFile(filePath);

    const block = skill.codeBlocks[0];
    expect(block.startLine).toBeGreaterThanOrEqual(0);
    expect(block.endLine).toBeGreaterThan(block.startLine);
  });
});

describe('isInCodeBlock', () => {
  it('should return true for lines inside code blocks', async () => {
    const filePath = join(fixturesPath, 'example-skill.md');
    const skill = await parseSkillFile(filePath);

    const block = skill.codeBlocks[0];
    // Line inside the code block
    expect(isInCodeBlock(block.startLine + 1, skill.codeBlocks)).toBe(true);
  });

  it('should return false for lines outside code blocks', async () => {
    const filePath = join(fixturesPath, 'example-skill.md');
    const skill = await parseSkillFile(filePath);

    // First line should not be in a code block
    expect(isInCodeBlock(0, skill.codeBlocks)).toBe(false);
  });
});
