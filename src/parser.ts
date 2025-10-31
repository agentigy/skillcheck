import { readFile } from 'fs/promises';
import { basename } from 'path';

/**
 * Represents a parsed Claude skill.md file
 */
export interface SkillFile {
  /** Absolute path to the file */
  path: string;
  /** Skill name (derived from filename) */
  name: string;
  /** Full file content */
  content: string;
  /** Code blocks that should be excluded from analysis */
  codeBlocks: CodeBlock[];
}

export interface CodeBlock {
  /** Starting line number (0-indexed) */
  startLine: number;
  /** Ending line number (0-indexed) */
  endLine: number;
  /** Code block content */
  content: string;
}

/**
 * Parses a Claude skill.md file and extracts structured information
 */
export async function parseSkillFile(filePath: string): Promise<SkillFile> {
  const content = await readFile(filePath, 'utf-8');
  const name = basename(filePath, '.md');
  const codeBlocks = extractCodeBlocks(content);

  return {
    path: filePath,
    name,
    content,
    codeBlocks,
  };
}

/**
 * Extracts code blocks from markdown content.
 * Code blocks should not be analyzed for security issues since they're examples.
 */
function extractCodeBlocks(content: string): CodeBlock[] {
  const blocks: CodeBlock[] = [];
  const lines = content.split('\n');

  let inCodeBlock = false;
  let blockStart = -1;
  let blockContent: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.trim().startsWith('```')) {
      if (!inCodeBlock) {
        // Start of code block
        inCodeBlock = true;
        blockStart = i;
        blockContent = [];
      } else {
        // End of code block
        inCodeBlock = false;
        blocks.push({
          startLine: blockStart,
          endLine: i,
          content: blockContent.join('\n'),
        });
      }
    } else if (inCodeBlock) {
      blockContent.push(line);
    }
  }

  return blocks;
}

/**
 * Checks if a line number is inside a code block
 */
export function isInCodeBlock(lineNumber: number, codeBlocks: CodeBlock[]): boolean {
  return codeBlocks.some(
    block => lineNumber >= block.startLine && lineNumber <= block.endLine
  );
}
