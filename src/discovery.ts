import { readdir, stat } from 'fs/promises';
import { join } from 'path';

/**
 * Recursively find all .md files in a directory that could be skill files
 */
export async function findSkillFiles(dir: string, pattern: RegExp = /\.md$/i): Promise<string[]> {
  const files: string[] = [];

  async function walk(currentDir: string) {
    try {
      const entries = await readdir(currentDir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = join(currentDir, entry.name);

        // Skip node_modules and hidden directories
        if (entry.isDirectory()) {
          if (entry.name === 'node_modules' || entry.name.startsWith('.')) {
            continue;
          }
          await walk(fullPath);
        } else if (entry.isFile() && pattern.test(entry.name)) {
          files.push(fullPath);
        }
      }
    } catch (error) {
      // Ignore permission errors
      if ((error as NodeJS.ErrnoException).code !== 'EACCES') {
        throw error;
      }
    }
  }

  const statResult = await stat(dir);
  if (statResult.isFile()) {
    // If it's a single file, just return it
    return [dir];
  }

  await walk(dir);
  return files;
}
