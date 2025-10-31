# SkillCheck

Security scanner for Claude SKILL.md files. Detects vulnerabilities before they reach production.

Built by Agentigy — securing AI agents and workflows.

## Features

- **Hardcoded Secrets Detection** - Finds API keys, tokens, passwords, and credentials
- **Command Injection Detection** - Identifies unsafe shell command execution
- **Path Traversal Detection** - Catches directory traversal vulnerabilities
- **Smart False Positive Reduction** - Context-aware analysis and placeholder detection
- **Beautiful CLI Output** - Color-coded, actionable security reports

## Installation

```bash
npm install @agentigy/skillcheck
```

Or for development:
```bash
npm install
npm run build
```

## Usage

### Scan a single file
```bash
npx skillcheck .claude/skills/my-skill.md
```

### Scan a directory
```bash
npx skillcheck .
```

### Configure failure threshold
```bash
# Fail CI on HIGH or CRITICAL issues (default: CRITICAL)
npx skillcheck --fail-on HIGH ./skills
```

### Generate SARIF output for GitHub Security
```bash
# Output SARIF format for GitHub Code Scanning
npx skillcheck --format sarif . > results.sarif
```

## Security Rules

### CRITICAL Severity

**Hardcoded Secrets (SECRET_EXPOSURE_001)**
- Detects: AWS keys, API keys, JWT tokens, private keys, GitHub tokens
- Excludes: Placeholders like `your_api_key_here`, `${API_KEY}`, `XXXX`
- CWE-798

**Command Injection (CMD_INJECTION_001)**
- Detects: Unsafe `bash`, `eval()`, `exec()`, `os.system()` with user input
- Context-aware: Skips when validation code is present nearby
- CWE-78

**Privilege Escalation (PRIV_ESCALATION_001)**
- Detects: `sudo`, `setuid/setgid`, `chmod 777`, `su`, `pkexec`, `doas`, kernel module loading, Docker socket access, system file modifications
- Context-aware: Skips when authorization checks are present nearby
- CWE-250

### HIGH Severity

**Path Traversal (PATH_TRAVERSAL_001)**
- Detects: `../` sequences, file operations with unvalidated user paths
- Context-aware: Skips when `path.resolve()` or validation exists
- CWE-22

**Information Disclosure (INFO_DISCLOSURE_001)**
- Detects: SSH keys, AWS credentials, `.env` files, `/etc/passwd`, environment variables, database dumps, browser cookies, Git credentials, connection strings, process lists
- Context-aware: Skips when redaction/filtering code is present nearby
- CWE-200

## Output Formats

### Console (default)
Human-readable output with color-coded severity levels. Best for local development and interactive use.

```bash
npx skillcheck ./skills
```

### SARIF
Machine-readable JSON format compatible with GitHub Code Scanning and other security platforms. Use this for CI/CD integration.

```bash
npx skillcheck --format sarif . > results.sarif
```

You can upload SARIF results to GitHub Security tab using:
```yaml
# .github/workflows/security.yml
- name: Upload SARIF results
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

## Exit Codes

- `0` - No issues found (or below fail threshold)
- `1` - Security issues found at or above fail threshold

## Development

### Run tests
```bash
npm test
```

### Run tests in watch mode
```bash
npm run test:watch
```

### Build
```bash
npm run build
```

### Lint
```bash
npm run lint
```

## Examples

### Vulnerable Skill (Will Fail)

```markdown
# Database Connector

Connect using:
api_key = "sk_live_51HqT2jK3xR9pQ8vN4mL5wY2"

Execute command:
os.system(f"rm {userInput}")
```

**Output:**
```
❌ Critical security issues found!
- Potential Generic API Key detected (Line 4)
- Potential command injection (Line 7)
```

### Secure Skill (Will Pass)

```markdown
# Database Connector

Validate input first:
if userInput not in ALLOWLIST:
    raise ValueError("Invalid input")

Connect using environment variable:
api_key = os.getenv("API_KEY")

Execute with validated input:
os.system(f"rm {shlex.quote(userInput)}")
```

**Output:**
```
✓ No security issues found!
```

## Architecture

- **Parser** - Extracts structure from skill.md files, identifies code blocks
- **Scanner** - Orchestrates rule execution, filters false positives
- **Rules** - Modular security checks with context-aware analysis
- **Reporters** - Multiple output formats (console, SARIF)
- **CLI** - Command-line interface for local and CI usage

## Future Enhancements

- [x] SARIF output format for GitHub Security tab
- [x] Privilege escalation detection
- [x] Information disclosure detection
- [ ] JSON output format
- [ ] GitHub Actions workflow
- [ ] Configuration file support
- [ ] Custom rule definitions
- [ ] VS Code extension

## License

MIT
