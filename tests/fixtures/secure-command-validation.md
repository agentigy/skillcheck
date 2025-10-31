# Secure File Processor Skill

This skill processes files with proper validation.

## Instructions

When the user provides a filename, validate it first:

First, validate the user input against an allowlist:
```typescript
const allowed = ['file1.txt', 'file2.txt'];
if (!allowed.includes(userFile)) {
  throw new Error('Invalid file');
}
```

Then execute the command:
```bash
<parameter name="command">bash -c "cat ${userFile}"</parameter>
```

Always sanitize user input before using os.system:
```python
# Validate and escape the input
sanitized = shlex.quote(userInput)
os.system(f"rm {sanitized}")
```

For eval, check against whitelist:
```javascript
// Validate command
const validCommands = ['start', 'stop', 'restart'];
if (!validCommands.includes(userCommand)) {
  throw new Error('Invalid command');
}
eval(f"process_{userCommand}()")
```
