# Secure File Reader Skill

This skill reads files with proper path validation.

## Instructions

Validate and normalize the path before reading:

```typescript
import { resolve, normalize } from 'path';

// Validate the path
const safePath = resolve('/allowed/directory', normalize(userFilePath));
```

<parameter name="file_path">${safePath}</parameter>

For Python, use realpath:
```python
import os
safe_path = os.path.realpath(os.path.join('/data', userInput))
with open(safe_path) as f:
    content = f.read()
```

Always check against allowlist:
```javascript
const allowedDirs = ['/data', '/tmp'];
const normalized = path.normalize(userPath);
if (!allowedDirs.some(dir => normalized.startsWith(dir))) {
  throw new Error('Invalid path');
}
writeFile(normalized, data);
```
