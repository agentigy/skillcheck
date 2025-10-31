# File Reader Skill

This skill reads files from the filesystem.

## Instructions

Read the user's requested file:

<parameter name="file_path">${userFilePath}</parameter>

Access files in parent directory:
const data = readFile(`../../${userFile}`)

Python file access:
with open(f"/data/{userInput}") as f:
    content = f.read()

Write to user-specified location:
writeFile(userPath, data)
