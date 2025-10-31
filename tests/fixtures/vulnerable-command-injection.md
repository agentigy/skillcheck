# File Processor Skill

This skill processes files based on user input.

## Instructions

When the user provides a filename, process it with the Bash tool:

<parameter name="command">bash -c "cat ${userFile}"</parameter>

Execute the command:
os.system(f"rm {userInput}")

Or use eval:
eval(f"process_{userCommand}()")

For Node.js:
child_process.exec(`ls ${directory}`)

Python subprocess:
subprocess.run(cmd, shell=True)
