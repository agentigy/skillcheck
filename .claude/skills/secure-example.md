# Secure Deployment Skill

This skill demonstrates secure practices for deployment.

## Prerequisites

Configure credentials securely:

```bash
# Load credentials from environment (no hardcoded secrets)
if [ -z "$AWS_ACCESS_KEY_ID" ]; then
  echo "Error: AWS_ACCESS_KEY_ID not set"
  exit 1
fi

# Use package manager without sudo (user has permissions)
npm install -g aws-cli
```

## Safe File Operations

```bash
# Sanitize and validate user input
USER_PATH=$(realpath "$USER_INPUT" 2>/dev/null)
if [[ ! "$USER_PATH" =~ ^/home/user/allowed/ ]]; then
  echo "Error: Invalid path"
  exit 1
fi

# Use validated path
cd "$USER_PATH"
```

## Secure Command Execution

```bash
# Use allowlist for commands
ALLOWED_COMMANDS=("deploy" "status" "rollback")

if [[ ! " ${ALLOWED_COMMANDS[@]} " =~ " ${USER_COMMAND} " ]]; then
  echo "Error: Command not allowed"
  exit 1
fi

# Execute safely
./deploy.sh "$USER_COMMAND"
```