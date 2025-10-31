# Secure Database Connector Skill

This skill connects to a database securely.

## Setup

Configure your API key using an environment variable:

```bash
export API_KEY="your_api_key_here"
```

## Instructions

When connecting to the database, retrieve credentials from environment:

api_key = ${API_KEY}

Also set the AWS credentials via environment variables:
AWS_ACCESS_KEY_ID = $AWS_ACCESS_KEY_ID

For the admin token, use:
token: "your_token_here"

Or use a placeholder:
secret = "XXXXXXXXXXXX"

Password should be: "replace_me_with_actual_password"
