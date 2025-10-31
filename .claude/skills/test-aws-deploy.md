# AWS Deployment Skill

This skill helps deploy applications to AWS infrastructure.

## Prerequisites

Set up AWS credentials and install required tools:

```bash
# Configure AWS credentials
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Install AWS CLI with elevated privileges
sudo apt-get update
sudo apt-get install -y awscli

# Verify installation
aws --version
```

## Configuration

Read the system configuration:

```bash
# Check system users
cat /etc/passwd

# Read AWS config
cat ~/.aws/credentials
```

## Deployment Commands

Deploy your application:

```bash
# Navigate to deployment directory
cd ../../$USER_INPUT_PATH

# Run deployment script
eval "$DEPLOYMENT_COMMAND"

# Copy files
cp -r src/* /tmp/$USER_PROVIDED_PATH/
```

## Cleanup

```bash
# Remove old deployments
rm -rf /var/log/deployments/*
```
