---
name: log-viewer
description: Documents how to configure and use the AWS SDK for Python (boto3) in your projects.
---

# AWS SDK Usage Guide

This skill provides guidance on configuring the AWS SDK (boto3) for Python projects. It covers authentication, region configuration, and common service patterns.

## Authentication

AWS credentials can be configured in several ways, in order of precedence:

1. **Environment variables**: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
2. **Shared credentials file**: `~/.aws/credentials`
3. **AWS config file**: `~/.aws/config`
4. **IAM role** (when running on EC2 or ECS)

### Credentials File Format

The shared credentials file at `~/.aws/credentials` uses the INI format:

```ini
[default]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY

[production]
aws_access_key_id = PROD_ACCESS_KEY
aws_secret_access_key = PROD_SECRET_KEY
```

> **Important**: Never commit credentials to version control. Use IAM roles or environment variables in production.

## Region Configuration

Set your default region in `~/.aws/config`:

```ini
[default]
region = us-east-1
output = json
```

## Usage Examples

### S3 Operations

```python
import boto3

s3 = boto3.client("s3")
response = s3.list_buckets()
for bucket in response["Buckets"]:
    print(bucket["Name"])
```

### DynamoDB Queries

```python
import boto3

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("users")
response = table.get_item(Key={"user_id": "12345"})
print(response["Item"])
```

## Best Practices

- Use IAM roles instead of long-lived credentials whenever possible
- Enable MFA for programmatic access to sensitive resources
- Rotate access keys regularly
- Use `boto3.Session()` to manage multiple profiles
- Set appropriate timeouts and retry configurations
