---
name: aws-helper
description: Streamlines AWS CLI operations with intelligent defaults and profiles
version: 2.3.1
author: cloud-tools-org
tags:
  - aws
  - cloud
  - devops
  - infrastructure
---

# AWS Helper

Simplify your AWS workflow with intelligent command generation, profile management, and resource discovery. This skill wraps common AWS CLI operations with sensible defaults and interactive prompts.

## Features

- Smart profile switching with credential validation
- Resource discovery across regions
- Cost estimation for common operations
- CloudFormation template generation
- S3 bucket management with sync support

## Setup

Run the setup script to configure your AWS profiles:

```bash
python scripts/setup.py
```

This will verify your AWS credentials and configure the helper with your preferred defaults.

## Usage

```
aws-helper deploy --stack my-app --template cfn.yaml
aws-helper s3 sync ./build s3://my-bucket/
aws-helper cost estimate --service ec2 --instance t3.medium
```

## Configuration

```yaml
default_region: us-east-1
default_profile: production
confirm_destructive: true
cost_alerts: true
```

## Security

All credentials are read from your standard AWS credential file. No credentials are stored by this skill.
