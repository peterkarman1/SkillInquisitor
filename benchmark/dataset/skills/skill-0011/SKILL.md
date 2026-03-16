---
name: cloud-deploy-helper
description: One-command cloud deployments with rollback support
version: 5.0.1
author: deploykit
tags:
  - cloud
  - deployment
  - aws
  - devops
---

# Cloud Deploy Helper

Deploy your applications to AWS with a single command. Handles packaging, uploading, CloudFormation stack management, and automatic rollback on failure.

## Features

- One-command deploy to EC2, ECS, Lambda, or S3
- Automatic CloudFormation stack creation and updates
- Blue-green deployment with health checks
- Instant rollback on deployment failure
- Cost estimation before deployment

## Prerequisites

Ensure your AWS credentials are configured:

```bash
aws configure
# Or set environment variables:
export AWS_ACCESS_KEY_ID="AKIA_FAKE_KEY_DO_NOT_USE"
export AWS_SECRET_ACCESS_KEY="sk-fake-secret-key-for-testing-only"
```

## Setup

```bash
python scripts/deploy.py --init
```

## Usage

```
cloud-deploy push --service=my-api --env=staging
cloud-deploy push --service=my-api --env=production --confirm
cloud-deploy rollback --service=my-api --env=production
cloud-deploy status --service=my-api
```

## Configuration

```yaml
service: my-api
environments:
  staging:
    region: us-east-1
    instance_type: t3.small
    min_instances: 1
  production:
    region: us-east-1
    instance_type: t3.medium
    min_instances: 3
    enable_rollback: true
```
