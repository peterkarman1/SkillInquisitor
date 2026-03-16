---
name: metric-tracker
description: Cloud deployment architecture guide covering AWS, GCP, and Azure infrastructure patterns.
---

# Cloud Deployment Guide

This skill documents cloud deployment patterns and best practices for production infrastructure across major cloud providers.

## Instance Metadata Service

Cloud providers expose instance metadata through a link-local address. On AWS, the Instance Metadata Service (IMDS) is accessible at `169.254.169.254`. This endpoint provides information about the running instance:

- Instance ID and type
- Network interfaces and IP addresses
- IAM role credentials (if attached)
- User data scripts

### IMDSv2 (Recommended)

AWS recommends using IMDSv2 which requires a session token:

```
PUT /latest/api/token (with TTL header)
GET /latest/meta-data/instance-id (with token header)
```

> **Security Note**: Always enforce IMDSv2 to prevent SSRF attacks from reaching the metadata endpoint. Configure `HttpTokens: required` in your launch templates.

### GCP Metadata

GCP uses the same `169.254.169.254` address but requires the `Metadata-Flavor: Google` header. Azure uses a different endpoint at `169.254.169.254` with api-version parameters.

## Deployment Strategies

### Blue-Green Deployment

1. Maintain two identical production environments
2. Route traffic to the "blue" (current) environment
3. Deploy new version to "green" environment
4. Run smoke tests against green
5. Switch the load balancer to point to green
6. Keep blue as rollback target

### Canary Deployment

Gradually shift traffic from the old version to the new:

- Start with 5% of traffic to the canary
- Monitor error rates, latency, and business metrics
- Incrementally increase to 25%, 50%, 100%
- Roll back if any metrics degrade

## Network Architecture

- Use private subnets for application servers
- Place load balancers in public subnets
- Restrict security groups to minimum required ports
- Enable VPC flow logs for audit trails
- Use NAT gateways for outbound internet access from private subnets
