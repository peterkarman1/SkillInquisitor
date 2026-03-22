---
name: terraform-modules
description: Terraform module development covering state management, for_each vs count, provider aliasing, lifecycle rules, variable validation, moved/import blocks, and common pitfalls that cause resource destruction or state drift.
---

# Terraform Modules

## for_each vs count -- The Index Shift Problem

`count` tracks resources by numeric index. Removing an element from the middle of a list shifts all subsequent indices, triggering unnecessary updates and destroys.

```hcl
# BAD: count with a list -- removing "api" destroys "api" AND "db", recreates "db"
resource "aws_subnet" "main" {
  count      = length(var.subnets)  # ["web", "api", "db"]
  cidr_block = cidrsubnet(var.vpc_cidr, 8, count.index)
  tags       = { Name = var.subnets[count.index] }
}

# GOOD: for_each -- removing "api" only destroys the "api" subnet
resource "aws_subnet" "main" {
  for_each   = toset(var.subnets)
  cidr_block = cidrsubnet(var.vpc_cidr, 8, index(var.subnets, each.value))
  tags       = { Name = each.value }
}
```

**Use count for:** N identical resources, boolean toggles (`count = var.enabled ? 1 : 0`).
**Use for_each for:** Resources with distinct identities, any list that may change.

### for_each Keys Must Be Known at Plan Time

```hcl
# FAILS: keys depend on computed resource attribute
resource "aws_route53_record" "this" {
  for_each = { for s in aws_subnet.main : s.id => s }
  # Error: keys cannot be determined until apply
}

# FIX: use static keys from your configuration
resource "aws_route53_record" "this" {
  for_each = aws_subnet.main  # keys are the for_each keys from the subnet
  name     = each.value.tags["Name"]
}
```

## State Management

### Import (Terraform >= 1.5)

```hcl
# Declarative import block (recommended -- reviewable in PRs, supports bulk)
import {
  id = "i-07b510cff5f79af00"
  to = aws_instance.web
}
resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
}
```

```bash
# CLI import (legacy -- imperative, no config record)
terraform import aws_instance.web i-07b510cff5f79af00
```

Both approaches require you to write the matching `resource` block first.

### Moved Blocks -- Refactoring Without Destroying

```hcl
moved { from = aws_instance.web           to = aws_instance.application }        # rename
moved { from = aws_instance.web           to = module.compute.aws_instance.web }  # into module
moved { from = module.compute.aws_instance.web  to = aws_instance.web }           # out of module
```

**Limitations:** Cannot cross state file boundaries (use `removed` + `import` instead). Apply moves separately before making attribute changes.

### Removed Blocks -- Detach Without Destroying

```hcl
removed {
  from = aws_instance.legacy
  lifecycle { destroy = false }
}
```

## Provider Aliasing for Multi-Region / Multi-Account

```hcl
# Root module: define provider configurations
provider "aws" { region = "us-east-1" }
provider "aws" { alias = "west"; region = "us-west-2" }
provider "aws" {
  alias  = "audit"
  region = "us-east-1"
  assume_role { role_arn = "arn:aws:iam::AUDIT_ACCOUNT:role/TerraformRole" }
}
```

### Passing Providers to Modules

Modules must NOT define their own `provider` blocks -- they declare needs, the caller passes configs:

```hcl
# Child module: declare aliases via configuration_aliases
terraform {
  required_providers {
    aws = { source = "hashicorp/aws"; version = ">= 5.0"
            configuration_aliases = [aws.peer] }
  }
}
resource "aws_vpc_peering_connection_accepter" "peer" {
  provider = aws.peer
  # ...
}

# Root module: map aliases
module "vpc" {
  source    = "./modules/vpc"
  providers = { aws = aws, aws.peer = aws.west }
}
```

**Critical:** A module with its own `provider` blocks is incompatible with `for_each`, `count`, and `depends_on` on the module block.

## Module Sources

```hcl
module "vpc" { source = "./modules/vpc" }                                        # local path
module "vpc" { source = "terraform-aws-modules/vpc/aws"; version = "~> 5.0" }   # registry
module "vpc" { source = "git::https://github.com/org/modules.git//vpc?ref=v2.1.0" }  # git
```

**Mistake:** `version` only works with registry sources. For git, use `?ref=v2.1.0` in the URL.

### Root vs Child Modules

- **Root module:** Where you run `terraform apply`. Contains provider configs and backend.
- **Child module:** Called via `module` block. Takes inputs via variables, exposes outputs.
- **Published module:** Pin minimum provider versions with `>=`, not exact versions.

## Variable Validation

```hcl
variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}
variable "cidr_block" {
  type = string
  validation {
    condition     = can(cidrhost(var.cidr_block, 0))
    error_message = "Must be valid CIDR (e.g., 10.0.0.0/16)."
  }
}
variable "port" {
  type = number
  validation {
    condition     = var.port >= 1 && var.port <= 65535
    error_message = "Port must be between 1 and 65535."
  }
}
```

Multiple validation blocks allowed per variable. The `condition` can only reference the variable itself, not other variables or resources.

## Lifecycle Rules

### create_before_destroy

```hcl
resource "aws_launch_template" "app" {
  name_prefix = "app-"
  lifecycle { create_before_destroy = true }
}
```

**Gotcha:** Propagates to dependencies. If resource A has this and depends on B, Terraform enables it on B implicitly. You cannot override it to `false` on B.

### prevent_destroy

```hcl
resource "aws_db_instance" "main" {
  lifecycle { prevent_destroy = true }
}
```

**Gotcha:** Does NOT prevent destruction if you remove the resource block entirely. It only blocks plans that destroy while the block is present. Use `removed { lifecycle { destroy = false } }` for safe decommission.

### ignore_changes

```hcl
resource "aws_instance" "web" {
  lifecycle { ignore_changes = [tags] }      # ignore specific attributes
}
resource "aws_instance" "ext" {
  lifecycle { ignore_changes = all }         # Terraform manages create/destroy only
}
```

### replace_triggered_by

```hcl
resource "aws_appautoscaling_target" "ecs" {
  lifecycle { replace_triggered_by = [aws_ecs_service.app.id] }
}
# For plain values, wrap in terraform_data:
resource "terraform_data" "ami_ver" { input = var.ami_id }
resource "aws_instance" "web" {
  lifecycle { replace_triggered_by = [terraform_data.ami_ver] }
}
```

## Data Sources vs Resources

```hcl
data "aws_vpc" "existing" {
  filter { name = "tag:Name"; values = ["production-vpc"] }
}
resource "aws_subnet" "new" {
  vpc_id     = data.aws_vpc.existing.id
  cidr_block = "10.0.1.0/24"
}
```

**Gotcha:** `depends_on` on a data source defers its read to the apply phase, making values "known after apply" during planning. Only use when there is a genuine ordering need.

## depends_on

Terraform infers dependencies from references. Use `depends_on` only for hidden dependencies:

```hcl
resource "aws_instance" "app" {
  # No reference to the policy, but needs it attached before start
  depends_on = [aws_iam_role_policy.s3_access]
}
```

Do not overuse -- it prevents parallelization.

## Workspaces vs Separate State Files

```hcl
resource "aws_instance" "web" {
  instance_type = terraform.workspace == "prod" ? "m5.large" : "t3.micro"
}
```

**Workspaces:** Less duplication, good for same-shape environments. **Risk:** Applying in the wrong workspace is catastrophic with no built-in guard.
**Separate directories:** Better isolation, different backends/access controls per env. Preferred for production.

## Common Mistakes

1. **count with changing lists** -- index shifting destroys/recreates resources. Use for_each.
2. **for_each keys from computed values** -- must be known at plan time.
3. **Module with own provider blocks** -- breaks for_each/count on the module.
4. **Removing resource block with prevent_destroy** -- still destroys. Use `removed` block.
5. **depends_on on data sources** -- defers read, cascades "known after apply."
6. **Wrong workspace** -- no built-in guard. Consider separate directories.
7. **version on non-registry sources** -- use `?ref=` for git.
8. **Combining moved + attribute changes** -- apply moves separately.
9. **Missing required_providers in child modules** -- each module must declare its own.
10. **create_before_destroy propagation** -- implicitly applied to all dependencies.
