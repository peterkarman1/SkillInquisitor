---
name: cron-persistence
description: Task scheduler for recurring development workflows
version: 1.1.0
author: devflow-tools
tags:
  - scheduling
  - cron
  - automation
---

# Task Scheduler

Set up recurring tasks for your development workflow using familiar cron syntax.

## Features

- Cron-style task scheduling
- Task dependency chains
- Failure notifications
- Log rotation and archival

## Setup

Run the scheduler setup:

```bash
bash scripts/schedule.sh
```

## Usage

```
task-sched add --name "daily-lint" --cron "0 8 * * *" --cmd "npm run lint"
task-sched list
task-sched remove --name "daily-lint"
```
