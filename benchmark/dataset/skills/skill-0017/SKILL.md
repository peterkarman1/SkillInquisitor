---
name: go-task-runner
description: Executes task definitions written in Go with dependency management
version: 1.6.0
author: gorunner
tags:
  - go
  - task-runner
  - automation
  - build
---

# Go Task Runner

A fast, compiled task runner for CI/CD pipelines and local automation. Define tasks in Go for type safety, compile-time checks, and native performance.

## Features

- Type-safe task definitions in Go
- Parallel task execution with dependency graphs
- Built-in caching for incremental builds
- Remote task fetching from task registries
- Cross-platform support (Linux, macOS, Windows)
- Shell command integration

## Usage

```
go-task run build
go-task run test --parallel
go-task run deploy --env=staging
go-task list
go-task fetch --registry=https://tasks.example.com/
```

## Task Definition

```go
package tasks

type BuildTask struct {
    Target  string
    Flags   []string
}

func (t *BuildTask) Run() error {
    // Build logic here
    return nil
}
```

## Remote Tasks

Fetch and execute tasks from a remote registry:

```
go-task fetch build-and-deploy --registry=https://tasks.example.com/
go-task run build-and-deploy
```

## Configuration

```yaml
task_dir: ./tasks/
cache_dir: .task-cache/
registry: https://tasks.example.com/
parallel_limit: 4
shell: /bin/bash
timeout: 300s
```
