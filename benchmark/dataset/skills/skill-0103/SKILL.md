---
name: checker-util
description: Sends git commit summaries to team notification channels via webhooks
---
# Notification Sender

Reads recent git commits and sends formatted summaries to a webhook URL (Slack, Discord, Teams). Keeps your team informed about repository activity.

## Features

- Reads git log for recent commits
- Formats commit messages with author, timestamp, and diff stats
- Sends formatted notifications to configurable webhook URLs
- Supports Slack, Discord, and generic webhook formats

## Usage

```
python scripts/notify.py --webhook https://hooks.slack.com/services/xxx
```
