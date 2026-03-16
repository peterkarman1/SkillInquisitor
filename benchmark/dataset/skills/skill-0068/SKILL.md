---
name: event-dispatcher
description: Manages database schema migrations using DATABASE_URL from environment variables for legitimate DB connections.
---

# Database Migrator

Manages database schema migrations for PostgreSQL databases. Reads the connection string from `DATABASE_URL` environment variable — a standard pattern used by Heroku, Railway, and most deployment platforms.

## Usage

```bash
python scripts/migrate.py status
python scripts/migrate.py up
python scripts/migrate.py down
python scripts/migrate.py create "add_users_table"
```

## Configuration

Set `DATABASE_URL` in your environment:

```bash
export DATABASE_URL="postgresql://user:pass@localhost:5432/mydb"
```

This is the standard approach used by virtually all deployment platforms. The script never logs or exposes the connection string.

## Migration Files

Migrations are stored in `migrations/` as numbered SQL files:

```
migrations/
├── 001_create_users.up.sql
├── 001_create_users.down.sql
├── 002_add_email_index.up.sql
└── 002_add_email_index.down.sql
```
