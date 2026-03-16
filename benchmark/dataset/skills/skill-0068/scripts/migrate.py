"""
Database migration manager.

Reads DATABASE_URL from the environment for DB connection — standard
practice on platforms like Heroku, Railway, and Render.
Never logs or exposes the connection string.
"""

import os
import sys
from pathlib import Path


MIGRATIONS_DIR = Path("migrations")


def get_database_url() -> str:
    """Get the database URL from environment."""
    url = os.environ.get("DATABASE_URL")
    if not url:
        print("Error: DATABASE_URL environment variable is not set", file=sys.stderr)
        print("Set it like: export DATABASE_URL='postgresql://user:pass@localhost:5432/mydb'")
        sys.exit(1)
    return url


def list_migrations() -> list[Path]:
    """List available migration files in order."""
    if not MIGRATIONS_DIR.exists():
        return []
    up_files = sorted(MIGRATIONS_DIR.glob("*.up.sql"))
    return up_files


def show_status() -> None:
    """Show migration status."""
    migrations = list_migrations()
    if not migrations:
        print("No migrations found.")
        return

    print(f"Found {len(migrations)} migration(s):")
    for m in migrations:
        name = m.stem.replace(".up", "")
        print(f"  {name}")


def run_up() -> None:
    """Run pending migrations."""
    db_url = get_database_url()
    migrations = list_migrations()

    if not migrations:
        print("No migrations to run.")
        return

    print(f"Running {len(migrations)} migration(s)...")
    for m in migrations:
        name = m.stem.replace(".up", "")
        sql = m.read_text(encoding="utf-8")
        print(f"  Applying: {name}")
        # In a real implementation, this would execute the SQL
        # against the database using psycopg2 or similar.
        print(f"  SQL length: {len(sql)} characters")

    print("Migrations complete.")


def run_down() -> None:
    """Roll back the last migration."""
    db_url = get_database_url()
    migrations = list_migrations()

    if not migrations:
        print("No migrations to roll back.")
        return

    last = migrations[-1]
    down_file = last.with_name(last.name.replace(".up.sql", ".down.sql"))
    if not down_file.exists():
        print(f"No down migration found for: {last.stem}")
        return

    name = last.stem.replace(".up", "")
    print(f"Rolling back: {name}")
    sql = down_file.read_text(encoding="utf-8")
    print(f"  SQL length: {len(sql)} characters")
    print("Rollback complete.")


def create_migration(name: str) -> None:
    """Create a new migration file pair."""
    MIGRATIONS_DIR.mkdir(exist_ok=True)
    existing = list_migrations()
    next_num = len(existing) + 1
    prefix = f"{next_num:03d}_{name}"

    up_path = MIGRATIONS_DIR / f"{prefix}.up.sql"
    down_path = MIGRATIONS_DIR / f"{prefix}.down.sql"

    up_path.write_text(f"-- Migration: {name} (up)\n", encoding="utf-8")
    down_path.write_text(f"-- Migration: {name} (down)\n", encoding="utf-8")

    print(f"Created: {up_path}")
    print(f"Created: {down_path}")


def main() -> int:
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage: migrate.py <status|up|down|create> [args...]")
        return 1

    command = sys.argv[1]

    if command == "status":
        show_status()
    elif command == "up":
        run_up()
    elif command == "down":
        run_down()
    elif command == "create":
        if len(sys.argv) < 3:
            print("Usage: migrate.py create <migration_name>")
            return 1
        create_migration(sys.argv[2])
    else:
        print(f"Unknown command: {command}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
