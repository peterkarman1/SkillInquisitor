---
name: sqlite-advanced
description: Use SQLite's advanced capabilities correctly -- FTS5 full-text search, JSON operators, window functions, WAL mode, UPSERT, strict tables, generated columns, and PRAGMA settings that are off by default.
---

# SQLite Advanced Features

## Critical Defaults That Catch Everyone

### Foreign keys are OFF by default

SQLite parses foreign key constraints but does not enforce them unless you explicitly enable enforcement. This must be done per connection, every time you open the database:

```sql
PRAGMA foreign_keys = ON;
```

Without this, INSERT/UPDATE/DELETE will silently ignore foreign key violations. This is the single most common SQLite gotcha.

### WAL mode is not the default

The default journal mode is DELETE (rollback journal). For any application with concurrent readers, switch to WAL immediately:

```sql
PRAGMA journal_mode = WAL;
```

WAL mode allows concurrent readers while a writer is active. In DELETE mode, readers block writers and vice versa. WAL mode persists across connections -- you only need to set it once per database file.

### Recommended PRAGMA settings for production

```sql
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;       -- Wait up to 5s instead of failing immediately
PRAGMA synchronous = NORMAL;      -- Safe with WAL; FULL is needlessly slow
PRAGMA cache_size = -64000;       -- 64MB cache (negative = KB)
PRAGMA foreign_keys = ON;
PRAGMA temp_store = MEMORY;       -- Store temp tables in memory
```

Set these at the start of every connection. They do not persist (except `journal_mode`).

## Flexible Typing and STRICT Tables

SQLite uses type affinity, not strict types. A column declared `INTEGER` will happily store the string `'hello'`. This is by design, but it causes subtle bugs when you expect type enforcement.

```sql
-- In a normal table, this succeeds silently:
CREATE TABLE t(x INTEGER);
INSERT INTO t VALUES('not a number');  -- Stores the string as-is
SELECT typeof(x) FROM t;              -- 'text'
```

### STRICT tables (3.37+)

Add `STRICT` at the end of CREATE TABLE to get type enforcement:

```sql
CREATE TABLE t(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  score REAL
) STRICT;

-- This now raises an error:
INSERT INTO t(id, name, score) VALUES(1, 'Alice', 'not a number');
-- Error: cannot store TEXT value in REAL column t.score
```

Allowed types in STRICT tables: `INT`, `INTEGER`, `REAL`, `TEXT`, `BLOB`, `ANY`.

The `ANY` type explicitly preserves whatever you insert without coercion -- useful when you genuinely want flexible typing on a specific column.

## FTS5: Full-Text Search

### Creating an FTS5 table

```sql
CREATE VIRTUAL TABLE articles USING fts5(title, body);
```

Do not add column types, constraints, or PRIMARY KEY to FTS5 table definitions -- they will cause an error. FTS5 tables have an implicit `rowid`.

### Querying with MATCH

```sql
SELECT * FROM articles WHERE articles MATCH 'sqlite';            -- Basic
SELECT * FROM articles WHERE articles MATCH '"full text search"'; -- Phrase
SELECT * FROM articles WHERE articles MATCH 'sqlite OR postgres'; -- Boolean (AND is implicit)
SELECT * FROM articles WHERE articles MATCH 'sql*';              -- Prefix
SELECT * FROM articles WHERE articles MATCH 'title:sqlite';      -- Column filter
```

### Ranking with bm25()

The built-in `bm25()` function scores results by relevance. Lower values mean better matches (it returns negative scores):

```sql
SELECT *, bm25(articles) AS score
FROM articles
WHERE articles MATCH 'database'
ORDER BY score;  -- Best matches first (most negative)
```

Weight columns differently by passing arguments to bm25 -- one weight per column in table definition order:

```sql
-- Give title matches 10x weight vs body
SELECT *, bm25(articles, 10.0, 1.0) AS score
FROM articles
WHERE articles MATCH 'database'
ORDER BY score;
```

### highlight() and snippet()

```sql
-- Wrap matches in HTML tags
SELECT highlight(articles, 0, '<b>', '</b>') AS title
FROM articles WHERE articles MATCH 'sqlite';

-- Extract a snippet with context (column, before-tag, after-tag, ellipsis, max-tokens)
SELECT snippet(articles, 1, '<b>', '</b>', '...', 32) AS excerpt
FROM articles WHERE articles MATCH 'sqlite';
```

The second argument to highlight/snippet is the column index (0-based, in table definition order).

### External content FTS5 tables

To keep FTS in sync with a regular table, use `content=` and triggers:

```sql
CREATE TABLE docs(id INTEGER PRIMARY KEY, title TEXT, body TEXT);
CREATE VIRTUAL TABLE docs_fts USING fts5(title, body, content=docs, content_rowid=id);

-- Sync trigger (insert). Add similar triggers for DELETE and UPDATE.
CREATE TRIGGER docs_ai AFTER INSERT ON docs BEGIN
  INSERT INTO docs_fts(rowid, title, body) VALUES(new.id, new.title, new.body);
END;
```

For DELETE/UPDATE triggers, use the special syntax `INSERT INTO docs_fts(docs_fts, rowid, ...) VALUES('delete', old.id, ...)` -- the first column name must match the table name. This is how FTS5 removes content from external content tables.

## JSON Functions

JSON support is built in since SQLite 3.38.0 (was opt-in before that).

### json_extract() and the ->> operator

```sql
-- json_extract returns JSON types (strings include quotes)
SELECT json_extract('{"name":"Alice","age":30}', '$.name');  -- 'Alice' (text)
SELECT json_extract('{"a":[1,2,3]}', '$.a');                 -- '[1,2,3]' (text, JSON)

-- -> returns JSON (preserves type)
SELECT '{"name":"Alice"}' -> '$.name';   -- "Alice" (with quotes -- JSON string)

-- ->> returns SQL value (unquoted)
SELECT '{"name":"Alice"}' ->> '$.name';  -- Alice (without quotes -- SQL text)
```

Key difference: `json_extract()` and `->>` return SQL values. The `->` operator returns a JSON value (strings stay quoted). When comparing or using in WHERE clauses, `->>` is usually what you want.

### json_each() -- iterate JSON arrays

```sql
-- Expand a JSON array into rows
SELECT value FROM json_each('[10, 20, 30]');
-- Returns: 10, 20, 30

-- Query rows where a JSON array column contains a value
SELECT * FROM events
WHERE EXISTS (
  SELECT 1 FROM json_each(events.tags) WHERE value = 'urgent'
);

-- Iterate object keys
SELECT key, value FROM json_each('{"a":1,"b":2}');
-- Returns: a|1, b|2
```

### json_group_array() and json_set()

```sql
-- Aggregate into JSON array
SELECT json_group_array(name) FROM users WHERE dept = 'eng';
-- Returns: '["Alice","Bob","Carol"]'
```

### json_set(), json_insert(), json_replace()

These differ in how they handle existing vs. missing keys:

| Function | Key exists | Key missing |
|----------|-----------|-------------|
| `json_set()` | Updates | Inserts |
| `json_insert()` | No-op | Inserts |
| `json_replace()` | Updates | No-op |

```sql
UPDATE config SET data = json_set(data, '$.theme', 'dark') WHERE id = 1;
```

## Window Functions (3.25+)

Standard SQL window functions -- compute across related rows without collapsing like GROUP BY:

```sql
-- Ranking
SELECT name, score,
  ROW_NUMBER() OVER (ORDER BY score DESC) AS row_num,
  RANK() OVER (PARTITION BY dept ORDER BY salary DESC) AS dept_rank
FROM employees;

-- LAG / LEAD for previous/next row
SELECT date, revenue,
  revenue - LAG(revenue) OVER (ORDER BY date) AS daily_change
FROM daily_sales;

-- Running total with frame spec
SELECT date, amount,
  SUM(amount) OVER (ORDER BY date ROWS UNBOUNDED PRECEDING) AS running_total
FROM transactions;
```

Frame specs: `ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW` (default with ORDER BY), `ROWS BETWEEN 2 PRECEDING AND 2 FOLLOWING` (sliding window).

## UPSERT: INSERT ... ON CONFLICT

Do not confuse `INSERT OR REPLACE` with `INSERT ... ON CONFLICT DO UPDATE`. They behave very differently:

- `INSERT OR REPLACE` **deletes** the conflicting row, then inserts. This resets the rowid, fires DELETE triggers, and cascades any ON DELETE foreign key actions.
- `INSERT ... ON CONFLICT DO UPDATE` **updates** the existing row in place. No deletion occurs.

```sql
-- Word frequency counter -- insert or increment
CREATE TABLE vocab(word TEXT PRIMARY KEY, count INT DEFAULT 1);
INSERT INTO vocab(word) VALUES('hello')
  ON CONFLICT(word) DO UPDATE SET count = count + 1;

-- Use excluded.column to reference the would-be-inserted value
CREATE TABLE kv(key TEXT PRIMARY KEY, value TEXT, updated_at TEXT);
INSERT INTO kv(key, value, updated_at) VALUES('theme', 'dark', datetime('now'))
  ON CONFLICT(key) DO UPDATE SET
    value = excluded.value,
    updated_at = excluded.updated_at;
```

The `excluded` pseudo-table refers to the row that was proposed for insertion. This is the same syntax as PostgreSQL.

When using UPSERT with a SELECT source, add `WHERE true` to the SELECT to avoid a parsing ambiguity where the parser confuses ON CONFLICT with a JOIN's ON clause:

```sql
INSERT INTO t1 SELECT * FROM t2 WHERE true
  ON CONFLICT(x) DO UPDATE SET y = excluded.y;
```

## RETURNING Clause (3.35+)

Get back rows affected by INSERT, UPDATE, or DELETE:

```sql
INSERT INTO users(name, email) VALUES('Alice', 'alice@example.com')
  RETURNING id, name;

DELETE FROM sessions WHERE expires_at < datetime('now')
  RETURNING user_id;
```

RETURNING only returns rows directly modified by the statement -- not rows affected by triggers or cascading foreign key actions.

## Generated Columns (3.31+)

```sql
CREATE TABLE products(
  price REAL,
  quantity INT,
  total REAL GENERATED ALWAYS AS (price * quantity) STORED,
  label TEXT AS (price || ' x ' || quantity) VIRTUAL
);
```

- **VIRTUAL** (default): computed on read, no disk space. Can be added via ALTER TABLE.
- **STORED**: computed on write, takes disk space, indexable. Cannot be added after table creation.

Generated columns cannot reference subqueries, aggregate functions, or other tables.

## Date and Time Functions

SQLite has no native datetime type. Dates are stored as TEXT (ISO-8601), INTEGER (Unix timestamp), or REAL (Julian day).

```sql
SELECT datetime('now');                              -- '2025-01-15 14:30:00'
SELECT unixepoch();                                  -- Unix timestamp as integer (3.38+)
SELECT date('now', '+7 days');                       -- Date arithmetic
SELECT date('now', '-1 month', 'start of month');    -- Modifiers chain left to right
SELECT julianday('2025-12-31') - julianday('2025-01-01');  -- Difference in days
SELECT strftime('%Y-%m', '2025-01-15');              -- Custom formatting
```

Before 3.38, there is no `unixepoch()` -- use `CAST(strftime('%s', 'now') AS INTEGER)` instead.

## Common Mistakes

1. **Forgetting PRAGMA foreign_keys = ON** -- constraints are parsed but not enforced by default.

2. **Not using WAL mode** -- DELETE journal mode causes `SQLITE_BUSY` errors under any concurrency.

3. **Not setting busy_timeout** -- without it, concurrent writes fail immediately with SQLITE_BUSY instead of retrying.

4. **INSERT OR REPLACE when you mean UPSERT** -- REPLACE deletes and re-inserts, which resets rowid, fires DELETE triggers, and cascades ON DELETE actions.

5. **Text affinity surprises** -- storing `'123'` in an INTEGER column of a non-STRICT table stores the integer 123. But a column with TEXT affinity stores everything as text, so comparing `WHERE id = 123` against a text `'123'` uses different comparison rules.

6. **Double-quoted string literals** -- SQLite treats `"hello"` as an identifier first, but if no such column exists, it falls back to treating it as a string literal. This masks typos. Always use single quotes for strings.

7. **Assuming AUTOINCREMENT works like MySQL** -- In SQLite, `INTEGER PRIMARY KEY` already auto-assigns rowids. Adding `AUTOINCREMENT` only prevents reuse of deleted rowids -- it does NOT change the auto-assignment behavior and adds overhead.

8. **PRIMARY KEYs can contain NULLs** -- unless the column is `INTEGER PRIMARY KEY` or the table is `STRICT`/`WITHOUT ROWID`, a PRIMARY KEY column allows NULL values. Always add an explicit `NOT NULL` constraint.

