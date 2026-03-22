---
name: postgres-queries
description: Write correct, performant PostgreSQL queries. Use when writing window functions, recursive CTEs, LATERAL joins, JSONB operations, upserts, array operations, or interpreting EXPLAIN ANALYZE output. Covers syntax pitfalls, indexing strategies, and performance traps that LLMs commonly get wrong.
---

# PostgreSQL Query Patterns

## Window Functions

ROW_NUMBER, RANK, DENSE_RANK all require `ORDER BY` inside `OVER()`. Without it,
ordering is nondeterministic. The differences only show with ties:
- ROW_NUMBER: always unique (1, 2, 3, 4)
- RANK: ties share rank, then skip (1, 2, 2, 4)
- DENSE_RANK: ties share rank, no skip (1, 2, 2, 3)

```sql
SELECT name, department, salary,
    ROW_NUMBER() OVER (PARTITION BY department ORDER BY salary DESC) AS rn,
    RANK()       OVER (PARTITION BY department ORDER BY salary DESC) AS rnk,
    DENSE_RANK() OVER (PARTITION BY department ORDER BY salary DESC) AS drnk
FROM employees;
```

**Default frame clause gotcha.** With `ORDER BY` present, aggregate window
functions default to `RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW` --
a running total, not the full partition:

```sql
-- Running sum (often unintended)
SELECT date, SUM(revenue) OVER (ORDER BY date) AS running_total FROM sales;

-- Full partition sum -- drop ORDER BY or specify the frame
SELECT date, SUM(revenue) OVER () AS total FROM sales;
SELECT date, SUM(revenue) OVER (ORDER BY date
    ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) AS total FROM sales;
```

**ROWS vs RANGE:** `ROWS` counts physical rows. `RANGE` groups ties. Use `ROWS`
for rolling windows:

```sql
SELECT date, AVG(revenue) OVER (ORDER BY date ROWS BETWEEN 6 PRECEDING AND CURRENT ROW)
    AS rolling_7d FROM sales;
```

LAG/LEAD ignore the frame entirely -- they always operate on the full partition.

## Recursive CTEs

Two parts joined by `UNION ALL`: a base case and a recursive term.

```sql
WITH RECURSIVE org_tree AS (
    -- Base case
    SELECT id, name, manager_id, 1 AS depth FROM employees WHERE manager_id IS NULL
    UNION ALL
    -- Recursive term
    SELECT e.id, e.name, e.manager_id, ot.depth + 1
    FROM employees e JOIN org_tree ot ON e.manager_id = ot.id
)
SELECT * FROM org_tree;
```

**Cycle prevention** -- use path tracking and a depth limit:

```sql
WITH RECURSIVE graph AS (
    SELECT id, parent_id, ARRAY[id] AS path, 1 AS depth
    FROM nodes WHERE parent_id IS NULL
    UNION ALL
    SELECT n.id, n.parent_id, g.path || n.id, g.depth + 1
    FROM nodes n JOIN graph g ON n.parent_id = g.id
    WHERE n.id <> ALL(g.path) AND g.depth < 100
)
SELECT * FROM graph;
```

**Common mistakes:** forgetting the `RECURSIVE` keyword; filtering in the outer
query (affects output) vs in the recursive term (controls traversal); the
recursive term can reference the CTE only once (no self-join).

## EXPLAIN ANALYZE

```sql
EXPLAIN (ANALYZE, BUFFERS) SELECT ...;
-- For writes: BEGIN; EXPLAIN (ANALYZE, BUFFERS) UPDATE ...; ROLLBACK;
```

Key fields: `cost=startup..total` (estimated), `actual time` (ms per loop),
`rows` (estimated vs actual), `loops` (multiply time/rows by this),
`Buffers: shared hit/read` (cache vs disk).

**What to look for:**
1. Bad row estimates (10x+ difference between estimated and actual) at the lowest
   differing node -- usually the root cause of bad plans. Fix with `ANALYZE table`.
2. Seq Scan removing many rows via Filter -- candidate for an index.
3. Nested Loop with high loop count on inner side -- consider Hash/Merge Join.

**Scan types:** Seq Scan (full table), Index Scan (B-tree + heap), Index Only
Scan (index alone), Bitmap Heap Scan (medium selectivity or OR conditions).

## CTEs vs Subqueries (PG 12+)

Since PostgreSQL 12, non-recursive CTEs referenced once are auto-inlined. Before
12, CTEs were always materialized (an "optimization fence"). Use `MATERIALIZED`
or `NOT MATERIALIZED` to override:

```sql
WITH active AS MATERIALIZED (SELECT * FROM users WHERE active) -- force materialize
SELECT * FROM active a1 JOIN active a2 ON a1.referrer_id = a2.id;
```

## LATERAL Joins

A subquery in FROM that can reference columns from preceding tables. Use for
top-N-per-group, set-returning functions, and multi-column correlated subqueries.

```sql
-- Top 3 orders per customer (more efficient than window functions for small N)
SELECT c.id, c.name, r.* FROM customers c
CROSS JOIN LATERAL (
    SELECT o.total, o.created_at FROM orders o
    WHERE o.customer_id = c.id ORDER BY o.created_at DESC LIMIT 3
) r;

-- LEFT JOIN LATERAL keeps rows with no matches; requires ON true
SELECT c.id, r.* FROM customers c
LEFT JOIN LATERAL (
    SELECT o.total FROM orders o WHERE o.customer_id = c.id
    ORDER BY o.created_at DESC LIMIT 1
) r ON true;
```

## Array Operations

```sql
SELECT ARRAY[1,2,3];            -- literal
SELECT (ARRAY['a','b','c'])[1]; -- 1-based indexing
SELECT (ARRAY[1,2,3])[10];     -- out-of-bounds returns NULL (no error)
```

**ANY/ALL:** Use `= ANY(array)` not `IN (array)`:

```sql
SELECT * FROM products WHERE 'electronics' = ANY(tags);
SELECT * FROM products WHERE id = ANY(ARRAY[1,2,3]);
```

**array_agg includes NULLs.** Filter them: `array_agg(x) FILTER (WHERE x IS NOT NULL)`.

**Multi-dimensional trap:** 2D arrays are flat matrices. `ARRAY[[1,2],[3,4]][1]`
returns NULL, not `{1,2}`. You need both subscripts: `[1][2]` returns `2`.

**unnest with ordinality** preserves position:
`SELECT * FROM unnest(ARRAY['a','b']) WITH ORDINALITY AS t(val, pos);`

## JSONB Operations

| Operator | Returns | Use |
|----------|---------|-----|
| `->` | jsonb | `data->'key'` -- keeps JSON type |
| `->>` | text | `data->>'key'` -- extract as text |
| `@>` | boolean | `data @> '{"k":"v"}'` -- containment |
| `?` | boolean | `data ? 'key'` -- key exists |

**The `->` vs `->>` trap:** `->` returns jsonb, so `data->'email' = 'alice@ex.com'`
fails silently (compares jsonb to text). Use `->>` for text comparison:

```sql
SELECT * FROM users WHERE data->>'email' = 'alice@example.com';  -- correct
```

**jsonb_set requires valid jsonb as the value.** Strings need inner quotes:

```sql
UPDATE users SET data = jsonb_set(data, '{name}', '"Alice"') WHERE id = 1;
--                                                 ^ quotes required
```

Other mutations: `data - 'key'` (remove), `data || '{"k":true}'::jsonb` (merge),
`data #- '{nested,key}'` (deep remove).

## UPSERT (INSERT ... ON CONFLICT)

```sql
INSERT INTO products (sku, name, price) VALUES ('ABC', 'Widget', 9.99)
ON CONFLICT (sku) DO UPDATE SET
    name = EXCLUDED.name, price = EXCLUDED.price, updated_at = now();
```

**Gotchas:**
- Conflict target must be a unique index or constraint -- arbitrary columns fail.
- Partial unique indexes need a matching WHERE: `ON CONFLICT (sku) WHERE active = true`.
- `DO NOTHING` does not return the existing row. Use a CTE with RETURNING + UNION ALL fallback.
- Conditional update to avoid no-op writes:

```sql
ON CONFLICT (sku) DO UPDATE SET name = EXCLUDED.name
WHERE products.name IS DISTINCT FROM EXCLUDED.name;
```

## Indexing Strategies

**Partial indexes** -- index a subset of rows. Your query WHERE must match the
index predicate:

```sql
CREATE INDEX idx ON orders (customer_id) WHERE status = 'active';
-- Used by: WHERE status = 'active' AND customer_id = 42
-- NOT used: WHERE customer_id = 42 (missing predicate match)
```

**Expression indexes** -- index computed values. Query must use the same expression:

```sql
CREATE INDEX idx ON users (lower(email));
-- Used by: WHERE lower(email) = '...'
-- NOT used: WHERE email = '...'
```

**GIN for JSONB/arrays** -- supports `@>`, `?`, `&&`. For specific key lookups,
a btree expression index (`(data->>'email')`) is usually faster.

**Covering indexes (INCLUDE)** -- enable index-only scans:

```sql
CREATE INDEX idx ON orders (customer_id) INCLUDE (total, status);
-- Index-only scan for: SELECT total, status WHERE customer_id = 42
```

**Multicolumn order matters.** Index on `(a, b, c)` helps queries filtering on
`a`, `a+b`, or `a+b+c`, but NOT queries filtering only on `b` or `c`.
