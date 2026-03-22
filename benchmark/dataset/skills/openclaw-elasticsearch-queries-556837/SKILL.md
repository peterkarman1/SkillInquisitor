---
name: elasticsearch-queries
description: Elasticsearch Query DSL covering bool queries, match vs term, nested types, multi-match, aggregations, pagination, mappings, and common pitfalls around analyzers, scoring, and field type mismatches.
---

# Elasticsearch Queries

## Bool Query: must, should, must_not, filter

The critical distinction is **scoring vs non-scoring**:

| Clause     | Required? | Affects Score? | Cacheable? |
|------------|-----------|----------------|------------|
| `must`     | Yes       | Yes            | No         |
| `filter`   | Yes       | No             | Yes        |
| `should`   | Depends   | Yes            | No         |
| `must_not` | Excluded  | No             | Yes        |

```json
{
  "query": {
    "bool": {
      "must":     [{ "match": { "title": "elasticsearch guide" } }],
      "filter":   [{ "term": { "status": "published" } },
                    { "range": { "date": { "gte": "2024-01-01" } } }],
      "should":   [{ "term": { "featured": true } }],
      "must_not": [{ "term": { "language": "de" } }]
    }
  }
}
```

**Rule:** If a clause influences ranking, use `must`/`should`. For yes/no filtering, use `filter` -- it is faster (cached, no scoring).

### The minimum_should_match Trap

When `should` appears with `must` or `filter`, should clauses are entirely optional (default `minimum_should_match: 0`). Documents matching zero should clauses still appear -- should only boosts score.

When `should` appears alone in a bool query, at least one must match (default `minimum_should_match: 1`).

```json
{ "bool": {
    "must": [{ "match": { "category": "books" } }],
    "should": [{ "match": { "title": "python" } }, { "match": { "title": "programming" } }],
    "minimum_should_match": 1
}}
```

Without `minimum_should_match: 1`, all books match even if the title contains neither term.

## Match vs Term Queries

### How Analysis Works

Indexing a `text` field: `"The Quick Brown Fox"` becomes tokens `["the", "quick", "brown", "fox"]`.

**term** -- no analysis of the search input:
```json
{ "term": { "title": "The Quick Brown Fox" } }   // 0 hits -- no such token exists
{ "term": { "title": "quick" } }                  // matches -- token exists
```

**match** -- analyzes the search input with the same analyzer:
```json
{ "match": { "title": "The Quick Brown Fox" } }   // matches -- finds any token (OR)
{ "match": { "title": { "query": "quick fox", "operator": "and" } } }  // all tokens required
```

| Query  | Field Type | Use Case |
|--------|------------|----------|
| `term` | `keyword`, `integer`, `date`, `boolean` | Exact match: IDs, status, enums |
| `match`| `text` | Full-text search |

**Common mistake:** `term` on a `text` field. The query is not analyzed but the data was -- they rarely match.

### The .keyword Sub-field

Dynamic mapping creates `text` + `keyword` sub-fields. Use `.keyword` for exact match and aggregations:

```json
{ "term": { "title.keyword": "The Quick Brown Fox" } }           // exact match
{ "aggs": { "titles": { "terms": { "field": "title.keyword" } } } }  // aggregation
```

## Mapping Types

### keyword vs text

- `text`: Analyzed, tokenized. For full-text search. Cannot aggregate or sort directly.
- `keyword`: Not analyzed. Case-sensitive. For exact values, sorting, aggregations.

```json
{ "properties": {
    "description": { "type": "text",
      "fields": { "keyword": { "type": "keyword", "ignore_above": 256 } } },
    "status": { "type": "keyword" }
}}
```

### nested vs object

**object** (default) flattens arrays -- field relationships are lost:

```json
// reviews: [{ "author": "john", "rating": 5 }, { "author": "jane", "rating": 3 }]
// Stored as: reviews.author: ["john","jane"], reviews.rating: [5,3]
// Query for john+rating:3 INCORRECTLY matches
```

**nested** preserves relationships but requires `nested` query/aggregation wrappers:

```json
{ "mappings": { "properties": {
    "reviews": { "type": "nested", "properties": {
        "author": { "type": "keyword" }, "rating": { "type": "integer" } } }
}}}

// Must use nested query wrapper:
{ "query": { "nested": { "path": "reviews", "query": { "bool": { "must": [
    { "match": { "reviews.author": "john" } },
    { "match": { "reviews.rating": 5 } }
]}}}}}
```

**Costs:** Each nested object is a separate Lucene document. Slower queries, more memory. Updates require reindexing the entire parent. Use object unless you must correlate fields within array elements.

## Multi-Match Query

```json
{ "multi_match": { "query": "python programming",
    "fields": ["title^3", "description", "tags^2"], "type": "best_fields" } }
```

**best_fields** (default): Score from the single best-matching field. Use when terms should appear together in one field.

**most_fields**: Combines scores from all matching fields. Use when same text is indexed with different analyzers (stemmed + unstemmed).

**cross_fields**: Treats all fields as one. Each term only needs to match in any one field, but all terms must be present. Use for data split across fields (first_name + last_name).

```json
{ "multi_match": { "query": "John Smith", "type": "cross_fields",
    "fields": ["first_name", "last_name"], "operator": "and" } }
```

**Gotcha:** cross_fields requires all fields to use the same analyzer. Different analyzers cause fields to be searched in separate groups, breaking the logic.

## Aggregations

### Terms Aggregation

```json
{ "size": 0, "aggs": { "popular_tags": {
    "terms": { "field": "tags.keyword", "size": 20 } } } }
```

Results are approximate for high-cardinality fields (each shard returns local top-N). Increase `shard_size` if accuracy matters.

### Sub-Aggregations

```json
{ "size": 0, "aggs": { "by_category": {
    "terms": { "field": "category.keyword", "size": 10 },
    "aggs": { "avg_price": { "avg": { "field": "price" } } }
}}}
```

### Date Histogram

```json
{ "size": 0, "aggs": { "by_month": {
    "date_histogram": { "field": "order_date", "calendar_interval": "month" },
    "aggs": { "revenue": { "sum": { "field": "amount" } } }
}}}
```

**calendar_interval** vs **fixed_interval**: `calendar_interval` for variable-length units (`month`, `quarter`, `year`). `fixed_interval` for fixed durations (`30d`, `1h`). Mixing them (e.g., `"month"` in `fixed_interval`) causes an error.

### Nested Aggregations

```json
{ "size": 0, "aggs": { "reviews_agg": {
    "nested": { "path": "reviews" },
    "aggs": { "avg_rating": { "avg": { "field": "reviews.rating" } } }
}}}
```

Use `reverse_nested` to access parent fields from inside a nested aggregation:

```json
{ "nested": { "path": "reviews" }, "aggs": {
    "high_ratings": { "filter": { "range": { "reviews.rating": { "gte": 4 } } },
      "aggs": { "parent": { "reverse_nested": {},
        "aggs": { "categories": { "terms": { "field": "category.keyword" } } } } } }
}}
```

### Composite Aggregation

For paginated iteration over all buckets (not just top-N):

```json
{ "size": 0, "aggs": { "all": { "composite": { "size": 100,
    "sources": [{ "cat": { "terms": { "field": "category.keyword" } } }],
    "after": { "cat": "electronics" }  // from previous response's after_key
}}}}
```

**Composite vs terms:** terms = approximate top-N, supports metric sorting. Composite = exact, paginated, no metric sorting.

## Pagination

**from + size** (standard): `from + size` cannot exceed 10,000 (default `max_result_window`).

**search_after** (deep pagination): Uses sort values from the last hit. Requires deterministic sort with a tiebreaker:

```json
{ "size": 10,
  "sort": [{ "date": "desc" }, { "_id": "asc" }],
  "search_after": ["2024-06-15T10:30:00.000Z", "doc_abc123"] }
```

**PIT + search_after** (consistent deep pagination): Open a Point in Time for a snapshot, then paginate with search_after within it. Close the PIT when done.

**Scroll API** (deprecated for pagination): Still useful for bulk export/reindexing, but holds cluster resources. Do not use for user-facing pagination.

## Index Settings

```json
PUT /my-index
{ "settings": {
    "number_of_shards": 3, "number_of_replicas": 1, "refresh_interval": "30s",
    "analysis": { "analyzer": {
        "my_analyzer": { "type": "custom", "tokenizer": "standard",
          "filter": ["lowercase", "my_synonyms"] } },
      "filter": { "my_synonyms": { "type": "synonym",
          "synonyms": ["quick,fast,speedy"] } } } },
  "mappings": { "properties": {
      "title": { "type": "text", "analyzer": "my_analyzer" } } } }
```

- `number_of_shards`: Immutable after creation. ~10-50 GB per shard is a good target.
- `number_of_replicas`: Dynamic. Set to 0 during bulk indexing for speed.
- `refresh_interval`: Default `1s`. Set `"30s"` or `"-1"` during heavy indexing.
- Analyzers: Set at creation. Changing requires a new index + reindex.

## Highlighting

```json
{ "query": { "match": { "body": "elasticsearch" } },
  "highlight": { "fields": { "body": {
    "pre_tags": ["<strong>"], "post_tags": ["</strong>"],
    "fragment_size": 150, "number_of_fragments": 3 } } } }
```

Requires `_source` enabled (default) or `term_vector: with_positions_offsets`.

## Common Mistakes

1. **term on a text field** -- query not analyzed, data was. Use match for text, term for keyword.
2. **Aggregating on text field** -- gives meaningless token buckets. Use `.keyword` sub-field.
3. **Querying nested fields without nested wrapper** -- silently returns wrong cross-object matches.
4. **filter vs must confusion** -- must scores, filter does not. Use filter for yes/no conditions.
5. **Ignoring minimum_should_match** -- should is optional when must/filter present.
6. **from + size > 10,000** -- use search_after + PIT for deep pagination.
7. **Scroll for user-facing pagination** -- holds cluster resources. Use search_after.
8. **Dynamic mapping in production** -- guesses types wrong. Define explicit mappings.
9. **calendar_interval vs fixed_interval** -- "month" in fixed_interval errors.
10. **number_of_shards is immutable** -- plan before indexing.
11. **cross_fields with different analyzers** -- breaks cross-field logic.
12. **Forgetting reverse_nested** -- empty results when accessing parent from nested agg.
