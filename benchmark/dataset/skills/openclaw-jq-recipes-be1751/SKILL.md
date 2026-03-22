---
name: jq-recipes
description: Practical jq patterns for filtering, transforming, and reshaping JSON data from the command line -- covering selection, mapping, reduction, error handling, format strings, and common gotchas.
---

# jq Recipes and Patterns

## Core Mental Model

Everything in jq is a filter: it takes an input and produces zero or more outputs. Literals like `42` or `"hello"` are filters that ignore their input. The pipe `|` chains filters. The comma `,` produces multiple outputs from the same input. Understanding this generator model is the key to avoiding confusion.

## Basic Selection

```bash
# Object field access
echo '{"name":"alice","age":30}' | jq '.name'          # "alice"
echo '{"name":"alice"}' | jq '.missing'                 # null (not an error)

# Nested access -- these are equivalent
jq '.foo.bar'
jq '.foo | .bar'

# Keys with special characters require bracket syntax
jq '.["foo-bar"]'
jq '.["foo.bar"]'       # NOT .foo.bar (that chains two lookups)

# Array indexing (zero-based, negative indices count from end)
jq '.[0]'               # first element
jq '.[-1]'              # last element
jq '.[2:5]'             # slice: indices 2,3,4 (exclusive end)
jq '.[:3]'              # first 3 elements
jq '.[-2:]'             # last 2 elements
```

## Iteration and Collection

```bash
# .[] iterates -- produces separate outputs, NOT an array
echo '[1,2,3]' | jq '.[]'
# Output: 1 \n 2 \n 3

# Wrap in [] to collect back into an array
echo '[1,2,3]' | jq '[.[] | . * 2]'    # [2,4,6]

# .[] on objects iterates over values (not keys)
echo '{"a":1,"b":2}' | jq '.[]'        # 1 \n 2

# keys and keys_unsorted return key arrays
echo '{"b":2,"a":1}' | jq 'keys'       # ["a","b"] (sorted)
```

## Object and Array Construction

```bash
# Object construction with shorthand
jq '{name: .name, age: .age}'
jq '{name, age}'                  # equivalent shorthand

# Dynamic keys require parentheses
jq '{(.key): .value}'             # key is evaluated as expression

# GOTCHA: without parens, it's a literal string key
jq '{key: .value}'                # produces {"key": ...}, NOT {<value of .key>: ...}

# Collecting iterator results into an array
jq '[.items[] | .id]'             # array of all .id values
```

## Filtering with select()

```bash
# select(condition) keeps input if condition is true, drops it otherwise
jq '.[] | select(.age >= 18)'
jq '[.[] | select(.status == "active")]'    # filter array, keep array form
jq 'map(select(.price < 100))'             # equivalent to above pattern

# Multiple conditions
jq '.[] | select(.type == "A" and .value > 10)'
jq '.[] | select(.name | test("^foo"))'     # regex match

# GOTCHA: select produces NO output when false, not null
# This means [.[] | select(false)] gives [], not [null, null, ...]
```

## map(), map_values(), and the Difference

```bash
# map(f) is equivalent to [.[] | f] -- always returns an array
jq 'map(.name)'                   # [.[] | .name]
jq 'map(. + 1)'                   # increment all array elements

# map_values(f) preserves structure: array in -> array out, object in -> object out
jq 'map_values(. * 2)'            # on {"a":1,"b":2} -> {"a":2,"b":4}

# KEY DIFFERENCE: map collects ALL outputs, map_values takes only first
echo '[1]' | jq 'map(., .)'       # [1, 1]
echo '[1]' | jq 'map_values(., .)'  # [1]  (only first output kept)
```

## to_entries, from_entries, with_entries

These convert between objects and arrays of `{key, value}` pairs.

```bash
# to_entries: object -> [{key, value}, ...]
echo '{"a":1,"b":2}' | jq 'to_entries'
# [{"key":"a","value":1},{"key":"b","value":2}]

# from_entries: [{key, value}, ...] -> object
# Also accepts "name"/"Name"/"Key" as alternatives to "key"

# with_entries(f) = to_entries | map(f) | from_entries
# Transform all keys:
jq 'with_entries(.key = "prefix_" + .key)'

# Filter object by value:
jq 'with_entries(select(.value > 0))'

# Rename a key:
jq 'with_entries(if .key == "old" then .key = "new" else . end)'
```

## reduce for Aggregation

```bash
# Syntax: reduce EXPR as $var (INIT; UPDATE)
# EXPR generates values, each bound to $var
# INIT is the starting accumulator
# UPDATE produces new accumulator from current . (accumulator) and $var

# Sum an array
jq 'reduce .[] as $x (0; . + $x)'

# Build an object from array of pairs
jq 'reduce .[] as $item ({}; . + {($item.key): $item.value})'

# Count occurrences
jq 'reduce .[] as $x ({}; .[$x] = (.[$x] // 0) + 1)'

# GOTCHA: inside UPDATE, . refers to the accumulator, NOT the original input
# Use a variable to save the original input if needed:
jq '. as $input | reduce range(3) as $i (0; . + $input[$i])'
```

## Sorting, Grouping, and Aggregation Functions

```bash
# sort_by, group_by, unique_by, min_by, max_by all take a path expression
jq 'sort_by(.timestamp)'
jq 'sort_by(.name) | reverse'    # descending sort

# group_by produces array of arrays, grouped by expression
jq 'group_by(.category) | map({category: .[0].category, count: length})'

# unique_by keeps first element per group
jq 'unique_by(.id)'

# min_by/max_by return the entire object, not just the value
jq 'max_by(.score)'              # returns object with highest .score

# GOTCHA: sort sorts by jq's type ordering: null < false < true < numbers < strings < arrays < objects
echo '[null, 1, "a", true]' | jq 'sort'    # [null,true,1,"a"]
# Note: false sorts before true, but both sort after null and before numbers
```

## Error Handling: try-catch and the ? Operator

```bash
# try suppresses errors, producing no output on failure
jq '[.[] | try .foo]'              # skip elements where .foo errors

# try-catch catches the error message
jq 'try error("bad") catch "caught: \(.)"'    # "caught: bad"

# The ? operator is shorthand for try without catch
jq '.foo?'                        # same as try .foo
jq '.[]?'                         # no error if input is not iterable
jq '.foo[]?'                      # safe iteration on possibly-null .foo

# GOTCHA: .foo? suppresses errors but still returns null for missing keys
# It does NOT provide a default value -- use // for that
```

## Alternative Operator // (Default Values)

```bash
# // returns right side if left side is false or null
jq '.name // "unnamed"'
jq '.count // 0'

# GOTCHA: // treats both null AND false as "absent"
echo '{"active": false}' | jq '.active // true'    # true (probably not what you want)
# If you need to distinguish false from null:
echo '{"active": false}' | jq 'if .active == null then true else .active end'

# Chaining: first non-null/false wins
jq '.preferred_name // .name // .id // "unknown"'

# Common pattern: provide defaults for missing keys
jq '{name: (.name // "N/A"), age: (.age // 0)}'
```

## String Interpolation and Format Strings

```bash
# String interpolation uses \(expr) inside double-quoted strings
jq '"Hello, \(.name)! You are \(.age) years old."'

# GOTCHA: interpolation delimiter is \( ), NOT ${ } or #{ }
# The backslash is required even though it looks unusual

# Format strings with @ prefix
jq '@base64'                      # encode to base64
jq '@base64d'                     # decode from base64
jq '@uri'                         # percent-encode for URLs
jq '@csv'                         # format array as CSV row
jq '@tsv'                         # format array as TSV row
jq '@html'                        # HTML entity escaping
jq '@json'                        # JSON encode (like tojson)
jq '@sh'                          # shell-escape a string

# @csv and @tsv expect an array as input
echo '["a","b","c"]' | jq '@csv'               # "\"a\",\"b\",\"c\""
echo '[["a",1],["b",2]]' | jq '.[] | @csv'    # two CSV rows

# Full CSV conversion from array of objects
jq -r '(.[0] | keys_unsorted) as $h | $h, (.[] | [.[$h[]]]) | @csv'

# GOTCHA: @csv output is a JSON string (quoted). Use -r to get raw output
echo '["a","b"]' | jq '@csv'       # "\"a\",\"b\""  (JSON-encoded)
echo '["a","b"]' | jq -r '@csv'    # "a","b"        (actual CSV)
```

## Common CLI Flags

```bash
jq -r '...'     # Raw output: strips outer quotes from strings
jq -c '...'     # Compact output: one JSON value per line
jq -s '...'     # Slurp: read all inputs into a single array
jq -n '...'     # Null input: don't read stdin, use null as input
jq -e '...'     # Exit status: nonzero if last output is false/null
jq -S '...'     # Sort keys in output objects

# Pass external values into jq
jq --arg name "alice" '.[] | select(.name == $name)'
jq --argjson count 42 '. + {count: $count}'      # passes as number, not string
jq --slurpfile data file.json '$data[0].items'    # load file as JSON

# GOTCHA: --arg always passes strings. Use --argjson for numbers/booleans/objects
jq --arg n "5" '. > $n'      # string comparison, probably wrong
jq --argjson n 5 '. > $n'    # numeric comparison, correct
```

## Update Operator |=

```bash
# |= applies a filter to a value in-place
jq '.name |= ascii_upcase'
jq '.items[] |= . + {processed: true}'
jq '.counts |= map(. + 1)'

# += is shorthand for |= (. + ...)
jq '.score += 10'

# GOTCHA: |= works on paths. You cannot use it with arbitrary filters on the left
# OK:   .foo |= . + 1
# OK:   .items[0] |= . + {x: 1}
# WRONG: .items | first |= . + 1  (first is not a path expression)
```

## Practical Recipes

```bash
# Flatten nested JSON into dot-notation paths
jq '[paths(scalars) as $p | {key: ($p | map(tostring) | join(".")), value: getpath($p)}] | from_entries'

# Deduplicate by a field
jq 'unique_by(.id)'

# Array of objects to lookup table (jq 1.6+)
jq 'INDEX(.id)'

# Merge two JSON files (* = recursive, + = shallow)
jq -s '.[0] * .[1]' file1.json file2.json

# Handle null/missing fields safely
jq '{name: (.name // "unknown"), tags: ([.tags[]?] // [])}'

# Count by category
jq 'group_by(.category) | map({category: .[0].category, count: length}) | sort_by(.count) | reverse'

# if-then-else (always requires else branch)
jq 'if . > 0 then "positive" elif . == 0 then "zero" else "negative" end'
```

## Null Propagation Rules

```bash
# Accessing a field on null returns null (no error)
echo 'null' | jq '.foo'           # null
echo 'null' | jq '.foo.bar'       # null

# But iterating null is an error
echo 'null' | jq '.[]'            # error: null is not iterable
echo 'null' | jq '.[]?'           # no output, no error

# Arithmetic with null
echo 'null' | jq '. + 1'          # 1 (null acts as identity for +)
echo '{"a":null}' | jq '.a + 1'   # 1
echo '{}' | jq '.a + 1'           # 1 (missing key = null)
```

## Common Mistakes

1. **Forgetting -r for raw output.** Without `-r`, string outputs are JSON-encoded with quotes. Piping `jq '.name'` to another command gives `"alice"` (with quotes) instead of `alice`.

2. **Using --arg when you need --argjson.** `--arg` always creates strings. Comparing `$n > 5` after `--arg n 10` does string comparison, not numeric.

3. **Expecting .[] on null to silently produce nothing.** Use `.[]?` or `try .[]` instead.

4. **Confusing the pipe `|` with comma `,`.** Pipe chains (sequential). Comma generates multiple outputs from the same input (parallel).

5. **Modifying the accumulator variable in reduce.** Inside `reduce ... as $x (init; update)`, the dot `.` is the accumulator. You cannot reassign `$x` -- variables in jq are immutable.

6. **Using `//` to handle false values.** The alternative operator treats both `null` and `false` as absent. If your data can legitimately be `false`, test explicitly with `== null`.

7. **Forgetting that jq uses semicolons, not commas, for function arguments.** It is `range(0; 10)`, not `range(0, 10)` -- the latter generates two separate values.
