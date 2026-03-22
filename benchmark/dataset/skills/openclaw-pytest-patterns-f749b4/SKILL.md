---
name: pytest-patterns
description: Write correct, idiomatic pytest tests. Use when working with fixtures, parametrize, marks, mocking, output capture, conftest hierarchy, or plugin configuration. Covers scope interactions, teardown patterns, and common gotchas that cause flaky or silently broken tests.
---

# Pytest Patterns

## Fixture Scoping and Teardown

Five scopes from narrowest to widest: `function` (default), `class`, `module`,
`package`, `session`. Wider scopes are created once and shared across more tests.

```python
@pytest.fixture(scope="module")
def db_connection():
    conn = create_connection()
    yield conn        # everything after yield is teardown
    conn.close()
```

**Yield fixtures:** Code before `yield` runs during setup; code after runs during
teardown. If setup raises before reaching yield, teardown does NOT run -- but
nothing needs cleanup since the resource was never created.

**Scope interaction rule:** A wider-scoped fixture cannot request a narrower-scoped
one. `session` cannot use `function`-scoped fixtures. This is a hard error.
Narrower requesting wider is fine.

**Isolation trap:** A module-scoped fixture persists across all tests in the file.
If test A inserts a row via a shared DB fixture, test B sees it. This is the #1
cause of order-dependent failures. Use function-scoped wrappers with rollback:

```python
@pytest.fixture
def db_session(module_db):       # module_db is module-scoped
    txn = module_db.begin_nested()  # SAVEPOINT
    yield module_db
    txn.rollback()               # undo this test's changes
```

## conftest.py

Pytest walks from rootdir to the test file's directory, loading `conftest.py`
at each level. Tests see fixtures from their directory and all parent directories.

```
project/
  conftest.py          # available to all tests
  tests/
    conftest.py        # available to tests/ subtree
    unit/
      conftest.py      # available to unit/ tests only
      test_foo.py      # sees all three conftest files
```

If two conftest files define a fixture with the same name, the closest one wins.
Do NOT put test functions in conftest.py -- they won't be collected.

**__init__.py pitfall:** Having `__init__.py` in your top-level test directory
alongside conftest.py can cause import errors if the directory is also importable
as a package. Omit `__init__.py` from test roots unless you need it.

## Parametrize

```python
@pytest.mark.parametrize("input_val, expected", [
    ("hello", 5),
    ("", 0),
], ids=["normal", "empty"])     # always provide ids for readability
def test_length(input_val, expected):
    assert len(input_val) == expected
```

**Stacking** creates a Cartesian product:

```python
@pytest.mark.parametrize("x", [1, 2])
@pytest.mark.parametrize("y", [10, 20])
def test_mul(x, y):  # runs 4 times: (1,10), (1,20), (2,10), (2,20)
    assert isinstance(x * y, int)
```

**indirect** routes values through a fixture via `request.param`:

```python
@pytest.fixture
def db(request):
    conn = connect(request.param)
    yield conn
    conn.close()

@pytest.mark.parametrize("db", ["postgres", "sqlite"], indirect=True)
def test_query(db):
    assert db.execute("SELECT 1")
```

For mixed fixture/non-fixture params, pass a list: `indirect=["db"]`.

**Marks on specific params:** Use `pytest.param`:

```python
@pytest.mark.parametrize("n", [
    1,
    pytest.param(0, marks=pytest.mark.xfail(reason="zero")),
    pytest.param(-1, marks=pytest.mark.skip),
])
def test_inverse(n): ...
```

**Mutable values are shared.** If a test mutates a parametrized dict, later
tests see the mutation. Copy first.

## Marks

**skip/skipif** -- skip unconditionally or based on a condition:

```python
@pytest.mark.skip(reason="not implemented")
def test_future(): ...

@pytest.mark.skipif(sys.platform == "win32", reason="unix only")
def test_unix_perms(): ...
```

**xfail -- strict vs non-strict.** `strict=False` (default) silently allows the
test to pass (XPASS), hiding when bugs get fixed. `strict=True` makes an
unexpected pass into a FAILURE -- alerting you to remove the mark:

```python
@pytest.mark.xfail(reason="Bug #1234", strict=True)
def test_known_bug():
    assert buggy_function() == "correct"
```

Set the default globally: `xfail_strict = true` in `[tool.pytest.ini_options]`.

**Custom marks** -- register to avoid warnings with `--strict-markers`:

```toml
[tool.pytest.ini_options]
markers = ["slow: long-running tests", "integration: needs external services"]
```

## Fixture Factories

Return a callable instead of a value when you need multiple instances with
different configurations:

```python
@pytest.fixture
def make_user():
    created = []
    def _make(name="test", role="member"):
        user = User(name=name, role=role)
        created.append(user)
        return user
    yield _make
    for u in created:
        u.delete()

def test_permissions(make_user):
    admin = make_user(role="admin")
    member = make_user(role="member")
    assert admin.can_delete(member)
```

## monkeypatch vs mock.patch

**monkeypatch** (pytest built-in): Simple attribute, env var, and dict replacement.
Auto-reverted after the test. No call tracking.

```python
def test_config(monkeypatch):
    monkeypatch.setenv("API_URL", "http://test")
    monkeypatch.setattr("myapp.config.DEBUG", True)
```

**unittest.mock.patch**: Full mock objects with call tracking, return values,
side effects, and spec enforcement.

```python
from unittest.mock import patch

def test_api():
    with patch("myapp.client.requests.get") as mock_get:
        mock_get.return_value.json.return_value = {"data": [1]}
        result = fetch_data()
        mock_get.assert_called_once()
```

**Rule of thumb:** monkeypatch for simple replacements (env vars, config values).
mock.patch when you need to assert how something was called.

**pytest-mock** wraps mock.patch as a `mocker` fixture with auto-cleanup:

```python
def test_email(mocker):
    m = mocker.patch("myapp.email.send")
    notify(user_id=1)
    m.assert_called_once_with("user@ex.com", subject="Hi")
```

## Output Capture

- **capsys**: Python-level sys.stdout/stderr. Use for print statements.
- **capfd**: File descriptor level. Use for C extensions or subprocess output.
- **caplog**: Logging module records.

capsys and capfd are mutually exclusive in the same test.

```python
def test_output(capsys):
    print("hello")
    assert capsys.readouterr().out == "hello\n"

def test_logging(caplog):
    with caplog.at_level(logging.WARNING):
        do_risky_op()
    assert "timeout" in caplog.text
```

**caplog gotcha:** Only captures loggers with `propagate = True`. Non-propagating
loggers are invisible to caplog.

## tmp_path (use this, not tmpdir)

`tmp_path` returns `pathlib.Path`. `tmpdir` returns legacy `py.path.local`.

```python
def test_file(tmp_path):
    p = tmp_path / "out.txt"
    p.write_text("content")
    assert p.read_text() == "content"
```

Session-scoped: `tmp_path_factory.mktemp("data")`.

## autouse Fixtures

Apply to every test in scope without explicit request:

```python
@pytest.fixture(autouse=True)
def reset_cache():
    Cache.clear()
    yield
    Cache.clear()
```

**Pitfalls:** Invisible dependencies (new developers don't know it exists); an
autouse in root conftest applies to ALL tests; cannot be disabled per-test.
Keep autouse fixtures in the narrowest conftest possible.

## Plugin Gotchas

### pytest-xdist

```bash
pytest -n auto              # parallel across CPUs
pytest -n auto --dist loadscope  # group by module/class
```

**Session-scoped fixtures run once per WORKER, not once globally.** Each xdist
worker is a separate process. A session fixture that starts a server spawns N
servers. Use file locks for coordination or `--dist loadscope` to group tests.

### pytest-asyncio

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"  # no @pytest.mark.asyncio needed
```

In `auto` mode, async tests and fixtures just work. In `strict` mode, every async
test needs `@pytest.mark.asyncio` explicitly.

**Event loop scope:** By default, a new loop per test. Session-scoped async
fixtures require: `asyncio_default_fixture_loop_scope = "session"`.
