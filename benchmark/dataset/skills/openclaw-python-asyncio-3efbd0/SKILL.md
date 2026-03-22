---
name: python-asyncio
description: Write correct concurrent Python with asyncio -- covering event loop lifecycle, TaskGroup vs gather, cancellation semantics, blocking I/O handling, and the subtle bugs (like garbage-collected tasks) that LLMs and developers commonly produce.
---

# Python asyncio

## Event Loop Lifecycle

### The modern way (Python 3.7+)

```python
import asyncio

async def main():
    print("hello")
    await asyncio.sleep(1)
    print("world")

asyncio.run(main())
```

`asyncio.run()` creates a new event loop, runs the coroutine to completion, then closes the loop. This is the only correct entry point for most programs.

### The old way (avoid)

```python
# LEGACY -- do not use in new code
loop = asyncio.get_event_loop()
loop.run_until_complete(main())
loop.close()
```

`get_event_loop()` behaves inconsistently: it creates a loop in the main thread but raises RuntimeError in other threads (since Python 3.10). The deprecation warnings are intentional -- use `asyncio.run()`.

You cannot call `asyncio.run()` from inside a running event loop. If you need async inside Jupyter notebooks or frameworks that already run a loop, `nest_asyncio` (third-party) is a pragmatic escape hatch, but it monkey-patches the loop.

## Creating Tasks and the GC Pitfall

```python
async def main():
    # WRONG -- task may be garbage-collected before completion
    asyncio.create_task(background_work())

    # CORRECT -- hold a reference
    task = asyncio.create_task(background_work())
    await task
```

The event loop keeps only **weak references** to tasks. If you do not store the Task object, the garbage collector can destroy it mid-execution. This produces a Heisenbug -- the task sometimes completes, sometimes silently disappears.

### Fire-and-forget pattern (correct)

```python
background_tasks = set()

async def spawn_background(coro):
    task = asyncio.create_task(coro)
    background_tasks.add(task)
    task.add_done_callback(background_tasks.discard)
```

This pattern from the official docs ensures tasks stay alive. The done callback removes them after completion to avoid unbounded memory growth.

## TaskGroup (Python 3.11+) vs asyncio.gather

### TaskGroup -- structured concurrency

```python
async def main():
    async with asyncio.TaskGroup() as tg:
        task1 = tg.create_task(fetch_url("https://example.com"))
        task2 = tg.create_task(fetch_url("https://example.org"))
    # Both are guaranteed done here.
    print(task1.result(), task2.result())
```

Key behaviors:
- If **any** task raises an exception, **all** remaining tasks are cancelled.
- The exception is raised as an `ExceptionGroup` when the context manager exits.
- No task can escape the scope -- when the `async with` block exits, all tasks are done or cancelled.
- You can add tasks dynamically by passing `tg` into coroutines.

### asyncio.gather -- the older approach

```python
results = await asyncio.gather(
    fetch_url("https://example.com"),
    fetch_url("https://example.org"),
)
```

Key behaviors:
- Returns results **in input order** (not completion order).
- If a task raises, gather raises it immediately -- but **other tasks keep running**.
- With `return_exceptions=True`, exceptions are returned as values instead of raised. You must check each result with `isinstance(result, BaseException)`.
- If gather itself is cancelled, all gathered tasks are cancelled.

### When to use which

| Scenario | Use |
|----------|-----|
| New code, Python 3.11+ | `TaskGroup` -- safer defaults |
| Need partial results on failure | `gather(return_exceptions=True)` |
| Need results in completion order | `as_completed()` |
| Fine-grained control over done/pending | `wait()` |
| Must support Python 3.10 or earlier | `gather` |

## Cancellation Semantics

### How cancellation works

```python
task = asyncio.create_task(some_coroutine())
task.cancel()  # Requests cancellation -- does not cancel immediately.
```

On the next `await` inside the task, a `CancelledError` is raised. The coroutine can catch it for cleanup but **must re-raise** it (or call `uncancel()`) for structured concurrency to work correctly.

```python
async def graceful_shutdown():
    try:
        await do_work()
    except asyncio.CancelledError:
        await cleanup()  # Runs before cancellation completes.
        raise             # MUST re-raise. Swallowing breaks TaskGroup/timeout.
```

### CancelledError is a BaseException

Since Python 3.9, `CancelledError` inherits from `BaseException`, not `Exception`. This means a bare `except Exception:` will **not** catch it, which is the correct behavior. Code that uses `except BaseException:` or `except:` will accidentally swallow cancellation -- this breaks `TaskGroup` and `asyncio.timeout()` internally.

### Shielding from cancellation

`asyncio.shield(awaitable)` prevents outer cancellation from propagating to the inner awaitable. However, the outer task still gets cancelled -- you get `CancelledError` at the `await` point while the shielded coroutine continues running. You must handle the shielded result separately (e.g., via a done callback) if the outer await is interrupted.

### Timeouts

```python
# Modern (Python 3.11+):
async with asyncio.timeout(5.0):
    result = await slow_operation()

# Older:
try:
    result = await asyncio.wait_for(slow_operation(), timeout=5.0)
except asyncio.TimeoutError:
    print("timed out")
```

`asyncio.timeout()` is a context manager that cancels the enclosed code on expiry. `wait_for()` wraps a single awaitable with a timeout.

Important: `wait_for()` returns a coroutine, not a task. It does not start executing until you `await` it. This means you cannot use it for concurrent timeout management like this:

```python
# WRONG -- runs sequentially, not concurrently:
a = asyncio.wait_for(f(), timeout=5)
b = asyncio.wait_for(g(), timeout=5)
await a  # g() hasn't started yet!
await b
```

## Waiting Primitives Compared

**`asyncio.gather(*awaitables)`** -- wraps in tasks, returns results in input order. No timeout -- wrap with `asyncio.timeout` if needed.

**`asyncio.wait(tasks, timeout=, return_when=)`** -- takes tasks (not coroutines), returns `(done, pending)` sets. You must await done tasks to get results. The timeout does **not** cancel pending tasks -- you must cancel them yourself. `return_when` options: `ALL_COMPLETED`, `FIRST_COMPLETED`, `FIRST_EXCEPTION`. Pass only tasks, not coroutines -- passing coroutines gives you different objects back, breaking identity checks.

**`asyncio.as_completed(awaitables, timeout=)`** -- yields awaitables in completion order (fastest first). You cannot tell which original task produced each result.

## Running Blocking Code

### asyncio.to_thread() (Python 3.9+)

```python
# Offload blocking I/O to a thread:
data = await asyncio.to_thread(requests.get, "https://example.com")
```

This runs the blocking function in a thread pool so the event loop is not blocked. The function must be thread-safe.

Limitations:
- Due to the GIL, this only helps with I/O-bound blocking -- CPU-bound work still holds the GIL.
- The default executor is a `ThreadPoolExecutor`. You can set a custom one with `loop.set_default_executor()`.

For Python < 3.9, use `loop.run_in_executor(None, blocking_function, arg1, arg2)` instead.

### Common deadlock: calling sync from async

```python
# DEADLOCK -- blocks the event loop:
async def handler():
    result = requests.get("https://example.com")  # Blocks!
    return result
```

Any blocking call (network I/O, `time.sleep()`, file I/O, heavy computation) inside an async function freezes the entire event loop. All other tasks stop progressing. Use `asyncio.to_thread()` for blocking I/O.

## Semaphore for Rate Limiting

```python
sem = asyncio.Semaphore(10)  # Max 10 concurrent operations

async def rate_limited_fetch(url):
    async with sem:
        return await aiohttp.ClientSession().get(url)

async def main():
    urls = [f"https://api.example.com/item/{i}" for i in range(1000)]
    async with asyncio.TaskGroup() as tg:
        tasks = [tg.create_task(rate_limited_fetch(url)) for url in urls]
```

The semaphore limits how many coroutines enter the `async with` block simultaneously. This prevents overwhelming APIs or exhausting file descriptors.

Do not use `asyncio.BoundedSemaphore` unless you specifically need the guarantee that `release()` is never called more times than `acquire()`. For rate limiting, plain `Semaphore` is correct.

## Queue for Producer-Consumer

```python
async def producer(queue: asyncio.Queue):
    for i in range(100):
        await queue.put(i)
    await queue.put(None)  # Sentinel to signal completion

async def consumer(queue: asyncio.Queue):
    while True:
        item = await queue.get()
        if item is None:
            break
        await process(item)
        queue.task_done()

async def main():
    queue = asyncio.Queue(maxsize=20)  # Backpressure at 20 items
    async with asyncio.TaskGroup() as tg:
        tg.create_task(producer(queue))
        tg.create_task(consumer(queue))
```

`maxsize` provides backpressure -- `put()` blocks when the queue is full. With `maxsize=0` (default), the queue is unbounded and a fast producer can exhaust memory.

Use `queue.join()` to wait until all items have been processed (every `put` matched by `task_done`). This is an alternative to sentinels for signaling completion.

## Async Generators

Cleanup pitfall: if the consumer stops iterating early (e.g., `break` in `async for`), the generator's `finally` block / context manager `__aexit__` may not run promptly. Always use `contextlib.aclosing()`:

```python
from contextlib import aclosing

async with aclosing(stream_data()) as stream:
    async for chunk in stream:
        if done:
            break  # Generator is properly closed by aclosing
```

Use `@contextlib.asynccontextmanager` to write async context managers as generators -- identical to synchronous `@contextmanager` but with `async def` and `await` in cleanup logic.

## Scheduling From Other Threads

Use `asyncio.run_coroutine_threadsafe(coro, loop)` to submit coroutines from a non-event-loop thread. It returns a `concurrent.futures.Future` that you can `.result()` on from the calling thread. Calling `create_task` from a non-event-loop thread is not thread-safe and produces undefined behavior.

## Debug Mode

Enable debug mode to catch common mistakes:

```python
# Option 1: environment variable
# PYTHONASYNCIODEBUG=1 python script.py

# Option 2: in code
asyncio.run(main(), debug=True)
```

Debug mode logs slow callbacks (>100ms), catches unawaited coroutines, detects non-thread-safe event loop access, and warns about unclosed transports.

## Common Mistakes

1. **Forgetting to await a coroutine.** `result = some_async_func()` gives you a coroutine object, not the result. Python emits a RuntimeWarning but the coroutine never executes.

2. **Garbage-collected tasks.** `asyncio.create_task(coro())` without storing the reference. The task can vanish mid-execution.

3. **Blocking the event loop.** `time.sleep()`, `requests.get()`, or any synchronous I/O inside async code. Use `await asyncio.sleep()` and `asyncio.to_thread()`.

4. **Swallowing CancelledError.** Catching `BaseException` or `except:` without re-raising `CancelledError` breaks structured concurrency (TaskGroup, timeout).

5. **Using `get_event_loop()` instead of `asyncio.run()`.** The old API has confusing thread-dependent behavior and is being deprecated for application-level use.

6. **`await` after `await` is sequential, not concurrent.** `await f(); await g()` runs sequentially. Use `gather()` or `TaskGroup` for concurrency.

7. **`wait_for()` is a coroutine, not a task.** You cannot create multiple `wait_for` calls and expect them to run concurrently -- they don't start until awaited.

8. **Passing coroutines to `asyncio.wait()`.** It expects tasks (or futures). Passing coroutines gives you different objects back, breaking identity checks for dispatch.

9. **Unbounded queue without backpressure.** `asyncio.Queue()` with default `maxsize=0` is unbounded. A fast producer can exhaust memory while consumers lag behind.

10. **Async generator cleanup.** Breaking out of `async for` without `aclosing()` or explicit `aclose()` may leave resources open.

