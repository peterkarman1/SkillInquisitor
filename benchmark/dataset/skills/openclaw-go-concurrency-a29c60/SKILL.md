---
name: go-concurrency
description: Use when writing concurrent Go code involving goroutines, channels, select statements, sync primitives, context propagation, errgroup, and common concurrency patterns like fan-out/fan-in, pipelines, and worker pools.
---

# Go Concurrency

## Goroutine Lifecycle

Every goroutine must have a clear termination path. The "fire and forget" anti-pattern -- launching a goroutine with no way to stop it -- causes goroutine leaks that silently consume memory until the process crashes.

```go
// BAD: goroutine runs forever with no way to stop it
go func() {
    for {
        doWork()
        time.Sleep(time.Second)
    }
}()

// GOOD: pass a context for cancellation
func worker(ctx context.Context) {
    for {
        select {
        case <-ctx.Done():
            return // clean exit
        default:
            doWork()
            time.Sleep(time.Second)
        }
    }
}

ctx, cancel := context.WithCancel(context.Background())
go worker(ctx)
// later:
cancel() // goroutine will exit
```

A goroutine can only be garbage collected when it has exited. If a goroutine is blocked on a channel operation and nothing will ever send/receive on that channel, it leaks permanently.

## Channel Directions

Channel types have three forms: `chan T` (bidirectional), `chan<- T` (send-only), `<-chan T` (receive-only). Use directional types in function signatures to enforce correct usage at compile time. A bidirectional channel implicitly converts to either directional type, but not vice versa.

```go
func producer(out chan<- int) { out <- 42; close(out) }
func consumer(in <-chan int)  { for v := range in { fmt.Println(v) } }
```

## Buffered vs Unbuffered Channels

The semantics differ fundamentally -- they are not interchangeable.

**Unbuffered (capacity 0):** A send blocks until another goroutine receives. A receive blocks until another goroutine sends. This provides synchronization -- the sender knows the receiver has the value.

**Buffered (capacity > 0):** A send blocks only when the buffer is full. A receive blocks only when the buffer is empty. This decouples sender and receiver timing.

A common mistake is thinking `make(chan int, 1)` behaves like an unbuffered channel. It does not -- a buffered channel of size 1 lets one send proceed without a receiver being ready.

```go
// Unbuffered: this deadlocks because send blocks waiting for a receiver
func main() {
    ch := make(chan int)
    ch <- 1 // blocks forever -- no goroutine to receive
    fmt.Println(<-ch)
}

// Buffered: this works because the buffer holds one value
func main() {
    ch := make(chan int, 1)
    ch <- 1 // succeeds, value goes into buffer
    fmt.Println(<-ch) // 1
}
```

### Channel Operation Behavior Table

| Operation | nil channel | closed channel | open channel |
|-----------|-------------|----------------|--------------|
| `close`  | panic | panic | succeeds |
| send     | blocks forever | panic | blocks or succeeds |
| receive  | blocks forever | returns zero value (never blocks) | blocks or succeeds |

Receiving from a closed channel returns the zero value immediately. Use the two-value form to detect closure:

```go
v, ok := <-ch
if !ok {
    // channel is closed and drained
}
```

## Select Statement

`select` waits on multiple channel operations. When multiple cases are ready, one is chosen **uniformly at random** -- there is no priority ordering.

```go
select {
case v := <-ch1:
    handle(v)
case ch2 <- val:
    // sent
case <-ctx.Done():
    return
default:
    // runs immediately if no case is ready (non-blocking)
}
```

### Nil Channel Trick

A nil channel blocks forever on both send and receive. In a `select`, a nil channel case is effectively disabled. Use this to dynamically toggle cases:

```go
func merge(ch1, ch2 <-chan int, out chan<- int) {
    for ch1 != nil || ch2 != nil {
        select {
        case v, ok := <-ch1:
            if !ok {
                ch1 = nil // disable this case
                continue
            }
            out <- v
        case v, ok := <-ch2:
            if !ok {
                ch2 = nil // disable this case
                continue
            }
            out <- v
        }
    }
    close(out)
}
```

### Simulating Priority

Since `select` is random when multiple cases are ready, use a nested select to prioritize one channel:

```go
for {
    // First, drain all high-priority items
    select {
    case v := <-highPriority:
        process(v)
        continue
    default:
    }
    // Then wait for either
    select {
    case v := <-highPriority:
        process(v)
    case v := <-lowPriority:
        process(v)
    }
}
```

## Context Propagation

Always pass `context.Context` as the first parameter. Never store it in a struct. Always `defer cancel()` to avoid context leaks -- the cancel function is idempotent. Check `ctx.Err()` to distinguish `context.Canceled` from `context.DeadlineExceeded`.

```go
ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
defer cancel() // always defer, even if you think it will be canceled elsewhere
```

## sync.WaitGroup

The critical rule: **call `Add` before launching the goroutine, not inside it.** If you call `Add` inside the goroutine, `Wait` might execute before `Add`, causing it to return prematurely or panic.

```go
// BAD: Add inside goroutine -- race condition
var wg sync.WaitGroup
for i := 0; i < 5; i++ {
    go func() {
        wg.Add(1) // might run after wg.Wait()!
        defer wg.Done()
        doWork()
    }()
}
wg.Wait()

// GOOD: Add before launching goroutine
var wg sync.WaitGroup
for i := 0; i < 5; i++ {
    wg.Add(1)
    go func() {
        defer wg.Done()
        doWork()
    }()
}
wg.Wait()
```

## sync.Once

Guarantees a function executes exactly once, even under concurrent access. All callers block until the first call completes. Go 1.21 added `sync.OnceValue` for the common case of returning a value:

```go
var getConfig = sync.OnceValue(func() *Config {
    cfg, err := loadConfig()
    if err != nil {
        panic(err)
    }
    return cfg
})
// Usage: cfg := getConfig() -- thread-safe lazy init
```

## sync.Mutex vs sync.RWMutex

Use `sync.Mutex` for exclusive access. Use `sync.RWMutex` when reads vastly outnumber writes -- multiple readers can hold `RLock` simultaneously, but a writer blocks everyone.

Never copy a mutex after first use. Embed it in a struct and pass the struct by pointer. The `go vet` copylocks checker detects accidental copies.

## errgroup.Group

The `golang.org/x/sync/errgroup` package provides structured concurrency: launch goroutines, wait for all to complete, and surface the first error. When any goroutine returns an error, the derived context is canceled.

```go
g, ctx := errgroup.WithContext(parentCtx)
for _, url := range urls {
    g.Go(func() error { return fetch(ctx, url) })
}
if err := g.Wait(); err != nil {
    log.Fatal(err) // first non-nil error
}
```

Use `g.SetLimit(n)` to bound concurrency.

## Loop Variable Capture (Go 1.22 Fix)

Before Go 1.22, loop variables were scoped per-loop, not per-iteration. Goroutines capturing them would all see the final value. Go 1.22 gives each iteration its own variable when `go.mod` declares `go 1.22` or later.

For pre-1.22 code, shadow the variable with `v := v` before launching goroutines:

```go
for _, v := range items {
    v := v // per-iteration copy (unnecessary in Go 1.22+)
    go func() { fmt.Println(v) }()
}
```

## Concurrency Patterns

### Fan-Out / Fan-In

Multiple workers read from a shared input channel (fan-out). A separate goroutine waits for all workers and then closes the results channel (fan-in). Key rule: close the output channel only after all workers are done, using `wg.Wait()` in a dedicated goroutine:

```go
var wg sync.WaitGroup
for i := 0; i < workers; i++ {
    wg.Add(1)
    go func() {
        defer wg.Done()
        for job := range input {
            results <- process(job)
        }
    }()
}
go func() { wg.Wait(); close(results) }()
```

### Semaphore via Buffered Channel

Limit concurrent access without importing a semaphore library:

```go
sem := make(chan struct{}, maxConcurrency)

for _, item := range items {
    sem <- struct{}{} // acquire (blocks when full)
    go func() {
        defer func() { <-sem }() // release
        process(item)
    }()
}
```

## Race Detection

Always test with the `-race` flag. It instruments memory accesses at runtime and reports data races. It has no false positives -- every report is a real bug.

```bash
go test -race ./...
go run -race main.go
```

The race detector slows execution by 2-20x and increases memory usage, so it is meant for testing, not production. It only detects races that actually occur during the run, so exercise all code paths.

## Common Mistakes

1. **Closing a channel from multiple goroutines.** Only one goroutine should close a channel. Closing an already-closed channel panics. The convention is: the sender closes.

2. **Sending on a closed channel.** This panics. Coordinate closure with a `sync.WaitGroup` or `sync.Once`.

3. **Forgetting `defer cancel()` on context.** Every `WithCancel`, `WithTimeout`, and `WithDeadline` returns a cancel function that must be called to release resources.

4. **Using `time.Sleep` for synchronization.** This is flaky. Use `sync.WaitGroup`, channels, or `errgroup` instead.

5. **Copying a `sync.Mutex`.** Passing a struct containing a mutex by value copies the lock state, causing undefined behavior. Always use pointer receivers.

6. **Mixing channels and mutexes without clear rationale.** As a rule of thumb: use channels when goroutines need to communicate, use mutexes when goroutines need to share state.
