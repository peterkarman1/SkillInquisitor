---
name: rust-ownership-patterns
description: Use when working with Rust ownership, borrowing, lifetimes, smart pointers, interior mutability, Pin/Unpin, and common patterns for satisfying the borrow checker including builder, newtype, and typestate patterns.
---

# Rust Ownership Patterns

## Ownership Rules

Every value in Rust has exactly one owner. When the owner goes out of scope, the value is dropped. Assignment moves ownership by default -- the original binding becomes invalid.

```rust
let s1 = String::from("hello");
let s2 = s1; // s1 is moved into s2
// println!("{s1}"); // ERROR: s1 has been moved
println!("{s2}"); // OK
```

Types that implement the `Copy` trait (integers, floats, bools, chars, tuples of `Copy` types) are duplicated on assignment instead of moved:

```rust
let x = 5;
let y = x; // x is copied, not moved
println!("{x} {y}"); // both valid
```

`Copy` requires `Clone`, and the type must not implement `Drop`. Any type that manages a heap resource (String, Vec, Box) cannot be `Copy`.

## Borrowing

Shared references (`&T`) allow multiple simultaneous readers. Exclusive references (`&mut T`) allow exactly one writer with no concurrent readers. This is enforced at compile time.

```rust
let mut v = vec![1, 2, 3];

let r1 = &v;
let r2 = &v;     // multiple shared borrows OK
println!("{r1:?} {r2:?}");

let r3 = &mut v;  // exclusive borrow -- r1 and r2 must not be used after this point
r3.push(4);
```

The borrow checker tracks the **liveness** of references, not just their scope. A shared reference is allowed to coexist with a later mutable reference as long as the shared reference is never used after the mutable borrow begins. This is called Non-Lexical Lifetimes (NLL), introduced in Rust 2018.

### Reborrowing

When you pass `&mut T` to a function taking `&mut T`, the compiler creates a temporary reborrow instead of moving the mutable reference. This is why you can use an `&mut` reference after passing it to a function:

```rust
fn push_one(v: &mut Vec<i32>) {
    v.push(1);
}

let mut v = vec![];
let r = &mut v;
push_one(r);  // reborrows r, does not move it
push_one(r);  // still valid
```

Reborrowing happens automatically for `&mut` references but not for smart pointers. You may need to explicitly call `&mut *smart_ptr` to reborrow.

## Lifetime Elision Rules

The compiler infers lifetimes using three rules, applied in order. If ambiguity remains after all three, you must annotate explicitly.

1. **Each elided input lifetime becomes a distinct lifetime parameter.**
   `fn f(x: &str, y: &str)` becomes `fn f<'a, 'b>(x: &'a str, y: &'b str)`

2. **If there is exactly one input lifetime, it is assigned to all elided output lifetimes.**
   `fn f(x: &str) -> &str` becomes `fn f<'a>(x: &'a str) -> &'a str`

3. **If one of the inputs is `&self` or `&mut self`, its lifetime is assigned to all elided output lifetimes.**
   `fn f(&self, x: &str) -> &str` becomes `fn f<'a, 'b>(&'a self, x: &'b str) -> &'a str`

If none of these rules resolve all output lifetimes, compilation fails:

```rust
// ERROR: cannot determine output lifetime
fn longest(a: &str, b: &str) -> &str { ... }

// FIX: annotate explicitly
fn longest<'a>(a: &'a str, b: &'a str) -> &'a str {
    if a.len() > b.len() { a } else { b }
}
```

## Common Lifetime Annotations

- `'a` -- a generic lifetime parameter, constrained by the caller
- `'static` -- the reference is valid for the entire program duration. String literals are `&'static str`. This does not mean the data lives forever -- it means the **reference** is valid for that long.
- `T: 'a` -- the type `T` contains no references shorter than `'a`
- `T: 'static` -- either `T` owns all its data, or any references it contains are `'static`. This is required for `thread::spawn` closures and many async runtimes.

A common mistake: `T: 'static` does **not** mean the value is immutable or lives forever. An owned `String` satisfies `'static` because it has no borrowed references at all.

## Pin and Unpin

`Pin<P>` wraps a pointer and prevents moving the pointed-to value. This exists for self-referential types -- if a struct has a pointer into itself and gets moved, the pointer dangles.

Most types implement the auto-trait `Unpin` (safe to move even when pinned). `Pin` only restricts `!Unpin` types, like most compiler-generated `Future`s. This is why `Future::poll` takes `Pin<&mut Self>` -- it guarantees the future stays in place between polls.

```rust
// Pinning on the heap (always safe):
let future = Box::pin(async { 42 });
// Pinning on the stack:
let future = std::pin::pin!(async { 42 });
```

For custom `Future` implementations, use the `pin-project` crate for safe field projections. Mark fields that need pinning with `#[pin]`; all other fields get normal `&mut` access.

## Interior Mutability

When you need to mutate data behind a shared reference (`&T`), use interior mutability. These move borrow checking to runtime.

| Type | Thread-safe | Panics on misuse | Notes |
|------|-------------|------------------|-------|
| `Cell<T>` | No | Never | Copy-based get/set, no references handed out |
| `RefCell<T>` | No | Yes | Runtime borrow count; double `borrow_mut()` panics |
| `Mutex<T>` | Yes | Poisoned on panic | Blocking lock |
| `RwLock<T>` | Yes | Poisoned on panic | Multiple readers or one writer |

`RefCell` trap: calling `borrow()` and `borrow_mut()` on the same `RefCell` simultaneously panics at runtime. The compiler cannot catch this.

## Rc vs Arc

Both provide shared ownership via reference counting. Value is dropped when the last strong reference is dropped.

- `Rc<T>` -- single-threaded only. Does not implement `Send` or `Sync`. Lower overhead.
- `Arc<T>` -- thread-safe. Uses atomic operations for the reference count.

Use `Rc::clone(&a)` (not `a.clone()`) to make it clear you are incrementing the reference count, not deep cloning the data.

**Weak references:** `Rc::downgrade` / `Arc::downgrade` creates a `Weak<T>` that does not prevent deallocation. Call `weak.upgrade()` to get `Option<Rc<T>>`. Use to break reference cycles (parent-child, caches, observer).

## Smart Pointer Summary

| Type | Heap-allocated | Shared ownership | Thread-safe | Use case |
|------|---------------|-----------------|-------------|----------|
| `Box<T>` | Yes | No | If T is | Single owner, heap allocation, recursive types |
| `Rc<T>` | Yes | Yes | No | Multiple owners, single thread |
| `Arc<T>` | Yes | Yes | Yes | Multiple owners, across threads |
| `Cow<'a, T>` | Conditional | No | If T is | Clone-on-write, avoids allocation when possible |

### Cow (Clone on Write)

`Cow<'a, T>` holds either a borrowed reference or an owned value. It clones only when mutation is needed, avoiding allocation in the common case:

```rust
fn process(input: &str) -> Cow<'_, str> {
    if input.contains("bad") { Cow::Owned(input.replace("bad", "good")) }
    else { Cow::Borrowed(input) } // zero allocation when no change needed
}
```

## String Types

Rust has multiple string types. The general pattern: borrowed types are cheap to pass around; owned types are needed for storage or modification.

| Owned | Borrowed | Use case |
|-------|----------|----------|
| `String` | `&str` | UTF-8 text (most common) |
| `OsString` | `&OsStr` | OS interfaces, env vars |
| `CString` | `&CStr` | FFI with C code (null-terminated) |
| `PathBuf` | `&Path` | File system paths (not guaranteed UTF-8) |

Accept `&str` in function parameters for flexibility -- `&String` auto-derefs to `&str`. For file paths, always use `Path`/`PathBuf` instead of `String`/`&str`.

## Iterator Ownership

| Method | Yields | Consumes collection |
|--------|--------|-------------------|
| `iter()` / `for x in &v` | `&T` | No |
| `iter_mut()` / `for x in &mut v` | `&mut T` | No |
| `into_iter()` / `for x in v` | `T` | Yes |

`into_iter()` moves elements out -- the collection is consumed and cannot be used afterward. The `for` loop sugar `for x in &v` calls `iter()`, `for x in &mut v` calls `iter_mut()`, and `for x in v` calls `into_iter()`.

## Common Borrow Checker Errors and Fixes

### Cannot borrow as mutable because also borrowed as immutable

```rust
let mut v = vec![1, 2, 3];
let first = &v[0];
v.push(4);          // ERROR: v is mutably borrowed while first exists
println!("{first}"); // first is used here
```

**Fix:** Finish using the immutable reference before mutating:

```rust
let mut v = vec![1, 2, 3];
let first = v[0]; // copy the value instead of borrowing
v.push(4);        // OK
println!("{first}");
```

### Cannot move out of borrowed content

Attempting `take_ownership(*r)` where `r` is `&Vec<i32>` fails because you cannot move out of a reference. Fix: clone, or change the function to accept `&[i32]`.

### Borrowed value does not live long enough

Returning `&str` from a function that creates a local `String` is a dangling reference. Fix: return the owned `String` instead.

### Simultaneous mutable access to different struct fields

The borrow checker treats a struct as one unit. Borrowing two fields mutably through `&mut self` methods requires splitting borrows:

```rust
struct Game {
    players: Vec<Player>,
    scores: Vec<i32>,
}

// This fails: two mutable borrows of self
// let p = &mut self.players;
// let s = &mut self.scores;

// Fix: destructure to borrow fields independently
let Game { players, scores } = &mut game;
players[0].update();
scores[0] += 1;
```

## Patterns

### Newtype

Wrap an existing type in a single-field tuple struct to create a distinct type with its own trait implementations:

```rust
struct Meters(f64);
struct Seconds(f64);

// Compiler prevents mixing these up:
fn speed(distance: Meters, time: Seconds) -> f64 {
    distance.0 / time.0
}
```

### Builder Pattern

The builder consumes and returns `self` to enable method chaining. Each setter takes `mut self` (not `&mut self`) so the builder moves through each call:

```rust
impl ServerConfigBuilder {
    fn new(host: impl Into<String>) -> Self {
        Self { host: host.into(), port: 8080, max_connections: 100 }
    }
    fn port(mut self, port: u16) -> Self { self.port = port; self }
    fn build(self) -> ServerConfig {
        ServerConfig { host: self.host, port: self.port, max_connections: self.max_connections }
    }
}

let config = ServerConfigBuilder::new("localhost").port(3000).build();
```

### Typestate Pattern

Encode state transitions in the type system so invalid sequences are compile-time errors. Each state is a zero-sized type used as a generic parameter:

```rust
struct Locked;
struct Unlocked;

struct Door<State> { _state: std::marker::PhantomData<State> }

impl Door<Locked> {
    fn unlock(self) -> Door<Unlocked> { Door { _state: std::marker::PhantomData } }
}

impl Door<Unlocked> {
    fn open(&self) { println!("Door is open"); }
}

// door.open(); // ERROR: no method `open` for Door<Locked>
// door.unlock().open(); // OK -- state transition enforced at compile time
```

## Common Mistakes

1. **Fighting the borrow checker with `clone()` everywhere.** Cloning is a valid escape hatch, but excessive cloning indicates a design issue. Consider using references, `Cow`, or restructuring data.

2. **Using `Rc<RefCell<T>>` as a default.** This is the Rust equivalent of giving up on ownership. Reserve it for cases with genuinely shared, mutable state like graph structures. Prefer passing `&mut T` where possible.

3. **Assuming `'static` means immortal.** `T: 'static` means the type can live as long as needed -- it either owns all its data or borrows with `'static` lifetime. An owned `String` is `'static`.

4. **Returning references to local variables.** The function creates and owns the data -- returning a reference to it creates a dangling reference. Return owned types instead.

5. **Using `String` in struct fields when `&str` would suffice.** If the struct does not need to own the string, use a lifetime parameter: `struct Foo<'a> { name: &'a str }`. But note this makes the struct borrow from something else, which has its own ergonomic costs.

6. **Ignoring `Cow` for functions that sometimes allocate.** If a function returns the input unchanged most of the time but occasionally modifies it, `Cow` avoids the allocation in the common case.
