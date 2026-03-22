---
name: protobuf-grpc
description: Design proto3 schemas with correct field numbering, backward compatibility, and well-known types. Build gRPC services with proper streaming patterns, error handling via status codes, and interceptors for cross-cutting concerns.
---

# Protocol Buffers and gRPC

## Proto3 Schema Design

### Basic Syntax

```protobuf
syntax = "proto3";

package acme.inventory.v1;

import "google/protobuf/timestamp.proto";

message Product {
  string id = 1;
  string name = 2;
  optional string description = 3;
  int32 price_cents = 4;
  repeated string tags = 5;
  ProductStatus status = 6;
  google.protobuf.Timestamp created_at = 7;
}

enum ProductStatus {
  PRODUCT_STATUS_UNSPECIFIED = 0;
  PRODUCT_STATUS_ACTIVE = 1;
  PRODUCT_STATUS_DISCONTINUED = 2;
}
```

### Field Numbering Rules

Field numbers are baked into the wire format. They cannot be changed after deployment.

- **1 through 15** use one byte on the wire. Reserve these for frequently-set fields.
- **16 through 2047** use two bytes.
- **19000 through 19999** are reserved by the protobuf implementation -- the compiler will reject them.
- **Never reuse a field number**. If you delete a field, add `reserved 4;` so nobody accidentally reuses it. Also reserve the name: `reserved "old_field_name";`.
- Field numbers and names must be reserved in separate `reserved` statements.

```protobuf
message Order {
  reserved 4, 8 to 10;
  reserved "legacy_status", "old_notes";
  string id = 1;
  // ...
}
```

### optional in Proto3

Proto3 originally removed `optional` -- all scalar fields were "implicit presence" (you could not distinguish between "set to default" and "not set"). Proto3 added `optional` back as an explicit presence marker.

- **Without optional**: A `string name = 1;` field reports as empty string `""` whether the sender set it to `""` or never set it at all.
- **With optional**: `optional string name = 1;` generates a `has_name()` method. You can distinguish "not set" from "set to empty".

Use `optional` whenever "not provided" and "default value" have different meanings (e.g., partial updates with field masks).

### oneof

```protobuf
message PaymentMethod {
  oneof method {
    CreditCard credit_card = 1;
    BankTransfer bank_transfer = 2;
    string voucher_code = 3;
  }
}
```

Only one field in a `oneof` can be set at a time. Setting one clears the others. Fields inside `oneof` cannot be `repeated` or `map`.

### map

```protobuf
message Config {
  map<string, string> labels = 1;
}
```

Map keys can be any integer or string type. Floats, bytes, enums, and messages are not valid map keys. Map fields cannot be `repeated`. Ordering is not guaranteed.

## Well-Known Types

Always use the standard types from `google.protobuf` instead of inventing your own.

| Type | Use for | JSON representation |
|---|---|---|
| `Timestamp` | A point in time | `"2024-01-15T10:30:00.000Z"` (RFC 3339) |
| `Duration` | A span of time | `"3.5s"` |
| `FieldMask` | Partial updates (which fields to read/write) | `"name,description"` |
| `Struct` / `Value` | Arbitrary JSON-like data | Native JSON object |
| `Any` | Embedding an arbitrary message with its type URL | `{"@type": "type.googleapis.com/...", ...}` |
| `Empty` | RPCs with no request or response body | `{}` |
| `StringValue`, `Int32Value`, etc. | Nullable scalars (distinguishing null from default) | The value itself, or `null` |

### Wrapper Types for Nullable Fields

Proto3 scalars cannot be null. If you need to distinguish "field is 0" from "field is not set", use a wrapper type:

```protobuf
import "google/protobuf/wrappers.proto";

message UserSettings {
  google.protobuf.Int32Value max_results = 1;  // null means "use server default"
  google.protobuf.BoolValue notifications_enabled = 2;
}
```

In JSON, wrapper types serialize as the raw value or `null`, making them natural for REST/JSON APIs. Alternatively, use `optional` for scalar fields if you do not need JSON null semantics.

## Backward Compatibility Rules

These rules apply to the binary wire format. JSON has stricter constraints (see below).

| Change | Safe? | Notes |
|---|---|---|
| Add a new field | Yes | Old code ignores unknown fields |
| Remove a field | Only if reserved | Must `reserved` the number and name |
| Rename a field | Binary: yes. JSON: no | Wire format uses numbers, but JSON uses names |
| Change a field number | No | Equivalent to deleting and adding a new field |
| Change a field type | Almost always no | A few compatible pairs exist (int32/uint32/int64/bool) but avoid this |
| Change repeated to scalar | No | Data loss -- last value wins |
| Change scalar to repeated | Mostly yes | Binary works; JSON will break |
| Add an enum value | Yes | Old code may see it as the default (0) |
| Remove an enum value | Only if reserved | Same as field removal |

### JSON Wire Safety

ProtoJSON is stricter than binary. Field names appear in the encoded output, so renaming a field is a breaking change in JSON even though it is safe in binary. Removing a field causes a parse error in JSON (unknown field rejection). Always consider whether your API uses JSON encoding when evaluating schema changes.

## Enum Best Practices

- **Always start with `FOO_UNSPECIFIED = 0`**. This is the default for missing fields. Giving it semantic meaning means you cannot distinguish "explicitly chose this" from "never set".
- **Prefix values with the enum name** to avoid C++ namespace collisions: `PRODUCT_STATUS_ACTIVE`, not `ACTIVE`.
- **Do not use `allow_alias`** unless you are genuinely migrating names.
- **Reserve removed values** just like fields: `reserved 3;` prevents accidental reuse.

```protobuf
enum Priority {
  PRIORITY_UNSPECIFIED = 0;
  PRIORITY_LOW = 1;
  PRIORITY_MEDIUM = 2;
  PRIORITY_HIGH = 3;
}
```

## gRPC Service Definitions

gRPC supports four RPC patterns:

```protobuf
service OrderService {
  // Unary: one request, one response
  rpc GetOrder(GetOrderRequest) returns (Order);

  // Server streaming: one request, stream of responses
  rpc WatchOrderStatus(WatchOrderStatusRequest) returns (stream OrderStatusUpdate);

  // Client streaming: stream of requests, one response
  rpc UploadLineItems(stream LineItem) returns (UploadSummary);

  // Bidirectional streaming: both sides stream
  rpc Chat(stream ChatMessage) returns (stream ChatMessage);
}
```

### When to Use Streaming

- **Server streaming**: Long-polling replacements, real-time feeds, large result sets.
- **Client streaming**: File uploads, batched writes, telemetry ingestion.
- **Bidirectional**: Chat, collaborative editing, anything interactive.

Unary RPCs are simpler to reason about, test, and retry. Default to unary unless you have a concrete reason for streaming.

## gRPC Error Handling

### Status Codes

gRPC has a fixed set of status codes. Use the right one -- do not stuff everything into `INTERNAL` or `UNKNOWN`.

| Code | When to use |
|---|---|
| `OK` | Success |
| `INVALID_ARGUMENT` | Client sent bad input (malformed request, validation failure) |
| `NOT_FOUND` | Requested resource does not exist |
| `ALREADY_EXISTS` | Create failed because the resource already exists |
| `PERMISSION_DENIED` | Caller is authenticated but not authorized |
| `UNAUTHENTICATED` | No valid credentials provided |
| `FAILED_PRECONDITION` | System is not in a state to handle the request (e.g., non-empty directory for rmdir) |
| `RESOURCE_EXHAUSTED` | Quota or rate limit exceeded |
| `UNAVAILABLE` | Transient -- the client should retry (with backoff) |
| `DEADLINE_EXCEEDED` | Timeout expired |
| `UNIMPLEMENTED` | Method not implemented on this server |
| `INTERNAL` | Invariant violated, unexpected server-side bug |
| `ABORTED` | Concurrency conflict (e.g., read-modify-write conflict) |

### Richer Error Details

The standard model only has a status code and a string message. For structured errors, use the Google richer error model (`google.rpc.Status` with `details` as `Any`):

```protobuf
import "google/rpc/status.proto";
import "google/rpc/error_details.proto";

// Server returns:
// - google.rpc.BadRequest with field violations for validation errors
// - google.rpc.RetryInfo with retry_delay for rate limiting
// - google.rpc.DebugInfo for internal debugging (strip in production)
```

This is supported in C++, Go, Java, and Python. The error details are sent as trailing metadata.

## Deadlines and Timeouts

Always set deadlines on the client side. Without a deadline, a hung server will hold resources indefinitely.

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
resp, err := client.GetOrder(ctx, req)
```

Server-side, check `ctx.Err()` to detect cancellation and avoid wasted work. Deadline propagation through chained RPCs happens automatically -- if client A calls service B which calls service C, the original deadline flows through.

## Interceptors (Middleware)

Interceptors run before and after each RPC. Use them for logging, authentication, metrics, and retries. Every language has unary and streaming variants for both client and server. For multiple interceptors, use chaining APIs (e.g., `grpc.ChainUnaryInterceptor(...)` in Go).

## Protobuf JSON Mapping

Proto3 defines a canonical JSON encoding. Key rules:

- **Field names become lowerCamelCase** in JSON. `user_name` becomes `"userName"`. Parsers accept both forms.
- **Enums serialize as strings**: `"PRODUCT_STATUS_ACTIVE"`, not `1`.
- **int64/uint64 serialize as strings** in JSON to avoid precision loss in JavaScript (`"9007199254740993"` not `9007199254740993`).
- **bytes serialize as base64**.
- **Wrapper types** serialize as their raw value or `null`. `Int32Value(5)` becomes `5`; unset becomes `null`.
- **Timestamp** becomes an RFC 3339 string: `"2024-01-15T10:30:00Z"`.
- **Duration** becomes `"3.5s"`.

### JSON vs Binary Compatibility

- Field renaming is safe in binary but breaks JSON.
- Removing a field is backward-compatible in binary (unknown fields are preserved) but breaks JSON (parsers may reject unknown fields).
- If your API serves JSON, treat field names as part of the contract.

## Code Generation Tooling

### protoc (Protocol Buffer Compiler)

The traditional tool. Requires manually managing plugins for each language:

```bash
protoc --go_out=. --go-grpc_out=. proto/service.proto
```

### buf

A modern alternative that manages plugins, linting, breaking change detection, and the BSR (Buf Schema Registry):

```yaml
# buf.yaml
version: v2
modules:
  - path: proto
lint:
  use:
    - STANDARD
breaking:
  use:
    - FILE
```

```bash
buf lint           # Check proto style
buf breaking       # Detect breaking changes vs main branch
buf generate       # Run code generation
```

`buf breaking` is particularly valuable in CI -- it catches backward-incompatible schema changes before they merge.

## Common Mistakes

- **Using int32/int64 for IDs**: IDs should be `string`. Numeric IDs hit JavaScript precision limits in JSON, are hard to migrate (e.g., from sequential to UUID), and leak information about cardinality.
- **Not using wrapper types for nullable fields**: Without `optional` or wrapper types, you cannot distinguish "zero" from "not set" for scalar fields.
- **Missing UNSPECIFIED enum value at 0**: If you give the 0 value semantic meaning, you cannot distinguish "explicitly set" from "default".
- **Using booleans for states that may expand**: A `bool is_active` cannot evolve into `ACTIVE / INACTIVE / SUSPENDED`. Use an enum from the start.
- **Reusing field numbers**: This silently corrupts data. Always `reserved` deleted numbers.
- **Not setting gRPC deadlines**: Without a deadline, stuck RPCs leak goroutines/threads/connections.
- **Returning INTERNAL for all errors**: Clients cannot distinguish retryable from permanent failures. Use the correct status code.
- **Large messages in streaming**: gRPC has a default 4MB message size limit. If you hit it, redesign to use smaller messages rather than increasing the limit.
- **Ignoring field ordering for efficiency**: Fields 1-15 take one byte to encode. Put your most common fields in this range.

