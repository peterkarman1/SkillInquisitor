---
name: kafka-producers-consumers
description: Configure Kafka producers and consumers correctly in Python using confluent-kafka, covering acks, idempotence, offset management, rebalancing, serialization, and exactly-once semantics.
---

# Kafka Producers and Consumers -- Configuration, Pitfalls, and Patterns

## Producer Configuration

### Acknowledgment Levels (acks)

The `acks` setting controls durability guarantees:

| acks | Behavior | Durability | Throughput |
|---|---|---|---|
| `0` | Fire and forget. No acknowledgment. | Lowest -- data loss possible | Highest |
| `1` | Leader acknowledges. Replicas may lag. | Medium -- loss if leader dies before replication | High |
| `all` (or `-1`) | All in-sync replicas acknowledge. | Highest -- no data loss if ISR > 1 | Lowest |

For any data you cannot afford to lose, use `acks=all`. Since Kafka 3.0, the default is `all`.

### Idempotent Producer

Without idempotence, retries can produce duplicate messages. Enable it to get exactly-once producer semantics:

```python
from confluent_kafka import Producer

config = {
    'bootstrap.servers': 'kafka1:9092,kafka2:9092',
    'acks': 'all',                     # Required for idempotence
    'enable.idempotence': True,        # Prevents duplicates on retry
    'max.in.flight.requests.per.connection': 5,  # Max allowed with idempotence
    'retries': 2147483647,             # Effectively infinite retries
}

producer = Producer(config)
```

Idempotence requirements:
- `acks` must be `all`. Setting it to `1` or `0` with idempotence raises a configuration error.
- `max.in.flight.requests.per.connection` must be <= 5.
- Since Kafka 3.0, idempotence is enabled by default.

### Batching: linger.ms and batch.size

Producers batch messages before sending. Two settings control batching:

- `linger.ms` -- how long to wait for more messages before sending a batch (default: 5ms in confluent-kafka / librdkafka, 0 in Java client).
- `batch.size` -- maximum batch size in bytes (default: 16384 = 16KB).

A batch is sent when either limit is reached, whichever comes first.

```python
config = {
    'bootstrap.servers': 'kafka1:9092',
    'linger.ms': 50,       # Wait up to 50ms to fill batch
    'batch.size': 65536,   # 64KB max batch size
}
```

For throughput-sensitive workloads, increase both. For latency-sensitive workloads, keep `linger.ms` low (0-5ms).

### Compression

Compression reduces network bandwidth and broker storage. Applied per batch.

| Type | Speed | Ratio | CPU | Best For |
|---|---|---|---|---|
| `snappy` | Fast | Low | Low | High-throughput, latency-sensitive |
| `lz4` | Fast | Low-Medium | Low | Default recommendation for most workloads |
| `zstd` | Medium | High | Medium | Storage-constrained, high compression needed |
| `gzip` | Slow | High | High | Rarely recommended -- high CPU cost |

```python
config = {
    'bootstrap.servers': 'kafka1:9092',
    'compression.type': 'lz4',
}
```

### Producer Delivery Callback and Flushing

`produce()` is asynchronous -- it queues the message in a local buffer. You must call `poll()` or `flush()` to trigger delivery callbacks and actually send messages:

```python
def delivery_callback(err, msg):
    if err is not None:
        print(f'Delivery failed: {err}')

producer.produce('my-topic', key=b'key1', value=b'value1',
                 callback=delivery_callback)
producer.poll(0)       # triggers callbacks (non-blocking with timeout=0)
producer.flush(30.0)   # blocks until all messages delivered or timeout
```

Always call `flush()` before process exit. Without it, messages in the local buffer are silently lost. Call `poll(0)` periodically in produce loops to trigger callbacks and free buffer space.

### Key Serialization and Partitioning

Messages with the same key always go to the same partition (assuming partition count does not change). This guarantees ordering per key. If the partition count changes (e.g., topic expanded from 6 to 12 partitions), the key-to-partition mapping changes and existing keys may land on different partitions.

## Consumer Configuration

### group.id and auto.offset.reset

```python
from confluent_kafka import Consumer

config = {
    'bootstrap.servers': 'kafka1:9092',
    'group.id': 'my-consumer-group',    # Required for consumer groups
    'auto.offset.reset': 'earliest',    # What to do when no committed offset exists
}

consumer = Consumer(config)
consumer.subscribe(['my-topic'])
```

`auto.offset.reset` values:
- `earliest` -- start from the beginning of the topic (replay all messages).
- `latest` -- start from the end (only new messages).
- `error` -- throw an error if no committed offset exists.

This setting ONLY applies when there is no committed offset for the consumer group on a partition. Once an offset is committed, `auto.offset.reset` is ignored. This is the most misunderstood Kafka setting.

### The Poll Loop

```python
try:
    while True:
        msg = consumer.poll(timeout=1.0)  # Blocks up to 1 second

        if msg is None:
            continue  # No message within timeout

        if msg.error():
            if msg.error().code() == KafkaError._PARTITION_EOF:
                continue  # End of partition, not an error
            else:
                raise KafkaException(msg.error())

        # Process message
        process(msg.key(), msg.value())
finally:
    consumer.close()  # Commits offsets and leaves group cleanly
```

Always call `consumer.close()` in a `finally` block. Without it:
- Offsets may not be committed.
- The consumer group does not know the consumer left -- it waits for `session.timeout.ms` before rebalancing, causing a delay.

### Offset Management

#### Auto Commit (default)

With `enable.auto.commit=True` (default), offsets are committed every `auto.commit.interval.ms` (default: 5000ms). This is fine for most workloads where occasional duplicates are acceptable.

#### Manual Commit (for at-least-once guarantees)

```python
config = {
    'bootstrap.servers': 'kafka1:9092',
    'group.id': 'my-group',
    'enable.auto.commit': False,
}
consumer = Consumer(config)
consumer.subscribe(['my-topic'])

while True:
    msg = consumer.poll(1.0)
    if msg is None or msg.error():
        continue
    process(msg)
    # Synchronous commit -- blocks until broker confirms
    consumer.commit(message=msg, asynchronous=False)
```

For better performance, batch messages and commit after processing the batch. `consumer.commit()` with no arguments commits the current position for all assigned partitions. `consumer.commit(message=msg)` commits that message's offset + 1.

## Consumer Rebalancing

### Partition Assignment Strategies

When consumers join or leave a group, partitions are reassigned. The strategy controls how:

| Strategy | Behavior | Stop-the-world |
|---|---|---|
| `range` | Assigns contiguous partition ranges per topic. Default. | Yes |
| `roundrobin` | Distributes partitions evenly across consumers. | Yes |
| `cooperative-sticky` | Incremental rebalancing. Only revokes partitions that must move. | No |

```python
config = {
    'bootstrap.servers': 'kafka1:9092',
    'group.id': 'my-group',
    'partition.assignment.strategy': 'cooperative-sticky',
}
```

With `range` or `roundrobin`, ALL partitions are revoked and reassigned during rebalance -- consumers stop processing entirely. With `cooperative-sticky`, only the partitions that need to move are revoked. This is almost always what you want.

### Rebalancing Storms

Rebalancing storms occur when consumers repeatedly join/leave the group. Common cause: processing takes longer than `max.poll.interval.ms` (default: 300000ms = 5 min), so the broker kicks the consumer, which rejoins and triggers another rebalance.

```python
config = {
    'max.poll.interval.ms': 600000,     # Increase if processing is slow
    'session.timeout.ms': 45000,        # Heartbeat-based liveness check
    'heartbeat.interval.ms': 15000,     # Must be < session.timeout.ms / 3
}
```

If processing is genuinely slow, decouple polling from processing -- hand messages to a worker queue so `poll()` can be called frequently (it also sends heartbeats).

## Message Ordering Guarantees

Kafka guarantees ordering only within a single partition. Messages with the same key go to the same partition and are ordered. Messages with different keys may go to different partitions with no ordering guarantee.

With `enable.idempotence=True` and `max.in.flight.requests.per.connection <= 5`, ordering is preserved even during retries. Without idempotence, retries can reorder messages if `max.in.flight.requests.per.connection > 1`.

## Exactly-Once Semantics (EOS)

Exactly-once requires a transactional producer and `read_committed` consumer isolation:

```python
# Transactional Producer
producer_config = {
    'bootstrap.servers': 'kafka1:9092',
    'transactional.id': 'my-transactional-producer-1',  # Must be unique per producer instance
    'acks': 'all',
    'enable.idempotence': True,
}

producer = Producer(producer_config)
producer.init_transactions()  # Must call once before any transactional operations

try:
    producer.begin_transaction()
    producer.produce('output-topic', key=b'key', value=b'value')
    producer.produce('output-topic', key=b'key2', value=b'value2')
    producer.commit_transaction()
except Exception as e:
    producer.abort_transaction()
    raise

# Consumer reading transactionally-produced messages
consumer_config = {
    'bootstrap.servers': 'kafka1:9092',
    'group.id': 'eos-consumer',
    'isolation.level': 'read_committed',  # Only read committed transactional messages
    'enable.auto.commit': False,
}
```

EOS is expensive. Use it only when duplicates or data loss are truly unacceptable (financial transactions, etc.). For most use cases, idempotent consumers (deduplication on the consumer side) are simpler and faster.

## Schema Registry and Avro Serialization

For production systems, use Schema Registry with `SerializingProducer` to enforce schemas and handle evolution:

```python
from confluent_kafka import SerializingProducer
from confluent_kafka.schema_registry import SchemaRegistryClient
from confluent_kafka.schema_registry.avro import AvroSerializer

schema_registry = SchemaRegistryClient({'url': 'http://schema-registry:8081'})
schema_str = '{"type":"record","name":"UserEvent","fields":[{"name":"user_id","type":"int"},{"name":"action","type":"string"}]}'

producer = SerializingProducer({
    'bootstrap.servers': 'kafka1:9092',
    'value.serializer': AvroSerializer(schema_registry, schema_str),
})
producer.produce('user-events', value={'user_id': 1, 'action': 'login'})
producer.flush()
```

Pass dicts directly to `SerializingProducer.produce()` -- it handles serialization. Do not manually serialize.

## Consumer Lag Monitoring

Consumer lag = latest partition offset - committed consumer offset. High lag means the consumer is falling behind. Check via CLI with `kafka-consumer-groups --bootstrap-server localhost:9092 --group my-group --describe`, or programmatically:

```python
partitions = consumer.assignment()
for tp in partitions:
    (lo, hi) = consumer.get_watermark_offsets(tp)
    committed = consumer.committed([tp])[0].offset
    lag = hi - committed
```

## Common Mistakes Summary

1. **Not flushing the producer**: `produce()` is async. Call `flush()` before process exit or messages are lost.
2. **Misunderstanding auto.offset.reset**: Only applies when no committed offset exists. Not a "start from beginning every time" setting.
3. **Not calling consumer.close()**: Causes delayed rebalancing (waits for session timeout) and may lose uncommitted offsets.
4. **Processing too slow for max.poll.interval.ms**: Consumer gets kicked from the group, triggering rebalance storms.
5. **Assuming cross-partition ordering**: Kafka only orders within a single partition. Use the same key for messages that must be ordered.
6. **Changing partition count**: Breaks key-to-partition mapping. Existing keys may move to different partitions.
7. **Setting acks=1 with enable.idempotence=True**: Configuration error. Idempotence requires `acks=all`.
8. **Not polling frequently enough**: `poll()` sends heartbeats. If you do not call it, the broker thinks the consumer is dead.
9. **Using kafka-python in production**: The `kafka-python` library is less maintained and significantly slower than `confluent-kafka`. Prefer `confluent-kafka`.
10. **Forgetting delivery callbacks**: Without a callback, you have no way to know if a message failed to deliver. Silently lost data.
