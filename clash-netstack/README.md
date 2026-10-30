## Usage

See the [examples](examples) directory for how to use the `clash-netstack` library.

## Source layout

```text
src/
  stack/              Public packet ingress/egress and protocol selection
  link/               L3 packets, output capacity, tracing and ICMP
  tcp/
    engine.rs         Tokio task and connection lifecycle
    connections.rs    Authoritative four-tuple index and non-reused connection IDs
    driver.rs         Indexed TCP delivery and bounded round-robin output
    schedule/         Protocol ready FIFO and indexed deadline heap
    stream.rs         AsyncRead/AsyncWrite adapter
    forward.rs        Native socket handoff
    buffers.rs        Per-connection buffer growth policy
    protocol/
      context.rs      Minimal transparent L3 endpoint context
      socket/         TCP configuration, lifecycle, stream I/O, input and output
      congestion/     CUBIC, Reno and disabled congestion control
      storage/        Protocol rings and out-of-order receive assembly
      tests/          Shared fixtures and protocol regressions by behavior
  udp/                Datagram parsing and forwarding
```

The TUN TCP state machine and its protocol storage are maintained here, derived
from smoltcp commit `6b126ba1e965add8d765dffee0338756ffdfb6da`. The migrated
code retains its [0BSD license](src/tcp/protocol/LICENSE-0BSD.txt). smoltcp still
provides wire codecs, address/time types, and ICMP handling from crates.io
0.14.0. WireGuard uses that upstream implementation independently of this TUN
TCP core; no workspace smoltcp patch is required.

Input uses one authoritative four-tuple index. Protocol output has its own
deduplicated FIFO: each ready connection emits one segment before rotating to
the tail, with a per-pass limit of 128 work items and 256 KiB. Immediate ingress
control responses, including SYN|ACK, run before application close handling.
Ingress itself is limited to a 32-packet engine batch.

The indexed minimum heap retains at most one protocol deadline per connection;
updates and cancellation remove old records immediately. The engine reuses one
Sleep for the earliest protocol deadline. Application/native I/O readiness is
separate, and no global socket scan is needed for packet delivery or timers.
No DRR, multiple engines, or new TCP recovery algorithm is introduced.

Sockets own their buffers; protocol processing and native socket handoff remain
owned by one engine task, so borrowed protocol slices never escape a synchronous
poll. Connection IDs are never reused, and removal unlinks both ready work and
the deadline before deleting the flow index. Local service disarms old protocol
wakers while mutating a socket and rearms them afterwards. Protocol completion
has an explicit, deduplicated notification queue; final relay/adapter handling
and reclamation do not depend on a remaining one-shot protocol waker.

TCP buffer tuning samples application-consumed RX bytes and cumulatively
acknowledged TX payload over at least max(smoothed RTT, 10 ms). The target is
twice the observed per-RTT progress, capped at twice the current capacity and
4 MiB per direction. Queue occupancy and application writes alone do not grow
buffers. TX buffers below 64 KiB may also double once per sampling interval
when relay service repeatedly fills the buffer and at least its current
capacity of payload is newly acknowledged. From 32 KiB, one fill plus newly
acknowledged payload of at least 1.5 times capacity also permits a probe, so
a WAN burst just below 64 KiB can complete startup growth without two full
32 KiB fills. This bounded startup probe avoids
small-buffer stalls when WAN bursts dilute local-RTT bandwidth estimates;
old pressure and ACK credit expire after each complete sample. A new fill
observed by that same service pass is recorded after settlement, unless TX
grew, so a burst arrival cannot erase pressure before its ACKs arrive. Sub-millisecond
measured RTTs use a 1 ms floor to match clock precision;
connections without an RTT measurement do not grow. Storage remains contiguous
and is retained until the connection is released.

## Run Tests
To run the tests, use the following command:

```bash
cargo test -p clash-netstack
```

## Disclaimer

Heavily based on [netstack-smoltcp](https://github.com/automesh-network/netstack-smoltcp) with simplified API and some modifications to fit the `clash-rs` ecosystem.

This library is not intended for production use and is provided as-is. Use at your own risk
