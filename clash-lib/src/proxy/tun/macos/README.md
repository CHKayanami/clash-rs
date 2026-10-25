# macOS TUN

macOS uses the native L3 `utun` interface through `tun-rs`. No TAP device or
additional kernel extension is used. Creating the interface and managing routes
requires sufficient system privileges.

```yaml
tun:
  enable: true
  device-id: dev://utun1989
  auto-route: true
  auto-detect-interface: true
  gateway: 198.18.0.1/30
  gateway-v6: fdfe:dcba:9876::1/64
  dns-hijack: true
  route-exclude-address:
    - 192.168.0.0/16
```

The default outbound interface comes from SystemConfiguration's primary network
service, rather than interface-name priorities. The TUN service listens for
Darwin routing and interface-change notifications, coalesces bursts, and updates
its scoped default routes when the physical interface or gateway changes.
`auto-route` or `auto-detect-interface` also updates socket interface binding;
an explicitly configured outbound interface continues to take precedence.
Owned TUN names are registered before native service publication and excluded
from automatic primary-interface selection through cleanup. Other VPN interfaces
are not rejected solely for having an `utun` name. If configd temporarily selects
an owned service, a still-present previous upstream interface can be retained.
Automatic policy-routing marks are assigned only on Linux; macOS DNS and
proxy sockets use interface binding without an automatically injected SO_MARK.
Changes to the outbound name, index or addresses invalidate TUN UDP route caches
and physical association generations. Scoped-route repair or gateway changes
alone do not reset UDP sessions. Failed route updates
are rolled back and retried after one second. Normal reconciliation runs every
30 seconds and verifies actual kernel routes, repairing external deletions.

Capture prefixes and exclusions are computed once. Route snapshots and mutations
use native routing APIs via `route_manager`, without spawning `route` processes.
Ordered sets provide logarithmic membership checks. The monitor blocks on route
notifications and a cancellation socket, without 250ms idle polling; neighbor
cache entries, failed updates, and query replies do not trigger reconciliation.

Excluded networks are subtracted from the routes captured by TUN. Their traffic
uses the system's existing routing table, preserving LAN and other VPN routes.
An explicit route conflict causes initialization to fail rather than replacing
an unrelated route. Only routes created by this runner are removed on shutdown.

With `auto-route` and matching DNS hijack rules, a private supplemental DNS
service is published through SystemConfiguration. Its server is a nearby IPv4
address (skipping network/broadcast addresses), with a dedicated host route into
TUN. Both UDP and TCP port 53
must match the hijack rules when TCP is enabled. No DNS service is published if
the address is excluded. Existing per-domain system resolvers can still take
precedence for their domains; application DoH/DoT is not port-53 DNS hijacking.

DNS keys are session-owned: dropping the native session, including process
termination, removes them without rewriting persistent network preferences.
Route setup failures roll back routes already created during initialization.
Abrupt process termination can still leave physical-interface scoped routes;
normal shutdown is required for their explicit cleanup.
The native worker retains the utun device until its DNS and route guards finish
cleanup, so pipeline shutdown cannot destroy the interface before route removal.

For `fd://` devices, the host (for example, NetworkExtension) owns interface
configuration, routes, and DNS. ClashRS does not change those settings. Native
network monitoring is started only if outbound auto-detection is requested.

The macOS data path uses Darwin `recvmsg_x` and `sendmsg_x`, with at most 32
independent IP datagrams per syscall. Every datagram has its own four-byte utun
family header. Each receive slot allocates one MTU plus a truncation guard.
Packets smaller than half the slot capacity are copied into compact allocations,
leaving the slot reusable. Larger packets take exclusive ownership of the entire
allocation without copying; no shared tail can pin oversized blocks downstream.
Their retained capacity is at most twice their payload length. Invalid or truncated datagrams are dropped
individually with debug logging; valid packets later in the same batch survive.
A batch containing only invalid datagrams does not report EOF. Successful partial sends
advance only by the reported count. Unreported non-retryable errors are not
replayed. Temporary ENOBUFS pressure yields before retrying.
Reader and writer share one duplicated descriptor and Tokio readiness registration.
Device I/O and its platform tests live together under `tun/device_io/`.

`tun-rs` still creates/configures devices and provides ordinary I/O on other
platforms. For external `fd://` devices, injection remains individual packet
writes through tun-rs: NetworkExtension netif utun queues have a known high-rate
injection issue, so native multi-message writes are enabled only for utun devices
created directly by ClashRS. Native receive batching also works with external
utun FDs. The private Darwin ABI follows Apple's
[socket_private.h](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/socket_private.h)
and [syscalls.master](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/syscalls.master).
These are private XNU interfaces with no stable public ABI guarantee; the C
`syscall()` entry point is deprecated on macOS. The numbers and layouts must be
rechecked when changing supported OS versions. Set `CLASH_RS_MACOS_TUN_NATIVE_IO=0`
in the process environment before startup to use ordinary tun-rs reads and
single-packet writes. No native batch reader/writer or duplicated descriptor is
created in that mode; neither private batch syscall is used.
There is no automatic replay through the plain writer after a syscall error,
because a failed batch may already have consumed an unreported prefix.

The reply queue has both a packet limit and a 4 MiB byte budget. On macOS,
system TCP packets returned directly from the device reader charge their actual
owned allocation capacity. Compact dispatcher replies charge their length.
Both paths share the same byte budget; there is no fixed MTU-dependent minimum charge. Budget
permits remain held until device I/O completes, and cancellation
returns them. This bounds queued packet storage, not total process memory.

System TCP listeners are bound before startup succeeds; failed bindings cannot
silently route packets into an unconsumed userspace TCP listener. NAT indexes
share one read/write lock, and checksum updates touch changed header words rather
than scanning payloads. Exhausting the NAT port range refuses new mappings
instead of overwriting existing connections.
NAT entries are stored inline; reverse lookups copy addresses under the read lock
without allocating or retaining a session reference. Idle mappings expire after
300 seconds, checked every 30 seconds.

`enable-tcp: false` disables both TCP forwarding and local ICMP replies;
UDP forwarding remains enabled. When TCP is enabled, ICMP echo replies are
synthesized locally and do not establish reachability of the requested target.
System TCP mode creates no smoltcp TCP listener or background task; its ICMP
responder is initialized only when needed. Reply batches reuse their storage
and drain currently ready packets without waiting for a full batch.

`tun/tcp.rs` owns TCP listener initialization and connection tasks. Stopping TUN
cancels those tasks and both UDP forwarding directions, including their DNS
queries. TCP relay configuration is shared across connections. At most 256 UDP
DNS queries are admitted concurrently, bounding retained query tasks and buffers.

## Validation

Deterministic unit tests cover route ownership and rollback, network-switch
failure and repair, exclusions, IPv6 gateway scopes, notification filtering and
cancellation, DNS eligibility, queue admission/cancellation, NAT capacity and
IPv4/IPv6 incremental checksums. Local datagram sockets exercise native batch
framing, truncation, backpressure, and wrapper error/cancellation behavior.
UDP dispatcher regressions verify network-change reconnection and association
generation isolation.

Privileged end-to-end validation should additionally cover Wi-Fi/Ethernet
switching, sleep/wake, IPv6-only networks, DNS resolution and normal shutdown.
Check `netstat -rn`, `scutil --dns`, and `scutil --nwi` before and after a run;
verify unrelated routes and DNS settings remain intact. Compile/unit-test
success alone does not establish those real-network behaviors.
