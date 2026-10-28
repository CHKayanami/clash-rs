# Android embedding

Build for `aarch64-linux-android` or `x86_64-linux-android` with the Android NDK,
not a GNU/Linux target. The minimum API level used by the build script is 26.
Install Rust, CMake, cargo-ndk 4.1.2, the Android NDK, and set `ANDROID_NDK_HOME`:

```sh
bash scripts/build_android.sh arm64-v8a
# Optional emulator ABI:
bash scripts/build_android.sh x86_64
```

The script builds `clash-ffi` with `clash-lib/standard` (the TLS provider) and
`clash-lib/tun`, without the embedded dashboard. Libraries are placed in
`target/android/jniLibs/<abi>/libclashrs.so`. Package all libraries in the ABI
directory, including the NDK `libc++_shared.so` runtime. The C ABI is not JNI; an Android host
must provide its own JNI bridge, or depend on `clash-lib` from a Rust JNI crate.
The workspace BoringSSL patch and Cargo.lock are required for reproducible builds.

## VPN host responsibilities

1. Obtain user consent with `VpnService.prepare` and create the interface with
   `VpnService.Builder`. Configure addresses, routes, DNS servers and MTU there.
2. Either exclude the core's application UID with `addDisallowedApplication`, or
   install `clash_lib::android::set_socket_protector(Some(callback))` before
   starting the core. The callback must synchronously call `VpnService.protect`
   on the borrowed fd and return an `io::Error` if Android rejects protection.
   TCP, proxy UDP/QUIC and direct DNS UDP sockets invoke it before connecting or
   sending. This does not cover network operations performed by external SDKs.
3. Transfer a unique, valid TUN descriptor to the core. Rust JNI hosts should
   call `clash_lib::android::register_tun_fd(owned_fd)` and retain its guard until
   the core thread exits. The guard closes an unclaimed descriptor if startup or
   reload fails before TUN initialization. On cancellation, `close_pending()` can
   release an unclaimed interface immediately; later adoption then fails safely.
   Once adopted, `tun-rs` becomes the sole owner and closes it on device drop.
   Never close an adopted fd or reuse the same descriptor for two cores.
   Initialize resources with TUN disabled before creating the VPN interface, then
   reload the prepared config with the registered fd to minimize network outage.
4. Use this TUN configuration, with the actual descriptor and host MTU:

```yaml
tun:
  enable: true
  device-id: fd://42
  mtu: 1500
  gateway: 172.19.0.1/30
  auto-route: false
  auto-detect-interface: false
  dns-hijack: [any:53]
```

Android startup rejects invalid descriptors, invalid MTUs and core-managed route
options. Configure route inclusion/exclusion in the VPN builder instead. Android
cannot query a host-supplied TUN's MTU through the desktop tun-rs interface; the
core uses the configured MTU (1500 if omitted). IPv6 requires a host IPv6 address,
routes and an MTU of at least 1280. The gateway setting must match the host.

For Rust embedders, `start_scaffold_instance` returns a thread and cancellation
token; cancel and join it before replacing the TUN. The C `clash_start` function
blocks and must not run on Android's main thread. Handle startup failures and
keep the foreground service and notification alive for the VPN lifetime.

Network changes and split tunnelling are owned by the Android host. The core's
Linux iptables, policy-routing, eBPF and process-table lookup paths are not used
on Android. `PROCESS-NAME` rules do not gain Android package matching from this
integration. Desktop interface binding is intentionally skipped on Android.
Compile success does not replace device tests for DNS, TCP/UDP, QUIC, IPv6,
network switching, permission revocation and repeated start/stop.
