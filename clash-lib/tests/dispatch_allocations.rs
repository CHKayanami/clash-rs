//! Isolated allocation and layout checks for outbound dispatch futures.
//! This allocator belongs only to this integration-test executable.
//! The test allocator forwards every pointer/layout unchanged to System; it
//! never changes allocation ownership, alignment, or deallocation lifetimes.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};
use clash_lib::dispatch_measurement::{measure_copy_runtime, measure_dispatch_futures};

thread_local! {
    static TRACKING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static ALLOCATED_BYTES: Cell<usize> = const { Cell::new(0) };
    static FREED_BYTES: Cell<usize> = const { Cell::new(0) };
}

struct DispatchAllocator;

fn record_allocation(bytes: usize) {
    if TRACKING.try_with(Cell::get).unwrap_or(false) {
        let _ = ALLOCATIONS.try_with(|count| count.set(count.get().saturating_add(1)));
        let _ = ALLOCATED_BYTES.try_with(|count| count.set(count.get().saturating_add(bytes)));
    }
}

// SAFETY: every operation delegates to System with the caller's original
// pointer, layout and size. The thread-local counters neither allocate nor
// access the allocated memory, including during thread-local teardown.
unsafe impl GlobalAlloc for DispatchAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if TRACKING.try_with(Cell::get).unwrap_or(false) {
            let _ = FREED_BYTES.try_with(|count| count.set(count.get().saturating_add(layout.size())));
        }
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record_allocation(size);
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[tokio::test]
async fn forwarding_runtime_allocations() {
    let tracking = Tracking;
    measure_copy_runtime(
        || {
            assert!(!TRACKING.get());
            ALLOCATIONS.set(0);
            ALLOCATED_BYTES.set(0);
            FREED_BYTES.set(0);
            TRACKING.set(true);
        },
        |name, _, expected| {
            TRACKING.set(false);
            let count = ALLOCATIONS.get();
            let bytes = ALLOCATED_BYTES.get();
            let freed = FREED_BYTES.get();
            println!("{name}: allocations={count} allocated_bytes={bytes} freed_bytes={freed}");
            assert_eq!(count, expected.unwrap(), "{name}");
            match name {
                "TCP copy initialization" => assert_eq!(bytes, 2048 + size_of::<tokio::time::Sleep>()),
                "splice copy initialization" => assert_eq!(bytes, size_of::<tokio::time::Sleep>()),
                _ => assert_eq!(bytes, 0, "{name} allocated during forwarding"),
            }
            match name {
                "TCP copy half-close" => assert_eq!(freed, 1024),
                "TCP copy completion" => assert_eq!(freed, 1024 + size_of::<tokio::time::Sleep>()),
                "splice copy completion" => assert_eq!(freed, size_of::<tokio::time::Sleep>()),
                _ => (),
            }
            count
        },
    ).await;
    drop(tracking);
}

#[global_allocator]
static ALLOCATOR: DispatchAllocator = DispatchAllocator;

struct Tracking;
impl Drop for Tracking {
    fn drop(&mut self) { TRACKING.set(false); }
}

#[tokio::test]
async fn native_dispatch_future_allocations_and_sizes() {
    let tracking = Tracking;
    measure_dispatch_futures(
        || {
            assert!(!TRACKING.get());
            ALLOCATIONS.set(0);
            TRACKING.set(true);
        },
        |name, bytes, expected| {
            TRACKING.set(false);
            let count = ALLOCATIONS.get();
            println!("{name}: future_bytes={bytes} allocations={count}");
            if matches!(name, "protocol enum" | "protocol UDP enum" | "group enum" | "pooled UDP enum") {
                assert!(bytes <= 512, "{name} retained an oversized dispatch future: {bytes}");
            }
            if name == "TCP bidirectional copy" {
                assert!(bytes <= 896, "TCP copy future grew: {bytes}");
            }
            if name.starts_with("boxed protocol") {
                assert_eq!(bytes, 2 * size_of::<usize>(), "{name} handle size");
            }
            if let Some(expected) = expected { assert_eq!(count, expected, "{name} allocations"); }
            count
        },
    ).await;
    drop(tracking);
}

// Type-only measurements: no dispatcher or DNS query is constructed or polled.
#[test]
fn top_level_dispatch_future_sizes() {
    use std::{future::Future, mem::size_of};
    use clash_lib::{
        app::{dispatcher::Dispatcher, dns::{query::QueryContext,
            upstream_pool::{UpstreamEntry, UpstreamPool}}},
    };
    fn dispatch_size<A, B, F: Future>(_: impl FnOnce(&'static Dispatcher, A, B) -> F) -> usize {
        size_of::<F>()
    }
    fn query_size<F: Future>(_: impl FnOnce(&'static UpstreamPool, &'static UpstreamEntry,
        &'static QueryContext, Option<&'static str>) -> F,
    ) -> usize { size_of::<F>() }
    fn udp_size<F: Future>(_: impl FnOnce(&'static UpstreamPool, &'static UpstreamEntry,
        std::net::SocketAddr, Option<&'static str>) -> F,
    ) -> usize { size_of::<F>() }
    let sizes = [
        ("TCP dispatch_stream", dispatch_size(Dispatcher::dispatch_stream)),
        ("UDP dispatch_datagram", dispatch_size(Dispatcher::dispatch_datagram)),
        ("DNS query_entry", query_size(UpstreamPool::query_entry)),
        ("DNS udp_pool", udp_size(UpstreamPool::udp_pool)),
    ];
    for (name, size) in sizes {
        println!("{name}: future_bytes={size}");
    }
    // Keep dispatch entry futures free of an outer async instrumentation layer.
    assert!(sizes[0].1 <= 2048, "TCP dispatch future grew: {}", sizes[0].1);
    assert!(sizes[1].1 <= 768, "UDP dispatch future grew: {}", sizes[1].1);
    // Bound DNS entry futures independently of the boxed dynamic-group branch.
    assert!(sizes[2].1 <= 6400, "DNS query future grew: {}", sizes[2].1);
    assert!(sizes[3].1 <= 2560, "DNS UDP future grew: {}", sizes[3].1);
}
