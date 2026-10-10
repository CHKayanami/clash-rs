//! Isolated allocation and layout checks for outbound dispatch futures.
//! This allocator belongs only to this integration-test executable.
//! The test allocator forwards every pointer/layout unchanged to System; it
//! never changes allocation ownership, alignment, or deallocation lifetimes.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};
use clash_lib::dispatch_measurement::measure_dispatch_futures;

thread_local! {
    static TRACKING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

struct DispatchAllocator;

fn record_allocation() {
    if TRACKING.try_with(Cell::get).unwrap_or(false) {
        let _ = ALLOCATIONS.try_with(|count| count.set(count.get().saturating_add(1)));
    }
}

// SAFETY: every operation delegates to System with the caller's original
// pointer, layout and size. The thread-local counters neither allocate nor
// access the allocated memory, including during thread-local teardown.
unsafe impl GlobalAlloc for DispatchAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record_allocation();
        unsafe { System.realloc(ptr, layout, size) }
    }
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
            if let Some(expected) = expected { assert_eq!(count, expected, "{name} allocations"); }
            count
        },
    ).await;
    drop(tracking);
}
