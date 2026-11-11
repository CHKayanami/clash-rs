use clash_ebpf_common::tracking::gate::GateWord;
use crate::maps::TRACKING_GATES;

pub use clash_ebpf_common::tracking::gate::{bucket, reply_bucket};

#[inline(always)]
pub fn word(bucket: u32) -> Option<&'static GateWord> {
    let ptr = TRACKING_GATES.get_ptr_mut(bucket)?;
    // Array values are stable, eight-byte aligned storage for the lifetime of
    // the program. Only atomic accesses are permitted; no pointer escapes BPF.
    Some(unsafe { &*ptr.cast::<GateWord>() })
}
