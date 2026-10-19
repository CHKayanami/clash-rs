//! Execute conditional deletion inside the packet writers' synchronization domain.
use std::{io, os::fd::{AsFd, AsRawFd}};
use aya::{Ebpf, maps::{Array, Map, MapData}, programs::{ProgramFd, SchedClassifier}};
use clash_ebpf_common::{TrackingGcBatch, TrackingGcRequest, GC_BATCH_SIZE};

pub(super) struct GcProgram {
    request: Array<MapData, TrackingGcBatch>,
    program: ProgramFd,
}

const BPF_PROG_TEST_RUN: libc::c_long = 10;

// Prefix of bpf_attr.test. Later optional fields are zero when attr_size ends
// here. Input memory stays initialized and live throughout the syscall; the
// collector owns the sole request slot and never invokes it concurrently.
#[repr(C)]
#[derive(Default)]
struct TestRunAttr {
    prog_fd: u32,
    retval: u32,
    data_size_in: u32,
    data_size_out: u32,
    data_in: u64,
    data_out: u64,
    repeat: u32,
    duration: u32,
}

impl GcProgram {
    pub(super) fn new(bpf: &mut Ebpf) -> Result<Self, String> {
        let program: &mut SchedClassifier = bpf.program_mut("tracking_gc")
            .ok_or("missing tracking_gc program")?.try_into().map_err(|e| format!("tracking_gc: {e}"))?;
        if program.fd().is_err() { program.load().map_err(|e| format!("load tracking_gc: {e}"))?; }
        let program = program.fd().map_err(|e| e.to_string())?.try_clone().map_err(|e| e.to_string())?;
        let Some(Map::Array(map)) = bpf.map("TRACKING_GC_REQUEST") else {
            return Err("missing TRACKING_GC_REQUEST map".to_string());
        };
        let fd = map.fd().as_fd().try_clone_to_owned().map_err(|e| e.to_string())?;
        let request = Array::try_from(Map::Array(MapData::from_fd(fd).map_err(|e| e.to_string())?))
            .map_err(|e| e.to_string())?;
        let mut collector = Self { request, program };
        // Probe the required execution capability at startup, not on the
        // first expiry. An empty batch performs no record mutations.
        collector.run(&[])?;
        Ok(collector)
    }

    /// Returns one bit per successfully deleted candidate. There is still
    /// exactly one request-slot owner and one synchronous execution at a time.
    pub(super) fn run(&mut self, requests: &[TrackingGcRequest]) -> Result<u32, String> {
        if requests.len() > GC_BATCH_SIZE { return Err("tracking GC batch too large".to_string()); }
        let mut batch = TrackingGcBatch { count: requests.len() as u32, ..TrackingGcBatch::default() };
        batch.requests[..requests.len()].copy_from_slice(requests);
        self.request.set(0, batch, 0).map_err(|e| e.to_string())?;
        let data = [0u8; 14];
        let mut attr = TestRunAttr { prog_fd: self.program.as_fd().as_raw_fd() as u32,
            data_size_in: data.len() as u32, data_in: data.as_ptr() as u64,
            repeat: 1, ..TestRunAttr::default() };
        let result = unsafe { libc::syscall(libc::SYS_bpf, BPF_PROG_TEST_RUN,
            &mut attr as *mut TestRunAttr, size_of::<TestRunAttr>()) };
        if result < 0 { return Err(format!("tracking_gc test run: {}", io::Error::last_os_error())); }
        let valid = (1u32 << requests.len()) - 1;
        if attr.retval & !valid != 0 { return Err("invalid tracking GC result mask".to_string()); }
        Ok(attr.retval)
    }
}
