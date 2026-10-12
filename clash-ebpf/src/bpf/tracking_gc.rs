//! Bounded userspace scans keep full-table walks off the packet path.
use std::{io, os::fd::{AsFd, AsRawFd, RawFd}, time::Duration};
use aya::{Ebpf, Pod, maps::{HashMap, Map, MapData, MapError}};
use clash_ebpf_common::{FlowTrackEntry, RedirectTuple, UdpReplyEntry, UdpReplyKey,
    tracking::expired};
use tokio::{task::{AbortHandle, spawn_blocking}, time::{interval, MissedTickBehavior}};
use tracing::warn;
use super::{BpfBatchAttr, bpf_batch_syscall};

const BPF_MAP_LOOKUP_BATCH: libc::c_long = 24;
const CHUNK: usize = 512;
const PERIOD: Duration = Duration::from_millis(100);

struct Scanner<K, V> {
    map: HashMap<MapData, K, V>,
    fd: RawFd,
    cursor: Option<u32>,
    keys: Vec<K>,
    values: Vec<V>,
}

impl<K: Pod + Default, V: Pod + Default> Scanner<K, V> {
    fn new(bpf: &Ebpf, name: &str) -> Result<Self, String> {
        let Some(Map::HashMap(map)) = bpf.map(name) else {
            return Err(format!("missing hash map {name}"));
        };
        let owned = map.fd().as_fd().try_clone_to_owned().map_err(|e| e.to_string())?;
        let data = MapData::from_fd(owned).map_err(|e| e.to_string())?;
        let fd = data.fd().as_fd().as_raw_fd();
        let map = HashMap::try_from(Map::HashMap(data)).map_err(|e| e.to_string())?;
        Ok(Self { map, fd, cursor: None, keys: vec![K::default(); CHUNK],
            values: vec![V::default(); CHUNK] })
    }

    fn step(&mut self, mut expired: impl FnMut(&K, &V) -> bool) -> Result<(), String>
    where V: PartialEq {
        let mut next = 0u32;
        let mut attr = BpfBatchAttr {
            in_batch: self.cursor.as_ref().map_or(0, |cursor| cursor as *const u32 as u64),
            out_batch: &mut next as *mut u32 as u64,
            keys: self.keys.as_mut_ptr() as u64,
            values: self.values.as_mut_ptr() as u64,
            count: CHUNK as u32, map_fd: self.fd as u32, elem_flags: 0, flags: 0,
        };
        // Hash batch cursors are u32 bucket positions. Buffers hold CHUNK fully
        // initialized Pod values and remain alive for the synchronous syscall.
        // ENOENT may still return the last partial batch; other errors expose no
        // usable output. Batch lookup is supported since Linux 5.6, and is
        // required for this bounded collector.
        let result = unsafe { bpf_batch_syscall(BPF_MAP_LOOKUP_BATCH, &mut attr) };
        let done = result == Err(libc::ENOENT as i64);
        if let Err(errno) = result {
            if !done {
                self.cursor = None;
                return Err(format!("tracking batch lookup: {}", io::Error::from_raw_os_error(errno as i32)));
            }
        }
        self.cursor = if done { None } else { Some(next) };
        for index in 0..attr.count as usize {
            let key = &self.keys[index];
            let observed = &self.values[index];
            if !expired(key, observed) { continue; }
            // Recheck changes after scanning; the final check/delete window is
            // intentionally best-effort, with no packet-side lock or tombstone.
            match self.map.get(key, 0) {
                Ok(current) if current == *observed && expired(key, &current) => {
                    if let Err(error) = self.map.remove(key) {
                        if !missing(&error) { return Err(error.to_string()); }
                    }
                }
                Ok(_) => (),
                Err(error) if missing(&error) => (),
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(())
    }
}

fn missing(error: &MapError) -> bool {
    matches!(error, MapError::KeyNotFound)
        || matches!(error, MapError::SyscallError(error)
            if error.io_error.raw_os_error() == Some(libc::ENOENT))
}

struct Collector {
    flows: Scanner<RedirectTuple, FlowTrackEntry>,
    replies: Scanner<UdpReplyKey, UdpReplyEntry>,
}

impl Collector {
    fn new(bpf: &Ebpf) -> Result<Self, String> {
        Ok(Self { flows: Scanner::new(bpf, "FLOW_TRACK")?,
            replies: Scanner::new(bpf, "UDP_REPLY_TRACK")? })
    }

    fn step(&mut self, now: u64) -> Result<(), String> {
        let seconds = (now / 1_000_000_000) as u32;
        self.flows.step(|key, entry| expired(entry.activity(), seconds, key.proto == 17))?;
        self.replies.step(|_, entry| now.saturating_sub(entry.last_seen_ns) > 121_000_000_000)
    }
}

fn monotonic_ns() -> Result<u64, String> {
    let mut clock = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // Same CLOCK_MONOTONIC time domain as bpf_ktime_get_ns (excludes suspend).
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut clock) } != 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(clock.tv_sec as u64 * 1_000_000_000 + clock.tv_nsec as u64)
}

pub(super) fn start(bpf: &Ebpf) -> Result<AbortHandle, String> {
    let mut collector = Collector::new(bpf)?;
    let task = tokio::spawn(async move {
        let mut ticks = interval(PERIOD);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticks.tick().await;
            match spawn_blocking(move || {
                let result = monotonic_ns().and_then(|now| collector.step(now));
                (collector, result)
            }).await {
                Ok((returned, result)) => {
                    collector = returned;
                    if let Err(error) = result {
                        warn!("eBPF tracking cleanup stopped: {error}");
                        break;
                    }
                }
                Err(error) => { warn!("eBPF tracking cleanup worker failed: {error}"); break; }
            }
        }
    });
    Ok(task.abort_handle())
}

#[cfg(test)]
#[path = "tracking_gc_tests.rs"]
mod tests;
