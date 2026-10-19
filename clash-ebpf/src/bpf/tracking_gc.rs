//! Bounded userspace scans keep full-table walks off the packet path.
use std::{io, os::fd::{AsFd, AsRawFd}, time::Duration};
use aya::{Ebpf, Pod, maps::{Map, MapData}};
#[cfg(test)]
use aya::maps::HashMap;
use clash_ebpf_common::{FlowTrackEntry, RedirectTuple, UdpReplyEntry, UdpReplyKey,
    TrackingGcRequest, GC_BATCH_SIZE, GC_FLOW, GC_UDP_REPLY, tracking::expired};
use tokio::{task::{AbortHandle, spawn_blocking}, time::sleep};
use tracing::warn;
use super::{BpfBatchAttr, bpf_batch_syscall, tracking_gc_program::GcProgram};

const BPF_MAP_LOOKUP_BATCH: libc::c_long = 24;
const CHUNK: usize = 512;
const BATCH_PAUSE: Duration = Duration::from_millis(100);
#[path = "tracking_gc_schedule.rs"]
mod schedule;
use schedule::Schedule;

trait GcValue<K>: Pod {
    fn request(&self, key: &K, now_ns: u64) -> TrackingGcRequest;
}

impl GcValue<RedirectTuple> for FlowTrackEntry {
    fn request(&self, key: &RedirectTuple, now_ns: u64) -> TrackingGcRequest {
        TrackingGcRequest { tuple: *key, generation: self.generation,
            activity: self.activity(), now_ns, kind: GC_FLOW, _pad: 0 }
    }
}

impl GcValue<UdpReplyKey> for UdpReplyEntry {
    fn request(&self, key: &UdpReplyKey, now_ns: u64) -> TrackingGcRequest {
        TrackingGcRequest { tuple: RedirectTuple { src_ip: key.client_ip,
            dst_ip: key.peer_ip, ip_version: key.ip_version,
            ..RedirectTuple::default() }, generation: self.generation,
            activity: self.last_seen_ns, now_ns, kind: GC_UDP_REPLY, _pad: 0 }
    }
}

struct Scanner<K, V> {
    data: MapData,
    #[cfg(test)]
    map: HashMap<MapData, K, V>,
    cursor: Option<u32>,
    complete: bool,
    entries: usize,
    capacity: u32,
    keys: Vec<K>,
    values: Vec<V>,
    requests: Vec<TrackingGcRequest>,
}

impl<K: Pod + Default, V: Pod + Default> Scanner<K, V> {
    fn new(bpf: &Ebpf, name: &str) -> Result<Self, String> {
        let Some(Map::HashMap(map)) = bpf.map(name) else {
            return Err(format!("missing hash map {name}"));
        };
        let capacity = map.info().map_err(|e| e.to_string())?.max_entries();
        let owned = map.fd().as_fd().try_clone_to_owned().map_err(|e| e.to_string())?;
        let data = MapData::from_fd(owned).map_err(|e| e.to_string())?;
        #[cfg(test)]
        let map = {
            let fd = data.fd().as_fd().try_clone_to_owned().map_err(|e| e.to_string())?;
            HashMap::try_from(Map::HashMap(MapData::from_fd(fd).map_err(|e| e.to_string())?))
                .map_err(|e| e.to_string())?
        };
        Ok(Self { data, #[cfg(test)] map, cursor: None, complete: false, entries: 0, capacity, keys: vec![K::default(); CHUNK],
            values: vec![V::default(); CHUNK], requests: Vec::with_capacity(GC_BATCH_SIZE) })
    }

    fn restart(&mut self) {
        self.cursor = None;
        self.complete = false;
        self.entries = 0;
    }

    fn usage_percent(&self) -> u64 {
        self.entries as u64 * 100 / self.capacity as u64
    }

    fn flush(&mut self, gc: &mut GcProgram) -> Result<(), String> {
        if self.requests.is_empty() { return Ok(()); }
        let deleted = gc.run(&self.requests)?;
        self.entries -= deleted.count_ones() as usize;
        self.requests.clear();
        Ok(())
    }

    fn step(&mut self, gc: &mut GcProgram, now_ns: u64,
        mut expired: impl FnMut(&K, &V) -> bool,
    ) -> Result<(), String> where V: GcValue<K> {
        if self.complete { return Ok(()); }
        let mut next = 0u32;
        let mut attr = BpfBatchAttr {
            in_batch: self.cursor.as_ref().map_or(0, |cursor| cursor as *const u32 as u64),
            out_batch: &mut next as *mut u32 as u64,
            keys: self.keys.as_mut_ptr() as u64,
            values: self.values.as_mut_ptr() as u64,
            count: CHUNK as u32, map_fd: self.data.fd().as_fd().as_raw_fd() as u32,
            elem_flags: 0, flags: 0,
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
        self.complete = done;
        self.entries += attr.count as usize;
        for index in 0..attr.count as usize {
            let key = &self.keys[index];
            let observed = &self.values[index];
            if !expired(key, observed) { continue; }
            // The BPF collector rechecks incarnation, activity and expiry while
            // excluding packet writers through the same bucket gate.
            self.requests.push(observed.request(key, now_ns));
            if self.requests.len() == GC_BATCH_SIZE { self.flush(gc)?; }
        }
        self.flush(gc)
    }
}

struct Collector {
    program: GcProgram,
    schedule: Schedule,
    flows: Scanner<RedirectTuple, FlowTrackEntry>,
    replies: Scanner<UdpReplyKey, UdpReplyEntry>,
}

impl Collector {
    fn new(bpf: &mut Ebpf) -> Result<Self, String> {
        let program = GcProgram::new(bpf)?;
        Ok(Self { program, schedule: Schedule::new(), flows: Scanner::new(bpf, "FLOW_TRACK")?,
            replies: Scanner::new(bpf, "UDP_REPLY_TRACK")? })
    }

    fn pause(&self) -> Duration {
        if self.flows.complete && self.replies.complete {
            self.schedule.pause()
        } else { BATCH_PAUSE }
    }

    fn step(&mut self, now: u64) -> Result<(), String> {
        if self.flows.complete && self.replies.complete {
            self.flows.restart();
            self.replies.restart();
        }
        let seconds = (now / 1_000_000_000) as u32;
        self.flows.step(&mut self.program, now, |key, entry| expired(entry.activity(), seconds, key.proto == 17))?;
        self.replies.step(&mut self.program, now, |_, entry| now.saturating_sub(entry.last_seen_ns) > 121_000_000_000)?;
        if self.flows.complete && self.replies.complete {
            let usage = self.flows.usage_percent().max(self.replies.usage_percent());
            self.schedule.update(usage, self.flows.entries == 0 && self.replies.entries == 0);
        }
        Ok(())
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

pub(super) fn start(bpf: &mut Ebpf) -> Result<AbortHandle, String> {
    let mut collector = Collector::new(bpf)?;
    let task = tokio::spawn(async move {
        loop {
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
            sleep(collector.pause()).await;
        }
    });
    Ok(task.abort_handle())
}

#[cfg(test)]
#[path = "tracking_gc_tests.rs"]
mod tests;
