//! Owner-local UDP I/O. Each ready association gets one send and receive batch;
//! a whole relay future is never polled inside the device task.
#[cfg(target_os = "linux")]
use crate::proxy::direct::recv::ReceiveSlots;
mod ready;
mod entries;
mod upload;
use entries::Entries;
use upload::Uploads;
pub(in crate::app::dispatcher::udp::association) mod session;
use std::{collections::{BTreeMap, HashSet, VecDeque}, future::Future, io, pin::Pin,
    sync::Arc, task::{Context, Poll}};
use futures::{future::poll_fn, task::waker_ref};
use tokio::{sync::mpsc, task::unconstrained};
use ready::{Queue, Ready};
use bytes::Bytes;
use tokio::time::Instant;
use session::Session;
use super::Upload;
use crate::proxy::datagram::{segments::DatagramSegments, batch::{MAX_BATCH_PACKETS, MAX_BATCH_BYTES}};

const ASSOCIATIONS: usize = 32;
const FRAMES: usize = 32;
const BYTES: usize = 512 * 1024;
const PENDING_FRAMES: usize = 512;
const PENDING_BYTES: usize = 4 * 1024 * 1024;
struct Entry {
    session: Session, ready: Arc<Ready>, output_queued: bool,
    output_frames: usize, output_bytes: usize, upload_head: usize, upload_tail: usize, control_generation: Option<u64>, local_queued: bool, compact_queued: bool, serviced: u64,
}
pub(crate) struct Engine {
    #[cfg(target_os = "linux")]
    receive_slots: ReceiveSlots,
    incoming: mpsc::UnboundedReceiver<Session>,
    entries: Entries,
    ingress: Uploads,
    ready: Arc<Queue>,
    outputs: VecDeque<u64>,
    local: VecDeque<u64>,
    compact: VecDeque<u64>,
    blocked: BTreeMap<u64, Arc<Ready>>,
    pending_uploads: HashSet<u64>,
    output_blocked: bool,
    pending_bytes: usize,
    pending_frames: usize,
    mtu: Option<usize>,
}
#[derive(Clone)]
pub(in crate::app::dispatcher::udp::association) struct Sender { channel: mpsc::UnboundedSender<Session>, offload: bool }

pub(super) fn channel(mtu: Option<usize>) -> (Sender, Engine) {
    let (sender, incoming) = mpsc::unbounded_channel();
    (Sender { channel: sender, offload: mtu.is_some() }, Engine { #[cfg(target_os = "linux")] receive_slots: Default::default(), incoming, entries: Entries::default(), ingress: Uploads::new(), ready: Arc::default(),
        outputs: VecDeque::new(), local: VecDeque::new(), compact: VecDeque::new(), blocked: BTreeMap::new(), pending_uploads: HashSet::new(), output_blocked: false, pending_bytes: 0, pending_frames: 0, mtu })
}
impl Sender {
    // Each queued registration owns an association-capacity permit.
    pub fn offload(&self) -> bool { self.offload }
    pub fn install(&self, session: Session) -> io::Result<()> {
        self.channel.send(session).map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
}
impl Engine {
    pub(crate) fn set_output_blocked(&mut self, blocked: bool) { self.output_blocked = blocked; }
    fn track_upload(&mut self, id: u64) {
        if self.entries.get(&id).is_some_and(|entry| entry.session.has_buffered_upload()) {
            self.pending_uploads.insert(id);
        } else { self.pending_uploads.remove(&id); }
    }
    fn schedule_local(&mut self, id: u64) {
        if let Some(entry) = self.entries.get_mut(&id) && !entry.local_queued {
            entry.local_queued = true; self.local.push_back(id);
        }
    }
    pub(crate) fn mtu(&self) -> Option<usize> { self.mtu }
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>, now: Instant) -> bool {
        // Only this explicitly bounded step bypasses Tokio's task budget. The
        // surrounding TUN loop keeps its own budget and visits every stage.
        let mut step = unconstrained(poll_fn(|cx| Poll::Ready(self.poll_bounded(cx, now))));
        match Pin::new(&mut step).poll(cx) {
            Poll::Ready(progress) => progress,
            Poll::Pending => unreachable!("bounded UDP step is synchronous"),
        }
    }
    fn receive_available(&self) -> bool {
        !self.output_blocked && self.pending_bytes < PENDING_BYTES && self.pending_frames < PENDING_FRAMES
    }
    fn poll_bounded(&mut self, cx: &mut Context<'_>, now: Instant) -> bool {
        self.ready.waker.register(cx.waker());
        let mut progress = false;
        for index in 0..ASSOCIATIONS {
            match self.incoming.poll_recv(cx) {
                Poll::Ready(Some(session)) => {
                    let ready = Ready::new(session.id, &self.ready);
                    let id = session.id;
                    self.entries.insert(session.id, Entry { session, ready, output_queued: false, output_frames: 0, output_bytes: 0, upload_head: usize::MAX, upload_tail: usize::MAX, control_generation: None, local_queued: false, compact_queued: false, serviced: 0 });
                    self.schedule_local(id);
                    progress = true;
                    if index + 1 == ASSOCIATIONS { cx.waker().wake_by_ref(); }
                },
                _ => break,
            }
        }
        if self.receive_available() {
            for _ in 0..ASSOCIATIONS {
                let Some((_, ready)) = self.blocked.pop_first() else { break; };
                self.schedule_local(ready.id);
            }
        }
        let mut external = self.ready.len();
        let visits = (self.local.len() + external).min(ASSOCIATIONS);
        let (mut frames, mut bytes) = (0, 0);
        for index in 0..visits {
            if frames >= FRAMES || bytes >= BYTES { break; }
            let (id, local) = if !self.local.is_empty() && (index % 2 == 0 || external == 0) {
                (self.local.pop_front().expect("local UDP work"), true)
            } else if let Some(ready) = self.ready.pop() { external = external.saturating_sub(1); (ready.id, false) }
            else { break; };
            let receive = self.receive_available();
            let Some(entry) = self.entries.get_mut(&id) else { continue; };
            let generation = entry.ready.generation();
            if !local && (entry.local_queued || generation == entry.serviced) { continue; }
            // Events arriving after this snapshot remain eligible next pass.
            entry.serviced = generation;
            entry.local_queued = false;
            let wake = waker_ref(&entry.ready);
            let mut local = Context::from_waker(&wake);
            let before = entry.session.replies.len();
            let checked = entry.control_generation == Some(generation);
            let work = entry.session.poll(&mut local, receive, checked, now, #[cfg(target_os = "linux")] &mut self.receive_slots);
            entry.control_generation = Some(generation);
            frames += work.frames; bytes += work.bytes; progress |= work.progress;
            if work.close { self.remove(id); continue; }
            if entry.session.replies.len() > before && !entry.compact_queued {
                entry.compact_queued = true; self.compact.push_back(id);
            }
            for group in entry.session.replies.iter().skip(before) {
                self.pending_bytes += group.packet.data.len(); self.pending_frames += 1;
            }
            if !entry.session.replies.is_empty() && !entry.output_queued {
                self.outputs.push_back(id); entry.output_queued = true;
            }
            if !receive && entry.session.replies.is_empty() {
                self.blocked.insert(id, entry.ready.clone());
            }
            self.track_upload(id);
            if work.again { self.schedule_local(id); }
        }
        if !self.local.is_empty() || !self.ready.is_empty() || (self.receive_available() && !self.blocked.is_empty()) {
            cx.waker().wake_by_ref();
        }
        progress
    }
    pub(crate) fn take_reply(&mut self) -> Option<DatagramSegments> {
        let id = self.outputs.pop_front()?;
        let entry = self.entries.get_mut(&id).expect("UDP reply owner");
        let group = entry.session.replies.pop_front().expect("UDP reply frame");
        self.pending_bytes -= group.packet.data.len(); self.pending_frames -= 1;
        entry.output_frames += 1; entry.output_bytes += group.packet.data.len();
        if entry.session.replies.is_empty() {
            entry.output_queued = false; entry.output_frames = 0; entry.output_bytes = 0;
            self.schedule_local(id);
        } else if entry.output_frames < MAX_BATCH_PACKETS && entry.output_bytes < MAX_BATCH_BYTES {
            // Keep a transport batch contiguous so native TUN UDP GSO can
            // coalesce it. Rotate at the frame/byte limit to preserve fairness.
            self.outputs.push_front(id);
        } else {
            entry.output_frames = 0; entry.output_bytes = 0; self.outputs.push_back(id);
        }
        Some(group)
    }
    pub(crate) fn needs_poll(&self) -> bool {
        !self.local.is_empty() || (self.receive_available() && !self.blocked.is_empty())
    }
    pub(crate) fn compact_pending(&mut self) {
        for id in &self.pending_uploads {
            if let Some(entry) = self.entries.get_mut(id) { entry.session.compact_pending(); }
        }
        // Only output owners are visited, bounded by the pending-frame budget.
        while let Some(id) = self.compact.pop_front() {
            if let Some(entry) = self.entries.get_mut(&id) {
                entry.compact_queued = false;
                for group in &mut entry.session.replies {
                    if !group.packet.data.is_unique() {
                        group.packet.data = Bytes::copy_from_slice(&group.packet.data);
                    }
                }
            }
        }
    }
    fn remove(&mut self, id: u64) {
        if let Some(entry) = self.entries.remove(&id) {
            entry.ready.close();
            for group in &entry.session.replies {
                self.pending_bytes -= group.packet.data.len(); self.pending_frames -= 1;
            }
            // Output owners are bounded by PENDING_FRAMES, including tiny UDP.
            if entry.output_queued { self.outputs.retain(|current| *current != id); }
        }
        self.pending_uploads.remove(&id);
        self.blocked.remove(&id);
        self.local.retain(|current| *current != id);
        self.compact.retain(|current| *current != id);
    }
}

#[cfg(test)]
mod tests;
