//! Ingress appends to session-local index chains. No payload is copied, and
//! every owner remains in this bounded batch until its synchronous flush ends.
use super::*;
use crate::proxy::direct::native::SendWorkspace;
use crate::proxy::datagram::batch::MAX_DIRECT_BATCH_PACKETS;
const END: usize = usize::MAX;

pub(super) struct Uploads {
    packets: Vec<Upload>,
    next: [usize; MAX_DIRECT_BATCH_PACKETS],
    dirty: Vec<(usize, u64)>,
    send: Box<SendWorkspace>,
}
impl Uploads {
    pub fn new() -> Self {
        Self { packets: Vec::with_capacity(MAX_DIRECT_BATCH_PACKETS), next: [END; MAX_DIRECT_BATCH_PACKETS],
            dirty: Vec::with_capacity(MAX_DIRECT_BATCH_PACKETS), send: Box::default() }
    }
}
impl Engine {
    pub(crate) fn queue_upload(&mut self, upload: Upload) {
        assert!(self.ingress.packets.len() < MAX_DIRECT_BATCH_PACKETS);
        let Some(entry) = self.entries.at_mut(upload.slot, upload.association) else { return; };
        let index = self.ingress.packets.len();
        if entry.upload_head == END {
            entry.upload_head = index;
            self.ingress.dirty.push((upload.slot, upload.association));
        } else { self.ingress.next[entry.upload_tail] = index; }
        entry.upload_tail = index;
        self.ingress.next[index] = END;
        self.ingress.packets.push(upload);
    }
    pub(crate) fn flush_ingress(&mut self, cx: &mut Context<'_>, now: Instant) {
        let mut step = unconstrained(poll_fn(|_| {
            for index in 0..self.ingress.dirty.len() {
                let (slot, id) = self.ingress.dirty[index];
                let Some(entry) = self.entries.at_mut(slot, id) else { continue; };
                let mut cursor = entry.upload_head;
                entry.upload_head = END; entry.upload_tail = END;
                let first = &self.ingress.packets[cursor];
                let mut group = [first; MAX_DIRECT_BATCH_PACKETS];
                let mut count = 0;
                while cursor != END {
                    group[count] = &self.ingress.packets[cursor]; count += 1;
                    cursor = self.ingress.next[cursor];
                }
                // Snapshot before polling: a concurrent close/timer/socket
                // wake advances the generation and must be serviced again.
                let generation = entry.ready.generation();
                let wake = waker_ref(&entry.ready);
                let mut local = Context::from_waker(&wake);
                let checked = entry.control_generation == Some(generation);
                let work = entry.session.upload_borrowed(&mut local, &group[..count], checked, now, &mut self.ingress.send);
                entry.control_generation = Some(generation);
                if work.close { self.remove(id); continue; }
                // A Pending socket is already armed. Only runnable local work
                // needs another step; do not immediately retry the same send.
                if entry.session.has_buffered_upload() { self.pending_uploads.insert(id); }
                else { self.pending_uploads.remove(&id); }
                if work.again { self.schedule_local(id); }
            }
            self.ingress.packets.clear(); self.ingress.dirty.clear();
            Poll::Ready(())
        }));
        let _ = Pin::new(&mut step).poll(cx);
    }
    #[cfg(test)]
    pub(crate) fn upload_batch(&mut self, cx: &mut Context<'_>, uploads: &mut Vec<Upload>, now: Instant) {
        for upload in uploads.drain(..) { self.queue_upload(upload); }
        self.flush_ingress(cx, now);
    }
}
