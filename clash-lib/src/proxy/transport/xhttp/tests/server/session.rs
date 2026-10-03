use std::{collections::BTreeMap, sync::atomic::{AtomicUsize, Ordering}};
use bytes::Bytes;
use parking_lot::Mutex;
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc, oneshot};
use super::super::super::body::{BodyChunk, RequestBody};

pub(super) struct Session {
    sender: Mutex<Option<mpsc::Sender<BodyChunk>>>,
    receiver: Mutex<Option<mpsc::Receiver<BodyChunk>>>,
    expected: usize,
    received: AtomicUsize,
    packets: AsyncMutex<(u64, BTreeMap<u64, Bytes>)>,
    changed: Notify,
}
impl Session {
    pub(super) fn new(expected: usize) -> Self {
        let (sender, receiver) = mpsc::channel(4);
        Self { sender: Mutex::new(Some(sender)), receiver: Mutex::new(Some(receiver)),
            expected, received: AtomicUsize::new(0), packets: AsyncMutex::new((0, BTreeMap::new())), changed: Notify::new() }
    }
    pub(super) fn body(&self) -> RequestBody {
        RequestBody::Stream(self.receiver.lock().take().expect("one download per session"))
    }
    pub(super) async fn echo(&self, data: Bytes) {
        let sender = self.sender.lock().as_ref().cloned();
        if let Some(sender) = sender {
            let length = data.len();
            let (consumed, _) = oneshot::channel();
            if sender.send(BodyChunk { data, consumed }).await.is_ok() {
                let total = self.received.fetch_add(length, Ordering::AcqRel) + length;
                if total >= self.expected { self.sender.lock().take(); }
                self.changed.notify_waiters();
            }
        }
    }
    pub(super) async fn packet(&self, sequence: u64, data: Bytes) {
        let mut packets = self.packets.lock().await;
        packets.1.insert(sequence, data);
        loop {
            let sequence = packets.0;
            let Some(data) = packets.1.remove(&sequence) else { break; };
            packets.0 += 1;
            self.echo(data).await;
        }
    }
    pub(super) async fn wait_for_data(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.received.load(Ordering::Acquire) != 0 { return; }
            changed.await;
        }
    }
}
