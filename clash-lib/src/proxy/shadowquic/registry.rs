use std::{
    collections::{HashMap, hash_map::Entry},
    io,
    time::{Duration, Instant},
};

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::sync::{Notify, mpsc::Sender};
use tokio_util::sync::CancellationToken;

use crate::session::SocksAddr;

use super::ids::ContextIds;

pub(super) type Packet = (Bytes, SocksAddr);
const MAX_PENDING_IDS: usize = 256;
const MAX_PENDING_BYTES: usize = 1024 * 1024;
const MAX_PENDING_PACKETS: usize = 32;
pub(super) const REGISTER_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(super) struct Route {
    session: u64,
    pub sender: Sender<Packet>,
    pub addr: SocksAddr,
    pub cancel: CancellationToken,
}

struct Pending {
    created: Instant,
    packets: Vec<Bytes>,
}

#[derive(Default)]
struct Tables {
    next_session: u64,
    send: ContextIds,
    recv: HashMap<u16, Route>,
    received: HashMap<u64, Vec<u16>>,
    pending: HashMap<u16, Pending>,
    pending_bytes: usize,
}

#[derive(Default)]
pub(super) struct Registry {
    tables: Mutex<Tables>,
    pub changed: Notify,
}

impl Registry {
    pub fn session(&self) -> u64 {
        let mut tables = self.tables.lock();
        let id = tables.next_session;
        tables.next_session = id.wrapping_add(1);
        id
    }

    pub fn allocate(&self) -> io::Result<u16> {
        self.tables.lock().send.allocate()
    }

    pub fn route(&self, id: u16) -> Option<Route> {
        self.tables.lock().recv.get(&id).cloned()
    }

    pub fn register(
        &self, session: u64, id: u16, addr: SocksAddr,
        sender: Sender<Packet>, cancel: CancellationToken,
    ) -> io::Result<()> {
        let mut tables = self.tables.lock();
        let route = Route { session, sender, addr, cancel };
        match tables.recv.entry(id) {
            Entry::Occupied(entry) => {
                let previous = entry.get();
                if previous.session != session || previous.addr != route.addr {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "shadowquic UDP context ID is already registered",
                    ));
                }
                return Ok(());
            }
            Entry::Vacant(entry) => { entry.insert(route.clone()); }
        }
        tables.received.entry(session).or_default().push(id);
        let pending = tables.pending.remove(&id);
        if let Some(pending) = &pending {
            tables.pending_bytes -= pending.packets.iter().map(Bytes::len).sum::<usize>();
        }
        drop(tables);
        if let Some(pending) = pending
            && pending.created.elapsed() < REGISTER_TIMEOUT
        {
            for packet in pending.packets {
                let _ = route.sender.try_send((packet, route.addr.clone()));
            }
        }
        self.changed.notify_waiters();
        Ok(())
    }

    // QUIC datagrams may overtake their reliable address registration.
    // Bound both the number of unknown IDs and the aggregate buffered payload.
    pub fn deliver(&self, id: u16, data: Bytes) {
        let mut tables = self.tables.lock();
        if let Some(route) = tables.recv.get(&id).cloned() {
            drop(tables);
            let _ = route.sender.try_send((data, route.addr));
            return;
        }
        if tables.pending_bytes + data.len() > MAX_PENDING_BYTES {
            return;
        }
        if !tables.pending.contains_key(&id)
            && tables.pending.len() >= MAX_PENDING_IDS
        {
            return;
        }
        let pending = tables.pending.entry(id).or_insert_with(|| Pending {
            created: Instant::now(), packets: Vec::new(),
        });
        if pending.packets.len() >= MAX_PENDING_PACKETS {
            return;
        }
        let len = data.len();
        pending.packets.push(data);
        tables.pending_bytes += len;
    }

    pub fn expire(&self) {
        let mut tables = self.tables.lock();
        tables.pending.retain(|_, pending| pending.created.elapsed() < REGISTER_TIMEOUT);
        tables.pending_bytes = tables.pending.values()
            .flat_map(|pending| &pending.packets).map(Bytes::len).sum();
    }

    pub fn remove_session(&self, session: u64, send_ids: &[u16]) {
        let mut tables = self.tables.lock();
        for id in send_ids {
            tables.send.release(*id);
        }
        if let Some(ids) = tables.received.remove(&session) {
            for id in ids {
                tables.recv.remove(&id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[test]
    fn ids_exhaust_and_are_released_without_affecting_other_sessions() {
        let registry = Registry::default();
        let ids: Vec<_> = (0..=u16::MAX).map(|_| registry.allocate().unwrap()).collect();
        assert!(registry.allocate().is_err());
        registry.remove_session(0, &[123]);
        assert_eq!(registry.allocate().unwrap(), 123);
        assert!(registry.allocate().is_err());
        // Only a lower bit in the cursor's current word is free after wrapping.
        registry.remove_session(0, &[100]);
        assert_eq!(registry.allocate().unwrap(), 100);
        assert!(registry.allocate().is_err());
        registry.remove_session(0, &ids);
        assert!(registry.tables.lock().send.is_empty());
    }

    #[tokio::test]
    async fn datagrams_overtake_registration_and_conflicting_ids_are_rejected() {
        let registry = Registry::default();
        let (sender, mut receiver) = mpsc::channel(32);
        let addr: SocksAddr = "[::1]:53".parse().unwrap();
        registry.deliver(1, Bytes::from_static(b"early"));
        registry.register(10, 1, addr.clone(), sender.clone(), CancellationToken::new()).unwrap();
        assert_eq!(receiver.recv().await.unwrap(), (Bytes::from_static(b"early"), addr.clone()));
        assert!(registry.tables.lock().pending.is_empty());
        assert_eq!(registry.tables.lock().pending_bytes, 0);
        assert!(registry.register(11, 1, addr.clone(), sender.clone(), CancellationToken::new()).is_err());
        registry.register(11, 2, addr, sender, CancellationToken::new()).unwrap();
        registry.remove_session(10, &[]);
        assert!(registry.route(1).is_none());
        assert!(registry.route(2).is_some());
    }

    #[test]
    fn unknown_datagram_buffers_have_packet_id_byte_and_time_limits() {
        let registry = Registry::default();
        for _ in 0..100 {
            registry.deliver(0, Bytes::from_static(b"x"));
        }
        assert_eq!(registry.tables.lock().pending[&0].packets.len(), MAX_PENDING_PACKETS);
        for id in 1..1000 {
            registry.deliver(id, Bytes::from_static(b"x"));
        }
        assert_eq!(registry.tables.lock().pending.len(), MAX_PENDING_IDS);
        for pending in registry.tables.lock().pending.values_mut() {
            pending.created = Instant::now() - REGISTER_TIMEOUT;
        }
        registry.expire();
        assert!(registry.tables.lock().pending.is_empty());
        assert_eq!(registry.tables.lock().pending_bytes, 0);
        for id in 0..100 {
            registry.deliver(id, Bytes::from(vec![0; 65535]));
        }
        assert!(registry.tables.lock().pending_bytes <= MAX_PENDING_BYTES);
        assert_eq!(registry.tables.lock().pending.len(), MAX_PENDING_BYTES / 65535);
    }

    #[tokio::test]
    async fn full_association_does_not_block_another_destination() {
        let registry = Registry::default();
        let (full, _receiver) = mpsc::channel(1);
        let (ready, mut receiver) = mpsc::channel(1);
        let addr: SocksAddr = "127.0.0.1:53".parse().unwrap();
        registry.register(0, 0, addr.clone(), full, CancellationToken::new()).unwrap();
        registry.register(1, 1, addr, ready, CancellationToken::new()).unwrap();
        registry.deliver(0, Bytes::new());
        registry.deliver(0, Bytes::new());
        registry.deliver(1, Bytes::from_static(b"ready"));
        assert_eq!(receiver.recv().await.unwrap().0, b"ready"[..]);
    }
}
