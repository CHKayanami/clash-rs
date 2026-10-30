//! One authoritative flow index. Handles are monotonic and never reused, so
//! delayed application wakes cannot address a replacement connection.
use std::{collections::HashMap, net::SocketAddr};
use super::protocol::Socket;

pub(crate) type Flow = (SocketAddr, SocketAddr);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SocketHandle(pub u64);

struct Entry {
    socket: Socket<'static>,
    flow: Flow,
    started: bool,
}

pub(crate) struct SocketTable {
    entries: HashMap<SocketHandle, Entry>,
    flows: HashMap<Flow, SocketHandle>,
    next_id: u64,
}

impl SocketTable {
    pub fn new() -> Self {
        Self { entries: HashMap::new(), flows: HashMap::new(), next_id: 0 }
    }

    pub fn find(&self, flow: &Flow) -> Option<SocketHandle> { self.flows.get(flow).copied() }

    pub fn add(&mut self, socket: Socket<'static>, flow: Flow) -> SocketHandle {
        assert!(!self.flows.contains_key(&flow), "duplicate TCP flow");
        self.next_id = self.next_id.checked_add(1).expect("TCP connection ID exhausted");
        let handle = SocketHandle(self.next_id);
        self.flows.insert(flow, handle);
        self.entries.insert(handle, Entry { socket, flow, started: false });
        handle
    }

    pub fn get_mut(&mut self, handle: SocketHandle) -> &mut Socket<'static> {
        &mut self.entries.get_mut(&handle).expect("live TCP handle").socket
    }

    pub fn mark_started(&mut self, handle: SocketHandle) {
        self.entries.get_mut(&handle).expect("live TCP handle").started = true;
    }

    pub fn started(&self, handle: SocketHandle) -> bool {
        self.entries.get(&handle).expect("live TCP handle").started
    }

    pub fn remove(&mut self, handle: SocketHandle) {
        let entry = self.entries.remove(&handle).expect("live TCP handle");
        self.flows.remove(&entry.flow);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::protocol::SocketBuffer;

    #[test]
    fn replacing_a_flow_never_reuses_a_stale_connection_id() {
        let mut table = SocketTable::new();
        let flow = ("192.0.2.2:49152".parse().unwrap(), "198.51.100.2:80".parse().unwrap());
        let socket = || Socket::new(SocketBuffer::new(vec![0; 64]), SocketBuffer::new(vec![0; 64]));
        let old = table.add(socket(), flow);
        assert_eq!(table.find(&flow), Some(old));
        table.remove(old);
        assert_eq!(table.find(&flow), None);
        let new = table.add(socket(), flow);
        assert_ne!(old, new);
        assert!(!table.entries.contains_key(&old));
        assert_eq!(table.find(&flow), Some(new));
    }
}
