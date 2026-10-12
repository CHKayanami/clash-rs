use std::{collections::{HashMap, HashSet}, io, net::SocketAddr, sync::Arc};
use crate::session::SocksAddr;
use super::flow::FlowState;

#[cfg(test)]
#[path = "peer_tests.rs"]
mod tests;

const MAX_PEERS: usize = 16384;

struct Peer {
    original: SocksAddr,
    flow: Option<u64>,
    other_flows: Vec<u64>,
}

/// Keep address restoration for late replies, but compact ordinary IP history.
/// IP tombstones prevent a later FakeIP alias from claiming an old real peer.
#[derive(Default)]
pub(super) struct PeerTable {
    peers: HashMap<SocksAddr, Peer>,
    real_history: HashSet<SocketAddr>,
}

impl PeerTable {
    pub(super) fn register(&mut self, state: &FlowState) -> io::Result<()> {
        if state.aliases.iter().any(|alias| self.peers.get(alias)
            .is_some_and(|peer| peer.original != state.original)
            || matches!(alias, SocksAddr::Ip(addr) if self.real_history.contains(addr)
                && state.original != *alias)) {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "ambiguous UDP reply address"));
        }
        let additional = state.aliases.iter().filter(|alias| !self.peers.contains_key(*alias)
            && !matches!(alias, SocksAddr::Ip(addr) if self.real_history.contains(addr))).count();
        if self.peers.len() + self.real_history.len() + additional > MAX_PEERS {
            return Err(io::Error::new(io::ErrorKind::OutOfMemory, "UDP reply mapping limit reached"));
        }
        for alias in &state.aliases {
            if let SocksAddr::Ip(addr) = alias { self.real_history.remove(addr); }
            match self.peers.get_mut(alias) {
                Some(peer) => {
                    if let Some(previous) = peer.flow.replace(state.id) {
                        peer.other_flows.push(previous);
                    }
                },
                None => { self.peers.insert(alias.clone(), Peer {
                    original: state.original.clone(), flow: Some(state.id), other_flows: Vec::new(),
                }); }
            }
        }
        Self::shrink_history(&mut self.real_history);
        Ok(())
    }

    pub(super) fn remove(&mut self, state: &FlowState, flows: &HashMap<u64, Arc<FlowState>>) {
        for alias in &state.aliases {
            let Some(peer) = self.peers.get_mut(alias) else { continue; };
            peer.other_flows.retain(|owner| *owner != state.id
                && flows.get(owner).is_some_and(|flow| !flow.is_closed()));
            if peer.flow == Some(state.id)
                || peer.flow.is_some_and(|owner| !flows.get(&owner).is_some_and(|flow| !flow.is_closed())) {
                peer.flow = peer.other_flows.pop();
            }
            if peer.flow.is_none() && peer.other_flows.is_empty() && peer.original == *alias
                && let SocksAddr::Ip(addr) = alias {
                self.real_history.insert(*addr);
                self.peers.remove(alias);
            }
        }
        // Reclaim the heavier buckets after a substantial contraction, without
        // resizing for every flow close. All of this runs on the control path.
        if self.peers.capacity() > 64 && self.peers.len() < self.peers.capacity() / 4 {
            self.peers.shrink_to((self.peers.len() * 2).max(64));
        }
    }

    fn shrink_history(history: &mut HashSet<SocketAddr>) {
        if history.capacity() > 64 && history.len() < history.capacity() / 4 {
            history.shrink_to((history.len() * 2).max(64));
        }
    }

    pub(super) fn select_sender(&mut self, state: &FlowState) {
        for alias in &state.aliases {
            if let Some(peer) = self.peers.get_mut(alias) && peer.flow != Some(state.id)
                && let Some(index) = peer.other_flows.iter().position(|&owner| owner == state.id) {
                match peer.flow.replace(state.id) {
                    Some(previous) => peer.other_flows[index] = previous,
                    None => { peer.other_flows.swap_remove(index); },
                }
            }
        }
    }

    pub(super) fn reply(&self, address: &SocksAddr) -> (Option<u64>, Option<&SocksAddr>) {
        self.peers.get(address).map_or((None, None), |peer| (peer.flow, Some(&peer.original)))
    }
}
