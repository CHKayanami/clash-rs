//! Packet reservations for either the stream adapter or an owner-local device.
use crate::Packet;
use std::collections::VecDeque;
use tokio::sync::mpsc;

pub(crate) enum Output {
    Channel(mpsc::Sender<Packet>),
    Local {
        packets: VecDeque<Packet>,
        limit: usize,
    },
}

pub(crate) enum Permit<'a> {
    Channel(mpsc::Permit<'a, Packet>),
    Local(&'a mut VecDeque<Packet>),
}

impl Output {
    pub fn local(limit: usize) -> Self {
        assert!(limit > 0);
        Self::Local {
            packets: VecDeque::with_capacity(limit),
            limit,
        }
    }

    pub fn capacity(&self) -> usize {
        match self {
            Self::Channel(sender) => sender.capacity(),
            Self::Local { packets, limit } => limit - packets.len(),
        }
    }

    pub fn reserve(&mut self) -> Option<Permit<'_>> {
        match self {
            Self::Channel(sender) => sender.try_reserve().ok().map(Permit::Channel),
            Self::Local { packets, limit } if packets.len() < *limit => {
                Some(Permit::Local(packets))
            }
            _ => None,
        }
    }

    pub fn send(&mut self, packet: Packet) -> Result<(), Packet> {
        match self.reserve() {
            Some(permit) => {
                permit.send(packet);
                Ok(())
            }
            None => Err(packet),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Local { packets, .. } => packets.len(),
            Self::Channel(sender) => sender.max_capacity() - sender.capacity(),
        }
    }

    pub fn pop(&mut self) -> Option<Packet> {
        match self {
            Self::Local { packets, .. } => packets.pop_front(),
            Self::Channel(_) => None,
        }
    }
}

impl Permit<'_> {
    pub fn send(self, packet: Packet) {
        match self {
            Self::Channel(permit) => {
                permit.send(packet);
            }
            Self::Local(packets) => packets.push_back(packet),
        }
    }
}
