//! Initialized views own individual receive slots, never sparse whole slabs.
use std::{io, mem::MaybeUninit, num::NonZeroU16, net::SocketAddr, sync::LazyLock};
use parking_lot::Mutex;
use bytes::Bytes;
use tokio::net::UdpSocket;
use super::{native, MAX_DATAGRAM_SIZE, MAX_GRO_PACKETS, ReceivedPacket};

const CACHE_BYTES: usize = 4 * 1024 * 1024;
type Slot = Box<[MaybeUninit<u8>]>;
static POOL: LazyLock<Mutex<Vec<Slot>>> = LazyLock::new(|| Mutex::new(Vec::new()));
struct Storage { slot: Option<Slot>, length: usize }
impl AsRef<[u8]> for Storage {
    fn as_ref(&self) -> &[u8] {
        let slot = self.slot.as_ref().expect("owned UDP receive slot");
        // SAFETY: recvmmsg initialized precisely this prefix before Storage
        // became a Bytes owner. The unread spare capacity is never exposed.
        unsafe { std::slice::from_raw_parts(slot.as_ptr().cast::<u8>(), self.length) }
    }
}
impl Drop for Storage {
    fn drop(&mut self) {
        let Some(slot) = self.slot.take() else { return; };
        let mut pool = POOL.lock();
        if (pool.len() + 1) * MAX_DATAGRAM_SIZE <= CACHE_BYTES { pool.push(slot); }
    }
}
pub(in crate::proxy::direct) fn recv_groups(socket: &UdpSocket, limit: usize,
    mut on_packet: impl FnMut(Bytes, SocketAddr, Option<NonZeroU16>)) -> io::Result<usize> {
    assert!(limit > 0 && limit <= MAX_GRO_PACKETS);
    let mut slots: [Option<Storage>; MAX_GRO_PACKETS] = std::array::from_fn(|_| None);
    {
        let mut pool = POOL.lock();
        for slot in &mut slots[..limit] {
            *slot = Some(Storage { slot: pool.pop(), length: 0 });
        }
    }
    for storage in slots[..limit].iter_mut().flatten() {
        if storage.slot.is_none() { storage.slot = Some(Box::new_uninit_slice(MAX_DATAGRAM_SIZE)); }
    }
    let pointers = std::array::from_fn::<_, MAX_GRO_PACKETS, _>(|i| {
        slots[i].as_mut().map_or(std::ptr::null_mut(), |storage| storage.slot.as_mut().unwrap().as_mut_ptr())
    });
    let mut packets: [Option<ReceivedPacket>; MAX_GRO_PACKETS] = [None; MAX_GRO_PACKETS];
    // SAFETY: each Box is a disjoint full-size allocation, stays owned by slots
    // during the call, and is exposed as u8 only after its initialized length is known.
    let count = unsafe { native::receive_slots(socket, limit, true, &pointers, &mut packets) }?;
    for (index, packet) in packets[..count].iter().enumerate() {
        let Some((_, length, address, size)) = packet else { continue; };
        let mut storage = slots[index].take().unwrap(); storage.length = *length;
        on_packet(Bytes::from_owner(storage), *address, *size);
    }
    Ok(count)
}

/// The integrated owner reuses slots without the process-wide recycle lock.
pub(in crate::proxy::direct) fn recv_groups_in(socket: &UdpSocket, limit: usize, gro: bool,
    pool: &mut super::ReceiveSlots,
    mut on_packet: impl FnMut(Bytes, SocketAddr, Option<NonZeroU16>)) -> io::Result<usize> {
    assert!(limit > 0 && limit <= MAX_GRO_PACKETS);
    let mut slots = pool.acquire::<MAX_GRO_PACKETS>(limit);
    let pointers = std::array::from_fn(|index| slots[index].as_mut()
        .map_or(std::ptr::null_mut(), |slot| slot.pointer()));
    let mut packets: [Option<ReceivedPacket>; MAX_GRO_PACKETS] = [None; MAX_GRO_PACKETS];
    // SAFETY: loans are exclusive and disjoint throughout this synchronous call.
    let result = unsafe { native::receive_slots(socket, limit, gro, &pointers, &mut packets) };
    if let Ok(count) = result {
        for (index, packet) in packets[..count].iter().enumerate() {
            if let Some((_, length, address, size)) = packet {
                // SAFETY: receive_slots reported exactly this initialized prefix.
                let data = unsafe { slots[index].as_ref().unwrap().freeze(*length) };
                on_packet(data, *address, *size);
            }
        }
    }
    for (index, slot) in slots.into_iter().enumerate() {
        if let Some(slot) = slot { pool.keep(index, slot); }
    }
    result
}
