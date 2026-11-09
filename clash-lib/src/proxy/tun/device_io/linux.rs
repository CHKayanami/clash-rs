//! Native offload frames cross the protocol owner without splitting TCP.
use std::{future::Future, io, os::fd::AsRawFd};
use clash_netstack::Packet;
use bytes::Bytes;
use tracing::warn;
use tun_rs::{AsyncDevice, VIRTIO_NET_HDR_LEN};
use super::{Reader, DEVICE_BATCH, frame::Frame, offload};

const _: () = assert!(VIRTIO_NET_HDR_LEN == offload::HEADER_LEN);

// Statically dispatched so tests can exercise real readiness without passing
// a socket to tun-rs APIs whose safety contract requires an actual TUN device.
pub(super) trait NativeReceive: Sync {
    fn receive<'a>(&'a self, buffer: &'a mut [u8]) -> impl Future<Output = io::Result<usize>> + Send + 'a;
    fn try_receive(&self, buffer: &mut [u8]) -> io::Result<usize>;
}
impl NativeReceive for AsyncDevice {
    fn receive<'a>(&'a self, buffer: &'a mut [u8]) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        self.recv(buffer)
    }
    fn try_receive(&self, buffer: &mut [u8]) -> io::Result<usize> { self.try_recv(buffer) }
}

impl Reader {
    pub(super) async fn recv_native<D: NativeReceive>(&mut self, device: &D, packets: &mut Vec<Packet>, offload: bool) -> io::Result<usize> {
        if let Some(error) = self.pending_error.take() { return Err(error); }
        loop {
            // One allocation/owner per burst, with room for a final maximum
            // frame after the 64 KiB byte budget. Slots stay immutable until
            // every packet slice has been sent, compacted or dropped.
            let mut buffer = self.pool.acquire();
            buffer.reset();
            let mut ranges = [(0usize, 0usize); DEVICE_BATCH];
            let (mut count, mut bytes) = (0, 0);
            let mut eof = false;
            for _ in 0..DEVICE_BATCH {
                let target = &mut buffer.as_mut()[bytes..bytes + self.frame_capacity];
                // try_recv clears stale readiness on EAGAIN without retaining
                // a per-frame async operation. Only the first frame waits.
                let result = if count == 0 { device.receive(target).await }
                    else { device.try_receive(target) };
                let length = match result {
                    Ok(0) => { eof = true; break; },
                    Ok(length) => length,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) if count > 0 && error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) if count > 0 => { self.pending_error = Some(error); break; },
                    Err(error) => return Err(error),
                };
                if offload && let Err(error) = offload::receive::prepare_shared(&mut buffer.as_mut()[bytes..bytes + length]) {
                    warn!("dropping invalid TUN frame: {error}"); continue;
                }
                ranges[count] = (bytes, length); count += 1; bytes += length;
                if bytes >= 64 * 1024 { break; }
            }
            if count == 0 && eof { return Ok(0); }
            let capacity = buffer.as_ref().len();
            buffer.truncate(bytes);
            let storage = Bytes::from_owner(buffer);
            for &(offset, length) in &ranges[..count] {
                let frame = storage.slice(offset..offset + length);
                if offload {
                    if let Err(error) = offload::receive::decode_shared(frame, capacity, packets) {
                        warn!("dropping invalid TUN frame: {error}");
                    }
                } else { packets.push(Packet::new(frame).with_backing_capacity(capacity)); }
            }
            if !packets.is_empty() { return Ok(packets.len()); }
            tokio::task::consume_budget().await;
        }
    }
}

pub(super) async fn send_native<P: Frame>(device: &AsyncDevice, packets: &mut [P], mtu: usize) -> io::Result<()> {
    let mut index = 0;
    while index < packets.len() {
        let packet = &packets[index];
        let header = packet.parts().map_or_else(|| packet.as_ref(), |(header, _)| header);
        if !super::valid_packet(header) { index += 1; continue; }
        let immediate = {
            let frame = offload::write::WriteFrame::new(&packets[index..], device.udp_gso(), mtu)?;
            let vectors = frame.vectors();
            // SAFETY: all iovecs and their immutable packet owners remain live
            // for one nonblocking atomic TUN write. No pointer escapes.
            let written = unsafe { libc::writev(device.as_raw_fd(), vectors.as_ptr().cast(), frame.vector_count() as _) };
            let result = if written < 0 { Err(io::Error::last_os_error()) } else { Ok(written as usize) };
            match result {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => None,
                result => Some((result, frame.length(), frame.count)),
            }
        };
        let (result, length, frames) = if let Some(result) = immediate { result } else {
            // No atomic TUN write occurred on Pending. Release sparse receive
            // slabs before retaining a batch while the device is backpressured.
            for packet in &mut packets[index..] { packet.compact(); }
            let frame = offload::write::WriteFrame::new(&packets[index..], device.udp_gso(), mtu)?;
            let vectors = frame.vectors();
            (device.send_vectored(&vectors[..frame.vector_count()]).await, frame.length(), frame.count)
        };
        if matches!(&result, Err(error) if error.kind() == io::ErrorKind::Interrupted) { continue; }
        if result? != length { return Err(io::Error::new(io::ErrorKind::WriteZero, "partial TUN offload frame")); }
        index += frames;
    }
    Ok(())
}

/// Borrow socket storage for one atomic nonblocking TUN write. EAGAIN leaves
/// ownership with the caller, which can encode a queued packet instead.
pub(super) fn try_send_tcp(device: &AsyncDevice, header: &[u8], payload: &[u8], size: Option<u16>) -> io::Result<bool> {
    use std::os::fd::AsRawFd;
    offload::borrowed::send(device.as_raw_fd(), header, payload, size)
}
