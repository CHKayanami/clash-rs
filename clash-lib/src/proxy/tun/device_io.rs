//! Device batches retain individual IP packet boundaries. Linux offload headers
//! and segmentation/aggregation are handled by tun-rs, not inferred from IP length.
use std::io;
use bytes::{Bytes, BytesMut};
use tun_rs::AsyncDevice;
#[cfg(target_os = "linux")]
use tun_rs::{GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};
#[cfg(target_os = "linux")]
use futures::FutureExt;

pub(super) const DEVICE_BATCH: usize = 32;

pub(super) struct Reader {
    original: Vec<u8>,
    #[cfg(target_os = "linux")]
    pending_error: Option<io::Error>,
    #[cfg(target_os = "linux")]
    buffers: Vec<Vec<u8>>,
    #[cfg(target_os = "linux")]
    sizes: Vec<usize>,
}

impl Reader {
    pub(super) fn new(device: &AsyncDevice) -> Self {
        #[cfg(target_os = "linux")]
        let slots = if device.tcp_gso() || device.udp_gso() { IDEAL_BATCH_SIZE } else { 1 };
        #[cfg(not(target_os = "linux"))]
        let _ = device;
        Self {
            #[cfg(target_os = "linux")]
            original: if slots > 1 { vec![0; 65535 + 80] } else { Vec::new() },
            #[cfg(not(target_os = "linux"))]
            original: vec![0; 65535 + 80],
            #[cfg(target_os = "linux")]
            pending_error: None,
            #[cfg(target_os = "linux")]
            buffers: (0..slots)
                .map(|_| vec![0; 65535]).collect(),
            #[cfg(target_os = "linux")]
            sizes: vec![0; slots],
        }
    }

    pub(super) async fn recv(&mut self, device: &AsyncDevice, packets: &mut Vec<BytesMut>) -> io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            if let Some(error) = self.pending_error.take() { return Err(error); }
            let mut bytes = 0;
            loop {
                let receive = device.recv_multiple(&mut self.original, &mut self.buffers, &mut self.sizes, 0);
                let result = if packets.is_empty() { receive.await }
                    else { match receive.now_or_never() { Some(result) => result, None => break } };
                let count = match result {
                    Ok(count) => count,
                    Err(error) if !packets.is_empty() && error.kind() == io::ErrorKind::WouldBlock => break,
                    // Deliver the prefix before reporting a subsequent device error.
                    Err(error) if !packets.is_empty() => { self.pending_error = Some(error); break; }
                    Err(error) => return Err(error),
                };
                if count == 0 || (count == 1 && self.sizes[0] == 0) { break; }
                for i in 0..count {
                    let size = self.sizes[i];
                    bytes += size;
                    // Compact owned packets never retain the large receive scratch.
                    packets.push(BytesMut::from(&self.buffers[i][..size]));
                }
                if packets.len() >= DEVICE_BATCH || bytes >= 64 * 1024 { break; }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let count = device.recv(&mut self.original).await?;
            if count > 0 { packets.push(BytesMut::from(&self.original[..count])); }
        }
        Ok(packets.len())
    }
}

pub(super) struct Writer {
    #[cfg(target_os = "linux")]
    gro: GROTable,
    #[cfg(target_os = "linux")]
    buffers: Vec<Vec<u8>>,
}

impl Writer {
    pub(super) fn new() -> Self {
        Self {
            #[cfg(target_os = "linux")]
            gro: GROTable::default(),
            #[cfg(target_os = "linux")]
            buffers: (0..DEVICE_BATCH).map(|_| Vec::new()).collect(),
        }
    }

    pub(super) async fn send(&mut self, device: &AsyncDevice, packets: &[Bytes]) -> io::Result<()> {
        assert!(packets.len() <= DEVICE_BATCH);
        #[cfg(target_os = "linux")]
        {
            // The default non-offload path can borrow packet bytes directly.
            // Avoid an extra payload copy when aggregation is unavailable.
            if !device.tcp_gso() { return send_plain(device, packets).await; }
            for (buffer, packet) in self.buffers.iter_mut().zip(packets) {
                buffer.clear();
                // tun-rs coalesces only within existing capacity. Reserve a
                // full IP frame plus both headroom allowances it requires.
                buffer.reserve(65535 + 2 * VIRTIO_NET_HDR_LEN);
                buffer.resize(VIRTIO_NET_HDR_LEN, 0);
                buffer.extend_from_slice(packet);
            }
            // Each slice is a complete IP packet with explicit virtio headroom.
            // tun-rs merges compatible flows only when the device supports it;
            // without offload it writes independent packets. Never retry an
            // errored batch: its successful prefix may already be on the device.
            device.send_multiple(&mut self.gro, &mut self.buffers[..packets.len()], VIRTIO_NET_HDR_LEN).await?;
        }
        #[cfg(not(target_os = "linux"))]
        send_plain(device, packets).await?;
        Ok(())
    }
}

async fn send_plain(device: &AsyncDevice, packets: &[Bytes]) -> io::Result<()> {
    let mut error = None;
    for packet in packets {
        match device.send(packet).await {
            Ok(count) if count == packet.len() => {}
            Ok(_) => return Err(io::Error::new(io::ErrorKind::WriteZero, "partial TUN packet write")),
            Err(err) if matches!(err.kind(), io::ErrorKind::InvalidInput
                | io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) => { error.get_or_insert(err); }
            Err(err) => return Err(err),
        }
    }
    error.map_or(Ok(()), Err)
}

#[cfg(all(test, target_os = "linux"))]
#[path = "device_io_tests.rs"]
mod tests;
