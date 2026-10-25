//! Device batches retain individual IP packet boundaries. Linux offload headers
//! and segmentation/aggregation are handled by tun-rs, not inferred from IP length.
use std::io;
use bytes::{Bytes, BytesMut};
use tun_rs::AsyncDevice;
#[cfg(target_os = "macos")]
use std::env::{self, VarError};
use tracing::debug;
#[cfg(target_os = "macos")]
use darwin::{Reader as DarwinReader, Writer as DarwinWriter};
#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "linux")]
use tun_rs::{GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};
#[cfg(target_os = "linux")]
use futures::FutureExt;

pub(super) const DEVICE_BATCH: usize = 32;

#[cfg(target_os = "macos")]
fn parse_native_io(value: &str) -> io::Result<bool> {
    match value {
        "0" | "false" => Ok(false),
        "1" | "true" => Ok(true),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput,
            "CLASH_RS_MACOS_TUN_NATIVE_IO must be 0, 1, false or true")),
    }
}

#[cfg(target_os = "macos")]
fn native_io_enabled() -> io::Result<bool> {
    match env::var("CLASH_RS_MACOS_TUN_NATIVE_IO") {
        Ok(value) => parse_native_io(&value),
        Err(VarError::NotPresent) => Ok(true),
        Err(error) => Err(io::Error::new(io::ErrorKind::InvalidInput, error)),
    }
}

pub(super) fn split(device: &AsyncDevice, frame_size: usize, native_batch: bool)
    -> io::Result<(Reader, Writer)> {
    #[cfg(target_os = "macos")]
    let native_io = native_io_enabled()?;
    #[cfg(not(target_os = "macos"))]
    let native_io = true;
    let reader = Reader::new(device, frame_size, native_io)?;
    let writer = Writer::new(&reader, native_batch)?;
    Ok((reader, writer))
}

pub(super) struct Reader {
    #[cfg(target_os = "macos")]
    darwin: Option<DarwinReader>,
    original: Vec<u8>,
    #[cfg(target_os = "linux")]
    pending_error: Option<io::Error>,
    #[cfg(target_os = "linux")]
    buffers: Vec<Vec<u8>>,
    #[cfg(target_os = "linux")]
    sizes: Vec<usize>,
}

impl Reader {
    pub(super) fn new(device: &AsyncDevice, frame_size: usize, native_io: bool) -> io::Result<Self> {
        #[cfg(target_os = "macos")]
        if frame_size == 0 || frame_size > 65535 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid TUN frame capacity"));
        }
        #[cfg(target_os = "linux")]
        let slots = if device.tcp_gso() || device.udp_gso() { IDEAL_BATCH_SIZE } else { 1 };
        #[cfg(not(target_os = "macos"))]
        let _ = (frame_size, native_io);
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let _ = device;
        Ok(Self {
            #[cfg(target_os = "macos")]
            darwin: native_io.then(|| DarwinReader::new(device, frame_size)).transpose()?,
            #[cfg(target_os = "macos")]
            original: if native_io { Vec::new() } else { vec![0; frame_size + 1] },
            #[cfg(target_os = "linux")]
            original: if slots > 1 { vec![0; 65535 + 80] } else { Vec::new() },
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            original: vec![0; 65535 + 80],
            #[cfg(target_os = "linux")]
            pending_error: None,
            #[cfg(target_os = "linux")]
            buffers: (0..slots)
                .map(|_| vec![0; 65535]).collect(),
            #[cfg(target_os = "linux")]
            sizes: vec![0; slots],
        })
    }

    pub(super) async fn recv(&mut self, device: &AsyncDevice, packets: &mut Vec<BytesMut>) -> io::Result<usize> {
        #[cfg(target_os = "linux")]
        if let Some(error) = self.pending_error.take() { return Err(error); }
        #[cfg(target_os = "linux")]
        {
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
        #[cfg(target_os = "macos")]
        if let Some(reader) = &mut self.darwin {
            reader.recv(packets).await?;
        } else {
            loop {
                let count = device.recv(&mut self.original).await?;
                if count == 0 { break; }
                if count >= self.original.len() {
                    debug!(size = count, "dropping oversized TUN packet");
                    continue;
                }
                packets.push(BytesMut::from(&self.original[..count]));
                break;
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let count = device.recv(&mut self.original).await?;
            if count > 0 { packets.push(BytesMut::from(&self.original[..count])); }
        }
        Ok(packets.len())
    }
}

pub(super) struct Writer {
    #[cfg(target_os = "macos")]
    darwin: Option<DarwinWriter>,
    #[cfg(target_os = "linux")]
    gro: GROTable,
    #[cfg(target_os = "linux")]
    buffers: Vec<Vec<u8>>,
}

impl Writer {
    fn new(reader: &Reader, native_batch: bool) -> io::Result<Self> {
        #[cfg(not(target_os = "macos"))]
        let _ = (reader, native_batch);
        Ok(Self {
            #[cfg(target_os = "macos")]
            darwin: if native_batch {
                reader.darwin.as_ref().map(DarwinReader::writer).transpose()?
            } else { None },
            #[cfg(target_os = "linux")]
            gro: GROTable::default(),
            #[cfg(target_os = "linux")]
            buffers: (0..DEVICE_BATCH).map(|_| Vec::new()).collect(),
        })
    }

    pub(super) async fn send(&mut self, device: &AsyncDevice, packets: &[Bytes]) -> io::Result<()> {
        assert!(packets.len() <= DEVICE_BATCH);
        #[cfg(target_os = "linux")]
        {
            // The default non-offload path can borrow packet bytes directly.
            // Avoid an extra payload copy when aggregation is unavailable.
            if !device.tcp_gso() { return send_plain(device, packets).await; }
            let count = prepare_offload(packets, &mut self.buffers);
            // Each slice is a complete IP packet with explicit virtio headroom.
            // tun-rs merges compatible flows only when the device supports it;
            // without offload it writes independent packets. Never retry an
            // errored batch: its successful prefix may already be on the device.
            if count > 0 {
                device.send_multiple(&mut self.gro, &mut self.buffers[..count], VIRTIO_NET_HDR_LEN).await?;
            }
        }
        #[cfg(target_os = "macos")]
        if let Some(writer) = &mut self.darwin {
            writer.send(packets).await?;
        } else {
            // NetworkExtension utun descriptors may use netif mode; do not
            // accelerate injection into its bounded kernel input queue.
            send_plain(device, packets).await?;
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        send_plain(device, packets).await?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn prepare_offload(packets: &[Bytes], buffers: &mut [Vec<u8>]) -> usize {
    let mut count = 0;
    for packet in packets {
        if !valid_packet(packet) { continue; }
        let buffer = &mut buffers[count];
        count += 1;
        buffer.clear();
        // tun-rs needs spare capacity for coalescing, plus virtio headroom.
        buffer.reserve(65535 + 2 * VIRTIO_NET_HDR_LEN);
        buffer.resize(VIRTIO_NET_HDR_LEN, 0);
        buffer.extend_from_slice(packet);
    }
    count
}

// Validate before entering tun-rs: its platform-specific validation may reject
// an entire offload batch or report InvalidData as a device failure.
fn valid_packet(packet: &[u8]) -> bool {
    if matches!(packet.first().map(|byte| byte >> 4), Some(4 | 6)) { return true; }
    debug!(size = packet.len(), "dropping TUN packet with invalid IP version");
    false
}

async fn send_plain(device: &AsyncDevice, packets: &[Bytes]) -> io::Result<()> {
    let mut error = None;
    for packet in packets {
        if !valid_packet(packet) { continue; }
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
#[path = "tests_linux.rs"]
mod tests;

#[cfg(all(test, target_os = "macos"))]
#[path = "tests_macos.rs"]
mod macos_tests;
