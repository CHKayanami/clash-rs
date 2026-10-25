//! Darwin multi-datagram I/O. ABI: XNU bsd/sys/socket_private.h msghdr_x;
//! syscall numbers: bsd/kern/syscalls.master. All pointers are call-local.
//! These are private XNU interfaces, not a stable public macOS ABI. The libc
//! syscall() entry point is deprecated; verify both numbers and layout when
//! updating supported macOS versions. CLASH_RS_MACOS_TUN_NATIVE_IO=0 selects tun-rs
//! ordinary reads and writes without either private batch syscall.
use std::{io, mem::{size_of, take, zeroed}, os::fd::{AsRawFd, BorrowedFd, OwnedFd}, ptr::null_mut, sync::Arc,
    time::Duration};

use bytes::{Bytes, BytesMut};
use libc::{iovec, msghdr};
use socket2::SockRef;
use tokio::io::unix::AsyncFd;
use tokio::time::sleep;
use tun_rs::AsyncDevice;
use tracing::debug;

use super::{DEVICE_BATCH, valid_packet};

const RECVMSG_X: i32 = 480;
const SENDMSG_X: i32 = 481;
const FAMILY_SIZE: usize = 4;

#[repr(C)]
struct Message {
    header: msghdr,
    data_len: usize,
}

const _: () = assert!(size_of::<Message>() == 56);
const _: () = assert!(std::mem::offset_of!(Message, data_len) == 48);

fn messages() -> [Message; DEVICE_BATCH] {
    // SAFETY: the C structure consists exclusively of integers and raw pointers;
    // zero is a valid empty value for all fields, including ABI padding.
    unsafe { zeroed() }
}

fn descriptor(device: &AsyncDevice) -> io::Result<AsyncFd<OwnedFd>> {
    // SAFETY: device owns the open FD for this borrow. The duplicate takes its
    // own ownership and registration, never outliving an unowned descriptor.
    let borrowed = unsafe { BorrowedFd::borrow_raw(device.as_raw_fd()) };
    let owned = borrowed.try_clone_to_owned()?;
    // SAFETY: OwnedFd returns one stable descriptor and keeps its file
    // description open until AsyncFd releases ownership or drops it.
    unsafe { AsyncFd::register(owned) }.map_err(io::Error::from)
}

fn syscall(fd: i32, headers: &mut [Message], operation: i32) -> io::Result<usize> {
    debug_assert!(!headers.is_empty() && headers.len() <= DEVICE_BATCH);
    // SAFETY: the caller pins live message/iovec/payload storage for this
    // synchronous call. XNU may write only the submitted headers and receive
    // buffers, and retains no userspace pointer after returning. No raw pointer
    // is stored in an async future or used across an await point.
    let result = unsafe {
        libc::syscall(operation, fd, headers.as_mut_ptr(), headers.len() as u32, libc::MSG_DONTWAIT)
    };
    if result < 0 { return Err(io::Error::last_os_error()); }
    let count = result as usize;
    if count > headers.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Darwin batch count exceeds capacity"));
    }
    Ok(count)
}

pub(super) struct Reader {
    io: Arc<AsyncFd<OwnedFd>>,
    buffers: Vec<BytesMut>,
    frame_size: usize,
}

impl Reader {
    pub(super) fn new(device: &AsyncDevice, frame_size: usize) -> io::Result<Self> {
        if frame_size == 0 || frame_size > 65535 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid TUN frame capacity"));
        }
        // One frame plus a truncation guard per slot. Tiny packets are detached
        // into compact storage; large packets take sole ownership of the slot.
        let allocation = frame_size + 1;
        Ok(Self { io: Arc::new(descriptor(device)?), frame_size,
            buffers: (0..DEVICE_BATCH).map(|_| BytesMut::with_capacity(allocation)).collect() })
    }

    pub(super) fn writer(&self) -> io::Result<Writer> {
        Writer::new(self.io.clone())
    }

    pub(super) async fn recv(&mut self, packets: &mut Vec<BytesMut>) -> io::Result<usize> {
        let initial = packets.len();
        loop {
            let mut ready = self.io.readable().await?;
            let count = match ready.try_io(|fd| receive(fd.as_raw_fd(), &mut self.buffers,
                self.frame_size, packets)) {
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(result) => result?,
                Err(_) => continue,
            };
            let delivered = packets.len() - initial;
            if count == 0 || delivered > 0 { return Ok(delivered); }
            // A consumed batch containing only invalid packets is not EOF.
            // Keep draining, but cooperate even if malformed input stays ready.
            drop(ready);
            tokio::task::consume_budget().await;
        }
    }
}

fn receive(fd: i32, buffers: &mut [BytesMut], frame_size: usize,
    packets: &mut Vec<BytesMut>) -> io::Result<usize> {
    let mut headers = messages();
    let mut families = [[0u8; FAMILY_SIZE]; DEVICE_BATCH];
    let empty = iovec { iov_base: null_mut(), iov_len: 0 };
    let mut vectors = [[empty; 2]; DEVICE_BATCH];
    for (index, buffer) in buffers.iter_mut().enumerate() {
        debug_assert!(buffer.is_empty());
        // Some socket protocols truncate without setting MSG_TRUNC. A guard
        // byte makes an oversized frame observable even on those protocols.
        buffer.reserve(frame_size + 1);
        vectors[index] = [
            iovec { iov_base: families[index].as_mut_ptr().cast(), iov_len: FAMILY_SIZE },
            iovec { iov_base: buffer.spare_capacity_mut().as_mut_ptr().cast(), iov_len: frame_size + 1 },
        ];
        headers[index].header.msg_iov = vectors[index].as_mut_ptr();
        headers[index].header.msg_iovlen = 2;
    }
    let count = syscall(fd, &mut headers, RECVMSG_X)?;
    for index in 0..count {
        let message = &headers[index];
        let family = u32::from_be_bytes(families[index]);
        if message.header.msg_flags & libc::MSG_TRUNC != 0
            || message.data_len <= FAMILY_SIZE || message.data_len > frame_size + FAMILY_SIZE
            || (family != libc::AF_INET as u32 && family != libc::AF_INET6 as u32) {
            debug!(index, family, size = message.data_len, flags = message.header.msg_flags,
                "dropping invalid or truncated utun datagram");
            continue;
        }
        // SAFETY: recvmsg_x initialized exactly data_len bytes across the two
        // declared iovecs. Bounds and truncation were checked before exposing
        // only the initialized payload, never the unused spare capacity.
        unsafe { buffers[index].set_len(message.data_len - FAMILY_SIZE); }
        let buffer = &mut buffers[index];
        if buffer.len() < buffer.capacity().div_ceil(2) {
            let packet = BytesMut::from(&buffer[..]);
            buffer.clear();
            packets.push(packet);
        } else {
            // No shared tail remains in the reader. A retained packet owns
            // its entire allocation, bounded by twice its initialized length.
            packets.push(take(buffer));
        }
    }
    Ok(count)
}

pub(super) struct Writer {
    io: Arc<AsyncFd<OwnedFd>>,
    max_bytes: usize,
}

impl Writer {
    fn new(io: Arc<AsyncFd<OwnedFd>>) -> io::Result<Self> {
        SockRef::from(io.as_ref().get_ref()).set_nosigpipe(true)?;
        let max_bytes = (SockRef::from(io.as_ref().get_ref()).send_buffer_size()? / 2).max(1);
        Ok(Self { io, max_bytes })
    }

    pub(super) async fn send(&mut self, packets: &[Bytes]) -> io::Result<()> {
        let mut start = 0;
        while start < packets.len() {
            if !valid_packet(&packets[start]) { start += 1; continue; }
            let count = batch_len(&packets[start..], self.max_bytes);
            let mut ready = self.io.writable().await?;
            let result = ready.try_io(|fd| transmit(fd.as_raw_fd(), &packets[start..start + count]));
            match result {
                Ok(Ok(0)) => return Err(io::Error::new(io::ErrorKind::WriteZero, "Darwin batch made no progress")),
                Ok(Ok(sent)) => start += sent,
                // XNU returns a positive count for a prefix followed by
                // ENOBUFS/EINTR/EWOULDBLOCK (uipc_syscalls.c sendmsg_x done).
                // These errors with no count therefore have no sent prefix.
                // ENOBUFS need not change kqueue writability, so yield using a
                // bounded delay rather than spinning on a writable socket.
                Ok(Err(error)) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                    sleep(Duration::from_millis(1)).await;
                }
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                // Never replay an errored suffix: a non-retryable error may
                // have consumed an unreported prefix inside the utun driver.
                Ok(Err(error)) => return Err(error),
                Err(_) => continue,
            }
        }
        Ok(())
    }
}

fn batch_len(packets: &[Bytes], max_bytes: usize) -> usize {
    let mut total = 0;
    let mut count = 0;
    for packet in packets.iter().take(DEVICE_BATCH) {
        if !matches!(packet.first().map(|byte| byte >> 4), Some(4 | 6)) { break; }
        let size = packet.len() + FAMILY_SIZE;
        if count > 0 && total + size > max_bytes { break; }
        total += size;
        count += 1;
    }
    count
}

fn transmit(fd: i32, packets: &[Bytes]) -> io::Result<usize> {
    let mut headers = messages();
    let mut families = [[0u8; FAMILY_SIZE]; DEVICE_BATCH];
    let empty = iovec { iov_base: null_mut(), iov_len: 0 };
    let mut vectors = [[empty; 2]; DEVICE_BATCH];
    for (index, packet) in packets.iter().enumerate() {
        let family = match packet.first().map(|byte| byte >> 4) {
            Some(4) => libc::AF_INET,
            Some(6) => libc::AF_INET6,
            _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid TUN IP version")),
        };
        families[index] = (family as u32).to_be_bytes();
        vectors[index] = [
            iovec { iov_base: families[index].as_mut_ptr().cast(), iov_len: FAMILY_SIZE },
            // sendmsg_x borrows these bytes read-only despite the C void* ABI.
            iovec { iov_base: packet.as_ptr().cast_mut().cast(), iov_len: packet.len() },
        ];
        headers[index].header.msg_iov = vectors[index].as_mut_ptr();
        headers[index].header.msg_iovlen = 2;
    }
    syscall(fd, &mut headers[..packets.len()], SENDMSG_X)
}

#[cfg(test)]
#[path = "darwin_tests.rs"]
mod tests;
