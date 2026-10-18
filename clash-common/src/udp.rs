//! Batched transparent UDP receive. Every message has its own ancillary buffer.
use std::{io, mem::{size_of, zeroed}, net::{SocketAddr, SocketAddrV6},
    os::fd::AsRawFd, ptr};
use bytes::Bytes;
use socket2::{SockAddr, SockAddrStorage};
use tokio::{io::Interest, net::UdpSocket};

pub const MAX_BATCH: usize = 16;
const MAX_PAYLOAD: usize = 65535;
const CONTROL_WORDS: usize = 32;

/// Reusable receive storage owned by one listening loop. Task migration does
/// not allocate additional storage; dropping the loop releases the buffer.
pub struct BatchReceiver {
    scratch: Box<[u8]>,
}

impl Default for BatchReceiver {
    fn default() -> Self {
        Self { scratch: vec![0; MAX_BATCH * MAX_PAYLOAD].into_boxed_slice() }
    }
}

/// GRO is optional: callers retain recvmmsg batching on kernels without it.
pub fn enable_gro(socket: &UdpSocket) -> io::Result<()> {
    let enabled: libc::c_int = 1;
    // SAFETY: a live FD and correctly sized, initialized socket-option value.
    let result = unsafe { libc::setsockopt(socket.as_raw_fd(), libc::SOL_UDP, libc::UDP_GRO,
        (&enabled as *const libc::c_int).cast(), size_of::<libc::c_int>() as _) };
    if result < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

fn canonical(address: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(v6) = address
        && let Some(ip) = v6.ip().to_ipv4_mapped() {
        SocketAddr::from((ip, v6.port()))
    } else { address }
}

impl BatchReceiver {
    /// Receive original-destination metadata with each datagram. Truncated payloads,
    /// truncated ancillary data and messages without an original destination are
    /// discarded; substituting the listener address would route them incorrectly.
    pub async fn recv_batch(
        &mut self, socket: &UdpSocket,
        packets: &mut Vec<(Bytes, SocketAddr, SocketAddr)>, limit: usize,
    ) -> io::Result<usize> {
        let limit = limit.min(MAX_BATCH);
        if limit == 0 { return Ok(0); }
        socket.async_io(Interest::READABLE, || {
            receive(socket, &mut self.scratch, packets, limit)
        }).await
    }
}

fn receive(
    socket: &UdpSocket, scratch: &mut [u8],
    packets: &mut Vec<(Bytes, SocketAddr, SocketAddr)>, limit: usize,
) -> io::Result<usize> {
    let mut addresses = std::array::from_fn::<_, MAX_BATCH, _>(|_| SockAddrStorage::zeroed());
    // usize alignment satisfies cmsghdr alignment on supported Linux ABIs.
    let mut controls = [[0usize; CONTROL_WORDS]; MAX_BATCH];
    let mut iovecs = std::array::from_fn::<_, MAX_BATCH, _>(|i| libc::iovec {
        // SAFETY: slots are disjoint initialized writable ranges, stable for the syscall.
        iov_base: unsafe { scratch.as_mut_ptr().add(i * MAX_PAYLOAD).cast() },
        iov_len: MAX_PAYLOAD,
    });
    let mut messages = std::array::from_fn::<_, MAX_BATCH, _>(|i| {
        // SAFETY: zero is valid for all lengths and nullable pointers.
        let mut message: libc::mmsghdr = unsafe { zeroed() };
        message.msg_hdr.msg_name = (&mut addresses[i] as *mut SockAddrStorage).cast();
        message.msg_hdr.msg_namelen = addresses[i].size_of();
        message.msg_hdr.msg_iov = &mut iovecs[i];
        message.msg_hdr.msg_iovlen = 1;
        message.msg_hdr.msg_control = controls[i].as_mut_ptr().cast();
        message.msg_hdr.msg_controllen = size_of::<[usize; CONTROL_WORDS]>() as _;
        message
    });
    let count = loop {
        // SAFETY: initialized message prefix and all pointer targets remain
        // exclusively borrowed and stationary until this nonblocking call returns.
        let count = unsafe { libc::recvmmsg(socket.as_raw_fd(), messages.as_mut_ptr(),
            limit as _, libc::MSG_DONTWAIT as _, ptr::null_mut()) };
        if count >= 0 { break count as usize; }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted { return Err(error); }
    };
    for i in 0..count {
        let msg = &messages[i].msg_hdr;
        if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 { continue; }
        let len = messages[i].msg_len as usize;
        if len > MAX_PAYLOAD { continue; }
        let storage = std::mem::replace(&mut addresses[i], SockAddrStorage::zeroed());
        // SAFETY: kernel initialized the address and length in this returned message.
        let Some(source) = (unsafe { SockAddr::new(storage, msg.msg_namelen) }).as_socket() else { continue; };
        let (destination, stride) = ancillary(msg);
        let Some(destination) = destination else { continue; };
        // Independent kernel messages must not retain one another's payloads.
        // Segments of a single GRO message still share its compact allocation.
        let data = Bytes::copy_from_slice(&scratch[i * MAX_PAYLOAD..i * MAX_PAYLOAD + len]);
        let source = canonical(source);
        let destination = canonical(destination);
        if len == 0 {
            packets.push((data, source, destination));
        } else {
            let stride = if stride == 0 { len } else { stride };
            let mut offset = 0;
            while offset < len {
                let next = (offset + stride).min(len);
                packets.push((data.slice(offset..next), source, destination));
                offset = next;
            }
        }
    }
    // Return consumed kernel messages, even if metadata validation discarded all.
    Ok(count)
}

fn ancillary(msg: &libc::msghdr) -> (Option<SocketAddr>, usize) {
    let mut destination = None;
    let mut stride = 0;
    // SAFETY: msg_control references the initialized, aligned kernel-returned
    // buffer. CMSG helpers walk within msg_controllen; validate every payload
    // length before an unaligned read. No reference escapes this synchronous call.
    unsafe {
        let base = msg.msg_control as usize;
        let end = base + msg.msg_controllen as usize;
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            let header = &*cmsg;
            let start = cmsg as usize;
            let header_len = libc::CMSG_LEN(0) as usize;
            let len = header.cmsg_len as usize;
            if len < header_len || start.checked_add(len).is_none_or(|value| value > end) { break; }
            let data = libc::CMSG_DATA(cmsg);
            let payload_len = len - header_len;
            if header.cmsg_level == libc::SOL_IP && header.cmsg_type == libc::IP_ORIGDSTADDR
                && payload_len >= size_of::<libc::sockaddr_in>() {
                let address = ptr::read_unaligned(data.cast::<libc::sockaddr_in>());
                destination = Some(SocketAddr::from((address.sin_addr.s_addr.to_ne_bytes(), u16::from_be(address.sin_port))));
            } else if header.cmsg_level == libc::SOL_IPV6 && header.cmsg_type == libc::IPV6_ORIGDSTADDR
                && payload_len >= size_of::<libc::sockaddr_in6>() {
                let address = ptr::read_unaligned(data.cast::<libc::sockaddr_in6>());
                destination = Some(SocketAddr::V6(SocketAddrV6::new(
                    address.sin6_addr.s6_addr.into(), u16::from_be(address.sin6_port),
                    u32::from_be(address.sin6_flowinfo), address.sin6_scope_id)));
            } else if header.cmsg_level == libc::SOL_UDP && header.cmsg_type == libc::UDP_GRO
                && payload_len >= size_of::<libc::c_int>() {
                let value = ptr::read_unaligned(data.cast::<libc::c_int>());
                if value <= 0 || value as usize > MAX_PAYLOAD { return (None, 0); }
                stride = value as usize;
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
    (destination, stride)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    fn option(socket: &UdpSocket, level: libc::c_int, name: libc::c_int, value: libc::c_int) {
        // SAFETY: live socket and initialized option with exact ABI size.
        assert_eq!(unsafe { libc::setsockopt(socket.as_raw_fd(), level, name,
            (&value as *const libc::c_int).cast(), size_of::<libc::c_int>() as _) }, 0);
    }

    #[tokio::test]
    async fn gro_batch_splits_payloads_without_losing_original_destination() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        enable_gro(&receiver).unwrap();
        option(&receiver, libc::SOL_IP, libc::IP_RECVORIGDSTADDR, 1);
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        option(&sender, libc::SOL_UDP, libc::UDP_SEGMENT, 32);
        let data: Vec<u8> = (0..8).flat_map(|i| [i; 32]).collect();
        sender.send_to(&data, receiver.local_addr().unwrap()).await.unwrap();
        let mut packets = Vec::new();
        let mut batch_receiver = BatchReceiver::default();
        let count = timeout(Duration::from_secs(2), batch_receiver.recv_batch(&receiver, &mut packets, 16)).await.unwrap().unwrap();
        assert_eq!(count, 1, "kernel should deliver one aggregated UDP message");
        assert_eq!(packets.len(), 8);
        let base = packets[0].0.as_ptr();
        for (i, (data, source, destination)) in packets.iter().enumerate() {
            assert_eq!(data.as_ref(), &[i as u8; 32]);
            assert_eq!(data.as_ptr(), base.wrapping_add(i * 32), "GRO segments share one message allocation");
            assert_eq!(*source, sender.local_addr().unwrap());
            assert_eq!(*destination, receiver.local_addr().unwrap());
        }
    }

    #[tokio::test]
    async fn missing_original_destination_is_not_replaced_by_listener_address() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(b"missing", receiver.local_addr().unwrap()).await.unwrap();
        let mut packets = Vec::new();
        let mut batch_receiver = BatchReceiver::default();
        let count = timeout(Duration::from_secs(2), batch_receiver.recv_batch(&receiver, &mut packets, 1)).await.unwrap().unwrap();
        assert_eq!(count, 1);
        assert!(packets.is_empty());
    }

    #[tokio::test]
    async fn transparent_batch_preserves_original_destinations_and_empty_packets() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let receiver = UdpSocket::bind(address).await.unwrap();
            let local = receiver.local_addr().unwrap();
            let (level, option) = if local.is_ipv4() {
                (libc::SOL_IP, libc::IP_RECVORIGDSTADDR)
            } else { (libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR) };
            let enabled: libc::c_int = 1;
            // SAFETY: option points to a live c_int and uses its exact size.
            assert_eq!(unsafe { libc::setsockopt(receiver.as_raw_fd(), level, option,
                (&enabled as *const libc::c_int).cast(), size_of::<libc::c_int>() as _) }, 0);
            let sender = UdpSocket::bind(address).await.unwrap();
            for payload in [&b"one"[..], &b""[..], &b"three"[..]] {
                sender.send_to(payload, local).await.unwrap();
            }
            let mut packets = Vec::new();
            let mut batch_receiver = BatchReceiver::default();
            timeout(Duration::from_secs(2), async {
                while packets.len() < 3 { batch_receiver.recv_batch(&receiver, &mut packets, 16).await.unwrap(); }
            }).await.unwrap();
            for (i, payload) in [&b"one"[..], &b""[..], &b"three"[..]].iter().enumerate() {
                assert_eq!(packets[i].0.as_ref(), *payload);
                if !payload.is_empty() {
                    assert!(packets[i].0.is_unique(), "independent messages must own independent allocations");
                }
                assert_eq!(packets[i].1, sender.local_addr().unwrap());
                assert_eq!(packets[i].2, local);
            }
        }
    }
}
