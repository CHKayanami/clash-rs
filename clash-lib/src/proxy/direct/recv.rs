use std::{cell::RefCell, io, net::SocketAddr};

use tokio::net::UdpSocket;

pub(super) const MAX_RECV_BATCH: usize = 16;
const MAX_DATAGRAM_SIZE: usize = 65535;

#[cfg(target_os = "linux")]
thread_local! {
    // At most 1 MiB of scratch per receiving worker, never per association.
    // Kernel writes initialize the returned ranges; packets handed to queues
    // own only their actual bytes and cannot pin this scratch allocation.
    static RECV_BUFFER: RefCell<Box<[std::mem::MaybeUninit<u8>]>> =
        RefCell::new(Box::new_uninit_slice(MAX_RECV_BATCH * MAX_DATAGRAM_SIZE));
}

#[cfg(not(target_os = "linux"))]
thread_local! {
    static RECV_BUFFER: RefCell<Vec<u8>> = RefCell::new(vec![0; MAX_DATAGRAM_SIZE]);
}

/// Drain a bounded batch without changing the per-packet datagram interface.
pub(super) fn recv_batch(
    socket: &UdpSocket,
    limit: usize,
    mut on_packet: impl FnMut(&[u8], SocketAddr),
) -> io::Result<usize> {
    let limit = limit.min(MAX_RECV_BATCH);
    if limit == 0 {
        return Ok(0);
    }
    RECV_BUFFER.with_borrow_mut(|buffer| {
        #[cfg(target_os = "linux")]
        {
            use socket2::{SockAddr, SockAddrStorage};
            use std::os::fd::AsRawFd;
            use tokio::io::Interest;

            let mut addresses = std::array::from_fn::<_, MAX_RECV_BATCH, _>(|_| {
                SockAddrStorage::zeroed()
            });
            let mut iovecs =
                std::array::from_fn::<_, MAX_RECV_BATCH, _>(|i| libc::iovec {
                    // SAFETY: each slot is a disjoint, live writable range. No Rust
                    // reference to uninitialized bytes is created.
                    iov_base: unsafe {
                        buffer.as_mut_ptr().add(i * MAX_DATAGRAM_SIZE).cast()
                    },
                    iov_len: MAX_DATAGRAM_SIZE,
                });
            let mut messages = std::array::from_fn::<_, MAX_RECV_BATCH, _>(|i| {
                // SAFETY: zero is valid for the scalar and pointer fields.
                let mut message: libc::mmsghdr = unsafe { std::mem::zeroed() };
                message.msg_hdr.msg_name =
                    (&mut addresses[i] as *mut SockAddrStorage).cast();
                message.msg_hdr.msg_namelen = addresses[i].size_of();
                message.msg_hdr.msg_iov = &mut iovecs[i];
                message.msg_hdr.msg_iovlen = 1;
                message
            });
            let count = socket.try_io(Interest::READABLE, || {
                loop {
                    // SAFETY: message/address/iovec arrays and all payload slots
                    // remain live and stable for the nonblocking syscall.
                    let count = unsafe {
                        libc::recvmmsg(
                            socket.as_raw_fd(),
                            messages.as_mut_ptr(),
                            limit as u32,
                            libc::MSG_DONTWAIT as _,
                            std::ptr::null_mut(),
                        )
                    };
                    if count >= 0 {
                        break Ok(count as usize);
                    }
                    let err = io::Error::last_os_error();
                    if err.kind() != io::ErrorKind::Interrupted {
                        break Err(err);
                    }
                }
            })?;
            for i in 0..count {
                let header = &messages[i].msg_hdr;
                if header.msg_flags & libc::MSG_TRUNC != 0 {
                    continue;
                }
                let storage =
                    std::mem::replace(&mut addresses[i], SockAddrStorage::zeroed());
                // SAFETY: recvmmsg initialized this sender's address and length.
                let address = unsafe { SockAddr::new(storage, header.msg_namelen) }
                    .as_socket()
                    .ok_or_else(|| {
                        io::Error::other("unexpected UDP sender address family")
                    })?;
                let len = messages[i].msg_len as usize;
                // SAFETY: the kernel initialized exactly msg_len bytes in this
                // slot; MSG_TRUNC was checked and len is bounded defensively.
                let packet = unsafe {
                    std::slice::from_raw_parts(
                        buffer.as_ptr().add(i * MAX_DATAGRAM_SIZE).cast::<u8>(),
                        len.min(MAX_DATAGRAM_SIZE),
                    )
                };
                on_packet(packet, address);
            }
            Ok(count)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let mut count = 0;
            while count < limit {
                match socket.try_recv_from(buffer) {
                    Ok((len, address)) => {
                        on_packet(&buffer[..len], address);
                        count += 1;
                    }
                    Err(err) if count > 0 => {
                        if err.kind() != io::ErrorKind::WouldBlock {
                            tracing::trace!(
                                "UDP batch receive error after progress: {err}"
                            );
                        }
                        break;
                    }
                    Err(err) => return Err(err),
                }
            }
            Ok(count)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[tokio::test]
    async fn receive_batch_preserves_boundaries_senders_and_empty_packets() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = receiver.local_addr().unwrap();
        let first_addr = first.local_addr().unwrap();
        let second_addr = second.local_addr().unwrap();
        for (sender, data) in [
            (&first, &b"one"[..]),
            (&second, &b""[..]),
            (&first, &b"three"[..]),
        ] {
            sender.send_to(data, destination).await.unwrap();
        }
        let mut packets = Vec::new();
        while packets.len() < 3 {
            receiver.readable().await.unwrap();
            match recv_batch(&receiver, 2, |data, addr| {
                packets.push((Bytes::copy_from_slice(data), addr))
            }) {
                Ok(count) => assert!(count <= 2),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(err) => panic!("receive failed: {err}"),
            }
        }
        assert_eq!(
            packets,
            vec![
                (Bytes::from_static(b"one"), first_addr),
                (Bytes::new(), second_addr),
                (Bytes::from_static(b"three"), first_addr),
            ]
        );
        // Reusing scratch for another batch must not overwrite queued packets.
        second.send_to(b"replacement", destination).await.unwrap();
        loop {
            receiver.readable().await.unwrap();
            match recv_batch(&receiver, 1, |_, _| {}) {
                Ok(1) => break,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => (),
                other => panic!("unexpected receive result: {other:?}"),
            }
        }
        assert_eq!(packets[0].0.as_ref(), b"one");
        assert_eq!(packets[2].0.as_ref(), b"three");
    }
}
