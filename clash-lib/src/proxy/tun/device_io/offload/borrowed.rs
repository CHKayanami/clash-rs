//! Borrowed payloads never escape the synchronous writev call.
use std::{io, os::fd::RawFd};
use super::HEADER_LEN;

pub(in crate::proxy::tun::device_io) fn send(fd: RawFd, header: &[u8], payload: &[u8], size: Option<u16>) -> io::Result<bool> {
    let ip = if header[0] >> 4 == 4 { usize::from(header[0] & 15) * 4 } else { 40 };
    let mut virtio = [0u8; HEADER_LEN];
    virtio[0] = 1;
    virtio[1] = if size.is_some() { if header[0] >> 4 == 6 { 4 } else { 1 } } else { 0 };
    virtio[2..4].copy_from_slice(&(header.len() as u16).to_ne_bytes());
    virtio[4..6].copy_from_slice(&size.unwrap_or(0).to_ne_bytes());
    virtio[6..8].copy_from_slice(&(ip as u16).to_ne_bytes());
    virtio[8..10].copy_from_slice(&16u16.to_ne_bytes());
    let vectors = [virtio.as_slice(), header, payload].map(|data| libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast(), iov_len: data.len(),
    });
    loop {
        // SAFETY: all slices and iovecs stay live and immutable throughout this
        // synchronous syscall. The caller keeps the nonblocking descriptor alive.
        let count = unsafe { libc::writev(fd, vectors.as_ptr(), vectors.len() as _) };
        if count >= 0 {
            if count as usize != virtio.len() + header.len() + payload.len() {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "partial borrowed TUN frame"));
            }
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted { continue; }
        if error.kind() == io::ErrorKind::WouldBlock { return Ok(false); }
        return Err(error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::{fd::AsRawFd, unix::net::UnixDatagram};

    #[test]
    fn borrowed_write_is_atomic_and_backpressure_does_not_replay_payload() {
        let (writer, reader) = UnixDatagram::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        reader.set_nonblocking(true).unwrap();
        let mut header = [0u8; 40];
        header[0] = 0x45;
        let payload = [0x5a; 512];
        assert!(send(writer.as_raw_fd(), &header, &payload, Some(256)).unwrap());
        let mut received = [0u8; 4096];
        let count = reader.recv(&mut received).unwrap();
        assert_eq!(count, HEADER_LEN + header.len() + payload.len());
        assert_eq!(&received[HEADER_LEN..HEADER_LEN + header.len()], header);
        assert_eq!(&received[HEADER_LEN + header.len()..count], payload);
        assert_eq!(received[0], 1);
        assert_eq!(received[1], 1);
        assert_eq!(u16::from_ne_bytes([received[4], received[5]]), 256);
        let mut count = 0;
        loop {
            match send(writer.as_raw_fd(), &header, &payload, None) {
                Ok(true) => count += 1,
                Ok(false) => break,
                Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => break,
                result => panic!("unexpected nonblocking write result: {result:?}"),
            }
            assert!(count < 4096, "nonblocking socket must eventually backpressure");
        }
        for _ in 0..count { reader.recv(&mut received).unwrap(); }
        assert_eq!(reader.recv(&mut received).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert!(send(writer.as_raw_fd(), &header, &payload, None).unwrap());
        reader.recv(&mut received).unwrap();
        assert_eq!(received[1], 0, "ordinary TCP uses partial checksum without GSO");
    }
}
