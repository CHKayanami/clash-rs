use std::{
    io::IoSliceMut,
    ops::DerefMut,
    sync::Arc,
    task::{Context, Poll},
};

use blake2::{Blake2b, Digest};
use futures::ready;
use generic_array::typenum::U32;
use quinn::{
    AsyncUdpSocket, TokioRuntime,
    udp::{RecvMeta, Transmit},
};
type Blake2b256 = Blake2b<U32>;

std::thread_local! {
    static SEND_BUF: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

struct SalamanderObfs {
    hasher: Blake2b256,
}

impl SalamanderObfs {
    /// create a new obfs
    pub fn new(key: Vec<u8>) -> Self {
        let mut hasher = Blake2b256::new();
        hasher.update(&key);
        Self { hasher }
    }

    pub fn obfs(&self, salt: &[u8], data: &mut [u8]) {
        let mut hasher = self.hasher.clone();
        hasher.update(salt);
        let res: [u8; 32] = hasher.finalize().into();

        data.iter_mut().enumerate().for_each(|(i, v)| {
            *v ^= res[i % 32];
        });
    }

    fn decrypt(&self, data: &mut [u8]) {
        // Callers already screen out short datagrams; return rather than panic
        // if one ever slips through, since this sits on the receive path.
        if data.len() <= 8 {
            debug_assert!(
                false,
                "salamander decrypt called with {} bytes",
                data.len()
            );
            return;
        }

        let (salt, data) = data.split_at_mut(8);
        self.obfs(salt, data);
        // data.advance(8); // sadlly IoSliceMut::advance is unstable
    }
}

pub struct Salamander {
    inner: Arc<dyn AsyncUdpSocket>,
    obfs: SalamanderObfs,
}

impl Salamander {
    pub fn new(socket: std::net::UdpSocket, key: Vec<u8>) -> std::io::Result<Self> {
        use quinn::Runtime;
        let inner = TokioRuntime.wrap_udp_socket(socket)?;

        std::io::Result::Ok(Self {
            inner,
            obfs: SalamanderObfs::new(key),
        })
    }
}

impl std::fmt::Debug for Salamander {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl AsyncUdpSocket for Salamander {
    fn create_io_poller(
        self: std::sync::Arc<Self>,
    ) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> std::io::Result<()> {
        SEND_BUF.with_borrow_mut(|buf| {
            let total_len = 8 + transmit.contents.len();
            buf.clear();
            buf.reserve(total_len);
            let salt: [u8; 8] = rand::random::<[u8; 8]>();
            buf.extend_from_slice(&salt);
            buf.extend_from_slice(transmit.contents);
            self.obfs.obfs(&salt, &mut buf[8..]);

            let mut v = transmit.to_owned();
            v.contents = buf.as_slice();
            self.inner.try_send(&v)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        let packet_nums = ready!(self.inner.poll_recv(cx, bufs, meta))?;

        let mut valid_count = 0;

        for i in 0..packet_nums {
            tracing::trace!(
                "meta addr {:?}, dst_ip: {:?}, len: {}, stride: {}",
                meta[i].addr,
                meta[i].dst_ip,
                meta[i].len,
                meta[i].stride,
            );

            let total_len = meta[i].len;
            let stride = meta[i].stride;
            let buf = bufs[i].deref_mut();
            let buf_len = buf.len();

            // Validate buffer bounds
            if total_len > buf_len {
                tracing::error!(
                    "invalid buffer: total_len={} > buf_len={}, addr={:?}",
                    total_len,
                    buf_len,
                    meta[i].addr
                );
                continue;
            }

            // Salamander packets must have at least 8 bytes (salt) + 1 byte
            // (data)
            if total_len <= 8 || stride <= 8 {
                tracing::debug!(
                    "invalid salamander packet: len={}, stride={}, addr={:?}",
                    total_len,
                    stride,
                    meta[i].addr
                );
                continue;
            }

            // Fast path: single packet (no GRO, typical on Windows/Mac)
            if total_len == stride {
                // Decrypt and strip the 8-byte salt prefix
                self.obfs.decrypt(&mut buf[..total_len]);
                buf.copy_within(8..total_len, 0);

                // Compact valid packets to the front
                if i != valid_count {
                    meta[valid_count] = meta[i];
                    bufs.swap(i, valid_count);
                }
                meta[valid_count].len = total_len - 8;
                meta[valid_count].stride = stride - 8;
                valid_count += 1;
                continue;
            }

            // Slow path: GRO-merged packets (Linux with GRO enabled)
            // When GRO is enabled, a single buffer may contain multiple
            // datagrams concatenated together, each of size `stride` (the last
            // one may be smaller). Each sub-datagram has its own 8-byte
            // salamander salt prefix that must be decrypted and stripped
            // independently.
            let mut read_offset = 0;
            let mut write_offset = 0;
            while read_offset < total_len {
                let seg_len = stride.min(total_len - read_offset);
                if seg_len <= 8 {
                    // Remaining segment too small to be valid
                    break;
                }

                // Ensure we don't read beyond buffer
                if read_offset + seg_len > buf_len {
                    tracing::error!(
                        "GRO segment out of bounds: read_offset={}, seg_len={}, \
                         buf_len={}",
                        read_offset,
                        seg_len,
                        buf_len
                    );
                    break;
                }

                // Decrypt this segment in place
                self.obfs
                    .decrypt(&mut buf[read_offset..read_offset + seg_len]);

                // Ensure we don't write beyond valid range
                let payload_len = seg_len - 8;
                if write_offset + payload_len > buf_len {
                    tracing::error!(
                        "GRO write out of bounds: write_offset={}, payload_len={}, \
                         buf_len={}",
                        write_offset,
                        payload_len,
                        buf_len
                    );
                    break;
                }

                // Copy decrypted payload (skip 8-byte salt) to compacted
                // position
                buf.copy_within(
                    read_offset + 8..read_offset + seg_len,
                    write_offset,
                );

                read_offset += seg_len;
                write_offset += payload_len;
            }

            // Only add to valid_count if we processed something
            if write_offset > 0 {
                // Compact valid packets to the front
                if i != valid_count {
                    meta[valid_count] = meta[i];
                    bufs.swap(i, valid_count);
                }
                meta[valid_count].len = write_offset;
                meta[valid_count].stride = stride - 8;
                valid_count += 1;
            }
        }

        Poll::Ready(Ok(valid_count))
    }

    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[test]
#[ignore = "crash on Windows"]
fn test_skip() {
    let mut data = b"12345678AA".to_vec();

    let obfs = SalamanderObfs::new(b"123456".to_vec());

    let bufs = &mut [IoSliceMut::new(&mut data)];
    bufs.iter_mut().filter(|x| x.len() > 8).for_each(|v| {
        obfs.decrypt(v);
        let data: &mut [u8] = v.as_mut();
        let data = &mut data[8..];
        unsafe {
            let b: IoSliceMut<'_> = std::mem::transmute(data);
            *v = b;
        }
        println!("{:?}", v);
    });
}

#[test]
fn test_obfs() {
    let obfs = SalamanderObfs::new(b"obfs".to_vec());
    let data = b"hhh";
    let salt: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    // Simulate encrypt: salt || obfs(data)
    let mut buf = Vec::with_capacity(8 + data.len());
    buf.extend_from_slice(&salt);
    buf.extend_from_slice(data);
    obfs.obfs(&salt, &mut buf[8..]);

    // Decrypt in place (same as poll_recv path)
    let res = &mut IoSliceMut::new(&mut buf);
    obfs.decrypt(res);

    assert!(std::str::from_utf8(res[8..].as_ref()).unwrap() == "hhh");
}

