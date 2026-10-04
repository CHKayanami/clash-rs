//! Manual retained-memory measurements for live streams after their first write.

use std::{
    hint::black_box,
    io,
    mem::size_of,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

use futures::task::noop_waker;
use memory_stats::memory_stats;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{stream::VLESS_COMMAND_TCP, VisionStream, VlessStream};
use crate::{proxy::{AnyStream, ProxyStream}, session::SocksAddr};

struct DiscardStream;

impl ProxyStream for DiscardStream {}

impl AsyncRead for DiscardStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for DiscardStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn measure<S: AsyncWrite + Unpin>(
    payload_size: usize,
    connections: usize,
    application_data: bool,
    mut create: impl FnMut() -> S,
) {
    let mut payload = vec![0; payload_size];
    payload[..3].copy_from_slice(if application_data { &[23, 3, 3] } else { &[22, 3, 1] });
    payload[3..5].copy_from_slice(&((payload_size - 5).min(16384) as u16).to_be_bytes());
    let mut live = Vec::with_capacity(connections);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let before = memory_stats().unwrap().physical_mem;
    let start = Instant::now();
    for _ in 0..connections {
        let mut stream = create();
        assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, &payload),
            Poll::Ready(Ok(written)) if written == payload.len()));
        live.push(stream);
    }
    let elapsed = start.elapsed();
    let after = memory_stats().unwrap().physical_mem;
    println!(
        "payload={payload_size} connections={connections} elapsed_us={} rss_delta={} stream_size={}",
        elapsed.as_micros(), after.saturating_sub(before), size_of::<S>(),
    );
    black_box(&live);
}

fn measure_vless(payload_size: usize, connections: usize) {
    let destination: SocksAddr = "1.2.3.4:443".parse().unwrap();
    measure(payload_size, connections, false, || {
        VlessStream::new(
            AnyStream::dynamic(DiscardStream),
            "5415d8e0-df92-3655-afa4-b79de66413f5",
            &destination, VLESS_COMMAND_TCP, None,
        ).unwrap()
    });
}

#[test]
#[ignore = "manual allocation/retained-memory measurement"]
fn vless_first_write_2k() {
    measure_vless(2048, 4096);
}

#[test]
#[ignore = "manual allocation/retained-memory measurement"]
fn vless_first_write_64k() {
    measure_vless(65536, 1024);
}

#[test]
#[ignore = "manual allocation/retained-memory measurement"]
fn vision_after_padding_end_64k() {
    measure(65535, 1024, true, || {
        VisionStream::new(
            AnyStream::dynamic(DiscardStream),
            "5415d8e0-df92-3655-afa4-b79de66413f5", None,
        ).unwrap()
    });
}
