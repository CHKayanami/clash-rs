//! Opt-in runtime allocation checks for each phase of forwarding.
use std::{future::Future, pin::{Pin, pin}, task::{Context, Poll}, time::Duration};
use futures::task::noop_waker_ref;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use crate::proxy::AnyStream;
use super::{TrafficTracker, copy_bidirectional};

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(noop_waker_ref()))
}

async fn warm_pair(a: &mut DuplexStream, b: &mut DuplexStream) {
    // DuplexStream allocates its queue on the first write. Keep these test
    // transport allocations separate from allocations made by the relay.
    let mut bytes = [0; 6];
    a.write_all(b"abcdef").await.unwrap();
    b.read_exact(&mut bytes).await.unwrap();
    b.write_all(b"abcdef").await.unwrap();
    a.read_exact(&mut bytes).await.unwrap();
}

pub async fn measure_copy_runtime(
    start: impl Fn(), finish: impl Fn(&str, usize, Option<usize>) -> usize,
) {
    for reverse in [false, true] {
        let (mut client, mut a) = tokio::io::duplex(64);
        let (mut b, mut server) = tokio::io::duplex(64);
        warm_pair(&mut client, &mut a).await;
        warm_pair(&mut b, &mut server).await;
        let (mut source, mut sink) = if reverse { (server, client) } else { (client, server) };
        let mut copy = pin!(copy_bidirectional(
            AnyStream::from(a), AnyStream::from(b), 1024,
            Duration::from_secs(10), Duration::from_secs(10), TrafficTracker::noop(),
        ));
        start();
        let result = poll_once(copy.as_mut());
        finish("TCP copy initialization", 0, Some(3));
        assert!(result.is_pending());

        source.shutdown().await.unwrap();
        start();
        let result = poll_once(copy.as_mut());
        finish("TCP copy half-close", 0, Some(0));
        assert!(result.is_pending());

        sink.write_all(b"abcdef").await.unwrap();
        start();
        let result = poll_once(copy.as_mut());
        finish("TCP copy half-close transfer", 0, Some(0));
        assert!(result.is_pending());
        let mut bytes = [0; 6];
        source.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"abcdef");

        sink.shutdown().await.unwrap();
        start();
        let result = poll_once(copy.as_mut());
        finish("TCP copy completion", 0, Some(0));
        let Poll::Ready(Ok(counts)) = result else { panic!("copy did not finish"); };
        assert_eq!(counts, if reverse { (6, 0) } else { (0, 6) });
    }
    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    measure_splice(&start, &finish).await;
}

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
async fn measure_splice(
    start: &impl Fn(), finish: &impl Fn(&str, usize, Option<usize>) -> usize,
) {
    use tokio::net::UnixStream;
    use super::splice;

    for reverse in [false, true] {
        let (client, mut a) = UnixStream::pair().unwrap();
        let (mut b, server) = UnixStream::pair().unwrap();
        let (mut source, mut sink) = if reverse { (server, client) } else { (client, server) };
        start();
        let mut copy = splice::new(
            None, None, TrafficTracker::noop(), Duration::from_secs(10), Duration::from_secs(10),
        ).unwrap();
        let result = copy.poll(&mut a, &mut b, &mut Context::from_waker(noop_waker_ref()));
        finish("splice copy initialization", 0, Some(1));
        assert!(result.is_pending());

        source.shutdown().await.unwrap();
        if reverse { b.readable().await.unwrap(); } else { a.readable().await.unwrap(); }
        start();
        let result = copy.poll(&mut a, &mut b, &mut Context::from_waker(noop_waker_ref()));
        finish("splice copy half-close", 0, Some(0));
        assert!(result.is_pending());

        sink.write_all(b"abcdef").await.unwrap();
        if reverse { a.readable().await.unwrap(); } else { b.readable().await.unwrap(); }
        start();
        let result = copy.poll(&mut a, &mut b, &mut Context::from_waker(noop_waker_ref()));
        finish("splice copy half-close transfer", 0, Some(0));
        assert!(result.is_pending());
        let mut bytes = [0; 6];
        source.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"abcdef");

        sink.shutdown().await.unwrap();
        if reverse { a.readable().await.unwrap(); } else { b.readable().await.unwrap(); }
        start();
        let result = copy.poll(&mut a, &mut b, &mut Context::from_waker(noop_waker_ref()));
        drop(copy);
        finish("splice copy completion", 0, Some(0));
        let Poll::Ready(Ok(counts)) = result else { panic!("splice did not finish"); };
        assert_eq!(counts, if reverse { (6, 0) } else { (0, 6) });
    }
}
