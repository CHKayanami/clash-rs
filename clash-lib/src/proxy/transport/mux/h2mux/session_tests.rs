use super::*;
use futures::future::poll_fn;
use h2::server::Builder as ServerBuilder;
use http::Response;
use std::{future::Future, task::Poll, time::Duration};
use tokio::{
    io::{duplex, AsyncReadExt},
    sync::oneshot,
    time::timeout,
};

async fn session(local_limit: usize, peer_limit: u32) -> (Arc<H2MuxSession>, oneshot::Receiver<()>) {
    let (client, mut server) = duplex(4096);
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        assert_eq!(server.read_u16().await.unwrap(), 2); // version 0, h2mux
        let mut builder = ServerBuilder::new();
        builder.max_concurrent_streams(peer_limit);
        let mut conn = builder.handshake::<_, Bytes>(server).await.unwrap();
        let mut streams = Vec::new();
        while let Some(Ok((req, mut respond))) = conn.accept().await {
            let mut send = respond.send_response(Response::new(()), false).unwrap();
            send.send_data(Bytes::from_static(&[0, b'x']), false).unwrap();
            streams.push((req, send));
        }
        let _ = tx.send(());
    });
    let session = H2MuxSession::new(AnyStream::new(client), MuxOption {
        max_streams: local_limit, ..Default::default()
    }).await.unwrap();
    (session, rx)
}

#[tokio::test]
async fn concurrent_open_cannot_exceed_local_stream_limit() {
    timeout(Duration::from_secs(5), async {
        let (session, closed) = session(1, 8).await;
        let dst = SocksAddr::Ip("127.0.0.1:80".parse().unwrap());
        let (first, second) = tokio::join!(
            session.open_stream(&dst, false), session.open_stream(&dst, false),
        );
        let first = first.unwrap();
        assert_eq!(second.err().unwrap().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(session.active_streams(), 1);
        assert!(!session.is_closed());
        drop(first);
        assert_eq!(session.active_streams(), 0);
        let next = session.open_stream(&dst, false).await.unwrap();
        drop((next, session));
        closed.await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn cancelled_open_releases_reserved_slot() {
    timeout(Duration::from_secs(5), async {
        let (session, closed) = session(0, 1).await;
        let dst = SocksAddr::Ip("127.0.0.1:80".parse().unwrap());
        let mut first = session.open_stream(&dst, false).await.unwrap();
        // Receiving the response also confirms the peer's SETTINGS were applied.
        first.read_exact(&mut [0; 1]).await.unwrap();
        // h2 allows one queued open beyond the peer's active-stream limit.
        let second = session.open_stream(&dst, false).await.unwrap();
        let mut pending = Box::pin(session.open_stream(&dst, false));
        poll_fn(|cx| match pending.as_mut().poll(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("second open should wait for peer capacity"),
        }).await;
        assert_eq!(session.active_streams(), 3);
        drop(pending);
        assert_eq!(session.active_streams(), 2);
        drop(second);
        assert_eq!(session.active_streams(), 1);
        drop((first, session));
        closed.await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn stream_keeps_session_alive_until_last_drop() {
    timeout(Duration::from_secs(5), async {
        let (session, closed) = session(1, 8).await;
        let weak = Arc::downgrade(&session);
        let dst = SocksAddr::Ip("127.0.0.1:80".parse().unwrap());
        let mut stream = session.open_stream(&dst, false).await.unwrap();
        drop(session);
        assert!(weak.upgrade().is_some());
        stream.read_exact(&mut [0; 1]).await.unwrap();
        drop(stream);
        assert!(weak.upgrade().is_none());
        closed.await.unwrap();
    }).await.unwrap();
}
