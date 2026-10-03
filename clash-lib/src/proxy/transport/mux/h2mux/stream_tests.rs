use bytes::Bytes;
use futures::{future::poll_fn, FutureExt};
use h2::{client::handshake, server::Builder, RecvStream, SendStream};
use http::Response;
use std::{pin::Pin, task::Poll, time::Duration};
use tokio::{
    io::{duplex, AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf},
    sync::oneshot,
    task::AbortHandle,
    time::timeout,
};

use super::H2MuxStream;
use super::super::protocol::build_h2_connect_request;

struct Drivers(AbortHandle, AbortHandle);

impl Drop for Drivers {
    fn drop(&mut self) {
        self.0.abort();
        self.1.abort();
    }
}

async fn pair(window: u32, prefix: Bytes) -> (H2MuxStream, RecvStream, SendStream<Bytes>, Drivers) {
    let (client, server) = duplex(4096);
    let (tx, rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let mut builder = Builder::new();
        builder.initial_window_size(window);
        let mut conn = builder.handshake::<_, Bytes>(server).await.unwrap();
        let (req, mut respond) = conn.accept().await.unwrap().unwrap();
        let send = respond.send_response(Response::new(()), false).unwrap();
        tx.send((req.into_body(), send)).unwrap();
        while conn.accept().await.is_some() {}
    });
    let (mut sender, conn) = handshake(client).await.unwrap();
    let driver = tokio::spawn(conn);
    let (response, send) = sender.send_request(build_h2_connect_request().unwrap(), false).unwrap();
    let (recv, peer_send) = rx.await.unwrap();
    let mut stream = H2MuxStream::new(response, send, prefix, None);
    poll_fn(|cx| stream.poll_resolve_recv(cx)).await.unwrap();
    (stream, recv, peer_send,
        Drivers(driver.abort_handle(), server.abort_handle()))
}

#[tokio::test]
async fn small_window_first_write_is_exact_and_cancellation_safe() {
    timeout(Duration::from_secs(5), async {
        let (mut stream, mut peer, mut send, _drivers) = pair(3, Bytes::from_static(b"prefix")).await;
        // Receive the peer SETTINGS before testing the restricted send window.
        send.send_data(Bytes::from_static(&[0, b'x']), false).unwrap();
        // A zero-length read must neither initiate the prefix nor consume DATA.
        assert_eq!(stream.read(&mut []).await.unwrap(), 0);
        assert!(stream.write_all(b"cancelled").now_or_never().is_none());
        let first = peer.data().await.unwrap().unwrap();
        assert_eq!(first.as_ref(), b"pre");
        peer.flow_control().release_capacity(first.len()).unwrap();
        let reader = tokio::spawn(async move {
            let mut wire = first.to_vec();
            while let Some(data) = peer.data().await {
                let data = data.unwrap();
                wire.extend_from_slice(&data);
                peer.flow_control().release_capacity(data.len()).unwrap();
            }
            wire
        });
        stream.write_all(b"replacement").await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(reader.await.unwrap(), b"prefixreplacement");
    }).await.unwrap();
}

#[tokio::test]
async fn empty_data_frames_do_not_report_eof() {
    timeout(Duration::from_secs(5), async {
        let (mut stream, _peer, mut send, _drivers) = pair(65535, Bytes::new()).await;
        send.send_data(Bytes::from_static(&[0, b'x']), false).unwrap();
        let mut byte = [0; 1];
        stream.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [b'x']);
        send.send_data(Bytes::new(), false).unwrap();
        send.send_data(Bytes::from_static(b"y"), true).unwrap();
        stream.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [b'y']);
        assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
    }).await.unwrap();
}

#[tokio::test]
async fn read_first_and_shutdown_send_the_destination_prefix() {
    timeout(Duration::from_secs(5), async {
        let (mut stream, mut peer, mut send, _drivers) = pair(65535, Bytes::from_static(b"prefix")).await;
        let mut reply = [0; 1];
        let pending = poll_fn(|cx| {
            let mut buf = ReadBuf::new(&mut reply);
            match Pin::new(&mut stream).poll_read(cx, &mut buf) {
                Poll::Pending => Poll::Ready(()),
                other => panic!("read completed before response: {other:?}"),
            }
        });
        pending.await;
        let data = peer.data().await.unwrap().unwrap();
        assert_eq!(data.as_ref(), b"prefix");
        send.send_data(Bytes::from_static(&[0, b'x']), true).unwrap();
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [b'x']);

        let (mut stream, mut peer, _send, _drivers) = pair(65535, Bytes::from_static(b"prefix")).await;
        stream.shutdown().await.unwrap();
        let mut wire = Vec::new();
        while let Some(data) = peer.data().await {
            wire.extend_from_slice(&data.unwrap());
        }
        assert_eq!(wire, b"prefix");
    }).await.unwrap();
}
