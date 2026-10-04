use super::*;
use crate::proxy::transport::h2_common::RECEIVE_WINDOW;
use futures::future::{pending, poll_fn};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use tokio::{io::{DuplexStream, ReadBuf}, sync::oneshot};

async fn stalled_stream(window: u32) -> (AnyStream, ServerTask) {
    let (client_io, server_io) = duplex(4096);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::Builder::new()
            .initial_window_size(window).handshake::<_, Bytes>(server_io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        let send = respond.send_response(grpc_response(), false).unwrap();
        while connection.accept().await.is_some() {}
        drop((request, send));
    });
    let mut stream = client().proxy_stream(AnyStream::new(client_io)).await.unwrap();
    // Process the server SETTINGS and initial response before measuring backpressure.
    let _ = timeout(Duration::from_millis(20), stream.read(&mut [0])).await;
    (stream, ServerTask(server))
}

#[tokio::test]
async fn empty_write_and_shutdown_need_no_window_capacity() {
    let (mut stream, _server) = stalled_stream(0).await;
    let written = timeout(Duration::from_secs(2), poll_fn(|cx| {
        Pin::new(&mut stream).poll_write(cx, &[])
    })).await.unwrap().unwrap();
    assert_eq!(written, 0);
    timeout(Duration::from_secs(2), stream.shutdown()).await.unwrap().unwrap();
    stream.shutdown().await.unwrap();
}

#[tokio::test]
async fn small_window_bounds_writes_and_blocks_flush_and_shutdown() {
    let (mut stream, _server) = stalled_stream(1).await;
    let payload = vec![b'x'; MAX_WRITE_SIZE * 4];
    let written = stream.write(&payload).await.unwrap();
    assert_eq!(written, MAX_WRITE_SIZE);
    assert!(timeout(Duration::from_millis(20), stream.write(b"next")).await.is_err());
    assert!(timeout(Duration::from_millis(20), stream.flush()).await.is_err());
    assert!(timeout(Duration::from_millis(20), stream.shutdown()).await.is_err());
}

#[tokio::test]
async fn one_byte_window_flushes_complete_frame_before_shutdown() {
    let (client_io, server_io) = duplex(4096);
    let (received_tx, received_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let mut connection = h2::server::Builder::new()
            .initial_window_size(1).handshake::<_, Bytes>(server_io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        let transfer = async move {
            let mut recv = request.into_body();
            let mut received = Vec::new();
            while let Some(data) = recv.data().await {
                let data = data.unwrap();
                received.extend_from_slice(&data);
                recv.flow_control().release_capacity(data.len()).unwrap();
            }
            received_tx.send(received).unwrap();
            let mut send = respond.send_response(grpc_response(), false).unwrap();
            send.send_trailers(ok_trailers()).unwrap();
        };
        tokio::pin!(transfer);
        tokio::select! {
            _ = &mut transfer => {
                while connection.accept().await.is_some() {}
            }
            _ = async { while connection.accept().await.is_some() {} } => {}
        }
    });
    let _server = ServerTask(server);
    timeout(Duration::from_secs(5), async {
        let mut stream = client().proxy_stream(AnyStream::new(client_io)).await.unwrap();
        let _ = timeout(Duration::from_millis(20), stream.read(&mut [0])).await;
        let payload = [b'x'; 130];
        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(received_rx.await.unwrap(), encode_frame(&payload));
        assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
    }).await.expect("a window smaller than the gRPC header must still make progress");
}

#[derive(Debug)]
struct TrackedIo {
    inner: DuplexStream,
    dropped: Arc<AtomicBool>,
}

impl ProxyStream for TrackedIo {}

impl Drop for TrackedIo {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

impl AsyncRead for TrackedIo {
    fn poll_read(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TrackedIo {
    fn poll_write(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn dropping_stream_before_response_releases_connection() {
    let dropped = Arc::new(AtomicBool::new(false));
    let (client_io, server_io) = duplex(4096);
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let request = connection.accept().await.unwrap().unwrap();
        accepted_tx.send(()).unwrap();
        tokio::select! {
            _ = pending::<()>() => {}
            _ = async { while connection.accept().await.is_some() {} } => {}
        }
        drop(request);
    });
    let _server = ServerTask(server);
    let stream = client().proxy_stream(AnyStream::dynamic(TrackedIo {
        inner: client_io, dropped: dropped.clone(),
    })).await.unwrap();
    accepted_rx.await.unwrap();
    drop(stream);
    timeout(Duration::from_secs(2), async {
        while !dropped.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    }).await.expect("the connection must be released without a response from the peer");
}

#[tokio::test]
async fn receive_window_applies_backpressure_and_small_reads_release_it() {
    let (client_io, server_io) = duplex(4096);
    let (sent_tx, mut sent_rx) = oneshot::channel();
    let payload_len = RECEIVE_WINDOW as usize * 3;
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (_request, mut respond) = connection.accept().await.unwrap().unwrap();
        let transfer = async move {
            let mut send = respond.send_response(grpc_response(), false).unwrap();
            let mut frame = encode_frame(&vec![b'x'; payload_len]);
            while !frame.is_empty() {
                send.reserve_capacity(frame.len());
                let capacity = poll_fn(|cx| send.poll_capacity(cx)).await.unwrap().unwrap();
                let data = frame.split_to(capacity.min(frame.len()));
                send.send_data(data, false).unwrap();
            }
            send.send_trailers(ok_trailers()).unwrap();
            sent_tx.send(()).unwrap();
        };
        tokio::pin!(transfer);
        tokio::select! {
            _ = &mut transfer => {
                while connection.accept().await.is_some() {}
            }
            _ = async { while connection.accept().await.is_some() {} } => {}
        }
    });
    let _server = ServerTask(server);
    let mut stream = client().proxy_stream(AnyStream::new(client_io)).await.unwrap();
    // The sender cannot queue the whole response before the application reads.
    assert!(timeout(Duration::from_millis(20), &mut sent_rx).await.is_err());
    timeout(Duration::from_secs(5), async {
        let mut total = 0;
        let mut buffer = [0; 137];
        loop {
            let len = stream.read(&mut buffer).await.unwrap();
            if len == 0 {
                break;
            }
            assert!(buffer[..len].iter().all(|byte| *byte == b'x'));
            total += len;
        }
        assert_eq!(total, payload_len);
        sent_rx.await.unwrap();
    }).await.expect("reads must replenish both stream and connection windows");
}

async fn reset_stream() -> (GrpcStream, ServerTask) {
    let (client_io, server_io) = duplex(4096);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        respond.send_reset(h2::Reason::CANCEL);
        while connection.accept().await.is_some() {}
        drop(request);
    });
    let (mut sender, connection) = h2::client::handshake(client_io).await.unwrap();
    let connection_task = ConnectionDriver::spawn(connection, None);
    let (response, send) = sender.send_request(client().req().unwrap(), false).unwrap();
    drop(sender);
    let mut stream = GrpcStream::new(response, send, connection_task);
    let error = timeout(Duration::from_secs(2), poll_fn(|cx| stream.poll_response(cx)))
        .await.unwrap().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ConnectionReset);
    (stream, ServerTask(server))
}

#[tokio::test]
async fn send_error_closes_write_side_and_discards_pending_frame() {
    let (mut stream, _server) = reset_stream().await;
    stream.pending_send = encode_frame(b"pending");
    let error = stream.send_data(encode_frame(b"late")).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::BrokenPipe);
    assert!(stream.write_closed);
    assert!(stream.pending_send.is_empty());
    assert_eq!(
        stream.write(b"retry").await.unwrap_err().to_string(),
        "gRPC stream write side is closed",
    );
}

#[tokio::test]
async fn capacity_error_also_closes_write_side() {
    let (mut stream, _server) = reset_stream().await;
    assert_eq!(stream.write(b"late").await.unwrap_err().kind(), ErrorKind::BrokenPipe);
    assert!(stream.write_closed);
    assert_eq!(
        stream.write(b"retry").await.unwrap_err().to_string(),
        "gRPC stream write side is closed",
    );
}
