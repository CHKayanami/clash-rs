use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context as TaskContext, Poll, Waker},
    time::Duration,
};

use clash_shadowsocks::{
    ProxyClientStream, ServerConfig,
    config::ServerType,
    context::Context,
    crypto::CipherKind,
    relay::{Address, tcprelay::ProxyServerStream},
};
use futures::task::noop_waker;
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, duplex}, time::timeout};

#[derive(Default)]
struct TransportState {
    bytes: Vec<u8>,
    budget: usize,
    flush_blocked: bool,
    fail_write: bool,
    fail_flush: bool,
    write_waker: Option<Waker>,
    shutdown: bool,
}

struct ControlledIo(Arc<Mutex<TransportState>>);

impl AsyncRead for ControlledIo {
    fn poll_read(self: Pin<&mut Self>, _: &mut TaskContext<'_>, _: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for ControlledIo {
    fn poll_write(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let mut state = self.0.lock().unwrap();
        assert!(!state.shutdown, "write after shutdown");
        if state.fail_write {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "injected write failure")));
        }
        if state.budget == 0 {
            state.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = data.len().min(state.budget);
        state.bytes.extend_from_slice(&data[..n]);
        state.budget -= n;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.lock().unwrap();
        if state.fail_flush {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "injected flush failure")));
        }
        if state.flush_blocked {
            state.write_waker = Some(cx.waker().clone());
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.0.lock().unwrap().shutdown = true;
        Poll::Ready(Ok(()))
    }
}

fn target() -> Address {
    ("example.test".to_owned(), 443).into()
}

fn request(payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    target().write_to_buf(&mut bytes);
    bytes.extend_from_slice(payload);
    bytes
}

fn controlled_client(budget: usize) -> (ProxyClientStream<ControlledIo>, Arc<Mutex<TransportState>>) {
    let state = Arc::new(Mutex::new(TransportState { budget, ..Default::default() }));
    let cfg = ServerConfig::new(("127.0.0.1", 8388), "".to_owned(), CipherKind::NONE).unwrap();
    let client = ProxyClientStream::from_stream(
        Context::new_shared(ServerType::Local), ControlledIo(state.clone()), &cfg, target(),
    );
    (client, state)
}

fn release(state: &Mutex<TransportState>) {
    let wake = {
        let mut state = state.lock().unwrap();
        state.budget = usize::MAX;
        state.flush_blocked = false;
        state.write_waker.take()
    };
    if let Some(wake) = wake { wake.wake(); }
}

#[test]
fn idle_flush_preserves_header_and_payload_coalescing() {
    let (mut client, state) = controlled_client(usize::MAX);
    let wake = noop_waker();
    let mut cx = TaskContext::from_waker(&wake);
    assert!(matches!(Pin::new(&mut client).poll_flush(&mut cx), Poll::Ready(Ok(()))));
    assert!(state.lock().unwrap().bytes.is_empty());
    assert!(matches!(Pin::new(&mut client).poll_write(&mut cx, b"request"), Poll::Ready(Ok(7))));
    assert_eq!(state.lock().unwrap().bytes, request(b"request"));
}

#[test]
fn flush_drains_pending_request_and_preserves_write_completion() {
    for payload in [&b""[..], &b"request"[..]] {
        let (mut client, state) = controlled_client(1);
        let wake = noop_waker();
        let mut cx = TaskContext::from_waker(&wake);
        assert!(Pin::new(&mut client).poll_write(&mut cx, payload).is_pending());
        assert!(Pin::new(&mut client).poll_flush(&mut cx).is_pending());
        release(&state);
        assert!(matches!(Pin::new(&mut client).poll_flush(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(state.lock().unwrap().bytes, request(payload));
        if !payload.is_empty() {
            assert!(matches!(Pin::new(&mut client).poll_write(&mut cx, payload), Poll::Ready(Ok(7))));
            assert_eq!(state.lock().unwrap().bytes, request(payload));
        }
    }
}

#[test]
fn shutdown_drains_pending_request_before_closing_transport() {
    for payload in [&b""[..], &b"request"[..]] {
        let (mut client, state) = controlled_client(1);
        let wake = noop_waker();
        let mut cx = TaskContext::from_waker(&wake);
        assert!(Pin::new(&mut client).poll_write(&mut cx, payload).is_pending());
        assert!(Pin::new(&mut client).poll_shutdown(&mut cx).is_pending());
        assert!(!state.lock().unwrap().shutdown);
        release(&state);
        assert!(matches!(Pin::new(&mut client).poll_shutdown(&mut cx), Poll::Ready(Ok(()))));
        let state = state.lock().unwrap();
        assert!(state.shutdown);
        assert_eq!(state.bytes, request(payload));
    }
}

#[test]
fn poll_handshake_drains_partial_write_and_flush_without_resending() {
    let (mut client, state) = controlled_client(1);
    state.lock().unwrap().flush_blocked = true;
    let wake = noop_waker();
    let mut cx = TaskContext::from_waker(&wake);

    assert!(client.needs_handshake());
    assert!(Pin::new(&mut client).poll_handshake(&mut cx).is_pending());
    assert_eq!(state.lock().unwrap().bytes.len(), 1);

    // Finish writing header; flush still blocks completion.
    state.lock().unwrap().budget = usize::MAX;
    assert!(Pin::new(&mut client).poll_handshake(&mut cx).is_pending());
    assert_eq!(state.lock().unwrap().bytes, request(b""));
    assert!(!client.needs_handshake());

    // Release flush to complete the handshake.
    state.lock().unwrap().flush_blocked = false;
    assert!(matches!(Pin::new(&mut client).poll_handshake(&mut cx), Poll::Ready(Ok(()))));

    // Re-calling poll_handshake does not resend the header.
    assert!(matches!(Pin::new(&mut client).poll_handshake(&mut cx), Poll::Ready(Ok(()))));
    assert_eq!(state.lock().unwrap().bytes, request(b""));
}

#[test]
fn poll_handshake_propagates_write_and_flush_errors() {
    for fail_flush in [false, true] {
        let (mut client, state) = controlled_client(if fail_flush { usize::MAX } else { 1 });
        state.lock().unwrap().flush_blocked = fail_flush;
        let wake = noop_waker();
        let mut cx = TaskContext::from_waker(&wake);
        assert!(Pin::new(&mut client).poll_handshake(&mut cx).is_pending());
        {
            let mut state = state.lock().unwrap();
            state.fail_flush = fail_flush;
            state.fail_write = !fail_flush;
        }
        let result = Pin::new(&mut client).poll_handshake(&mut cx);
        assert!(matches!(result, Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe));
    }
}

#[test]
fn poll_read_before_write_does_not_split_header_and_coalesces_first_write() {
    let (mut client, state) = controlled_client(usize::MAX);
    let wake = noop_waker();
    let mut cx = TaskContext::from_waker(&wake);
    let mut storage = [0; 1];

    // Reading early must not emit the Shadowsocks header by itself.
    assert!(Pin::new(&mut client).poll_read(&mut cx, &mut ReadBuf::new(&mut storage)).is_pending());
    assert!(state.lock().unwrap().bytes.is_empty());

    // First write coalesces header + payload in one flight.
    assert!(matches!(Pin::new(&mut client).poll_write(&mut cx, b"GET /"), Poll::Ready(Ok(5))));
    assert_eq!(state.lock().unwrap().bytes, request(b"GET /"));
}

async fn half_close_allows_response(method: CipherKind, password: &str) {
    let cfg = ServerConfig::new(("127.0.0.1", 8388), password.to_owned(), method).unwrap();
    let (client_io, server_io) = duplex(128);
    let mut client = ProxyClientStream::from_stream(
        Context::new_shared(ServerType::Local), client_io, &cfg, target(),
    );
    let mut server = ProxyServerStream::from_stream(
        Context::new_shared(ServerType::Server), server_io, method, cfg.key(),
    );
    let send = async {
        client.shutdown().await?;
        let mut response = Vec::new();
        client.read_to_end(&mut response).await?;
        assert_eq!(response, b"hello");
        Ok::<(), io::Error>(())
    };
    let receive = async {
        assert_eq!(server.handshake().await?, target());
        let mut request = Vec::new();
        server.read_to_end(&mut request).await?;
        assert!(request.is_empty());
        server.write_all(b"hello").await?;
        server.shutdown().await
    };
    let (sent, received) = timeout(Duration::from_secs(5), async {
        tokio::join!(send, receive)
    }).await.expect("half-closed relay stalled");
    sent.unwrap();
    received.unwrap();
}

#[tokio::test]
async fn plain_half_close_allows_response() {
    half_close_allows_response(CipherKind::NONE, "").await;
}

#[cfg(feature = "aead-cipher")]
#[tokio::test]
async fn aead_half_close_allows_response() {
    half_close_allows_response(CipherKind::AES_256_GCM, "test-password").await;
}

#[cfg(feature = "aead-cipher-2022")]
#[tokio::test]
async fn aead2022_half_close_allows_response() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    half_close_allows_response(CipherKind::AEAD2022_BLAKE3_AES_256_GCM, &STANDARD.encode([7; 32])).await;
}
