use super::*;
use crate::proxy::{
    AnyStream,
    anytls::{padding::PaddingFactory, session::AnyTlsClientSession},
};
use futures::future::join_all;
use tokio::{spawn, time::{Duration, timeout}};

async fn echo(
    _dest: SocksAddr,
    mut stream: DuplexStream,
    cancel: CancellationToken,
) {
    let mut buffer = vec![0u8; 8192];
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            result = stream.read(&mut buffer) => {
                let n = result.unwrap();
                if n == 0 {
                    return;
                }
                stream.write_all(&buffer[..n]).await.unwrap();
            }
        }
    }
}

async fn send(writer: &mut DuplexStream, frames: &[Frame]) {
    let mut buffer = BytesMut::new();
    for frame in frames {
        frame.encode_into(&mut buffer);
    }
    writer.write_all(&buffer).await.unwrap();
}

fn open_frames(id: u32, payload: &[u8]) -> [Frame; 2] {
    let dest = SocksAddr::try_from(("example.com".to_owned(), 80)).unwrap();
    let mut buffer = BytesMut::new();
    dest.write_buf(&mut buffer);
    buffer.extend_from_slice(payload);
    [Frame::control(Command::Syn, id), Frame::data(id, buffer.freeze())]
}

async fn read_data(reader: &mut FrameReader<DuplexStream>) -> Frame {
    loop {
        let frame = reader.read().await.unwrap().unwrap();
        if frame.cmd == Command::Psh {
            return frame;
        }
    }
}

#[tokio::test]
async fn multiplexed_streams_survive_fin_and_reuse_session() {
    timeout(Duration::from_secs(5), async {
        let (mut client, server) = duplex(65536);
        let server = spawn(run_session(server, echo));
        send(&mut client, &open_frames(1, b"first")).await;
        send(&mut client, &open_frames(2, b"second")).await;
        let mut reader = FrameReader::new(client);
        let mut responses = HashMap::new();
        for _ in 0..2 {
            let frame = read_data(&mut reader).await;
            responses.insert(frame.stream_id, frame.data);
        }
        assert_eq!(&responses[&1][..], b"first");
        assert_eq!(&responses[&2][..], b"second");

        send(&mut reader.reader, &[
            Frame::control(Command::Fin, 1),
            Frame::data(2, Bytes::from_static(b"still alive")),
        ]).await;
        send(&mut reader.reader, &open_frames(3, b"reused")).await;
        responses.clear();
        for _ in 0..2 {
            let frame = read_data(&mut reader).await;
            responses.insert(frame.stream_id, frame.data);
        }
        assert_eq!(&responses[&2][..], b"still alive");
        assert_eq!(&responses[&3][..], b"reused");
        send(&mut reader.reader, &[Frame::control(Command::HeartRequest, 0)]).await;
        let frame = reader.read().await.unwrap().unwrap();
        assert_eq!(frame.cmd, Command::HeartResponse);
        drop(reader);
        server.await.unwrap().unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn server_fin_drains_response_and_keeps_session_open() {
    timeout(Duration::from_secs(5), async {
        let (mut client, server) = duplex(65536);
        let respond = |_, mut app: DuplexStream, cancel: CancellationToken| async move {

            let response = vec![b'x'; 100_000];
            tokio::select! {
                _ = cancel.cancelled() => {},
                result = app.write_all(&response) => result.unwrap(),
            }
        };
        let server = spawn(run_session(server, respond));
        send(&mut client, &open_frames(1, b"")).await;
        let mut reader = FrameReader::new(client);
        let mut received = 0;
        loop {
            let frame = reader.read().await.unwrap().unwrap();
            match frame.cmd {
                Command::Psh => {
                    assert!(frame.data.iter().all(|byte| *byte == b'x'));
                    received += frame.data.len();
                }
                Command::Fin => break,
                _ => {}
            }
        }
        assert_eq!(received, 100_000);
        send(&mut reader.reader, &open_frames(2, b"")).await;
        let mut received = 0;
        loop {
            let frame = reader.read().await.unwrap().unwrap();
            assert_eq!(frame.stream_id, 2);
            match frame.cmd {
                Command::Psh => received += frame.data.len(),
                Command::Fin => break,
                _ => panic!("unexpected response frame"),
            }
        }
        assert_eq!(received, 100_000);
        drop(reader);
        server.await.unwrap().unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn outbound_interoperates_with_multiplexed_inbound() {
    timeout(Duration::from_secs(10), async {
        let (client, mut server) = duplex(65536);
        let server = spawn(async move {
            let mut hash = [0u8; 32];
            server.read_exact(&mut hash).await.unwrap();
            let padding_len = server.read_u16().await.unwrap() as usize;
            let mut padding = vec![0u8; padding_len];
            server.read_exact(&mut padding).await.unwrap();
            run_session(server, echo).await.unwrap();
        });
        let session = AnyTlsClientSession::new(
            AnyStream::new(client),
            "test-password",
            PaddingFactory::default_factory(),
        ).await.unwrap();
        let mut requests = Vec::new();
        for index in 0..8 {
            let session = session.clone();
            requests.push(spawn(async move {
                let dest = SocksAddr::try_from(("example.com".to_owned(), 80))
                    .unwrap();
                let mut stream = session.open_stream(&dest).await.unwrap();
                let payload = vec![index; 100_000];
                stream.write_all(&payload).await.unwrap();
                let mut response = vec![0u8; payload.len()];
                stream.read_exact(&mut response).await.unwrap();
                assert_eq!(response, payload);
                stream.shutdown().await.unwrap();
            }));
        }
        for result in join_all(requests).await {
            result.unwrap();
        }
        session.mark_closed();
        drop(session);
        server.await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn disconnect_cancels_active_streams() {
    timeout(Duration::from_secs(5), async {
        let (mut client, server) = duplex(65536);
        let (opened, mut opened_rx) = mpsc::channel(1);
        let server = spawn(run_session(server, move |dest, app, cancel| {
            let opened = opened.clone();
            async move {
                opened.send(cancel.clone()).await.unwrap();
                echo(dest, app, cancel).await;
            }
        }));
        send(&mut client, &open_frames(1, b"")).await;
        let cancel = opened_rx.recv().await.unwrap();
        drop(client);
        server.await.unwrap().unwrap();
        cancel.cancelled().await;
    }).await.unwrap();
}

#[tokio::test]
async fn frame_reader_preserves_partial_frame_across_cancellation() {
    let (mut client, server) = duplex(4096);
    let mut reader = FrameReader::new(server);
    let mut encoded = BytesMut::new();
    Frame::data(1, Bytes::from_static(b"partial")).encode_into(&mut encoded);
    client.write_all(&encoded[..4]).await.unwrap();
    assert!(timeout(Duration::from_millis(10), reader.read()).await.is_err());
    client.write_all(&encoded[4..]).await.unwrap();
    let frame = reader.read().await.unwrap().unwrap();
    assert_eq!(frame.stream_id, 1);
    assert_eq!(&frame.data[..], b"partial");
}

#[tokio::test]
async fn tcp_and_udp_share_session_with_independent_lifetimes() {
    use crate::proxy::{
        anytls::inbound::datagram::InboundDatagramAnytls,
        transport::uot::{UDP_OVER_TCP_V2_MAGIC_HOST, encode_uot_connect_request},
    };
    use futures::{SinkExt, StreamExt};

    timeout(Duration::from_secs(5), async {
        let (client, mut server) = duplex(65536);
        let server = spawn(async move {
            let mut hash = [0u8; 32];
            server.read_exact(&mut hash).await.unwrap();
            let padding_len = server.read_u16().await.unwrap() as usize;
            let mut padding = vec![0u8; padding_len];
            server.read_exact(&mut padding).await.unwrap();
            run_session(server, |dest, mut app, cancel| async move {
                if dest.host() != UDP_OVER_TCP_V2_MAGIC_HOST {
                    echo(dest, app, cancel).await;
                    return;
                }
                assert_eq!(app.read_u8().await.unwrap(), 1);
                let dest = SocksAddr::read_from(&mut app).await.unwrap();
                let mut datagram = InboundDatagramAnytls::new(
                    AnyStream::new(app), dest,
                );
                loop {
                    let packet = tokio::select! {
                        _ = cancel.cancelled() => return,
                        packet = datagram.next() => match packet {
                            Some(packet) => packet,
                            None => return,
                        }
                    };
                    datagram.send(packet).await.unwrap();
                }
            }).await.unwrap();
        });
        let session = AnyTlsClientSession::new(
            AnyStream::new(client),
            "test-password",
            PaddingFactory::default_factory(),
        ).await.unwrap();
        let dest = SocksAddr::try_from(("example.com".to_owned(), 53)).unwrap();
        let mut tcp = session.open_stream(&dest).await.unwrap();
        let magic = SocksAddr::try_from((UDP_OVER_TCP_V2_MAGIC_HOST.to_owned(), 0))
            .unwrap();
        let mut udp = session.open_stream(&magic).await.unwrap();
        udp.write_all(&encode_uot_connect_request(&dest)).await.unwrap();
        tcp.write_all(b"tcp").await.unwrap();
        let mut response = [0u8; 3];
        tcp.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"tcp");
        tcp.shutdown().await.unwrap();
        for payload in [b"first".as_slice(), b"second".as_slice()] {
            udp.write_u16(payload.len() as u16).await.unwrap();
            udp.write_all(payload).await.unwrap();
            assert_eq!(udp.read_u16().await.unwrap() as usize, payload.len());
            let mut response = vec![0u8; payload.len()];
            udp.read_exact(&mut response).await.unwrap();
            assert_eq!(response, payload);
        }
        udp.shutdown().await.unwrap();
        drop(tcp);
        drop(udp);
        session.mark_closed();
        drop(session);
        server.await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn early_target_close_preserves_response_during_upload() {
    timeout(Duration::from_secs(5), async {
        let (mut client, server) = duplex(65536);
        let server = spawn(run_session(server, |_, mut app, cancel| async move {
            let response = vec![b'r'; 100_000];
            tokio::select! {
                _ = cancel.cancelled() => {},
                result = app.write_all(&response) => result.unwrap(),
            }
        }));
        send(&mut client, &open_frames(1, &vec![b'q'; 60_000])).await;
        send(&mut client, &[Frame::data(1, Bytes::from(vec![b'q'; 60_000]))]).await;
        let mut reader = FrameReader::new(client);
        let mut received = 0;
        loop {
            let frame = reader.read().await.unwrap().unwrap();
            match frame.cmd {
                Command::Psh => {
                    assert!(frame.data.iter().all(|byte| *byte == b'r'));
                    received += frame.data.len();
                }
                Command::Fin => break,
                _ => {}
            }
        }
        assert_eq!(received, 100_000);
        drop(reader);
        server.await.unwrap().unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn inbound_small_frame_uses_one_tls_record() {
    use crate::proxy::anytls::tls_records_tests::{
        TlsPair, assert_single_application_record, tls_pair,
    };
    let TlsPair { mut client, server, server_writes, .. } = tls_pair().await;
    let (sender, receiver) = mpsc::channel(1);
    sender.send(Frame::data(1, Bytes::from_static(b"hello"))).await.unwrap();
    drop(sender);
    let writer = spawn(write_frames(server, receiver));
    let mut frame = [0u8; 12];
    client.read_exact(&mut frame).await.unwrap();
    assert_eq!(&frame[..7], &[2, 0, 0, 0, 1, 0, 5]);
    assert_eq!(&frame[7..], b"hello");
    writer.await.unwrap().unwrap();
    assert_single_application_record(&server_writes);
}
