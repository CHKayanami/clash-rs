use super::{make_handler, read_frame_raw};
use bytes::{Bytes, BytesMut};
use crate::{
    app::{dns::{MockClashResolver, ThreadSafeDNSResolver}, net::OutboundInterface},
    proxy::{
        AnyOutboundDatagram, AnyStream, OutboundHandler,
        datagram::UdpPacket,
        anytls::{
            padding::PaddingFactory, session::AnyTlsClientSession,
            types::{Command, Frame},
        },
        transport::uot::{encode_uot_packet_request, UDP_OVER_TCP_V2_MAGIC_HOST},
        utils::RemoteConnector,
    },
    session::{Session, SocksAddr},
};
use futures::{SinkExt, StreamExt, future::join_all};
use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    sync::{Arc, atomic::{AtomicUsize, Ordering}},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, duplex},
    spawn,
    sync::Barrier,
    time::{Duration, sleep, timeout},
};

#[derive(Debug, Default)]
pub struct CountingConnector {
    dials: AtomicUsize,
}

async fn consume_auth(stream: &mut (impl AsyncReadExt + Unpin)) {
    let mut hash = [0u8; 32];
    stream.read_exact(&mut hash).await.unwrap();
    let length = stream.read_u16().await.unwrap() as usize;
    let mut padding = vec![0u8; length];
    stream.read_exact(&mut padding).await.unwrap();
}

impl CountingConnector {
    pub async fn connect_stream(
        &self,
        _resolver: ThreadSafeDNSResolver,
        _address: &str,
        _port: u16,
        _tfo: bool,
        _iface: Option<&Arc<OutboundInterface>>,
        #[cfg(target_os = "linux")] _packet_mark: Option<u32>,
    ) -> io::Result<AnyStream> {
        self.dials.fetch_add(1, Ordering::Relaxed);
        // Keep the dial pending while the other broken-stream retries arrive.
        sleep(Duration::from_millis(20)).await;
        let (client, mut server) = duplex(65536);
        spawn(async move {
            consume_auth(&mut server).await;
            let mut buffer = [0u8; 8192];
            while server.read(&mut buffer).await.is_ok_and(|n| n > 0) {}
        });
        Ok(AnyStream::new(client))
    }

    pub async fn connect_datagram(
        &self,
        _resolver: ThreadSafeDNSResolver,
        _src: Option<SocketAddr>,
        _destination: SocksAddr,
        _iface: Option<&Arc<OutboundInterface>>,
        #[cfg(target_os = "linux")] _packet_mark: Option<u32>,
    ) -> io::Result<AnyOutboundDatagram> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported, "stream-only test connector",
        ))
    }
}

#[tokio::test]
async fn concurrent_broken_session_retries_share_one_dial() {
    timeout(Duration::from_secs(5), async {
        let handler = Arc::new(make_handler(false, false));
        let (client, mut server) = duplex(65536);
        let stale = AnyTlsClientSession::new(AnyStream::new(client), "secret",
            PaddingFactory::default_factory()).await.unwrap();
        stale.set_peer_version(2);
        handler.session_pool.add_session(stale).await;
        let server = spawn(async move {
            consume_auth(&mut server).await;
            let mut streams = 0;
            while streams < 8 {
                let (command, _, _) = read_frame_raw(&mut server).await;
                if command == Command::Syn as u8 {
                    streams += 1;
                }
            }
            // Break the transport with all eight open_stream calls awaiting ACK.
        });
        let resolver: ThreadSafeDNSResolver = Arc::new(MockClashResolver::new());
        let connector = Arc::new(CountingConnector::default());
        let start = Arc::new(Barrier::new(8));
        let mut requests = Vec::new();
        for _ in 0..8 {
            let handler = handler.clone();
            let resolver = resolver.clone();
            let connector = connector.clone();
            let start = start.clone();
            requests.push(spawn(async move {
                let sess = Session {
                    destination: SocksAddr::try_from(("example.com".to_owned(), 80))
                        .unwrap(),
                    ..Default::default()
                };
                start.wait().await;
                handler.open_stream_with_retry(resolver, &RemoteConnector::Counting(connector.clone()),
                    &sess, &sess.destination).await.unwrap()
            }));
        }
        let results = join_all(requests).await;
        let streams: Vec<_> = results.into_iter().map(Result::unwrap).collect();
        assert_eq!(connector.dials.load(Ordering::Relaxed), 1);
        assert_eq!(streams.len(), 8);
        server.await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn udp_first_packet_precedes_v2_stream_ack() {
    udp_first_packet_ack(false).await;
}

#[tokio::test]
async fn udp_late_stream_rejection_is_reported() {
    udp_first_packet_ack(true).await;
}

async fn udp_first_packet_ack(reject: bool) {
    timeout(Duration::from_secs(2), async {
        let handler = make_handler(true, false);
        let (client, mut server) = duplex(65536);
        let session = AnyTlsClientSession::new(
            AnyStream::new(client), "secret", PaddingFactory::default_factory(),
        ).await.unwrap();
        session.set_peer_version(2);
        handler.session_pool.add_session(session).await;
        let server = spawn(async move {
            consume_auth(&mut server).await;
            let dest = SocksAddr::domain_name(UDP_OVER_TCP_V2_MAGIC_HOST, 0);
            let mut expected = BytesMut::new();
            dest.write_buf(&mut expected);
            let target = "192.0.2.1:53".parse().unwrap();
            expected.extend_from_slice(&encode_uot_packet_request(&target));
            let stream_id = loop {
                let (command, id, data) = read_frame_raw(&mut server).await;
                if command == Command::Psh as u8 {
                    // Read UoT setup before routing the UDP connection.
                    assert_eq!(data, expected.as_ref());
                    break id;
                }
            };
            let mut expected_packet = vec![0, 192, 0, 2, 1, 0, 53, 0, 8];
            expected_packet.extend_from_slice(b"dns-test");
            let mut packet = Vec::new();
            let mut packet_frames = 0;
            loop {
                let (command, id, data) = read_frame_raw(&mut server).await;
                if command == Command::Psh as u8 {
                    assert_eq!(id, stream_id);
                    packet_frames += 1;
                    packet.extend_from_slice(&data);
                    assert!(packet.len() <= expected_packet.len());
                    assert_eq!(packet, expected_packet[..packet.len()]);
                    if packet.len() < expected_packet.len() { continue; }
                    assert_eq!(packet_frames, 1, "small UDP packet must use one PSH");
                    // sing-box can sniff the first datagram before opening its
                    // outbound and reporting handshake success.
                    let mut reply = BytesMut::new();
                    if reject {
                        Frame::with_data(Command::SynAck, id,
                            Bytes::from_static(b"UDP route rejected"),
                        ).encode_into(&mut reply);
                    } else {
                        Frame::control(Command::SynAck, stream_id).encode_into(&mut reply);
                        Frame::with_data(Command::Psh, id, Bytes::from(packet))
                            .encode_into(&mut reply);
                    }
                    server.write_all(&reply).await.unwrap();
                    break;
                }
            }
        });
        let sess = Session {
            destination: "192.0.2.1:53".parse().unwrap(),
            ..Default::default()
        };
        let resolver: ThreadSafeDNSResolver = Arc::new(MockClashResolver::new());
        let datagram = handler.connect_datagram_with_connector(
            &sess, resolver, &RemoteConnector::Counting(Arc::new(
                CountingConnector::default(),
            )),
        ).await.unwrap();
        let read_error = datagram.read_error_handle().unwrap();
        let (mut sink, mut stream) = datagram.split();
        sink.send(UdpPacket::new(
            Bytes::from_static(b"dns-test"), SocksAddr::any_ipv4(),
            sess.destination.clone(),
        )).await.unwrap();
        if reject {
            assert!(stream.next().await.is_none());
            let error = read_error.get().unwrap();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
            assert!(error.to_string().contains("UDP route rejected"));
            assert!(sink.send(UdpPacket::new(
                Bytes::from_static(b"retry"), SocksAddr::any_ipv4(),
                sess.destination.clone(),
            )).await.is_err());
        } else {
            let reply = stream.next().await.unwrap();
            assert_eq!(reply.data, Bytes::from_static(b"dns-test"));
        }
        server.await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn vectored_writes_preserve_frame_limit_and_unwritten_suffix() {
    timeout(Duration::from_secs(2), async {
        let (client, mut server) = duplex(131072);
        let session = AnyTlsClientSession::new(
            AnyStream::new(client), "secret", PaddingFactory::default_factory(),
        ).await.unwrap();
        let dest = SocksAddr::domain_name("example.test", 80);
        let mut stream = session.open_stream(&dest).await.unwrap();
        consume_auth(&mut server).await;
        loop {
            let (command, _, _) = read_frame_raw(&mut server).await;
            if command == Command::Psh as u8 { break; }
        }
        let prefix = vec![42; 65530];
        let suffix = b"remaining-bytes";
        let written = stream.write_vectored(&[
            IoSlice::new(&[]), IoSlice::new(&prefix), IoSlice::new(suffix),
        ]).await.unwrap();
        assert_eq!(written, 65535);
        stream.write_all(&suffix[5..]).await.unwrap();
        let mut frames = Vec::new();
        while frames.len() < 2 {
            let (command, _, data) = read_frame_raw(&mut server).await;
            if command == Command::Psh as u8 { frames.push(data); }
        }
        assert_eq!(frames[0].len(), 65535);
        assert_eq!(&frames[0][..65530], prefix);
        assert_eq!(&frames[0][65530..], &suffix[..5]);
        assert_eq!(frames[1], suffix[5..]);
    }).await.unwrap();
}
