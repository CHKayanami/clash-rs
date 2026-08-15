use bytes::Bytes;
use http::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{pool::H2MuxPool, protocol::*, session::H2MuxSession};
use crate::{
    proxy::{AnyStream, transport::mux::MuxOption},
    session::SocksAddr,
};

#[test]
fn test_mux_option_validation() {
    use crate::proxy::transport::mux::MuxProtocol;

    let opt_h2 = MuxOption {
        enable: true,
        protocol: MuxProtocol::H2Mux,
        ..Default::default()
    };
    assert!(opt_h2.validate().is_ok());

    let opt_smux = MuxOption {
        enable: true,
        protocol: MuxProtocol::Smux,
        ..Default::default()
    };
    assert!(opt_smux.validate().is_err());

    let opt_yamux = MuxOption {
        enable: true,
        protocol: MuxProtocol::Yamux,
        ..Default::default()
    };
    assert!(opt_yamux.validate().is_err());
}

#[test]
fn test_stream_request_encoding() {
    let req_ip = StreamRequest::new(SocksAddr::Ip("1.2.3.4:80".parse().unwrap()), false);
    let bytes_ip = req_ip.encode().unwrap();
    assert_eq!(&bytes_ip[..3], &[0x00, 0x00, 0x01]); // flags=0, type=1 (ipv4)

    let req_domain = StreamRequest::new(SocksAddr::Domain("example.com".to_string(), 443), false);
    let bytes_domain = req_domain.encode().unwrap();
    assert_eq!(&bytes_domain[..4], &[0x00, 0x00, 0x03, 11]); // flags=0, type=3, len=11
}

#[tokio::test]
async fn test_h2mux_session_echo_and_concurrency() {
    let (client_io, mut server_io) = tokio::io::duplex(1024 * 1024);

    // Spawn mock sing-box H2Mux server
    tokio::spawn(async move {
        // 1. Read session request header (version + protocol)
        let version = server_io.read_u8().await.unwrap();
        let protocol = server_io.read_u8().await.unwrap();
        assert_eq!(protocol, PROTOCOL_H2MUX);
        if version == VERSION_1 {
            let padding = server_io.read_u8().await.unwrap();
            if padding != 0 {
                let pad_len = server_io.read_u16().await.unwrap();
                let mut pad = vec![0u8; pad_len as usize];
                server_io.read_exact(&mut pad).await.unwrap();
            }
        }

        // 2. HTTP/2 handshake
        let mut server = h2::server::handshake(server_io).await.unwrap();
        while let Some(Ok((req, mut respond))) = server.accept().await {
            assert_eq!(req.method(), http::Method::CONNECT);
            assert_eq!(
                req.uri().to_string(),
                format!("{MUX_DESTINATION_HOST}:{MUX_DESTINATION_PORT}")
            );

            tokio::spawn(async move {
                let response = Response::builder().status(200).body(()).unwrap();
                let mut send_stream = respond.send_response(response, false).unwrap();
                let mut recv_stream = req.into_body();

                // Send sing-box StreamResponse success (0x00)
                let _ = send_stream.send_data(Bytes::from_static(&[STATUS_SUCCESS]), false);

                let mut first_frame = true;
                while let Some(Ok(chunk)) = recv_stream.data().await {
                    let len = chunk.len();
                    let _ = recv_stream.flow_control().release_capacity(len);

                    if first_frame {
                        // Skip the stream request header (flags + address) in echo test
                        first_frame = false;
                        // Minimum StreamRequest size is 2 (flags) + 1 (addr type) + 4 (ipv4) + 2 (port) = 9
                        if chunk.len() > 9 {
                            let _ = send_stream.send_data(chunk.slice(9..), false);
                        }
                    } else {
                        let _ = send_stream.send_data(chunk, false);
                    }
                }
                let _ = send_stream.send_data(Bytes::new(), true);
            });
        }
    });

    let opt = MuxOption {
        enable: true,
        max_connections: 2,
        min_streams: 2,
        max_streams: 10,
        padding: false,
        ..Default::default()
    };

    let session = H2MuxSession::new(Box::new(client_io) as AnyStream, opt)
        .await
        .unwrap();

    let dst = SocksAddr::Ip("1.2.3.4:8080".parse().unwrap());

    // Test multiple concurrent streams
    let mut handles = Vec::new();
    for i in 0..5 {
        let session = session.clone();
        let dst = dst.clone();
        handles.push(tokio::spawn(async move {
            let mut stream = session.open_stream(&dst, false).await.unwrap();
            let msg = format!("hello h2mux stream {i}");
            stream.write_all(msg.as_bytes()).await.unwrap();

            let mut buf = vec![0u8; msg.len()];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(String::from_utf8(buf).unwrap(), msg);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn test_h2mux_pool_dispatch() {
    let opt = MuxOption {
        enable: true,
        max_connections: 2,
        min_streams: 2,
        max_streams: 4,
        padding: false,
        ..Default::default()
    };

    let pool = H2MuxPool::new(opt);

    let dialer = || async {
        let (client_io, mut server_io) = tokio::io::duplex(1024 * 1024);
        tokio::spawn(async move {
            let _version = server_io.read_u8().await.unwrap();
            let _protocol = server_io.read_u8().await.unwrap();
            let mut server = h2::server::handshake(server_io).await.unwrap();
            while let Some(Ok((req, mut respond))) = server.accept().await {
                tokio::spawn(async move {
                    let response = Response::builder().status(200).body(()).unwrap();
                    let mut send_stream = respond.send_response(response, false).unwrap();
                    let mut recv_stream = req.into_body();

                    let _ = send_stream.send_data(Bytes::from_static(&[STATUS_SUCCESS]), false);

                    let mut first = true;
                    while let Some(Ok(chunk)) = recv_stream.data().await {
                        let len = chunk.len();
                        let _ = recv_stream.flow_control().release_capacity(len);
                        if first {
                            first = false;
                            if chunk.len() > 9 {
                                let _ = send_stream.send_data(chunk.slice(9..), false);
                            }
                        } else {
                            let _ = send_stream.send_data(chunk, false);
                        }
                    }
                    let _ = send_stream.send_data(Bytes::new(), true);
                });
            }
        });
        Ok(Box::new(client_io) as AnyStream)
    };

    let dst = SocksAddr::Ip("1.2.3.4:9000".parse().unwrap());

    let mut stream1 = pool.open_stream(&dst, false, dialer).await.unwrap();
    stream1.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    stream1.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    let mut stream2 = pool.open_stream(&dst, false, dialer).await.unwrap();
    stream2.write_all(b"pong").await.unwrap();
    let mut buf2 = [0u8; 4];
    stream2.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, b"pong");
}
