use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::session::Session;

pub(crate) fn build_tls_client_hello(server_name: &str) -> Vec<u8> {
    let name_bytes = server_name.as_bytes();
    let sni_ext_len = 2 + 1 + 2 + name_bytes.len();
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&0x0000u16.to_be_bytes()); // Ext Type: server_name
    sni_ext.extend_from_slice(&(sni_ext_len as u16).to_be_bytes()); // Ext Len
    sni_ext.extend_from_slice(&((name_bytes.len() + 3) as u16).to_be_bytes()); // ServerNameList Len
    sni_ext.push(0x00); // HostName Type
    sni_ext.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes()); // HostName Len
    sni_ext.extend_from_slice(name_bytes);

    let extensions_len = sni_ext.len();
    let mut client_hello = Vec::new();
    client_hello.push(0x01); // Handshake Type: ClientHello
    let handshake_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensions_len;
    client_hello.push((handshake_len >> 16) as u8);
    client_hello.push((handshake_len >> 8) as u8);
    client_hello.push(handshake_len as u8);
    client_hello.extend_from_slice(&[0x03, 0x03]); // Version TLS 1.2
    client_hello.extend_from_slice(&[0xaa; 32]); // Random 32 bytes
    client_hello.push(0x00); // Session ID len 0
    client_hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // Cipher suites (len 2)
    client_hello.extend_from_slice(&[0x01, 0x00]); // Compression methods (len 1)
    client_hello.extend_from_slice(&(extensions_len as u16).to_be_bytes());
    client_hello.extend_from_slice(&sni_ext);

    let mut record = Vec::new();
    record.push(0x16); // ContentType: Handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record layer
    record.extend_from_slice(&(client_hello.len() as u16).to_be_bytes());
    record.extend_from_slice(&client_hello);
    record
}

#[test]
fn test_tls_sni_builder_and_parser() {
    let payload = build_tls_client_hello("www.rust-lang.org");
    let sni = tls::parse_tls_sni(&payload);
    assert_eq!(sni, Some("www.rust-lang.org".to_string()));

    let raw_handshake = &payload[5..];
    let handshake_sni = tls::parse_client_hello_handshake(raw_handshake);
    assert_eq!(handshake_sni, Some("www.rust-lang.org".to_string()));
}

#[test]
fn test_http_host_parser_various_methods() {
    let get_req =
        b"GET /index.html HTTP/1.1\r\nHost: example.org\r\nAccept: */*\r\n\r\n";
    assert_eq!(
        http::parse_http_host(get_req),
        Some("example.org".to_string())
    );

    let post_req = b"POST /submit HTTP/1.1\r\nHOST: sub.domain.com:8080\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(
        http::parse_http_host(post_req),
        Some("sub.domain.com".to_string())
    );

    let connect_req = b"CONNECT static.cloudflare.com:443 HTTP/1.1\r\nhost: static.cloudflare.com:443\r\n\r\n";
    assert_eq!(
        http::parse_http_host(connect_req),
        Some("static.cloudflare.com".to_string())
    );
}

#[tokio::test]
async fn test_sniffer_stream_tls() {
    let config = SnifferConfig {
        enable: true,
        override_destination: false,
        tls: Some(SniffProtocolConfig {
            ports: PortMatcher::new(vec![PortRange::Single(443)]),
            override_destination: None,
        }),
        ..Default::default()
    };
    let sniffer = Sniffer::new(config);

    let (client, mut server) = tokio::io::duplex(1024);
    let sample = build_tls_client_hello("crates.io");
    let sample_len = sample.len();

    tokio::spawn(async move {
        server.write_all(&sample).await.unwrap();
    });

    let sess = Session {
        destination: "1.1.1.1:443".parse().unwrap(),
        ..Default::default()
    };

    let (domain, mut stream, override_dest) =
        sniffer.sniff_stream(&sess, Box::new(client)).await;
    assert_eq!(domain, Some("crates.io".to_string()));
    assert!(!override_dest);

    // Verify stream still has the initial bytes
    let mut buf = vec![0u8; 10];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(
        &buf[0..5],
        &[0x16, 0x03, 0x01, 0x00, (sample_len - 5) as u8]
    );
}

#[tokio::test]
async fn test_sniffer_stream_http_with_override() {
    let config = SnifferConfig {
        enable: true,
        override_destination: false,
        http: Some(SniffProtocolConfig {
            ports: PortMatcher::new(vec![PortRange::Single(80)]),
            override_destination: Some(true),
        }),
        ..Default::default()
    };
    let sniffer = Sniffer::new(config);

    let (client, mut server) = tokio::io::duplex(1024);
    let req = b"GET / HTTP/1.1\r\nHost: mydomain.test\r\n\r\n";

    tokio::spawn(async move {
        server.write_all(req).await.unwrap();
    });

    let sess = Session {
        destination: "10.0.0.1:80".parse().unwrap(),
        ..Default::default()
    };

    let (domain, _stream, override_dest) =
        sniffer.sniff_stream(&sess, Box::new(client)).await;
    assert_eq!(domain, Some("mydomain.test".to_string()));
    assert!(override_dest);
}

#[tokio::test]
async fn test_sniffer_skip_domain() {
    let config = SnifferConfig {
        enable: true,
        skip_domains: vec!["+.apple.com".to_string()],
        tls: Some(SniffProtocolConfig {
            ports: PortMatcher::new(vec![PortRange::Single(443)]),
            override_destination: None,
        }),
        ..Default::default()
    };
    let sniffer = Sniffer::new(config);

    let (client, mut server) = tokio::io::duplex(1024);
    let sample = build_tls_client_hello("gateway.icloud.apple.com");

    tokio::spawn(async move {
        server.write_all(&sample).await.unwrap();
    });

    let sess = Session {
        destination: "17.0.0.1:443".parse().unwrap(),
        ..Default::default()
    };

    let (domain, _stream, _) = sniffer.sniff_stream(&sess, Box::new(client)).await;
    assert_eq!(domain, None);
}

#[test]
fn test_domain_matcher() {
    let config = SnifferConfig {
        enable: true,
        skip_domains: vec!["+.apple.com".to_string(), "Mijia Cloud".to_string()],
        force_domains: vec!["+.google.com".to_string()],
        ..Default::default()
    };
    let sniffer = Sniffer::new(config);

    assert!(sniffer.is_domain_skipped("gateway.icloud.apple.com"));
    assert!(sniffer.is_domain_skipped("apple.com"));
    assert!(!sniffer.is_domain_skipped("google.com"));

    assert!(
        sniffer.matches_domain_list("www.google.com", &sniffer.config.force_domains)
    );
}

#[test]
fn test_port_matcher() {
    let matcher =
        PortMatcher::new(vec![PortRange::Single(80), PortRange::Range(8080, 8088)]);
    assert!(matcher.contains(80));
    assert!(matcher.contains(8080));
    assert!(matcher.contains(8085));
    assert!(matcher.contains(8088));
    assert!(!matcher.contains(443));
    assert!(!matcher.contains(8089));
}

#[tokio::test]
async fn test_sniffer_parse_pure_ip_disabled() {
    let config = SnifferConfig {
        enable: true,
        parse_pure_ip: false,
        tls: Some(SniffProtocolConfig {
            ports: PortMatcher::new(vec![PortRange::Single(443)]),
            override_destination: None,
        }),
        ..Default::default()
    };
    let sniffer = Sniffer::new(config);

    let (client, mut server) = tokio::io::duplex(1024);
    let sample = build_tls_client_hello("example.com");

    tokio::spawn(async move {
        server.write_all(&sample).await.unwrap();
    });

    let sess = Session {
        destination: "93.184.216.34:443".parse().unwrap(),
        ..Default::default()
    };

    let (domain, _stream, _) = sniffer.sniff_stream(&sess, Box::new(client)).await;
    assert_eq!(domain, None);
}

#[tokio::test]
async fn test_sniffer_stream_tls_fragmented() {
    let config = SnifferConfig {
        enable: true,
        tls: Some(SniffProtocolConfig {
            ports: PortMatcher::new(vec![PortRange::Single(443)]),
            override_destination: None,
        }),
        ..Default::default()
    };
    let sniffer = Sniffer::new(config);

    let (client, mut server) = tokio::io::duplex(1024);
    let sample = build_tls_client_hello("fragmented.rust-lang.org");
    let sample_clone = sample.clone();

    tokio::spawn(async move {
        // Send in tiny chunks to test fragmented streaming reassembly
        for chunk in sample_clone.chunks(5) {
            server.write_all(chunk).await.unwrap();
            tokio::task::yield_now().await;
        }
    });

    let sess = Session {
        destination: "1.1.1.1:443".parse().unwrap(),
        ..Default::default()
    };

    let (domain, mut stream, _) =
        sniffer.sniff_stream(&sess, Box::new(client)).await;
    assert_eq!(domain, Some("fragmented.rust-lang.org".to_string()));

    let mut all_bytes = Vec::new();
    stream.read_to_end(&mut all_bytes).await.unwrap();
    assert_eq!(all_bytes, sample);
}

#[tokio::test]
async fn test_sniffer_stream_http_fragmented() {
    let config = SnifferConfig {
        enable: true,
        http: Some(SniffProtocolConfig {
            ports: PortMatcher::new(vec![PortRange::Single(80)]),
            override_destination: None,
        }),
        ..Default::default()
    };
    let sniffer = Sniffer::new(config);

    let (client, mut server) = tokio::io::duplex(1024);
    let req = b"GET /index.html HTTP/1.1\r\nHost: fragmented-http.org\r\nUser-Agent: test\r\n\r\n";

    tokio::spawn(async move {
        for chunk in req.chunks(4) {
            server.write_all(chunk).await.unwrap();
            tokio::task::yield_now().await;
        }
    });

    let sess = Session {
        destination: "1.2.3.4:80".parse().unwrap(),
        ..Default::default()
    };

    let (domain, mut stream, _) =
        sniffer.sniff_stream(&sess, Box::new(client)).await;
    assert_eq!(domain, Some("fragmented-http.org".to_string()));

    let mut all_bytes = Vec::new();
    stream.read_to_end(&mut all_bytes).await.unwrap();
    assert_eq!(all_bytes, req);
}

#[tokio::test]
async fn test_sniffer_tcp_negative_cache() {
    let config = SnifferConfig {
        enable: true,
        tls: Some(SniffProtocolConfig {
            ports: PortMatcher::new(vec![PortRange::Single(443)]),
            override_destination: None,
        }),
        ..Default::default()
    };
    let sniffer = Sniffer::new(config.clone());
    let target_addr: std::net::SocketAddr = "192.168.1.100:443".parse().unwrap();
    let sess = Session {
        destination: SocksAddr::Ip(target_addr),
        ..Default::default()
    };

    // 1. Fail 3 times with garbage non-TLS data
    for _ in 0..3 {
        let (client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            server.write_all(b"SSH-2.0-OpenSSH_8.9\r\n").await.unwrap();
        });
        let (domain, _, _) = sniffer.sniff_stream(&sess, Box::new(client)).await;
        assert_eq!(domain, None);
    }

    // 2. 4th attempt should hit negative cache and skip sniffing
    assert!(
        sniffer
            .tcp_neg_cache
            .lock()
            .should_skip(&target_addr, std::time::Instant::now())
    );

    // 3. Now send valid TLS with force sniff (or after clear) to restore success
    let (client, mut server) = tokio::io::duplex(1024);
    let sample = build_tls_client_hello("recovered.org");
    tokio::spawn(async move {
        server.write_all(&sample).await.unwrap();
    });

    let force_sess = Session {
        destination: SocksAddr::Domain("recovered.org".into(), 443),
        ..Default::default()
    };
    // Force sniffing ignores negative cache
    let mut config_with_force = config.clone();
    config_with_force.force_domains = vec!["recovered.org".to_string()];
    let sniffer_force = Sniffer::new(config_with_force);
    let (domain, _, _) = sniffer_force
        .sniff_stream(&force_sess, Box::new(client))
        .await;
    assert_eq!(domain, Some("recovered.org".to_string()));
}

#[test]
fn test_hostname_validation() {
    assert!(tls::is_valid_hostname("example.com"));
    assert!(tls::is_valid_hostname("sub.domain.co.uk"));
    assert!(tls::is_valid_hostname("my-domain_123.org"));
    assert!(!tls::is_valid_hostname(""));
    assert!(!tls::is_valid_hostname("-bad.com"));
    assert!(!tls::is_valid_hostname("bad-.com"));
    assert!(!tls::is_valid_hostname(".dot.at.start"));
    assert!(!tls::is_valid_hostname("space in.com"));
}
