use futures::{SinkExt, StreamExt};
use watfaq_netstack::NetStack;
use super::common::{self, build_tcp_ack, build_tcp_syn_packet, is_syn_ack,
    parse_server_isn, parse_tcp_data};

fn client_segment(seq: u32, ack: u32, flags: u8, payload: &[u8]) -> bytes::Bytes {
    let mut packet = build_tcp_ack(seq, ack, u16::MAX).to_vec();
    packet[33] = flags;
    packet.extend_from_slice(payload);
    let length = packet.len() as u16;
    packet[2..4].copy_from_slice(&length.to_be_bytes());
    packet[10..12].fill(0);
    packet[36..38].fill(0);
    let checksum = common::tcp_udp_checksum([1, 1, 1, 1], [2, 2, 2, 2], 6, &packet[20..]);
    packet[36..38].copy_from_slice(&checksum.to_be_bytes());
    let checksum = common::ipv4_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.into()
}

/// Handoff after sniffing must preserve both the sniffed prefix and bytes
/// already queued by the generic stream, then drain both TCP half-closes.
#[tokio::test]
async fn native_handoff_preserves_prefix_buffered_bytes_and_half_close() {
    use std::{sync::{Arc, atomic::{AtomicUsize, Ordering}}, time::Duration};
    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};

    tokio::time::timeout(Duration::from_secs(10), async {
        let (stack, mut listener, _udp) = NetStack::new();
        let (mut sink, mut packets) = stack.split();
        sink.send(build_tcp_syn_packet().into()).await.unwrap();
        let reply = packets.next().await.unwrap().unwrap();
        assert!(is_syn_ack(reply.data()));
        let mut ack = parse_server_isn(reply.data()).wrapping_add(1);
        sink.send(build_tcp_ack(1, ack, u16::MAX).into()).await.unwrap();
        let mut stream = listener.next().await.unwrap();
        let upload = b"sniffed-prefix-and-buffered-tail";
        sink.send(client_segment(1, ack, 0x18, upload).into()).await.unwrap();
        let mut prefix = vec![0; 7];
        stream.read_exact(&mut prefix).await.unwrap();
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let native = TcpStream::connect(server.local_addr().unwrap()).await.unwrap();
        let (mut peer, _) = server.accept().await.unwrap();
        let up = Arc::new(AtomicUsize::new(0));
        let down = Arc::new(AtomicUsize::new(0));
        let (count_up, count_down) = (up.clone(), down.clone());
        let relay = tokio::spawn(stream.forward(native, prefix, Box::new(move |u, d| {
            count_up.fetch_add(u, Ordering::Relaxed);
            count_down.fetch_add(d, Ordering::Relaxed);
        }), Duration::from_secs(2), Duration::from_secs(2)));
        let seq = 1 + upload.len() as u32;
        sink.send(client_segment(seq, ack, 0x11, &[]).into()).await.unwrap();
        let mut received = Vec::new();
        peer.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, upload);
        let response_len = 16 * 1024 * 1024;
        let writer = tokio::spawn(async move {
            let chunk = vec![0xab; 16 * 1024];
            for _ in 0..response_len / chunk.len() { peer.write_all(&chunk).await.unwrap(); }
            peer.shutdown().await.unwrap();
        });
        let mut received = Vec::new();
        loop {
            let packet = packets.next().await.unwrap().unwrap();
            if let Some((start, length)) = parse_tcp_data(packet.data()) {
                let ip_length = (packet.data()[0] & 15) as usize * 4;
                let tcp_length = (packet.data()[ip_length + 12] >> 4) as usize * 4;
                if start == ack && length > 0 {
                    received.extend_from_slice(&packet.data()[ip_length + tcp_length..]);
                    ack = ack.wrapping_add(length as u32);
                }
                let fin = packet.data()[ip_length + 13] & 1 != 0;
                if fin && start.wrapping_add(length as u32) == ack { ack = ack.wrapping_add(1); }
                sink.send(build_tcp_ack(seq + 1, ack, u16::MAX).into()).await.unwrap();
                if fin { break; }
            }
        }
        writer.await.unwrap();
        assert_eq!(received.len(), response_len);
        assert!(received.iter().all(|byte| *byte == 0xab));
        assert_eq!(relay.await.unwrap().unwrap(), (upload.len() as u64, response_len as u64));
        assert_eq!(up.load(Ordering::Relaxed), upload.len());
        assert_eq!(down.load(Ordering::Relaxed), response_len);
    }).await.expect("native handoff stalled");
}

#[tokio::test]
async fn cancelled_native_handoff_releases_socket() {
    use std::time::Duration;
    use tokio::{io::AsyncReadExt, net::{TcpListener, TcpStream}};

    tokio::time::timeout(Duration::from_secs(5), async {
        let (stack, mut listener, _udp) = NetStack::new();
        let (mut sink, mut packets) = stack.split();
        sink.send(build_tcp_syn_packet().into()).await.unwrap();
        let reply = packets.next().await.unwrap().unwrap();
        let ack = parse_server_isn(reply.data()).wrapping_add(1);
        sink.send(build_tcp_ack(1, ack, u16::MAX).into()).await.unwrap();
        let stream = listener.next().await.unwrap();
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let native = TcpStream::connect(server.local_addr().unwrap()).await.unwrap();
        let (mut peer, _) = server.accept().await.unwrap();
        let relay = tokio::spawn(stream.forward(native, Vec::new(), Box::new(|_, _| {}),
            Duration::from_secs(1), Duration::from_secs(1)));
        tokio::task::yield_now().await;
        relay.abort();
        let _ = relay.await;
        let result = peer.read(&mut [0; 1]).await;
        assert!(matches!(result, Ok(0)) || result.is_err());
        loop {
            let packet = packets.next().await.unwrap().unwrap();
            if common::is_rst(packet.data()) { break; }
        }
        drop(listener);
    }).await.expect("cancelled socket was not released");
}

#[tokio::test]
async fn native_handoff_half_close_deadline_releases_idle_peer() {
    use std::time::Duration;
    use tokio::{io::AsyncReadExt, net::{TcpListener, TcpStream}};

    tokio::time::timeout(Duration::from_secs(3), async {
        let (stack, mut listener, _udp) = NetStack::new();
        let (mut sink, mut packets) = stack.split();
        sink.send(build_tcp_syn_packet().into()).await.unwrap();
        let reply = packets.next().await.unwrap().unwrap();
        let ack = parse_server_isn(reply.data()).wrapping_add(1);
        sink.send(build_tcp_ack(1, ack, u16::MAX).into()).await.unwrap();
        let stream = listener.next().await.unwrap();
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let native = TcpStream::connect(server.local_addr().unwrap()).await.unwrap();
        let (mut peer, _) = server.accept().await.unwrap();
        let relay = tokio::spawn(stream.forward(native, Vec::new(), Box::new(|_, _| {}),
            Duration::from_millis(20), Duration::from_millis(20)));
        sink.send(client_segment(1, ack, 0x11, &[]).into()).await.unwrap();
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
        // Keep the peer's write half open. The relay must have its own timer
        // registration rather than relying on more network traffic to wake it.
        assert_eq!(relay.await.unwrap().unwrap(), (0, 0));
    }).await.expect("half-close timer did not wake the relay");
}

#[tokio::test]
async fn stopping_stack_wakes_pending_stream_reader() {
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    tokio::time::timeout(Duration::from_secs(3), async {
        let (stack, mut listener, _udp) = NetStack::new();
        let (mut sink, mut packets) = stack.split();
        sink.send(build_tcp_syn_packet().into()).await.unwrap();
        let _reply = packets.next().await.unwrap().unwrap();
        let mut stream = listener.next().await.unwrap();
        let read = tokio::spawn(async move { stream.read_u8().await });
        tokio::task::yield_now().await;
        drop(listener);
        assert!(read.await.unwrap().is_err());
    }).await.expect("stack shutdown left a stream reader asleep");
}


#[tokio::test]
async fn cancelled_pending_handoff_drops_prefix_and_sends_reset() {
    use std::time::Duration;
    use tokio::{io::AsyncReadExt, net::{TcpListener, TcpStream}};

    tokio::time::timeout(Duration::from_secs(3), async {
        let (stack, mut listener, _udp) = NetStack::new();
        let (mut sink, mut packets) = stack.split();
        sink.send(build_tcp_syn_packet().into()).await.unwrap();
        let reply = packets.next().await.unwrap().unwrap();
        let ack = parse_server_isn(reply.data()).wrapping_add(1);
        sink.send(build_tcp_ack(1, ack, u16::MAX).into()).await.unwrap();
        let stream = listener.next().await.unwrap();
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let native = TcpStream::connect(server.local_addr().unwrap()).await.unwrap();
        let (mut peer, _) = server.accept().await.unwrap();
        let mut relay = Box::pin(stream.forward(native, b"cancelled-prefix".to_vec(),
            Box::new(|_, _| panic!("cancelled handoff must not forward data")),
            Duration::from_secs(1), Duration::from_secs(1)));
        // Submit and cancel without yielding, so the engine cannot adopt it.
        assert!(futures::poll!(&mut relay).is_pending());
        drop(relay);
        assert_eq!(peer.read(&mut [0; 32]).await.unwrap(), 0);
        loop {
            let packet = packets.next().await.unwrap().unwrap();
            if common::is_rst(packet.data()) { break; }
        }
    }).await.expect("pending handoff cancellation did not reset both endpoints");
}
