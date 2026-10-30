use super::*;
use std::time::Duration;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};

#[tokio::test]
async fn shutdown_handoff_drains_pending_adapter_writes_without_reading_new_downloads() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (stack, mut listener, _udp) = NetStack::new();
        let (mut sink, mut packets) = stack.split();
        sink.send(build_tcp_syn_packet().into()).await.unwrap();
        let syn = packets.next().await.unwrap().unwrap();
        let mut ack = parse_server_isn(syn.data()).wrapping_add(1);
        sink.send(build_tcp_ack(1, ack, u16::MAX).into()).await.unwrap();
        let mut stream = listener.next().await.unwrap();
        let request = b"sniffed-upload-with-fin";
        sink.send(client_segment(1, ack, 0x19, request).into()).await.unwrap();
        let mut prefix = vec![0; 7];
        stream.read_exact(&mut prefix).await.unwrap();
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let native = TcpStream::connect(server.local_addr().unwrap()).await.unwrap();
        let (mut peer, _) = server.accept().await.unwrap();
        let upstream = tokio::spawn(async move {
            peer.write_all(b"must-not-be-downloaded-after-shutdown").await.unwrap();
            let mut received = Vec::new();
            peer.read_to_end(&mut received).await.unwrap();
            received
        });
        // Larger than initial protocol TX: some accepted bytes must wait in
        // the adapter ring. Shutdown and handoff must drain them before FIN.
        let accepted = vec![0xab; 64 * 1024];
        stream.write_all(&accepted).await.unwrap();
        stream.shutdown().await.unwrap();
        let relay = tokio::spawn(stream.forward(native, prefix, Box::new(|_, _| {}),
            Duration::from_secs(2), Duration::from_secs(2)));
        let mut delivered = Vec::new();
        loop {
            let packet = packets.next().await.unwrap().unwrap();
            if let Some((start, length)) = parse_tcp_data(packet.data()) {
                let ip = (packet.data()[0] & 15) as usize * 4;
                let tcp = (packet.data()[ip + 12] >> 4) as usize * 4;
                assert_eq!(packet.data()[ip + 13] & 4, 0, "unexpected reset");
                if start == ack && length > 0 {
                    delivered.extend_from_slice(&packet.data()[ip + tcp..]);
                    ack = ack.wrapping_add(length as u32);
                }
                let fin = packet.data()[ip + 13] & 1 != 0;
                if fin { ack = ack.wrapping_add(1); }
                sink.send(build_tcp_ack(2 + request.len() as u32, ack, u16::MAX).into()).await.unwrap();
                if fin { break; }
            }
        }
        assert_eq!(delivered, accepted);
        assert_eq!(upstream.await.unwrap(), request);
        assert_eq!(relay.await.unwrap().unwrap(), (request.len() as u64, 0));
    }).await.expect("pending adapter writes stalled during shutdown handoff");
}
