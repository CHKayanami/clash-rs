use super::*;
use clash_netstack::TcpDriver;
use futures::task::noop_waker;
use std::task::Context;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn close_before_handshake_resets_after_output_backpressure() {
    for shutdown in [false, true] {
        // SYN-ACK occupies the only output slot, so closing must retain the
        // reset until the device drains output. No handshake ACK is injected.
        let (mut driver, mut listener) = TcpDriver::new(1500, 1).unwrap();
        driver.receive(build_tcp_syn_packet().into()).unwrap();
        let mut stream = listener.next().await.unwrap();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let _ = driver.poll(&mut cx);
        if shutdown { stream.shutdown().await.unwrap(); }
        else { drop(stream); }
        let _ = driver.poll(&mut cx);
        let syn_ack = driver.take_output().unwrap();
        assert!(is_syn_ack(syn_ack.data()));
        let next_sequence = parse_server_isn(syn_ack.data()).wrapping_add(1);
        assert!(driver.take_output().is_none());
        let _ = driver.poll(&mut cx);
        let reset = driver.take_output().expect("close must send RST before handshake ACK");
        assert!(common::is_rst(reset.data()));
        assert_eq!(parse_server_isn(reset.data()), next_sequence);
        assert_eq!(common::ipv4_checksum(&reset.data()[..20]), 0);
        assert_eq!(common::tcp_udp_checksum([2, 2, 2, 2], [1, 1, 1, 1],
            6, &reset.data()[20..]), 0);
    }
}
