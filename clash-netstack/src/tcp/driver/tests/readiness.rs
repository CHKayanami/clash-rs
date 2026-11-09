use super::*;
use std::sync::Arc;
use futures::task::waker_ref;
use crate::tcp::ready::{Ready, ReadyQueue};

fn window(driver: &mut Driver, sockets: &mut SocketTable, handle: SocketHandle,
    ack: TcpSeqNumber, bytes: u16) {
    let packet = client_packet(49152, Some(ack));
    let (ip, payload) = parse_ip(packet.data()).unwrap();
    let tcp = TcpPacket::new_checked(payload).unwrap();
    let mut repr = parse_tcp(&tcp, &ip, false).unwrap();
    repr.window_len = bytes; // The fixture negotiated a shift of seven.
    sockets.get_mut(handle).process(&mut driver.context, &ip, &repr);
}

fn arm(sockets: &mut SocketTable, handle: SocketHandle, queue: &Arc<ReadyQueue>) {
    let ready = Ready::new(handle.0, queue.clone());
    sockets.get_mut(handle).register_send_waker(&waker_ref(&ready));
}

#[test]
fn pure_window_growth_wakes_a_reader_without_acknowledging_new_data() {
    let mut driver = Driver::new(1500);
    let mut sockets = SocketTable::new();
    let (handle, ack) = established_with_data(&mut driver, &mut sockets, 49152, 80 * 1024);
    window(&mut driver, &mut sockets, handle, ack, 0);
    assert_eq!(Buffers::read_budget(sockets.get_mut(handle)), 0);
    let queue = Arc::new(ReadyQueue::default());
    arm(&mut sockets, handle, &queue);
    window(&mut driver, &mut sockets, handle, ack, 1024);
    assert!(Buffers::read_budget(sockets.get_mut(handle)) > 0);
    assert_eq!(queue.pop().unwrap().id, handle.0);
    assert_eq!(sockets.get_mut(handle).send_queue(), 80 * 1024);
    arm(&mut sockets, handle, &queue);
    window(&mut driver, &mut sockets, handle, ack, 1024);
    window(&mut driver, &mut sockets, handle, ack, 256);
    assert!(queue.is_empty(), "unchanged/shrinking windows must not spuriously wake");
}

#[test]
fn egress_resumes_read_ahead_after_sending_unsent_bytes_without_an_ack() {
    let mut driver = Driver::new(1500);
    let mut sockets = SocketTable::new();
    let (handle, ack) = established_with_data(&mut driver, &mut sockets, 49152, 80 * 1024);
    window(&mut driver, &mut sockets, handle, ack, 256);
    assert_eq!(Buffers::read_budget(sockets.get_mut(handle)), 0);
    let queue = Arc::new(ReadyQueue::default());
    arm(&mut sockets, handle, &queue);
    let (output, mut received) = mpsc::channel(512);
    let mut device = NetstackDevice::new(output);
    driver.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    assert!(received.try_recv().is_ok());
    assert_eq!(sockets.get_mut(handle).send_queue(), 80 * 1024);
    assert!(Buffers::read_budget(sockets.get_mut(handle)) > 0);
    assert_eq!(queue.pop().unwrap().id, handle.0);
    arm(&mut sockets, handle, &queue);
    driver.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    assert!(queue.is_empty(), "restored permission must not wake on every poll");
}
