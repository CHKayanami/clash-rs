// Derived from smoltcp; see ../LICENSE-0BSD.txt.
use super::*;

#[test]
fn test_buffer_growth_preserves_wrapped_receive_and_reassembly() {
    let mut s = socket_established();
    s.rx_capacity_limit = 256;
    // Move the ring head near the end, then keep both committed bytes
    // and out-of-order bytes spanning the physical wrap boundary.
    assert_eq!(s.rx_buffer.enqueue_slice(&[b'x'; 60]), 60);
    s.rx_buffer.dequeue_allocated(60);
    assert_eq!(s.rx_buffer.enqueue_slice(b"ab"), 2);
    assert_eq!(s.rx_buffer.write_unallocated(3, b"fgh"), 3);
    s.assembler.add(3, 3).unwrap();
    let sequence = s.remote_seq_no;
    s.grow_receive_buffer(SocketBuffer::new(vec![0; 256]));
    assert_eq!(s.remote_seq_no, sequence);
    assert_eq!(s.recv_queue(), 2);
    assert_eq!(s.rx_buffer.write_unallocated(0, b"cde"), 3);
    assert_eq!(s.assembler.add_then_remove_front(0, 3).unwrap(), 6);
    s.rx_buffer.enqueue_unallocated(6);
    let mut data = [0; 8];
    assert_eq!(s.recv_slice(&mut data).unwrap(), 8);
    assert_eq!(&data, b"abcdefgh");
    assert!(s.window_to_update(&s.cx));
}

#[test]
fn test_buffer_growth_preserves_unacknowledged_send() {
    let mut s = socket_established();
    assert_eq!(s.tx_buffer.enqueue_slice(&[b'x'; 60]), 60);
    s.tx_buffer.dequeue_allocated(60);
    s.send_slice(b"abcdefgh").unwrap();
    let sequence = s.local_seq_no;
    let sent = s.remote_last_seq;
    s.grow_send_buffer(SocketBuffer::new(vec![0; 256]));
    assert_eq!(s.local_seq_no, sequence);
    assert_eq!(s.remote_last_seq, sent);
    assert_eq!(s.send_queue(), 8);
    let mut data = [0; 8];
    assert_eq!(s.tx_buffer.read_allocated(0, &mut data), 8);
    assert_eq!(&data, b"abcdefgh");
}

#[test]
fn test_buffer_growth_negotiates_limit_with_small_initial_window() {
    let mut s = socket();
    s.set_receive_capacity_limit(4 * 1024 * 1024);
    s.listen(LOCAL_PORT).unwrap();
    assert_eq!(s.remote_win_shift, 7);
    let reply = send(
        &mut s,
        Instant::from_millis(0),
        &TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            window_scale: Some(0),
            ..SEND_TEMPL
        },
    );
    assert!(reply.is_none());
    recv(&mut s, Instant::from_millis(0), |reply| {
        let reply = reply.unwrap();
        assert_eq!(reply.window_scale, Some(7));
        // SYN windows are never scaled and cannot advertise unallocated storage.
        assert_eq!(reply.window_len, 64);
    });
    s.grow_receive_buffer(SocketBuffer::new(vec![0; 128 * 1024]));
    assert_eq!(s.remote_win_shift, 7);
    assert_eq!(s.scaled_window(), 1024);
}

#[test]
fn test_buffer_growth_without_peer_scaling_stays_unscaled() {
    let mut s = socket();
    s.set_receive_capacity_limit(4 * 1024 * 1024);
    s.listen(LOCAL_PORT).unwrap();
    send(
        &mut s,
        Instant::from_millis(0),
        &TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            window_scale: None,
            ..SEND_TEMPL
        },
    );
    assert_eq!(s.remote_win_shift, 0);
    s.grow_receive_buffer(SocketBuffer::new(vec![0; 128 * 1024]));
    assert_eq!(s.scaled_window(), u16::MAX);
    assert_eq!(s.remote_win_shift, 0);
}

#[test]
#[should_panic]
fn test_buffer_growth_rejects_receive_shrink() {
    let mut s = socket_established();
    s.grow_receive_buffer(SocketBuffer::new(vec![0; 32]));
}

#[test]
#[should_panic]
fn test_buffer_growth_rejects_exceeding_receive_limit() {
    let mut s = socket_established();
    s.grow_receive_buffer(SocketBuffer::new(vec![0; 128]));
}

#[test]
#[should_panic]
fn test_buffer_growth_rejects_late_window_scale_change() {
    let mut s = socket_established();
    s.set_receive_capacity_limit(128);
}

#[test]
fn test_buffer_growth_syn_window_rejects_outside_and_clips_oversized_data() {
    for offset in [0, 4096, 8192] {
        let mut s = growth_handshake(4096);
        let ack = s.local_seq_no;
        let payload = [b'x'; 8192];
        send(
            &mut s,
            Instant::from_millis(0),
            &TcpRepr {
                seq_number: REMOTE_SEQ + 1 + offset,
                ack_number: Some(ack),
                payload: &payload,
                ..SEND_TEMPL
            },
        );
        assert_eq!(s.recv_queue(), if offset == 0 { 4096 } else { 0 });
        assert!(s.assembler.is_empty());
    }
}

#[test]
fn test_buffer_growth_after_handshake_publishes_scaled_window() {
    for (initial, capacity) in [(4096, 8192), (4096, 128 * 1024), (64, 8192)] {
        let mut s = growth_handshake(initial);
        s.grow_receive_buffer(SocketBuffer::new(vec![0; capacity]));
        assert!(s.window_to_update(&s.cx));
        let TestSocket { socket, cx } = &mut s;
        assert_eq!(socket.poll_at(cx), PollAt::Now);
        recv(&mut s, Instant::from_millis(0), |reply| {
            assert_eq!(reply.unwrap().window_len as usize, capacity >> 7);
        });
        assert_eq!(s.remote_last_win_len, capacity);
        assert!(!s.window_to_update(&s.cx));
    }
}

#[test]
fn test_buffer_growth_small_increase_waits_for_other_output() {
    let mut s = growth_handshake(4096);
    s.grow_receive_buffer(SocketBuffer::new(vec![0; 5120]));
    assert!(!s.window_to_update(&s.cx));
    recv_nothing(&mut s, Instant::from_millis(0));
    s.send_slice(b"x").unwrap();
    recv(&mut s, Instant::from_millis(0), |reply| {
        assert_eq!(reply.unwrap().window_len as usize, 5120 >> 7);
    });
    assert_eq!(s.remote_last_win_len, 5120);
}

#[test]
fn test_buffer_growth_below_double_publishes_a_segment_of_new_space() {
    let mut s = growth_handshake(4096);
    s.grow_receive_buffer(SocketBuffer::new(vec![0; 6144]));
    assert!(s.window_to_update(&s.cx));
    recv(&mut s, Instant::ZERO, |reply| {
        assert_eq!(reply.unwrap().window_len as usize, 6144 >> 7);
    });
    assert!(!s.window_to_update(&s.cx));
}

#[test]
fn test_buffer_growth_rst_restores_listener_scaling_and_reassembly() {
    let mut s = socket();
    s.set_receive_capacity_limit(4 * 1024 * 1024);
    s.listen(LOCAL_PORT).unwrap();
    send(
        &mut s,
        Instant::from_millis(0),
        &TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            window_scale: None,
            ..SEND_TEMPL
        },
    );
    recv(&mut s, Instant::from_millis(0), |_| {});
    assert_eq!(s.remote_win_shift, 0);
    s.grow_receive_buffer(SocketBuffer::new(vec![0; 128 * 1024]));
    assert_eq!(s.rx_buffer.write_unallocated(3, b"abc"), 3);
    s.assembler.add(3, 3).unwrap();
    assert_eq!(s.tx_buffer.enqueue_slice(b"stale"), 5);
    send(
        &mut s,
        Instant::from_millis(0),
        &TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ + 1,
            ack_number: None,
            ..SEND_TEMPL
        },
    );
    assert_eq!(s.state(), State::Listen);
    assert_eq!(s.listen_endpoint.port, LOCAL_PORT);
    assert_eq!(s.remote_win_shift, 7);
    assert!(s.assembler.is_empty());
    assert_eq!((s.recv_queue(), s.send_queue()), (0, 0));
    assert_eq!(s.remote_last_ack, None);
    assert_eq!(s.remote_last_win_len, 0);
    s.listen(LOCAL_PORT).unwrap();
    send(
        &mut s,
        Instant::from_millis(0),
        &TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            window_scale: Some(0),
            ..SEND_TEMPL
        },
    );
    recv(&mut s, Instant::from_millis(0), |reply| {
        assert_eq!(reply.unwrap().window_scale, Some(7));
    });
}

#[test]
#[should_panic]
fn test_buffer_growth_limit_rejects_pending_abort() {
    let mut s = socket_established();
    s.abort();
    s.set_receive_capacity_limit(128);
}

#[test]
fn test_buffer_growth_wakes_blocked_sender_only_on_capacity_increase() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::task::{Wake, Waker};
    struct Counter(AtomicUsize);
    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let counter = Arc::new(Counter(AtomicUsize::new(0)));
    let waker = Waker::from(counter.clone());
    let mut s = socket_established();
    s.send_slice(&[b'x'; 64]).unwrap();
    assert!(!s.can_send());
    s.register_send_waker(&waker);
    s.grow_send_buffer(SocketBuffer::new(vec![0; 128]));
    assert!(s.can_send());
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    s.register_send_waker(&waker);
    s.grow_send_buffer(SocketBuffer::new(vec![0; 128]));
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
}

#[test]
fn test_buffer_wraparound_rx() {
    let mut s = socket_established();
    s.rx_buffer = SocketBuffer::new(vec![0; 6]);
    s.assembler = Assembler::new();
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abc"[..],
            ..SEND_TEMPL
        }
    );
    s.recv(|buffer| {
        assert_eq!(buffer, b"abc");
        (buffer.len(), ())
    })
    .unwrap();
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 3,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"defghi"[..],
            ..SEND_TEMPL
        }
    );
    let mut data = [0; 6];
    assert_eq!(s.recv_slice(&mut data[..]), Ok(6));
    assert_eq!(data, &b"defghi"[..]);
}

#[test]
fn test_buffer_wraparound_tx() {
    let mut s = socket_established();
    s.set_nagle_enabled(false);

    s.tx_buffer = SocketBuffer::new(vec![b'.'; 9]);
    assert_eq!(s.send_slice(b"xxxyyy"), Ok(6));
    assert_eq!(s.tx_buffer.dequeue_many(3), &b"xxx"[..]);
    assert_eq!(s.tx_buffer.len(), 3);

    // "abcdef" not contiguous in tx buffer
    assert_eq!(s.send_slice(b"abcdef"), Ok(6));
    recv!(
        s,
        Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"yyyabc"[..],
            ..RECV_TEMPL
        })
    );
    recv!(
        s,
        Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"def"[..],
            ..RECV_TEMPL
        })
    );
}
