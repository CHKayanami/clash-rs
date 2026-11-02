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

#[test]
fn tx_shrink_preserves_wrapped_unacknowledged_and_unsent_bytes() {
    let mut s = socket_established_with_buffer_sizes(128, 64);
    assert_eq!(s.tx_buffer.enqueue_slice(&[b'a'; 120]), 120);
    s.tx_buffer.dequeue_allocated(100);
    assert_eq!(s.tx_buffer.enqueue_slice(&[b'b'; 100]), 100);
    s.remote_last_seq = s.local_seq_no + 80;
    let mut expected = vec![0; 120];
    assert_eq!(s.tx_buffer.read_allocated(0, &mut expected), 120);
    let before = (s.local_seq_no, s.remote_last_seq, s.timer, s.acknowledged_bytes);
    s.shrink_send_buffer(SocketBuffer::new(vec![0; 120]));
    assert_eq!(s.send_capacity(), 120);
    assert_eq!((s.local_seq_no, s.remote_last_seq, s.timer, s.acknowledged_bytes), before);
    let mut actual = vec![0; 120];
    assert_eq!(s.tx_buffer.read_allocated(0, &mut actual), 120);
    assert_eq!(actual, expected);
    send(&mut s, Instant::ZERO, &TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 21),
        ..SEND_TEMPL
    });
    assert_eq!(s.send_queue(), 100);
    assert_eq!(s.tx_buffer.read_allocated(0, &mut actual[..100]), 100);
    assert_eq!(&actual[..100], &expected[20..]);
}

#[test]
#[should_panic]
fn tx_shrink_rejects_storage_smaller_than_accepted_data() {
    let mut s = socket_established_with_buffer_sizes(128, 64);
    assert_eq!(s.send_slice(&[b'x'; 64]), Ok(64));
    s.shrink_send_buffer(SocketBuffer::new(vec![0; 63]));
}

#[test]
fn tx_state_distinguishes_dispatched_data_from_unsent_data() {
    for window in [32, 4096] {
        let mut s = socket_established_with_buffer_sizes(128, 64);
        s.set_congestion_control(CongestionControl::None);
        s.remote_win_len = window;
        assert_eq!(s.send_slice(&[b'x'; 128]), Ok(128));
        let before = s.transmit_state();
        assert_eq!(before.unsent, 128);
        assert_eq!(before.queued, 128);
        recv(&mut s, Instant::ZERO, |reply| {
            assert_eq!(reply.unwrap().payload.len(), window.min(128));
        });
        let after = s.transmit_state();
        assert_eq!(after.queued, 128);
        assert_eq!(after.unsent, 128 - window.min(128));
    }
}

#[test]
fn rx_reclaim_honors_old_credit_and_keeps_the_advertised_right_edge() {
    let mut s = socket_established_with_buffer_sizes(64, 128);
    s.set_ack_delay(None);
    assert!(s.limit_receive_admission(64));
    assert_eq!(s.receive_state().required, 128);
    send(&mut s, Instant::ZERO, &TcpRepr {
        seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1),
        payload: &[b'a'; 64], ..SEND_TEMPL
    });
    recv(&mut s, Instant::ZERO, |reply| {
        let reply = reply.unwrap();
        assert_eq!(reply.ack_number, Some(REMOTE_SEQ + 65));
        assert_eq!(reply.window_len, 64);
        // ACK advances, but credit is not extended while a reclaim is pending.
        assert_eq!(reply.ack_number.unwrap() + reply.window_len as usize, REMOTE_SEQ + 129);
    });
    assert_eq!(s.receive_state().required, 128);
    assert_eq!(s.recv_slice(&mut [0; 64]), Ok(64));
    assert_eq!(s.receive_state().required, 64);
    let shift = s.remote_win_shift;
    s.shrink_receive_buffer(SocketBuffer::new(vec![0; 64]));
    assert_eq!(s.remote_win_shift, shift);
    // The remaining bytes of the earlier grant are still accepted after shrink.
    send(&mut s, Instant::ZERO, &TcpRepr {
        seq_number: REMOTE_SEQ + 65, ack_number: Some(LOCAL_SEQ + 1),
        payload: &[b'b'; 64], ..SEND_TEMPL
    });
    let mut actual = [0; 64];
    assert_eq!(s.recv_slice(&mut actual), Ok(64));
    assert_eq!(actual, [b'b'; 64]);
}

#[test]
#[should_panic]
fn rx_reclaim_rejects_empty_storage_with_outstanding_credit() {
    let mut s = socket_established_with_buffer_sizes(64, 128);
    assert_eq!(s.recv_queue(), 0);
    s.shrink_receive_buffer(SocketBuffer::new(vec![0; 64]));
}

#[test]
fn rx_reclaim_preserves_wrapped_out_of_order_bytes_and_can_fill_the_gap() {
    let mut s = socket_established_with_buffer_sizes(64, 128);
    // An endpoint can advertise less credit than its physical storage.
    s.remote_last_win_len = 64;
    assert_eq!(s.rx_buffer.enqueue_slice(&[0; 120]), 120);
    s.rx_buffer.dequeue_allocated(120);
    assert_eq!(s.rx_buffer.write_unallocated(32, &[b'h'; 8]), 8);
    s.assembler.add(32, 8).unwrap();
    assert_eq!(s.receive_state().stored, 40);
    assert_eq!(s.receive_state().required, 64);
    s.shrink_receive_buffer(SocketBuffer::new(vec![0; 64]));
    send(&mut s, Instant::ZERO, &TcpRepr {
        seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1),
        payload: &[b'a'; 32], ..SEND_TEMPL
    });
    let mut actual = [0; 40];
    assert_eq!(s.recv_slice(&mut actual), Ok(40));
    assert_eq!(&actual[..32], &[b'a'; 32]);
    assert_eq!(&actual[32..], &[b'h'; 8]);
}

#[test]
fn rx_reclaim_keeps_scaled_credit_when_ack_rounding_moves_the_wire_edge() {
    let mut s = socket_established_with_buffer_sizes(64, 1024);
    s.remote_win_shift = 7;
    s.remote_last_win_len = 1024;
    s.receive_advertised_end = Some(REMOTE_SEQ + 1025);
    s.set_ack_delay(None);
    s.limit_receive_admission(512);
    send(&mut s, Instant::ZERO, &TcpRepr {
        seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1),
        payload: &[b'a'; 65], ..SEND_TEMPL
    });
    recv(&mut s, Instant::ZERO, |reply| {
        // Scaling may round the wire window down; earlier credit stays valid.
        assert_eq!(reply.unwrap().window_len, 7);
    });
    assert_eq!(s.recv_slice(&mut [0; 65]), Ok(65));
    assert_eq!(s.receive_state().required, 959);
    send(&mut s, Instant::ZERO, &TcpRepr {
        seq_number: REMOTE_SEQ + 66, ack_number: Some(LOCAL_SEQ + 1),
        payload: &[b'a'; 447], ..SEND_TEMPL
    });
    recv(&mut s, Instant::ZERO, |reply| {
        assert_eq!(reply.unwrap().window_len, 4);
    });
    assert_eq!(s.recv_slice(&mut [0; 447]), Ok(447));
    assert_eq!(s.receive_state().required, 512);
    s.shrink_receive_buffer(SocketBuffer::new(vec![0; 512]));
    assert_eq!(s.remote_win_shift, 7);
    send(&mut s, Instant::ZERO, &TcpRepr {
        seq_number: REMOTE_SEQ + 513, ack_number: Some(LOCAL_SEQ + 1),
        payload: &[b'b'; 512], ..SEND_TEMPL
    });
    assert_eq!(s.recv_queue(), 512);
}

#[test]
fn rx_controller_keeps_idle_reclaim_while_consuming_old_advertised_credit() {
    use crate::tcp::buffers::Buffers;
    use tokio::time::{Duration as TokioDuration, Instant as TokioInstant};

    let (mut buffers, _) = Buffers::new();
    let mut s = socket_established_with_buffer_sizes(16 * 1024, 64 * 1024);
    s.remote_last_win_len = 64 * 1024;
    s.receive_advertised_end = Some(REMOTE_SEQ + 1 + 64 * 1024);
    s.set_ack_delay(None);
    let now = TokioInstant::now() + TokioDuration::from_secs(31);
    assert!(buffers.reclaim(&mut s.socket, now));
    assert_eq!(s.recv_capacity(), 64 * 1024);
    let payload = [b'x'; 16 * 1024];
    for batch in 0..3 {
        send(&mut s, Instant::ZERO, &TcpRepr {
            seq_number: REMOTE_SEQ + 1 + batch * payload.len(),
            ack_number: Some(LOCAL_SEQ + 1), payload: &payload, ..SEND_TEMPL
        });
        assert_eq!(s.recv_slice(&mut [0; 16 * 1024]), Ok(payload.len()));
        buffers.grow(&mut s.socket, payload.len(), false, true, now);
        buffers.reclaim(&mut s.socket, now);
        recv(&mut s, Instant::ZERO, |reply| { assert!(reply.is_ok()); });
    }
    assert_eq!(s.recv_capacity(), 16 * 1024);
    assert!(s.receive_admission_limit.is_none());
}

#[test]
fn rx_reassembly_without_readable_bytes_does_not_arm_an_expired_idle_deadline() {
    use crate::tcp::buffers::Buffers;
    use tokio::time::{Duration as TokioDuration, Instant as TokioInstant};

    let (mut buffers, _) = Buffers::new();
    let mut s = socket_established_with_buffer_sizes(16 * 1024, 64 * 1024);
    assert!(buffers.idle_deadline(&s.socket).is_some());
    send(&mut s, Instant::ZERO, &TcpRepr {
        seq_number: REMOTE_SEQ + 1025,
        ack_number: Some(LOCAL_SEQ + 1), payload: b"hole", ..SEND_TEMPL
    });
    assert_eq!(s.recv_queue(), 0);
    assert!(s.receive_state().stored > 0);
    let now = TokioInstant::now() + TokioDuration::from_secs(31);
    for _ in 0..3 {
        assert!(!buffers.reclaim(&mut s.socket, now));
        assert_eq!(buffers.idle_deadline(&s.socket), None);
    }
    assert_eq!(s.recv_capacity(), 64 * 1024);
}
