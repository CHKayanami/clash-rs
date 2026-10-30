// Derived from smoltcp; see ../LICENSE-0BSD.txt.
use super::*;

#[test]
fn test_time_wait_retransmit() {
    let mut s = socket_time_wait(false);
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]
    );
    send!(s, time 5_000, TcpRepr {
        control: TcpControl::Fin,
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1 + 1),
        ..SEND_TEMPL
    }, Some(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + 1,
        ack_number: Some(REMOTE_SEQ + 1 + 1),
        ..RECV_TEMPL
    }));
    assert_eq!(
        s.timer,
        Timer::Close {
            expires_at: Instant::from_secs(5) + CLOSE_DELAY
        }
    );
}

#[test]
fn test_data_retransmit() {
    let mut s = socket_established();
    s.send_slice(b"abcdef").unwrap();
    recv!(s, time 1000, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abcdef"[..],
        ..RECV_TEMPL
    }));
    recv_nothing!(s, time 1050);
    recv!(s, time 2000, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abcdef"[..],
        ..RECV_TEMPL
    }));
}

#[test]

fn test_congestion_window_limits_data_in_flight() {
    let mut s = socket_established_with_buffer_sizes(8192, 64);
    s.set_congestion_control(CongestionControl::Reno);
    s.remote_win_len = 65535;
    s.remote_mss = 1024;

    let data = [b'x'; 8192];
    s.send_slice(&data[..]).unwrap();

    // Reno's initial congestion window is 2048 bytes: only two
    // 1024-byte segments may be in flight, the rest must wait for ACKs.
    recv!(s, time 0, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload: &data[..1024],
        ..RECV_TEMPL
    }));
    recv!(s, time 0, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + 1024,
        ack_number: Some(REMOTE_SEQ + 1),
        payload: &data[..1024],
        ..RECV_TEMPL
    }));
    recv_nothing!(s, time 0);

    // ACKing one segment frees congestion window space and grows
    // cwnd (slow start), allowing further segments out.
    send!(s, time 10, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1 + 1024),
        window_len: 65535,
        ..SEND_TEMPL
    });
    recv!(s, time 10, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + 2048,
        ack_number: Some(REMOTE_SEQ + 1),
        payload: &data[..1024],
        ..RECV_TEMPL
    }));
}

#[test]

fn test_congestion_window_doesnt_limit_fast_retransmit() {
    let mut s = socket_established_with_buffer_sizes(8192, 64);
    s.set_congestion_control(CongestionControl::Reno);
    s.remote_win_len = 65535;
    s.remote_mss = 1024;

    // Normal ACK of previously received segment
    send!(s, time 0, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        window_len: 65535,
        ..SEND_TEMPL
    });

    let data = [b'x'; 8192];
    s.send_slice(&data[..]).unwrap();

    // Reno's initial congestion window is 2048 bytes, allowing 2 segments
    recv!(s, time 0, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload: &data[..1024],
        ..RECV_TEMPL
    }));

    recv!(s, time 0, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + 1024,
        ack_number: Some(REMOTE_SEQ + 1),
        payload: &data[..1024],
        ..RECV_TEMPL
    }));
    recv_nothing!(s, time 0);

    // Send three duplicate ACKS, treating the first segment as lost
    send!(s, time 10, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        window_len: 65535,
        ..SEND_TEMPL
    });
    send!(s, time 10, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        window_len: 65535,
        ..SEND_TEMPL
    });
    send!(s, time 10, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        window_len: 65535,
        ..SEND_TEMPL
    });

    // A fast retrnasmit should be sent and not be blocked by congestion control
    recv!(s, time 20, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload: &data[..1024],
        ..RECV_TEMPL
    }));
}

#[test]
fn test_data_retransmit_bursts() {
    let mut s = socket_established();
    s.remote_mss = 6;
    s.send_slice(b"abcdef012345").unwrap();

    recv!(s, time 0, Ok(TcpRepr {
        control:    TcpControl::None,
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abcdef"[..],
        ..RECV_TEMPL
    }), exact);
    recv!(s, time 0, Ok(TcpRepr {
        control:    TcpControl::Psh,
        seq_number: LOCAL_SEQ + 1 + 6,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"012345"[..],
        ..RECV_TEMPL
    }), exact);
    recv_nothing!(s, time 0);

    recv_nothing!(s, time 50);

    recv!(s, time 1000, Ok(TcpRepr {
        control:    TcpControl::None,
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abcdef"[..],
        ..RECV_TEMPL
    }), exact);
    recv!(s, time 1500, Ok(TcpRepr {
        control:    TcpControl::Psh,
        seq_number: LOCAL_SEQ + 1 + 6,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"012345"[..],
        ..RECV_TEMPL
    }), exact);
    recv_nothing!(s, time 1550);
}

#[test]
fn test_data_retransmit_bursts_half_ack() {
    let mut s = socket_established();
    s.remote_mss = 6;
    s.send_slice(b"abcdef012345").unwrap();

    recv!(s, time 0, Ok(TcpRepr {
        control:    TcpControl::None,
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abcdef"[..],
        ..RECV_TEMPL
    }), exact);
    recv!(s, time 0, Ok(TcpRepr {
        control:    TcpControl::Psh,
        seq_number: LOCAL_SEQ + 1 + 6,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"012345"[..],
        ..RECV_TEMPL
    }), exact);
    // Acknowledge the first packet
    send!(s, time 5, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1 + 6),
        window_len: 6,
        ..SEND_TEMPL
    });
    // The second packet should be re-sent.
    recv!(s, time 1500, Ok(TcpRepr {
        control:    TcpControl::Psh,
        seq_number: LOCAL_SEQ + 1 + 6,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"012345"[..],
        ..RECV_TEMPL
    }), exact);

    recv_nothing!(s, time 1550);
}

#[test]
fn test_retransmit_timer_restart_on_partial_ack() {
    let mut s = socket_established();
    s.remote_mss = 6;
    s.send_slice(b"abcdef012345").unwrap();

    recv!(s, time 0, Ok(TcpRepr {
        control:    TcpControl::None,
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abcdef"[..],
        ..RECV_TEMPL
    }), exact);
    recv!(s, time 0, Ok(TcpRepr {
        control:    TcpControl::Psh,
        seq_number: LOCAL_SEQ + 1 + 6,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"012345"[..],
        ..RECV_TEMPL
    }), exact);
    // Acknowledge the first packet
    send!(s, time 600, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1 + 6),
        window_len: 6,
        ..SEND_TEMPL
    });
    // The ACK of the first packet should restart the retransmit timer and delay a retransmission.
    recv_nothing!(s, time 2399);
    // The second packet should be re-sent.
    recv!(s, time 2400, Ok(TcpRepr {
        control:    TcpControl::Psh,
        seq_number: LOCAL_SEQ + 1 + 6,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"012345"[..],
        ..RECV_TEMPL
    }), exact);
}

#[test]
fn test_data_retransmit_bursts_half_ack_close() {
    let mut s = socket_established();
    s.remote_mss = 6;
    s.send_slice(b"abcdef012345").unwrap();
    s.close();

    recv!(s, time 0, Ok(TcpRepr {
        control:    TcpControl::None,
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abcdef"[..],
        ..RECV_TEMPL
    }), exact);
    recv!(s, time 0, Ok(TcpRepr {
        control:    TcpControl::Fin,
        seq_number: LOCAL_SEQ + 1 + 6,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"012345"[..],
        ..RECV_TEMPL
    }), exact);
    // Acknowledge the first packet
    send!(s, time 5, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1 + 6),
        window_len: 6,
        ..SEND_TEMPL
    });
    // The second packet should be re-sent.
    recv!(s, time 1500, Ok(TcpRepr {
        control:    TcpControl::Fin,
        seq_number: LOCAL_SEQ + 1 + 6,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"012345"[..],
        ..RECV_TEMPL
    }), exact);

    recv_nothing!(s, time 1550);
}

#[test]
fn test_send_data_after_syn_ack_retransmit() {
    let mut s = socket_syn_received();
    recv!(s, time 50, Ok(TcpRepr {
        control:    TcpControl::Syn,
        seq_number: LOCAL_SEQ,
        ack_number: Some(REMOTE_SEQ + 1),
        max_seg_size: Some(BASE_MSS),
        ..RECV_TEMPL
    }));
    recv!(s, time 1050, Ok(TcpRepr { // retransmit
        control:    TcpControl::Syn,
        seq_number: LOCAL_SEQ,
        ack_number: Some(REMOTE_SEQ + 1),
        max_seg_size: Some(BASE_MSS),
        ..RECV_TEMPL
    }));
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state(), State::Established);
    s.send_slice(b"abcdef").unwrap();
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"abcdef"[..],
            ..RECV_TEMPL
        }]
    )
}

#[test]
fn test_established_retransmit_for_dup_ack() {
    let mut s = socket_established();
    // Duplicate ACKs do not replace the retransmission timer
    s.send_slice(b"abc").unwrap();
    recv!(s, time 1000, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abc"[..],
        ..RECV_TEMPL
    }));
    // Retransmit timer is on because all data was sent
    assert_eq!(s.tx_buffer.len(), 3);
    // ACK nothing new
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );
    // Retransmit
    recv!(s, time 4000, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abc"[..],
        ..RECV_TEMPL
    }));
}

#[test]
fn test_established_retransmit_reset_after_ack() {
    let mut s = socket_established();
    s.remote_win_len = 6;
    s.send_slice(b"abcdef").unwrap();
    s.send_slice(b"123456").unwrap();
    s.send_slice(b"ABCDEF").unwrap();
    recv!(s, time 1000, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abcdef"[..],
        ..RECV_TEMPL
    }));
    send!(s, time 1005, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1 + 6),
        window_len: 6,
        ..SEND_TEMPL
    });
    recv!(s, time 1010, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + 6,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"123456"[..],
        ..RECV_TEMPL
    }));
    send!(s, time 1015, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
        window_len: 6,
        ..SEND_TEMPL
    });
    recv!(s, time 1020, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + 6 + 6,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"ABCDEF"[..],
        ..RECV_TEMPL
    }));
}

#[test]
fn test_established_queue_during_retransmission() {
    let mut s = socket_established();
    s.remote_mss = 6;
    s.send_slice(b"abcdef123456ABCDEF").unwrap();
    recv!(s, time 1000, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abcdef"[..],
        ..RECV_TEMPL
    })); // this one is dropped
    recv!(s, time 1005, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + 6,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"123456"[..],
        ..RECV_TEMPL
    })); // this one is received
    recv!(s, time 1010, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + 6 + 6,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"ABCDEF"[..],
        ..RECV_TEMPL
    })); // also dropped
    recv!(s, time 3000, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abcdef"[..],
        ..RECV_TEMPL
    })); // retransmission
    send!(s, time 3005, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
        ..SEND_TEMPL
    }); // acknowledgement of both segments
    recv!(s, time 3010, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + 6 + 6,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"ABCDEF"[..],
        ..RECV_TEMPL
    })); // retransmission of only unacknowledged data
}

#[test]
fn test_close_wait_retransmit_reset_after_ack() {
    let mut s = socket_close_wait();
    s.remote_win_len = 6;
    s.send_slice(b"abcdef").unwrap();
    s.send_slice(b"123456").unwrap();
    s.send_slice(b"ABCDEF").unwrap();
    recv!(s, time 1000, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1 + 1),
        payload:    &b"abcdef"[..],
        ..RECV_TEMPL
    }));
    send!(s, time 1005, TcpRepr {
        seq_number: REMOTE_SEQ + 1 + 1,
        ack_number: Some(LOCAL_SEQ + 1 + 6),
        window_len: 6,
        ..SEND_TEMPL
    });
    recv!(s, time 1010, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + 6,
        ack_number: Some(REMOTE_SEQ + 1 + 1),
        payload:    &b"123456"[..],
        ..RECV_TEMPL
    }));
    send!(s, time 1015, TcpRepr {
        seq_number: REMOTE_SEQ + 1 + 1,
        ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
        window_len: 6,
        ..SEND_TEMPL
    });
    recv!(s, time 1020, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + 6 + 6,
        ack_number: Some(REMOTE_SEQ + 1 + 1),
        payload:    &b"ABCDEF"[..],
        ..RECV_TEMPL
    }));
}

#[test]
fn test_fin_wait_1_retransmit_reset_after_ack() {
    let mut s = socket_established();
    s.remote_win_len = 6;
    s.send_slice(b"abcdef").unwrap();
    s.send_slice(b"123456").unwrap();
    s.send_slice(b"ABCDEF").unwrap();
    s.close();
    recv!(s, time 1000, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abcdef"[..],
        ..RECV_TEMPL
    }));
    send!(s, time 1005, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1 + 6),
        window_len: 6,
        ..SEND_TEMPL
    });
    recv!(s, time 1010, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + 6,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"123456"[..],
        ..RECV_TEMPL
    }));
    send!(s, time 1015, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
        window_len: 6,
        ..SEND_TEMPL
    });
    recv!(s, time 1020, Ok(TcpRepr {
        control:    TcpControl::Fin,
        seq_number: LOCAL_SEQ + 1 + 6 + 6,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"ABCDEF"[..],
        ..RECV_TEMPL
    }));
}

#[test]
fn test_fast_retransmit_after_triple_duplicate_ack() {
    let mut s = socket_established();
    s.remote_mss = 3;

    // Normal ACK of previously received segment
    send!(s, time 0, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        ..SEND_TEMPL
    });

    // Send a long string of text divided into several packets
    // because of previously received "window_len"
    s.send_slice(b"aaaBBBcccDDDeeeFFF").unwrap();

    // This packet is lost
    recv!(s, time 1000, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"aaa"[..],
        ..RECV_TEMPL
    }));

    // These packets arrive
    recv!(s, time 1005, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + 3,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"BBB"[..],
        ..RECV_TEMPL
    }));
    recv!(s, time 1010, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + (3 * 2),
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"ccc"[..],
        ..RECV_TEMPL
    }));
    recv!(s, time 1015, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + (3 * 3),
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"DDD"[..],
        ..RECV_TEMPL
    }));

    // Duplicate ACKs trigger fast rentramsit after 3rd successive one
    send!(s, time 1050, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        ..SEND_TEMPL
    });
    send!(s, time 1055, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        ..SEND_TEMPL
    });
    send!(s, time 1060, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        ..SEND_TEMPL
    });

    // Fast retransmit should have triggered
    recv!(s, time 1100, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"aaa"[..],
        ..RECV_TEMPL
    }));

    // Transmission should continue as normal after re-transitting the first segment
    recv!(s, time 1105, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + (3 * 4),
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"eee"[..],
        ..RECV_TEMPL
    }));
    recv!(s, time 1110, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + (3 * 5),
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"FFF"[..],
        ..RECV_TEMPL
    }));

    // ACK all received segments
    send!(s, time 1120, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1 + (3 * 5)),
        ..SEND_TEMPL
    });
}

#[test]
fn test_fast_retransmit_duplicate_detection_with_data() {
    let mut s = socket_established();

    s.send_slice(b"abc").unwrap(); // This is lost
    recv!(s, time 1000, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abc"[..],
        ..RECV_TEMPL
    }));

    // Normal ACK of previously received segment
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );
    // First duplicate
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );
    // Second duplicate
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );

    assert_eq!(s.local_rx_dup_acks, 2, "duplicate ACK counter is not set");

    // This packet has content, hence should not be detected
    // as a duplicate ACK and should reset the duplicate ACK count
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"xxxxxx"[..],
            ..SEND_TEMPL
        }
    );

    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 3,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 58,
            ..RECV_TEMPL
        }]
    );

    assert_eq!(
        s.local_rx_dup_acks, 0,
        "duplicate ACK counter is not reset when receiving data"
    );
}

#[test]
fn test_fast_retransmit_duplicate_detection_with_window_update() {
    let mut s = socket_established();

    s.send_slice(b"abc").unwrap(); // This is lost
    recv!(s, time 1000, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abc"[..],
        ..RECV_TEMPL
    }));

    // Normal ACK of previously received segment
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );
    // First duplicate
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );
    // Second duplicate
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );

    assert_eq!(s.local_rx_dup_acks, 2, "duplicate ACK counter is not set");

    // This packet has a window update, hence should not be detected
    // as a duplicate ACK and should reset the duplicate ACK count
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 400,
            ..SEND_TEMPL
        }
    );

    assert_eq!(
        s.local_rx_dup_acks, 0,
        "duplicate ACK counter is not reset when receiving a window update"
    );
}

#[test]
fn test_fast_retransmit_duplicate_detection() {
    let mut s = socket_established();
    s.remote_mss = 6;

    // Normal ACK of previously received segment
    send!(s, time 0, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        ..SEND_TEMPL
    });

    // First duplicate, should not be counted as there is nothing to resend
    send!(s, time 0, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        ..SEND_TEMPL
    });

    assert_eq!(
        s.local_rx_dup_acks, 0,
        "duplicate ACK counter is set but wound not transmit data"
    );

    // Send a long string of text divided into several packets
    // because of small remote_mss
    s.send_slice(b"xxxxxxyyyyyywwwwwwzzzzzz").unwrap();

    // This packet is reordered in network
    recv!(s, time 1000, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"xxxxxx"[..],
        ..RECV_TEMPL
    }));
    recv!(s, time 1005, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + 6,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"yyyyyy"[..],
        ..RECV_TEMPL
    }));
    recv!(s, time 1010, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + (6 * 2),
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"wwwwww"[..],
        ..RECV_TEMPL
    }));
    recv!(s, time 1015, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + (6 * 3),
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"zzzzzz"[..],
        ..RECV_TEMPL
    }));

    // First duplicate ACK
    send!(s, time 1050, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        ..SEND_TEMPL
    });
    // Second duplicate ACK
    send!(s, time 1055, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        ..SEND_TEMPL
    });
    // Reordered packet arrives which should reset duplicate ACK count
    send!(s, time 1060, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1 + (6 * 3)),
        ..SEND_TEMPL
    });

    assert_eq!(
        s.local_rx_dup_acks, 0,
        "duplicate ACK counter is not reset when receiving ACK which updates send window"
    );

    // ACK all received segments
    send!(s, time 1120, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1 + (6 * 4)),
        ..SEND_TEMPL
    });
}

#[test]
fn test_fast_retransmit_dup_acks_counter() {
    let mut s = socket_established();

    s.send_slice(b"abc").unwrap(); // This is lost
    recv!(s, time 0, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abc"[..],
        ..RECV_TEMPL
    }));

    send!(s, time 0, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        ..SEND_TEMPL
    });

    // A lot of retransmits happen here
    s.local_rx_dup_acks = u8::MAX - 1;

    // Send 3 more ACKs, which could overflow local_rx_dup_acks,
    // but intended behaviour is that we saturate the bounds
    // of local_rx_dup_acks
    send!(s, time 0, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        ..SEND_TEMPL
    });
    send!(s, time 0, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        ..SEND_TEMPL
    });
    send!(s, time 0, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        ..SEND_TEMPL
    });
    assert_eq!(
        s.local_rx_dup_acks,
        u8::MAX,
        "duplicate ACK count should not overflow but saturate"
    );
}

#[test]
fn test_fast_retransmit_zero_window_does_not_loop() {
    let mut s = socket_established();

    send!(s, time 1000, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        ..SEND_TEMPL
    });

    s.send_slice(b"abc").unwrap();

    recv!(s, time 1000, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abc"[..],
        ..RECV_TEMPL
    }));

    // 3 dup acks
    send!(s, time 1050, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        ..SEND_TEMPL
    });
    send!(s, time 1050, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        ..SEND_TEMPL
    });
    send!(s, time 1050, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        ..SEND_TEMPL
    });
    // The ack with zero-window does not count as a duplicated ack
    // and will not trigger fast retransmit by itself.
    send!(s, time 1050, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        window_len: 0, // boom
        ..SEND_TEMPL
    });

    // Per RFC 1122 §4.2.2.16 fast retransmit is okay (a MAY) despite the zero-window condition.
    recv!(s, time 1050, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abc"[..],
        ..RECV_TEMPL
    }));

    // Ensure an RTO timer is set in the future (not immediately to avoid a busy loop).
    recv_nothing!(s, time 1051);
    assert_eq!(
        s.socket.poll_at(&mut s.cx),
        PollAt::Time(Instant::from_millis(2050))
    );
}

#[test]
fn test_fast_retransmit_retries_after_failed_emit() {
    let mut s = socket_established();
    s.remote_mss = 1;

    // Baseline ack
    send!(s, time 1000, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        ..SEND_TEMPL
    });

    // We will not get acks for this data
    let data_to_send = b"abc";
    assert_eq!(s.send_slice(data_to_send), Ok(3));
    for (i, chunk) in data_to_send.chunks(s.remote_mss).enumerate() {
        recv!(s, time 1000 + i as i64, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + i,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    chunk,
            ..RECV_TEMPL
        }));
    }

    // Send 3 duplicate ACKs pointing to the "a" segment to trigger fast retransmit
    for _ in 0..3 {
        send!(s, time 1100, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
    }

    // Fail to fast-retransmit
    assert_eq!(
        s.socket.dispatch(&mut s.cx, |_, _, (_, repr)| {
            assert_eq!(repr.payload, &b"a"[..]);
            assert_eq!(repr.seq_number, LOCAL_SEQ + 1);
            Err::<_, ()>(())
        }),
        Err(())
    );
    assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Now);

    // The fast-retransmit should be retried
    recv!(s, time 1200, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"a"[..],
        ..RECV_TEMPL
    }));
    recv_nothing!(s);
    assert_ne!(s.socket.poll_at(&mut s.cx), PollAt::Now);
}

#[test]
fn test_retransmit_exponential_backoff() {
    let mut s = socket_established();
    s.send_slice(b"abcdef").unwrap();
    recv!(s, time 0, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abcdef"[..],
        ..RECV_TEMPL
    }));

    let expected_retransmission_instant = s.rtte.retransmission_timeout().total_millis() as i64;
    recv_nothing!(s, time expected_retransmission_instant - 1);
    recv!(s, time expected_retransmission_instant, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abcdef"[..],
        ..RECV_TEMPL
    }));

    // "current time" is expected_retransmission_instant, and we want to wait 2 * retransmission timeout
    let expected_retransmission_instant = 3 * expected_retransmission_instant;

    recv_nothing!(s, time expected_retransmission_instant - 1);
    recv!(s, time expected_retransmission_instant, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abcdef"[..],
        ..RECV_TEMPL
    }));
}

#[test]
fn test_data_retransmit_ack_more_than_expected() {
    let mut s = socket_established();
    s.remote_mss = 6;
    s.send_slice(b"aaaaaabbbbbbcccccc").unwrap();

    recv!(s, time 0, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"aaaaaa"[..],
        ..RECV_TEMPL
    }));
    recv!(s, time 0, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + 6,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"bbbbbb"[..],
        ..RECV_TEMPL
    }));
    recv!(s, time 0, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + 12,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"cccccc"[..],
        ..RECV_TEMPL
    }));
    recv_nothing!(s, time 0);

    recv_nothing!(s, time 50);

    // retransmit timer expires, we want to retransmit all 3 packets
    // but we only manage to retransmit 2 (due to e.g. lack of device buffer space)
    assert!(s.timer.is_retransmit());
    recv!(s, time 1000, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"aaaaaa"[..],
        ..RECV_TEMPL
    }));
    recv!(s, time 1000, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + 6,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"bbbbbb"[..],
        ..RECV_TEMPL
    }));

    // ack first packet.
    send!(
        s,
        time 3000,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            ..SEND_TEMPL
        }
    );

    // this should keep retransmit timer on, because there's
    // still unacked data.
    assert!(s.timer.is_retransmit());

    // ack all three packets.
    // This might confuse the TCP stack because after the retransmit
    // it "thinks" the 3rd packet hasn't been transmitted yet, but it is getting acked.
    send!(
        s,
        time 3000,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 18),
            ..SEND_TEMPL
        }
    );

    // this should exit retransmit mode.
    assert!(!s.timer.is_retransmit());
    // and consider all data ACKed.
    assert!(s.tx_buffer.is_empty());
    recv_nothing!(s, time 5000);
}

#[test]
fn test_retransmit_fin() {
    let mut s = socket_established();
    s.close();
    recv!(s, time 0, Ok(TcpRepr {
        control: TcpControl::Fin,
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        ..RECV_TEMPL
    }));

    recv_nothing!(s, time 999);
    recv!(s, time 1000, Ok(TcpRepr {
        control: TcpControl::Fin,
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        ..RECV_TEMPL
    }));
}

#[test]
fn test_retransmit_fin_wait() {
    let mut s = socket_fin_wait_1();
    // we send FIN
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }]
    );
    // remote also sends FIN, does NOT ack ours.
    send!(
        s,
        TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );
    // we ack it
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::None,
            seq_number: LOCAL_SEQ + 2,
            ack_number: Some(REMOTE_SEQ + 2),
            ..RECV_TEMPL
        }]
    );

    // we haven't got an ACK for our FIN, we should retransmit.
    recv_nothing!(s, time 999);
    recv!(
        s,
        time 1000,
        [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 2),
            ..RECV_TEMPL
        }]
    );
    recv_nothing!(s, time 2999);
    recv!(
        s,
        time 3000,
        [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 2),
            ..RECV_TEMPL
        }]
    );
}

#[test]
fn test_zero_window_probe_after_rto() {
    let mut s = socket_established();

    s.send_slice(b"abcdef").unwrap();
    recv!(s, time 0, Ok(TcpRepr {
        control:    TcpControl::Psh,
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abcdef"[..],
        ..RECV_TEMPL
    }), exact);

    // Retransmit timer is armed.
    assert_eq!(
        s.socket.poll_at(&mut s.cx),
        PollAt::Time(Instant::from_millis(1000))
    );

    // Close the window, no ack.
    send!(s, time 600, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        window_len: 0,
        ..SEND_TEMPL
    });
    // Retransmit timer is untouched as nothing was Ack'ed.
    assert_eq!(
        s.socket.poll_at(&mut s.cx),
        PollAt::Time(Instant::from_millis(1000))
    );

    recv_nothing!(s, time 999);
    // Timer expires, but window is closed.
    recv_nothing!(s, time 1000);

    // Expect a zero-window probe to be scheduled.
    assert_eq!(
        s.socket.poll_at(&mut s.cx),
        PollAt::Time(Instant::from_millis(3000))
    );

    // Per RFC 9293 §3.8.6.1 we expect a 1 byte probe to be sent.
    recv!(s, time 3000, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"a"[..],
        ..RECV_TEMPL
    }), exact);
    // Exponential backoff of the zero-window probe timer.
    assert_eq!(
        s.socket.poll_at(&mut s.cx),
        PollAt::Time(Instant::from_millis(7000))
    );
    recv!(s, time 7000, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"a"[..],
        ..RECV_TEMPL
    }), exact);

    // Open the window.
    send!(s, time 8000, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        window_len: 64,
        ..SEND_TEMPL
    });

    // Data is resent as the window is now open.
    recv!(s, time 8000, Ok(TcpRepr {
        control:    TcpControl::Psh,
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abcdef"[..],
        ..RECV_TEMPL
    }), exact);
    // The retransmit timer is armed again.
    assert_eq!(
        s.socket.poll_at(&mut s.cx),
        PollAt::Time(Instant::from_millis(10000))
    );
}

#[test]
fn test_timer_retransmit() {
    const RTO: Duration = Duration::from_millis(100);
    let mut r = Timer::new();
    assert!(!r.should_retransmit(Instant::from_secs(1)));
    r.set_for_retransmit(Instant::from_millis(1000), RTO);
    assert!(!r.should_retransmit(Instant::from_millis(1000)));
    assert!(!r.should_retransmit(Instant::from_millis(1050)));
    assert!(r.should_retransmit(Instant::from_millis(1101)));
    r.set_for_retransmit(Instant::from_millis(1101), RTO);
    assert!(!r.should_retransmit(Instant::from_millis(1101)));
    assert!(!r.should_retransmit(Instant::from_millis(1150)));
    assert!(!r.should_retransmit(Instant::from_millis(1200)));
    assert!(r.should_retransmit(Instant::from_millis(1301)));
    r.set_for_idle(Instant::from_millis(1301), None);
    assert!(!r.should_retransmit(Instant::from_millis(1350)));
}

#[test]
fn test_rtt_estimator() {
    let mut r = RttEstimator::default();

    let rtos = &[
        6000, 5000, 4252, 3692, 3272, 2956, 2720, 2540, 2408, 2308, 2232, 2176, 2132, 2100,
        2076, 2060, 2048, 2036, 2028, 2024, 2020, 2016, 2012, 2012,
    ];

    for &rto in rtos {
        r.sample(2000);
        assert_eq!(r.retransmission_timeout(), Duration::from_millis(rto));
    }
}

#[test]
fn test_rtt_estimator_min_rto() {
    let mut r = RttEstimator {
        min_rto: 10,
        initial_rto: 10,
        ..Default::default()
    };

    // Imitate a sub-millisecond link which samples as 0ms.
    r.sample(0);
    assert_eq!(r.retransmission_timeout(), Duration::from_millis(10));

    // With the RFC floor the same link gets a 1s RTO instead. Terrible.
    r.min_rto = 1000;
    r.sample(0);
    assert_eq!(r.retransmission_timeout(), Duration::from_millis(1000));
}

#[test]
fn test_set_get_rto() {
    let mut s = socket_established();

    assert_eq!(s.min_rto(), Duration::from_millis(1000));
    assert_eq!(s.initial_rto(), Duration::from_millis(1000));

    s.set_min_rto(Duration::from_millis(20));
    s.set_initial_rto(Duration::from_millis(50));
    assert_eq!(s.min_rto(), Duration::from_millis(20));
    assert_eq!(s.initial_rto(), Duration::from_millis(50));

    // It gets the clamps (otherwise u16 is bad idea.)
    s.set_min_rto(Duration::from_millis(0));
    assert_eq!(s.min_rto(), Duration::from_millis(1));
    s.set_min_rto(Duration::from_secs(120));
    assert_eq!(s.min_rto(), Duration::from_millis(60_000));
}

#[test]
fn test_set_min_rto_raises_current_rto() {
    let mut s = socket_established();
    s.set_min_rto(Duration::from_millis(20));

    s.rtte.sample(1);
    assert_eq!(s.rtte.retransmission_timeout(), Duration::from_millis(20));

    // Raising the floor applies to the connection in progress.
    s.set_min_rto(Duration::from_millis(500));
    assert_eq!(s.rtte.retransmission_timeout(), Duration::from_millis(500));
}

#[test]
fn test_set_initial_rto_does_not_undo_backoff() {
    let mut s = socket_established();
    s.set_initial_rto(Duration::from_millis(50));
    assert_eq!(s.rtte.retransmission_timeout(), Duration::from_millis(50));

    // Three consecutive timeouts wrap rto_count back to zero, so the guard
    // cannot rely on it alone.
    for _ in 0..3 {
        s.rtte.on_rto();
    }
    assert_eq!(s.rtte.rto_count, 0);
    assert_eq!(s.rtte.retransmission_timeout(), Duration::from_millis(400));

    // The backed-off RTO must survive; RFC 6298 (5.5) makes the backoff a MUST.
    s.set_initial_rto(Duration::from_millis(50));
    assert_eq!(s.rtte.retransmission_timeout(), Duration::from_millis(400));
    assert_eq!(s.initial_rto(), Duration::from_millis(50));
}

#[test]
fn test_rto_config_survives_reset() {
    let mut s = socket_established();
    s.set_min_rto(Duration::from_millis(20));
    s.set_initial_rto(Duration::from_millis(50));
    s.rtte.sample(400);

    // listen() and connect() both go through reset().
    s.reset();

    assert_eq!(s.min_rto(), Duration::from_millis(20));
    assert_eq!(s.initial_rto(), Duration::from_millis(50));
    assert!(!s.rtte.have_measurement);
    assert_eq!(s.rtte.retransmission_timeout(), Duration::from_millis(50));
}

#[test]
fn test_set_get_congestion_control() {
    let mut s = socket_established();

    {
        s.set_congestion_control(CongestionControl::Reno);
        assert_eq!(s.congestion_control(), CongestionControl::Reno);
    }

    {
        s.set_congestion_control(CongestionControl::Cubic);
        assert_eq!(s.congestion_control(), CongestionControl::Cubic);
    }

    s.set_congestion_control(CongestionControl::None);
    assert_eq!(s.congestion_control(), CongestionControl::None);
}
