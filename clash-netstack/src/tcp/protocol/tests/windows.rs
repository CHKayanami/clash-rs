// Derived from smoltcp; see ../LICENSE-0BSD.txt.
use super::*;

#[test]
fn test_close_wait_no_window_update() {
    let mut s = socket_established();
    send!(
        s,
        TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &[1, 2, 3, 4],
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::CloseWait);

    // we ack the FIN, with the reduced window size.
    recv!(
        s,
        Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 6),
            window_len: 60,
            ..RECV_TEMPL
        })
    );

    let rx_buf = &mut [0; 32];
    assert_eq!(s.recv_slice(rx_buf), Ok(4));

    // check that we do NOT send a window update even if it has changed.
    recv_nothing!(s);
}

#[test]
fn test_time_wait_no_window_update() {
    let mut s = socket_fin_wait_2();
    send!(
        s,
        TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 2),
            payload: &[1, 2, 3, 4],
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::TimeWait);

    // we ack the FIN, with the reduced window size.
    recv!(
        s,
        Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 2,
            ack_number: Some(REMOTE_SEQ + 6),
            window_len: 60,
            ..RECV_TEMPL
        })
    );

    let rx_buf = &mut [0; 32];
    assert_eq!(s.recv_slice(rx_buf), Ok(4));

    // check that we do NOT send a window update even if it has changed.
    recv_nothing!(s);
}

#[test]
fn test_zero_window_ack() {
    let mut s = socket_established();
    s.rx_buffer = SocketBuffer::new(vec![0; 6]);
    s.assembler = Assembler::new();
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        }
    );
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 0,
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 6,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"123456"[..],
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 0,
            ..RECV_TEMPL
        })
    );
}

#[test]
fn test_zero_window_ack_not_rate_limited() {
    let mut s = socket_established();
    s.rx_buffer = SocketBuffer::new(vec![0; 6]);
    s.assembler = Assembler::new();
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        }
    );
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 0,
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 6,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"123456"[..],
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 0,
            ..RECV_TEMPL
        })
    );
    // The remote retransmits into the zero window again within a second,
    // e.g. because the ACK above was lost. The ACK must not be withheld by
    // challenge ACK rate limiting: it is the remote's only way to learn
    // the window state, and a data segment cannot cause an ACK loop.
    send!(
        s,
        time 100,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 6,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"123456"[..],
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 0,
            ..RECV_TEMPL
        })
    );
}

#[test]
fn test_zero_window_fin() {
    let mut s = socket_established();
    s.rx_buffer = SocketBuffer::new(vec![0; 6]);
    s.assembler = Assembler::new();
    s.ack_delay = None;

    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        }
    );
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 0,
            ..RECV_TEMPL
        }]
    );

    // Even though the sequence space for the FIN itself is outside the window,
    // it is not data, so FIN must be accepted when window full.
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 6,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &[],
            control: TcpControl::Fin,
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::CloseWait);
    assert_eq!(s.last_scaled_window(), Some(0));

    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 7),
            window_len: 0,
            ..RECV_TEMPL
        }]
    );
}

#[test]
fn test_zero_window_ack_on_window_growth() {
    let mut s = socket_established();
    s.rx_buffer = SocketBuffer::new(vec![0; 6]);
    s.assembler = Assembler::new();
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        }
    );
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 0,
            ..RECV_TEMPL
        }]
    );
    recv_nothing!(s, time 0);
    s.recv(|buffer| {
        assert_eq!(&buffer[..3], b"abc");
        (3, ())
    })
    .unwrap();
    recv!(s, time 0, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1 + 6),
        window_len: 3,
        ..RECV_TEMPL
    }));
    recv_nothing!(s, time 0);
    s.recv(|buffer| {
        assert_eq!(buffer, b"def");
        (buffer.len(), ())
    })
    .unwrap();
    recv!(s, time 0, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1 + 6),
        window_len: 6,
        ..RECV_TEMPL
    }));
}

#[test]
fn test_window_update_with_delay_ack() {
    let mut s = socket_established_with_buffer_sizes(6, 6);
    s.ack_delay = Some(Duration::from_millis(10));

    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        }
    );

    recv_nothing!(s, time 5);

    s.recv(|buffer| {
        assert_eq!(&buffer[..2], b"ab");
        (2, ())
    })
    .unwrap();
    recv!(
        s,
        time 5,
        Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 2,
            ..RECV_TEMPL
        })
    );

    s.recv(|buffer| {
        assert_eq!(&buffer[..1], b"c");
        (1, ())
    })
    .unwrap();
    recv_nothing!(s, time 5);

    s.recv(|buffer| {
        assert_eq!(&buffer[..1], b"d");
        (1, ())
    })
    .unwrap();
    recv!(
        s,
        time 5,
        Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 4,
            ..RECV_TEMPL
        })
    );
}

#[test]
fn test_announce_window_after_read() {
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
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            window_len: 3,
            ..RECV_TEMPL
        }]
    );
    // Test that `dispatch` updates `remote_last_win_len`
    assert_eq!(s.remote_last_win_len, s.rx_buffer.window());
    s.recv(|buffer| (buffer.len(), ())).unwrap();
    assert!(s.window_to_update());
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            window_len: 6,
            ..RECV_TEMPL
        }]
    );
    assert_eq!(s.remote_last_win_len, s.rx_buffer.window());
    // Provoke immediate ACK to test that `process` updates `remote_last_win_len`
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 6,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"def"[..],
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            window_len: 6,
            ..RECV_TEMPL
        })
    );
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 3,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abc"[..],
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 9),
            window_len: 0,
            ..RECV_TEMPL
        })
    );
    assert_eq!(s.remote_last_win_len, s.rx_buffer.window());
    s.recv(|buffer| (buffer.len(), ())).unwrap();
    assert!(s.window_to_update());
}

#[test]
fn test_zero_window_probe_enter_on_win_update() {
    let mut s = socket_established();

    assert!(!s.timer.is_zero_window_probe());

    s.send_slice(b"abcdef123456!@#$%^").unwrap();

    assert!(!s.timer.is_zero_window_probe());

    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            ..SEND_TEMPL
        }
    );

    assert!(s.timer.is_zero_window_probe());
}

#[test]
fn test_zero_window_probe_enter_on_send() {
    let mut s = socket_established();

    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            ..SEND_TEMPL
        }
    );

    assert!(!s.timer.is_zero_window_probe());

    s.send_slice(b"abcdef123456!@#$%^").unwrap();

    assert!(s.timer.is_zero_window_probe());
}

#[test]
fn test_zero_window_probe_exit() {
    let mut s = socket_established();

    s.send_slice(b"abcdef123456!@#$%^").unwrap();

    assert!(!s.timer.is_zero_window_probe());

    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            ..SEND_TEMPL
        }
    );

    assert!(s.timer.is_zero_window_probe());

    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 6,
            ..SEND_TEMPL
        }
    );

    assert!(!s.timer.is_zero_window_probe());
}

#[test]
fn test_zero_window_probe_exit_ack() {
    let mut s = socket_established();

    s.send_slice(b"abcdef123456!@#$%^").unwrap();
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            ..SEND_TEMPL
        }
    );

    recv!(
        s,
        time 1000,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"a"[..],
            ..RECV_TEMPL
        }]
    );

    send!(
        s,
        time 1010,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 2),
            window_len: 6,
            ..SEND_TEMPL
        }
    );

    recv!(
        s,
        time 1010,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 2,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"bcdef1"[..],
            ..RECV_TEMPL
        }]
    );
}

#[test]

fn test_zero_window_probe_not_capped_by_cwnd() {
    let mut s = socket_established_with_buffer_sizes(8192, 64);
    s.set_congestion_control(CongestionControl::Reno);
    s.remote_win_len = 65535;
    s.remote_mss = 1024;

    let data = [b'x'; 4096];
    s.send_slice(&data[..]).unwrap();

    // Reno's initial cwnd is 2048: two segments fill the congestion window
    // exactly, leaving cwnd_remaining() == 0.
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

    // The remote closes its window without acknowledging anything new, so
    // no congestion window space is freed either.
    send!(s, time 10, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        window_len: 0,
        ..SEND_TEMPL
    });

    // Arm the probe timer. (Set directly because the ACK above carries no
    // new data; in real traffic this state is reached e.g. when the
    // controller shrinks cwnd below the flight size while probing.)
    s.timer
        .set_for_zero_window_probe(Instant::from_millis(10), Duration::from_millis(100));

    // The probe must carry 1 byte of data past the window edge even though
    // the congestion window is exhausted: an empty probe occupies no
    // sequence space and elicits no reply, so the connection would stall
    // if the remote's window update got lost.
    recv!(s, time 110, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1 + 2048,
        ack_number: Some(REMOTE_SEQ + 1),
        payload: &data[..1],
        ..RECV_TEMPL
    }));
}

#[test]
fn test_zero_window_probe_backoff_nack_reply() {
    let mut s = socket_established();
    s.send_slice(b"abcdef123456!@#$%^").unwrap();
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            ..SEND_TEMPL
        }
    );

    recv_nothing!(s, time 999);
    recv!(
        s,
        time 1000,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"a"[..],
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        time 1100,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            ..SEND_TEMPL
        }
    );

    recv_nothing!(s, time 2999);
    recv!(
        s,
        time 3000,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"a"[..],
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        time 3100,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            ..SEND_TEMPL
        }
    );

    recv_nothing!(s, time 6999);
    recv!(
        s,
        time 7000,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"a"[..],
            ..RECV_TEMPL
        }]
    );
}

#[test]
fn test_zero_window_probe_backoff_no_reply() {
    let mut s = socket_established();
    s.send_slice(b"abcdef123456!@#$%^").unwrap();
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            ..SEND_TEMPL
        }
    );

    recv_nothing!(s, time 999);
    recv!(
        s,
        time 1000,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"a"[..],
            ..RECV_TEMPL
        }]
    );

    recv_nothing!(s, time 2999);
    recv!(
        s,
        time 3000,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"a"[..],
            ..RECV_TEMPL
        }]
    );
}

#[test]
fn test_zero_window_probe_shift() {
    let mut s = socket_established();

    s.send_slice(b"abcdef123456!@#$%^").unwrap();
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            ..SEND_TEMPL
        }
    );

    recv_nothing!(s, time 999);
    recv!(
        s,
        time 1000,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"a"[..],
            ..RECV_TEMPL
        }]
    );

    recv_nothing!(s, time 2999);
    recv!(
        s,
        time 3000,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"a"[..],
            ..RECV_TEMPL
        }]
    );

    // ack the ZWP byte, but still advertise zero window.
    // this should restart the ZWP timer.
    send!(
        s,
        time 3100,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 2),
            window_len: 0,
            ..SEND_TEMPL
        }
    );

    // ZWP should be sent at 3100+1000 = 4100
    recv_nothing!(s, time 4099);
    recv!(
        s,
        time 4100,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 2,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"b"[..],
            ..RECV_TEMPL
        }]
    );
}

#[test]
fn test_zero_window_reopens_inflight_data() {
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

    // Acknowledge the first packet but set the window to zero.
    send!(s, time 100, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1 + 6),
        window_len: 0,
        ..SEND_TEMPL
    });
    // Retransmit timer is armed (RFC 6298 (5.3)).
    assert_eq!(
        s.socket.poll_at(&mut s.cx),
        PollAt::Time(Instant::from_millis(1100))
    );

    recv_nothing!(s, time 1099);
    // Retransmit timer fires but the window is closed so nothing is received.
    recv_nothing!(s, time 1100);
    // Zero-window probe timer is armed (RFC 9293 §3.8.6.1)
    assert_eq!(
        s.socket.poll_at(&mut s.cx),
        PollAt::Time(Instant::from_millis(3100))
    );

    // Reopen the window.
    send!(s, time 2000, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1 + 6),
        window_len: 64,
        ..SEND_TEMPL
    });

    // The window is reopened, so the in-flight data is resent immediately.
    assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Now);
    recv!(s, time 2000, Ok(TcpRepr {
        control:    TcpControl::Psh,
        seq_number: LOCAL_SEQ + 1 + 6,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"012345"[..],
        ..RECV_TEMPL
    }), exact);
    // Retransmit timer is armed.
    assert_eq!(
        s.socket.poll_at(&mut s.cx),
        PollAt::Time(Instant::from_millis(4000))
    );
}
