// Derived from smoltcp; see ../LICENSE-0BSD.txt.
use super::*;

#[test]
fn test_closed_reject() {
    let mut s = socket();
    assert_eq!(s.state, State::Closed);

    let tcp_repr = TcpRepr {
        control: TcpControl::Syn,
        ..SEND_TEMPL
    };
    assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
}

#[test]
fn test_closed_reject_after_listen() {
    let mut s = socket();
    s.listen(LOCAL_END).unwrap();
    s.close();

    let tcp_repr = TcpRepr {
        control: TcpControl::Syn,
        ..SEND_TEMPL
    };
    assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
}

#[test]
fn test_closed_close() {
    let mut s = socket();
    s.close();
    assert_eq!(s.state, State::Closed);
}

#[test]
fn test_listen_sack_option() {
    let mut s = socket_listen();
    send!(
        s,
        TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            sack_permitted: false,
            ..SEND_TEMPL
        }
    );
    assert!(!s.remote_has_sack);
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }]
    );

    let mut s = socket_listen();
    send!(
        s,
        TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            sack_permitted: true,
            ..SEND_TEMPL
        }
    );
    assert!(s.remote_has_sack);
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            sack_permitted: true,
            ..RECV_TEMPL
        }]
    );
}

#[test]
fn test_listen_syn_win_scale_buffers() {
    for (buffer_size, shift_amt) in &[
        (64, 0),
        (128, 0),
        (1024, 0),
        (65535, 0),
        (65536, 1),
        (65537, 1),
        (131071, 1),
        (131072, 2),
        (524287, 3),
        (524288, 4),
        (655350, 4),
        (1048576, 5),
    ] {
        let mut s = socket_with_buffer_sizes(64, *buffer_size);
        s.state = State::Listen;
        s.listen_endpoint = LISTEN_END;
        assert_eq!(s.remote_win_shift, *shift_amt);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.remote_win_shift, *shift_amt);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(*shift_amt),
                window_len: u16::try_from(*buffer_size).unwrap_or(u16::MAX),
                ..RECV_TEMPL
            }]
        );
    }
}

#[test]
fn test_listen_syn_tiny_mss_is_clamped() {
    let mut s = socket_listen();
    send!(
        s,
        TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            max_seg_size: Some(10),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::SynReceived);
    assert_eq!(s.remote_mss, MIN_REMOTE_MSS);
}

#[test]
fn test_listen_syn_zero_mss_is_ignored() {
    let mut s = socket_listen();
    send!(
        s,
        TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            max_seg_size: Some(0),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::SynReceived);
    assert_eq!(s.remote_mss, DEFAULT_MSS);
}

#[test]
fn test_listen_sanity() {
    let mut s = socket();
    s.listen(LOCAL_PORT).unwrap();
    sanity!(s, socket_listen());
}

#[test]
fn test_listen_validation() {
    let mut s = socket();
    assert_eq!(s.listen(0), Err(ListenError::Unaddressable));
}

#[test]
fn test_listen_twice() {
    let mut s = socket();
    assert_eq!(s.listen(80), Ok(()));
    // multiple calls to listen are okay if its the same local endpoint and the state is still in listening
    assert_eq!(s.listen(80), Ok(()));
    s.set_state(State::SynReceived); // state change, simulate incoming connection
    assert_eq!(s.listen(80), Err(ListenError::InvalidState));
}

#[test]
fn test_listen_syn() {
    let mut s = socket_listen();
    send!(
        s,
        TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            ..SEND_TEMPL
        }
    );
    sanity!(s, socket_syn_received());
}

#[test]
fn test_listen_syn_reject_ack() {
    let mut s = socket_listen();

    let tcp_repr = TcpRepr {
        control: TcpControl::Syn,
        seq_number: REMOTE_SEQ,
        ack_number: Some(LOCAL_SEQ),
        ..SEND_TEMPL
    };
    assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));

    assert_eq!(s.state, State::Listen);
}

#[test]
fn test_listen_rst() {
    let mut s = socket_listen();
    let tcp_repr = TcpRepr {
        control: TcpControl::Rst,
        seq_number: REMOTE_SEQ,
        ack_number: None,
        ..SEND_TEMPL
    };
    assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
    assert_eq!(s.state, State::Listen);
}

#[test]
fn test_listen_close() {
    let mut s = socket_listen();
    s.close();
    assert_eq!(s.state, State::Closed);
}

#[test]
fn test_syn_received_ack() {
    let mut s = socket_syn_received();
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Established);
    sanity!(s, socket_established());
}

#[test]
fn test_syn_received_ack_too_low() {
    let mut s = socket_syn_received();
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ), // wrong
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            control: TcpControl::Rst,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            window_len: 0,
            ..RECV_TEMPL
        })
    );
    assert_eq!(s.state, State::SynReceived);
}

#[test]
fn test_syn_received_ack_too_high() {
    let mut s = socket_syn_received();
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 2), // wrong
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            control: TcpControl::Rst,
            seq_number: LOCAL_SEQ + 2,
            ack_number: None,
            window_len: 0,
            ..RECV_TEMPL
        })
    );
    assert_eq!(s.state, State::SynReceived);
}

#[test]
fn test_syn_received_fin() {
    let mut s = socket_syn_received();
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            control: TcpControl::Fin,
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
            ack_number: Some(REMOTE_SEQ + 1 + 6 + 1),
            window_len: 58,
            ..RECV_TEMPL
        }]
    );
    assert_eq!(s.state, State::CloseWait);

    let mut s2 = socket_close_wait();
    s2.remote_last_ack = Some(REMOTE_SEQ + 1 + 6 + 1);
    s2.remote_last_win_len = 58;
    sanity!(s, s2);
}

#[test]
fn test_syn_received_rst() {
    let mut s = socket_syn_received();
    s.listen_endpoint = LISTEN_END;
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Listen);
    assert_eq!(s.listen_endpoint, LISTEN_END);
    assert_eq!(s.tuple, None);
}

#[test]
fn test_syn_received_no_window_scaling() {
    let mut s = socket_listen();
    send!(
        s,
        TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state(), State::SynReceived);
    assert_eq!(s.tuple, Some(TUPLE));
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            window_scale: None,
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_scale: None,
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.remote_win_shift, 0);
    assert_eq!(s.remote_win_scale, None);
}

#[test]
fn test_syn_received_window_scaling() {
    for scale in 0..14 {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                window_scale: Some(scale),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_scale: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.remote_win_scale, Some(scale));
    }
}

#[test]
fn test_syn_received_close() {
    let mut s = socket_syn_received();
    s.close();
    assert_eq!(s.state, State::FinWait1);
}

#[test]
fn test_connect_validation() {
    let mut s = socket();
    assert_eq!(
        s.socket
            .connect(&mut s.cx, REMOTE_END, (IpvXAddress::UNSPECIFIED, 0)),
        Err(ConnectError::Unaddressable)
    );
    assert_eq!(
        s.socket
            .connect(&mut s.cx, REMOTE_END, (IpvXAddress::UNSPECIFIED, 1024)),
        Err(ConnectError::Unaddressable)
    );
    assert_eq!(
        s.socket
            .connect(&mut s.cx, (IpvXAddress::UNSPECIFIED, 0), LOCAL_END),
        Err(ConnectError::Unaddressable)
    );
    s.socket
        .connect(&mut s.cx, REMOTE_END, LOCAL_END)
        .expect("Connect failed with valid parameters");
    assert_eq!(s.tuple, Some(TUPLE));
}

#[test]
fn test_connect() {
    let mut s = socket();
    s.local_seq_no = LOCAL_SEQ;
    s.socket
        .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
        .unwrap();
    assert_eq!(s.tuple, Some(TUPLE));
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            window_scale: Some(0),
            sack_permitted: true,
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ + 1),
            max_seg_size: Some(BASE_MSS - 80),
            window_scale: Some(0),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.tuple, Some(TUPLE));
}

#[test]
fn test_connect_synack_tiny_mss_is_clamped() {
    let mut s = socket();
    s.local_seq_no = LOCAL_SEQ;
    s.socket
        .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
        .unwrap();
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            window_scale: Some(0),
            sack_permitted: true,
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ + 1),
            max_seg_size: Some(10),
            window_scale: Some(0),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Established);
    assert_eq!(s.remote_mss, MIN_REMOTE_MSS);
}

#[test]
fn test_connect_synack_zero_mss_is_ignored() {
    let mut s = socket();
    s.local_seq_no = LOCAL_SEQ;
    s.socket
        .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
        .unwrap();
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            window_scale: Some(0),
            sack_permitted: true,
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ + 1),
            max_seg_size: Some(0),
            window_scale: Some(0),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Established);
    assert_eq!(s.remote_mss, DEFAULT_MSS);
}

#[test]
fn test_connect_unspecified_local() {
    let mut s = socket();
    assert_eq!(s.socket.connect(&mut s.cx, REMOTE_END, 80), Ok(()));
}

#[test]
fn test_connect_specified_local() {
    let mut s = socket();
    assert_eq!(
        s.socket.connect(&mut s.cx, REMOTE_END, (REMOTE_ADDR, 80)),
        Ok(())
    );
}

#[test]
fn test_connect_twice() {
    let mut s = socket();
    assert_eq!(s.socket.connect(&mut s.cx, REMOTE_END, 80), Ok(()));
    assert_eq!(
        s.socket.connect(&mut s.cx, REMOTE_END, 80),
        Err(ConnectError::InvalidState)
    );
}

#[test]
fn test_syn_sent_sanity() {
    let mut s = socket();
    s.local_seq_no = LOCAL_SEQ;
    s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
    sanity!(s, socket_syn_sent());
}

#[test]
fn test_syn_sent_syn_ack() {
    let mut s = socket_syn_sent();
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            window_scale: Some(0),
            sack_permitted: true,
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ + 1),
            max_seg_size: Some(BASE_MSS - 80),
            window_scale: Some(0),
            ..SEND_TEMPL
        }
    );
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }]
    );
    recv_nothing!(s, time 1000);
    assert_eq!(s.state, State::Established);
    sanity!(s, socket_established());
}

#[test]
fn test_syn_sent_syn_received_ack() {
    let mut s = socket_syn_sent();
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            window_scale: Some(0),
            sack_permitted: true,
            ..RECV_TEMPL
        }]
    );

    // A SYN packet changes the SYN-SENT state to SYN-RECEIVED.
    send!(
        s,
        TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS - 80),
            window_scale: Some(0),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::SynReceived);

    // The socket will then send a SYN|ACK packet.
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            window_scale: Some(0),
            ..RECV_TEMPL
        }]
    );
    recv_nothing!(s);

    // The socket may retransmit the SYN|ACK packet.
    recv!(
        s,
        time 1001,
        Ok(TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            window_scale: Some(0),
            ..RECV_TEMPL
        })
    );

    // An ACK packet changes the SYN-RECEIVED state to ESTABLISHED.
    send!(
        s,
        TcpRepr {
            control: TcpControl::None,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Established);
    sanity!(s, socket_established());
}

#[test]
fn test_syn_sent_syn_ack_not_incremented() {
    let mut s = socket_syn_sent();
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            window_scale: Some(0),
            sack_permitted: true,
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ), // WRONG
            max_seg_size: Some(BASE_MSS - 80),
            window_scale: Some(0),
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            control: TcpControl::Rst,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            window_len: 0,
            ..RECV_TEMPL
        })
    );
    assert_eq!(s.state, State::SynSent);
}

#[test]
fn test_syn_sent_syn_received_rst() {
    let mut s = socket_syn_sent();
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            window_scale: Some(0),
            sack_permitted: true,
            ..RECV_TEMPL
        }]
    );

    // A SYN packet changes the SYN-SENT state to SYN-RECEIVED.
    send!(
        s,
        TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS - 80),
            window_scale: Some(0),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::SynReceived);

    // A RST packet changes the SYN-RECEIVED state to CLOSED.
    send!(
        s,
        TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Closed);
}

#[test]
fn test_syn_sent_rst() {
    let mut s = socket_syn_sent();
    send!(
        s,
        TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Closed);
}

#[test]
fn test_syn_sent_rst_no_ack() {
    let mut s = socket_syn_sent();
    send!(
        s,
        TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::SynSent);
}

#[test]
fn test_syn_sent_rst_bad_ack() {
    let mut s = socket_syn_sent();
    send!(
        s,
        TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ,
            ack_number: Some(TcpSeqNumber(1234)),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::SynSent);
}

#[test]
fn test_syn_sent_bad_ack() {
    let mut s = socket_syn_sent();
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            window_scale: Some(0),
            sack_permitted: true,
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            control: TcpControl::None, // Unexpected
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ + 1), // Correct
            ..SEND_TEMPL
        }
    );

    // It should trigger no response and change no state
    recv!(s, []);
    assert_eq!(s.state, State::SynSent);
}

#[test]
fn test_syn_sent_bad_ack_seq_1() {
    let mut s = socket_syn_sent();
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            window_scale: Some(0),
            sack_permitted: true,
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            control: TcpControl::None,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ), // WRONG
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            control: TcpControl::Rst,
            seq_number: LOCAL_SEQ, // matching the ack_number of the unexpected ack
            ack_number: None,
            window_len: 0,
            ..RECV_TEMPL
        })
    );

    // It should trigger a RST, and change no state
    assert_eq!(s.state, State::SynSent);
}

#[test]
fn test_syn_sent_bad_ack_seq_2() {
    let mut s = socket_syn_sent();
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            window_scale: Some(0),
            sack_permitted: true,
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            control: TcpControl::None,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ + 123456), // WRONG
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            control: TcpControl::Rst,
            seq_number: LOCAL_SEQ + 123456, // matching the ack_number of the unexpected ack
            ack_number: None,
            window_len: 0,
            ..RECV_TEMPL
        })
    );

    // It should trigger a RST, and change no state
    assert_eq!(s.state, State::SynSent);
}

#[test]
fn test_syn_sent_close() {
    let mut s = socket();
    s.close();
    assert_eq!(s.state, State::Closed);
}

#[test]
fn test_syn_sent_sack_option() {
    let mut s = socket_syn_sent();
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            window_scale: Some(0),
            sack_permitted: true,
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ + 1),
            max_seg_size: Some(BASE_MSS - 80),
            window_scale: Some(0),
            sack_permitted: true,
            ..SEND_TEMPL
        }
    );
    assert!(s.remote_has_sack);

    let mut s = socket_syn_sent();
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            window_scale: Some(0),
            sack_permitted: true,
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ + 1),
            max_seg_size: Some(BASE_MSS - 80),
            window_scale: Some(0),
            sack_permitted: false,
            ..SEND_TEMPL
        }
    );
    assert!(!s.remote_has_sack);
}

#[test]
fn test_syn_sent_win_scale_buffers() {
    for (buffer_size, shift_amt) in &[
        (64, 0),
        (128, 0),
        (1024, 0),
        (65535, 0),
        (65536, 1),
        (65537, 1),
        (131071, 1),
        (131072, 2),
        (524287, 3),
        (524288, 4),
        (655350, 4),
        (1048576, 5),
    ] {
        let mut s = socket_with_buffer_sizes(64, *buffer_size);
        s.local_seq_no = LOCAL_SEQ;
        assert_eq!(s.remote_win_shift, *shift_amt);
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(*shift_amt),
                window_len: u16::try_from(*buffer_size).unwrap_or(u16::MAX),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
    }
}

#[test]
fn test_syn_sent_syn_ack_no_window_scaling() {
    let mut s = socket_syn_sent_with_buffer_sizes(1048576, 1048576);
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            // scaling does NOT apply to the window value in SYN packets
            window_len: 65535,
            window_scale: Some(5),
            sack_permitted: true,
            ..RECV_TEMPL
        }]
    );
    assert_eq!(s.remote_win_shift, 5);
    send!(
        s,
        TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ + 1),
            max_seg_size: Some(BASE_MSS - 80),
            window_scale: None,
            window_len: 42,
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Established);
    assert_eq!(s.remote_win_shift, 0);
    assert_eq!(s.remote_win_scale, None);
    assert_eq!(s.remote_win_len, 42);
}

#[test]
fn test_syn_sent_syn_ack_window_scaling() {
    let mut s = socket_syn_sent();
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            window_scale: Some(0),
            sack_permitted: true,
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ + 1),
            max_seg_size: Some(BASE_MSS - 80),
            window_scale: Some(7),
            window_len: 42,
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Established);
    assert_eq!(s.remote_win_scale, Some(7));
    // scaling does NOT apply to the window value in SYN packets
    assert_eq!(s.remote_win_len, 42);
}

#[test]
fn test_bad_seq_syn_with_data_rate_limited() {
    let mut s = socket_established();
    // An out-of-window SYN carrying data must not be exempt from challenge
    // ACK rate limiting: RFC 5961 (4.2) says challenge ACKs sent in
    // response to SYNs should be throttled.
    send!(
        s,
        TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ + 1 + 256,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        })
    );

    // The second one within the rate limit window gets no reply.
    send!(
        s,
        time 100,
        TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ + 1 + 256,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Established);
}

#[test]
fn test_listen() {
    let mut s = socket();
    s.listen(LISTEN_END).unwrap();
    assert_eq!(s.state, State::Listen);
}

#[test]
fn test_listen_timeout() {
    let mut s = socket_listen();
    s.set_timeout(Some(Duration::from_millis(100)));
    assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Ingress);
}

#[test]
fn test_connect_timeout() {
    let mut s = socket();
    s.local_seq_no = LOCAL_SEQ;
    s.socket
        .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
        .unwrap();
    s.set_timeout(Some(Duration::from_millis(100)));
    recv!(s, time 150, Ok(TcpRepr {
        control:    TcpControl::Syn,
        seq_number: LOCAL_SEQ,
        ack_number: None,
        max_seg_size: Some(BASE_MSS),
        window_scale: Some(0),
        sack_permitted: true,
        ..RECV_TEMPL
    }));
    assert_eq!(s.state, State::SynSent);
    assert_eq!(
        s.socket.poll_at(&mut s.cx),
        PollAt::Time(Instant::from_millis(250))
    );
    recv!(s, time 250, Ok(TcpRepr {
        control:    TcpControl::Rst,
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(TcpSeqNumber(0)),
        window_scale: None,
        ..RECV_TEMPL
    }));
    assert_eq!(s.state, State::Closed);
}

#[test]
fn test_closed_timeout() {
    let mut s = socket_established();
    s.set_timeout(Some(Duration::from_millis(200)));
    s.remote_last_ts = Some(Instant::from_millis(100));
    s.abort();
    assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Now);
    recv!(s, time 100, Ok(TcpRepr {
        control:    TcpControl::Rst,
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        ..RECV_TEMPL
    }));
    assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Ingress);
}

#[test]
fn test_tsval_established_connection() {
    let mut s = socket_established();
    s.set_tsval_generator(Some(|| 1));

    assert!(s.timestamp_enabled());

    // First roundtrip after establishing.
    s.send_slice(b"abcdef").unwrap();
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"abcdef"[..],
            timestamp: Some(TcpTimestampRepr::new(1, 0)),
            ..RECV_TEMPL
        }]
    );
    assert_eq!(s.tx_buffer.len(), 6);
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            timestamp: Some(TcpTimestampRepr::new(500, 1)),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.tx_buffer.len(), 0);
    // Second roundtrip.
    s.send_slice(b"foobar").unwrap();
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"foobar"[..],
            timestamp: Some(TcpTimestampRepr::new(1, 500)),
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.tx_buffer.len(), 0);
}
