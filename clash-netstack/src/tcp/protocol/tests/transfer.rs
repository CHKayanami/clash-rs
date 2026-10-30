// Derived from smoltcp; see ../LICENSE-0BSD.txt.
use super::*;

#[test]
fn test_peek_slice() {
    const BUF_SIZE: usize = 10;

    let send_buf = b"0123456";

    let mut s = socket_established_with_buffer_sizes(BUF_SIZE, BUF_SIZE);

    // Populate the recv buffer
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &send_buf[..],
            ..SEND_TEMPL
        }
    );

    // Peek into the recv buffer
    let mut peeked_buf = [0u8; BUF_SIZE];
    let actually_peeked = s.peek_slice(&mut peeked_buf[..]).unwrap();
    let mut recv_buf = [0u8; BUF_SIZE];
    let actually_recvd = s.recv_slice(&mut recv_buf[..]).unwrap();
    assert_eq!(
        &mut peeked_buf[..actually_peeked],
        &mut recv_buf[..actually_recvd]
    );
}

#[test]
fn test_peek_slice_buffer_wrap() {
    const BUF_SIZE: usize = 10;

    let send_buf = b"0123456789";

    let mut s = socket_established_with_buffer_sizes(BUF_SIZE, BUF_SIZE);

    let _ = s.rx_buffer.enqueue_slice(&send_buf[..8]);
    let _ = s.rx_buffer.dequeue_many(6);
    let _ = s.rx_buffer.enqueue_slice(&send_buf[..5]);

    let mut peeked_buf = [0u8; BUF_SIZE];
    let actually_peeked = s.peek_slice(&mut peeked_buf[..]).unwrap();
    let mut recv_buf = [0u8; BUF_SIZE];
    let actually_recvd = s.recv_slice(&mut recv_buf[..]).unwrap();
    assert_eq!(
        &mut peeked_buf[..actually_peeked],
        &mut recv_buf[..actually_recvd]
    );
}

#[test]
fn test_established_rfc2018_cases() {
    // This test case verifies the exact scenarios described on pages 8-9 of RFC 2018. Please
    // ensure its behavior does not deviate from those scenarios.

    let (mut s, segment) = setup_rfc2018_cases();
    // RFC 2018:
    //
    // Case 2: The first segment is dropped but the remaining 7 are received.
    //
    // Upon receiving each of the last seven packets, the data receiver will return a TCP ACK
    // segment that acknowledges sequence number 5000 and contains a SACK option specifying one
    // block of queued data:
    //
    //   Triggering   ACK      Left Edge  Right Edge
    //   Segment
    //
    //   5000         (lost)
    //   5500         5000     5500       6000
    //   6000         5000     5500       6500
    //   6500         5000     5500       7000
    //   7000         5000     5500       7500
    //   7500         5000     5500       8000
    //   8000         5000     5500       8500
    //   8500         5000     5500       9000
    //
    for offset in (500..3500).step_by(500) {
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + offset + 5000,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 5000),
                window_len: 4000,
                sack_ranges: [
                    Some((
                        REMOTE_SEQ.0 as u32 + 1 + 5500,
                        REMOTE_SEQ.0 as u32 + 1 + 5500 + offset as u32
                    )),
                    None,
                    None
                ],
                ..RECV_TEMPL
            })
        );
    }
}

#[test]
fn test_established_send() {
    let mut s = socket_established();
    // First roundtrip after establishing.
    s.send_slice(b"abcdef").unwrap();
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"abcdef"[..],
            ..RECV_TEMPL
        }]
    );
    assert_eq!(s.tx_buffer.len(), 6);
    assert_eq!(s.buffer_delivery().1, 0);
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.tx_buffer.len(), 0);
    assert_eq!(s.buffer_delivery().1, 6);
    // A duplicate ACK must not count the same bytes twice.
    send!(s, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1 + 6),
        ..SEND_TEMPL
    });
    assert_eq!(s.buffer_delivery().1, 6);
    // Second roundtrip.
    s.send_slice(b"foobar").unwrap();
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"foobar"[..],
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
    assert_eq!(s.buffer_delivery().1, 12);
}

#[test]
fn test_established_send_no_ack_send() {
    let mut s = socket_established();
    s.set_nagle_enabled(false);
    s.send_slice(b"abcdef").unwrap();
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"abcdef"[..],
            ..RECV_TEMPL
        }]
    );
    s.send_slice(b"foobar").unwrap();
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"foobar"[..],
            ..RECV_TEMPL
        }]
    );
}

#[test]
fn test_established_send_buf_gt_win() {
    let mut data = [0; 32];
    for (i, elem) in data.iter_mut().enumerate() {
        *elem = i as u8
    }

    let mut s = socket_established();
    s.remote_win_len = 16;
    s.send_slice(&data[..]).unwrap();
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[0..16],
            ..RECV_TEMPL
        }]
    );
}

#[test]
fn test_established_send_window_shrink() {
    let mut s = socket_established();

    // 6 octets fit on the remote side's window, so we send them.
    s.send_slice(b"abcdef").unwrap();
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"abcdef"[..],
            ..RECV_TEMPL
        }]
    );
    assert_eq!(s.tx_buffer.len(), 6);

    println!(
        "local_seq_no={} remote_win_len={} remote_last_seq={}",
        s.local_seq_no, s.remote_win_len, s.remote_last_seq
    );

    // - Peer doesn't ack them yet
    // - Sends data so we need to reply with an ACK
    // - ...AND and sends a window announcement that SHRINKS the window, so data we've
    //   previously sent is now outside the window. Yes, this is allowed by TCP.
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 3,
            payload: &b"xyzxyz"[..],
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.tx_buffer.len(), 6);

    println!(
        "local_seq_no={} remote_win_len={} remote_last_seq={}",
        s.local_seq_no, s.remote_win_len, s.remote_last_seq
    );

    // More data should not get sent since it doesn't fit in the window
    s.send_slice(b"foobar").unwrap();
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 64 - 6,
            ..RECV_TEMPL
        }]
    );
}

#[test]
fn test_established_send_wrap() {
    let mut s = socket_established();
    let local_seq_start = TcpSeqNumber(i32::MAX - 1);
    s.local_seq_no = local_seq_start + 1;
    s.remote_last_seq = local_seq_start + 1;
    s.send_slice(b"abc").unwrap();
    recv!(s, time 1000, Ok(TcpRepr {
        seq_number: local_seq_start + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abc"[..],
        ..RECV_TEMPL
    }));
}

#[test]
fn test_established_no_ack() {
    let mut s = socket_established();
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: None,
            ..SEND_TEMPL
        }
    );
}

#[test]
fn test_established_bad_ack() {
    let mut s = socket_established();
    // Already acknowledged data.
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(TcpSeqNumber(LOCAL_SEQ.0 - 1)),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
    // Data not yet transmitted.
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 10),
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        })
    );
    assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
}

#[test]
fn test_established_bad_seq() {
    let mut s = socket_established();
    // Data outside of receive window.
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 256,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        })
    );
    assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);

    // Challenge ACKs are rate-limited, we don't get a second one immediately.
    send!(
        s,
        time 100,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 256,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );

    // If we wait a bit, we do get a new one.
    send!(
        s,
        time 2000,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 256,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        })
    );
    assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
}

#[test]
fn test_old_data_ack_not_rate_limited() {
    let mut s = socket_established();
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
            window_len: 58,
            ..RECV_TEMPL
        }]
    );
    s.recv(|data| {
        assert_eq!(data, b"abcdef");
        (6, ())
    })
    .unwrap();
    // The remote retransmits data we already acknowledged, e.g. because
    // the ACK above was lost. Each retransmission must elicit a duplicate
    // ACK, even within the challenge ACK rate limit window: withholding it
    // strands the remote in retransmission backoff.
    send!(
        s,
        time 100,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            ..RECV_TEMPL
        })
    );
    send!(
        s,
        time 200,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            ..RECV_TEMPL
        })
    );
}

#[test]
fn test_bad_seq_rst_dropped_silently() {
    let mut s = socket_established();
    // Out-of-window RSTs are silently dropped, per RFC 9293 (3.10.7.4)
    // and RFC 5961 (3.2): no challenge ACK, no state change.
    send!(
        s,
        TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ + 1 + 256,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Established);

    // A payload doesn't make it eligible for the data segment exemption
    // from challenge ACK rate limiting either: still no reply.
    send!(
        s,
        time 100,
        TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ + 1 + 256,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Established);
}

#[test]
fn test_established_options_reduce_payload_when_local_mss_limited() {
    const EFFECTIVE_MSS: usize = 64;

    // construct socket where remote MSS is less than local MSS
    let mut s = socket_established();
    s.set_tsval_generator(Some(|| 1));
    s.remote_mss = EFFECTIVE_MSS;

    // Payload should contain 12 bytes less due to timestamp
    s.send_slice(&[0; EFFECTIVE_MSS]).unwrap();
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &[0; EFFECTIVE_MSS - 12],
            timestamp: Some(TcpTimestampRepr::new(1, 0)),
            ..RECV_TEMPL
        }]
    );
}

#[test]
fn test_established_options_reduce_payload_when_remote_mss_limited() {
    const EFFECTIVE_MSS: usize = BASE_MSS as usize;

    // construct socket where remote MSS is more than local MSS
    let mut s = socket_established_with_buffer_sizes(EFFECTIVE_MSS, 64);
    s.set_tsval_generator(Some(|| 1));
    s.remote_mss = 9999;
    s.remote_win_len = 9999;

    // Payload should contain 12 bytes less due to timestamp
    s.send_slice(&[0; EFFECTIVE_MSS]).unwrap();
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &[0; EFFECTIVE_MSS - 12],
            timestamp: Some(TcpTimestampRepr::new(1, 0)),
            ..RECV_TEMPL
        }]
    );
}

#[test]
fn test_established_tiny_mss_with_options_makes_progress() {
    // Connect with timestamps enabled to a remote advertising an absurdly
    // small MSS. Without the MIN_SND_MSS clamp, an MSS smaller than the
    // options length would result in an effective MSS of zero, sending
    // empty segments in a loop without ever making progress.
    let mut s = socket();
    s.set_tsval_generator(Some(|| 1));
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
            timestamp: Some(TcpTimestampRepr::new(1, 0)),
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
            timestamp: Some(TcpTimestampRepr::new(500, 1)),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Established);
    assert_eq!(s.remote_mss, MIN_REMOTE_MSS);

    s.send_slice(&[0; 64]).unwrap();
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &[0; MIN_REMOTE_MSS - 12],
            timestamp: Some(TcpTimestampRepr::new(1, 500)),
            ..RECV_TEMPL
        }]
    );
}

#[test]
fn test_established_rst() {
    let mut s = socket_established();
    send!(
        s,
        TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Closed);
}

#[test]
fn test_established_rst_no_ack() {
    let mut s = socket_established();
    send!(
        s,
        TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ + 1,
            ack_number: None,
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Closed);
}

#[test]
fn test_established_rst_bad_seq() {
    let mut s = socket_established();
    // Out-of-window RSTs are dropped silently, per RFC 9293 (3.10.7.4)
    // and RFC 5961 (3.2).
    send!(
        s,
        TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ, // Wrong seq
            ack_number: None,
            ..SEND_TEMPL
        }
    );

    assert_eq!(s.state, State::Established);

    // An in-window RST still resets the connection.
    send!(
        s,
        time 2000,
        TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ + 1, // Correct seq
            ack_number: None,
            ..SEND_TEMPL
        }
    );

    assert_eq!(s.state, State::Closed);
}

#[test]
fn test_established_bad_seq_challenge_ack_updated() {
    let mut s = socket_established();
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ, // Wrong seq
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        })
    );

    assert_eq!(s.state, State::Established);

    // Send something to advance seq by 1
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1, // correct seq
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"a"[..],
            ..SEND_TEMPL
        }
    );

    // Send the wrong seq again, check that the challenge ack is correctly updated
    // The ack number must be updated even if we don't call dispatch on the socket
    // See https://github.com/smoltcp-rs/smoltcp/issues/338
    send!(
        s,
        time 2000,
        TcpRepr {
            seq_number: REMOTE_SEQ, // Wrong seq
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 2), // this has changed
            window_len: 63,
            ..RECV_TEMPL
        })
    );
}

#[test]
fn test_three_way_handshake() {
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
    assert_eq!(s.state(), State::Established);
    assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
    assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
}

#[test]
fn test_duplicate_seq_ack() {
    let mut s = socket_recved();
    // remote retransmission
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 58,
            ..RECV_TEMPL
        })
    );
}

#[test]
fn test_maximum_segment_size() {
    let mut s = socket_listen();
    s.tx_buffer = SocketBuffer::new(vec![0; 32767]);
    send!(
        s,
        TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            max_seg_size: Some(1000),
            ..SEND_TEMPL
        }
    );
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
            window_len: 32767,
            ..SEND_TEMPL
        }
    );
    s.send_slice(&[0; 1200][..]).unwrap();
    recv!(
        s,
        Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &[0; 1000][..],
            ..RECV_TEMPL
        })
    );
}

#[test]
fn test_psh_transmit() {
    let mut s = socket_established();
    s.remote_mss = 6;
    s.send_slice(b"abcdef").unwrap();
    s.send_slice(b"123456").unwrap();
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
        payload:    &b"123456"[..],
        ..RECV_TEMPL
    }), exact);
}

#[test]
fn test_fill_peer_window() {
    let mut s = socket_established();
    s.remote_mss = 6;
    s.send_slice(b"abcdef123456!@#$%^").unwrap();
    recv!(
        s,
        [
            TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            },
            TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"123456"[..],
                ..RECV_TEMPL
            },
            TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"!@#$%^"[..],
                ..RECV_TEMPL
            }
        ]
    );
}

#[test]
fn test_established_timeout() {
    let mut s = socket_established();
    s.set_timeout(Some(Duration::from_millis(2000)));
    recv_nothing!(s, time 250);
    assert_eq!(
        s.socket.poll_at(&mut s.cx),
        PollAt::Time(Instant::from_millis(2250))
    );
    s.send_slice(b"abcdef").unwrap();
    assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Now);
    recv!(s, time 255, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abcdef"[..],
        ..RECV_TEMPL
    }));
    assert_eq!(
        s.socket.poll_at(&mut s.cx),
        PollAt::Time(Instant::from_millis(1255))
    );
    recv!(s, time 1255, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"abcdef"[..],
        ..RECV_TEMPL
    }));
    assert_eq!(
        s.socket.poll_at(&mut s.cx),
        PollAt::Time(Instant::from_millis(2255))
    );
    recv!(s, time 2255, Ok(TcpRepr {
        control:    TcpControl::Rst,
        seq_number: LOCAL_SEQ + 1 + 6,
        ack_number: Some(REMOTE_SEQ + 1),
        ..RECV_TEMPL
    }));
    assert_eq!(s.state, State::Closed);
}

#[test]
fn test_established_keep_alive_timeout() {
    let mut s = socket_established();
    s.set_keep_alive(Some(Duration::from_millis(50)));
    s.set_timeout(Some(Duration::from_millis(100)));
    recv!(s, time 100, Ok(TcpRepr {
        seq_number: LOCAL_SEQ,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &[0],
        ..RECV_TEMPL
    }));
    recv_nothing!(s, time 100);
    assert_eq!(
        s.socket.poll_at(&mut s.cx),
        PollAt::Time(Instant::from_millis(150))
    );
    send!(s, time 105, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        ..SEND_TEMPL
    });
    assert_eq!(
        s.socket.poll_at(&mut s.cx),
        PollAt::Time(Instant::from_millis(155))
    );
    recv!(s, time 155, Ok(TcpRepr {
        seq_number: LOCAL_SEQ,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &[0],
        ..RECV_TEMPL
    }));
    recv_nothing!(s, time 155);
    assert_eq!(
        s.socket.poll_at(&mut s.cx),
        PollAt::Time(Instant::from_millis(205))
    );
    recv_nothing!(s, time 200);
    recv!(s, time 205, Ok(TcpRepr {
        control:    TcpControl::Rst,
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        ..RECV_TEMPL
    }));
    recv_nothing!(s, time 205);
    assert_eq!(s.state, State::Closed);
}

#[test]
fn test_responds_to_keep_alive() {
    let mut s = socket_established();
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        })
    );
}

#[test]
fn test_sends_keep_alive() {
    let mut s = socket_established();
    s.set_keep_alive(Some(Duration::from_millis(100)));

    // drain the forced keep-alive packet
    assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Now);
    recv!(s, time 0, Ok(TcpRepr {
        seq_number: LOCAL_SEQ,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &[0],
        ..RECV_TEMPL
    }));

    assert_eq!(
        s.socket.poll_at(&mut s.cx),
        PollAt::Time(Instant::from_millis(100))
    );
    recv_nothing!(s, time 95);
    recv!(s, time 100, Ok(TcpRepr {
        seq_number: LOCAL_SEQ,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &[0],
        ..RECV_TEMPL
    }));

    assert_eq!(
        s.socket.poll_at(&mut s.cx),
        PollAt::Time(Instant::from_millis(200))
    );
    recv_nothing!(s, time 195);
    recv!(s, time 200, Ok(TcpRepr {
        seq_number: LOCAL_SEQ,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &[0],
        ..RECV_TEMPL
    }));

    send!(s, time 250, TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        ..SEND_TEMPL
    });
    assert_eq!(
        s.socket.poll_at(&mut s.cx),
        PollAt::Time(Instant::from_millis(350))
    );
    recv_nothing!(s, time 345);
    recv!(s, time 350, Ok(TcpRepr {
        seq_number: LOCAL_SEQ,
        ack_number: Some(REMOTE_SEQ + 1),
        payload:    &b"\x00"[..],
        ..RECV_TEMPL
    }));
}

#[test]
fn test_set_hop_limit() {
    let mut s = socket_syn_received();

    s.set_hop_limit(Some(0x2a));
    assert_eq!(
        s.socket.dispatch(&mut s.cx, |_, _, (ip_repr, _)| {
            assert_eq!(ip_repr.hop_limit(), 0x2a);
            Ok::<_, ()>(())
        }),
        Ok(())
    );

    // assert that user-configurable settings are kept,
    // see https://github.com/smoltcp-rs/smoltcp/issues/601.
    s.reset();
    assert_eq!(s.hop_limit(), Some(0x2a));
}

#[test]
#[should_panic(expected = "the time-to-live value of a packet must not be zero")]
fn test_set_hop_limit_zero() {
    let mut s = socket_syn_received();
    s.set_hop_limit(Some(0));
}

#[test]
fn test_delayed_ack() {
    let mut s = socket_established();
    s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abc"[..],
            ..SEND_TEMPL
        }
    );

    // No ACK is immediately sent.
    recv_nothing!(s);

    // After 10ms, it is sent.
    recv!(s, time 11, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1 + 3),
        window_len: 61,
        ..RECV_TEMPL
    }));
}

#[test]
fn test_delayed_ack_win() {
    let mut s = socket_established();
    s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abc"[..],
            ..SEND_TEMPL
        }
    );

    // Reading the data off the buffer should cause a window update.
    s.recv(|data| {
        assert_eq!(data, b"abc");
        (3, ())
    })
    .unwrap();

    // However, no ACK or window update is immediately sent.
    recv_nothing!(s);

    // After 10ms, it is sent.
    recv!(s, time 11, Ok(TcpRepr {
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1 + 3),
        ..RECV_TEMPL
    }));
}

#[test]
fn test_delayed_ack_reply() {
    let mut s = socket_established();
    s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abc"[..],
            ..SEND_TEMPL
        }
    );

    s.recv(|data| {
        assert_eq!(data, b"abc");
        (3, ())
    })
    .unwrap();

    s.send_slice(&b"xyz"[..]).unwrap();

    // Writing data to the socket causes ACK to not be delayed,
    // because it is immediately sent with the data.
    recv!(
        s,
        Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            payload: &b"xyz"[..],
            ..RECV_TEMPL
        })
    );
}

#[test]
fn test_delayed_ack_every_rmss() {
    let mut s = socket_established_with_buffer_sizes(DEFAULT_MSS * 2, DEFAULT_MSS * 2);
    s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &[0; DEFAULT_MSS - 1],
            ..SEND_TEMPL
        }
    );

    // No ACK is immediately sent.
    recv_nothing!(s);

    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + (DEFAULT_MSS - 1),
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"a"[..],
            ..SEND_TEMPL
        }
    );

    // No ACK is immediately sent.
    recv_nothing!(s);

    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + DEFAULT_MSS,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"a"[..],
            ..SEND_TEMPL
        }
    );

    // RMSS+1 bytes of data has been received, so ACK is sent without delay.
    recv!(
        s,
        Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + (DEFAULT_MSS + 1)),
            window_len: (DEFAULT_MSS - 1) as u16,
            ..RECV_TEMPL
        })
    );
}

#[test]
fn test_delayed_ack_every_rmss_or_more() {
    let mut s = socket_established_with_buffer_sizes(DEFAULT_MSS * 2, DEFAULT_MSS * 2);
    s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &[0; DEFAULT_MSS],
            ..SEND_TEMPL
        }
    );

    // No ACK is immediately sent.
    recv_nothing!(s);

    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + DEFAULT_MSS,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"a"[..],
            ..SEND_TEMPL
        }
    );

    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + (DEFAULT_MSS + 1),
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"b"[..],
            ..SEND_TEMPL
        }
    );

    // RMSS+2 bytes of data has been received, so ACK is sent without delay.
    recv!(
        s,
        Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + (DEFAULT_MSS + 2)),
            window_len: (DEFAULT_MSS - 2) as u16,
            ..RECV_TEMPL
        })
    );
}

#[test]
fn test_nagle() {
    let mut s = socket_established();
    s.remote_mss = 6;

    s.send_slice(b"abcdef").unwrap();
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"abcdef"[..],
            ..RECV_TEMPL
        }]
    );

    // If there's data in flight, full segments get sent.
    s.send_slice(b"foobar").unwrap();
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"foobar"[..],
            ..RECV_TEMPL
        }]
    );

    s.send_slice(b"aaabbbccc").unwrap();
    // If there's data in flight, not-full segments don't get sent.
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"aaabbb"[..],
            ..RECV_TEMPL
        }]
    );

    // Data gets ACKd, so there's no longer data in flight
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6 + 6),
            ..SEND_TEMPL
        }
    );

    // Now non-full segment gets sent.
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"ccc"[..],
            ..RECV_TEMPL
        }]
    );
}

#[test]
fn test_nagle_works_with_reduced_payload_from_options() {
    const EFFECTIVE_MSS: usize = 64;

    let mut s = socket_established_with_buffer_sizes(256, 64);
    s.set_nagle_enabled(true);
    s.set_tsval_generator(Some(|| 1));
    s.remote_mss = EFFECTIVE_MSS;

    // Send small segment to "arm" Nagle's
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

    // A full segment (once options are accounted for) should not be delayed and contain 12 bytes less due to timestamp
    s.send_slice(&[0; EFFECTIVE_MSS - 12]).unwrap();
    recv!(
        s,
        time 0,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &[0; EFFECTIVE_MSS - 12],
            timestamp: Some(TcpTimestampRepr::new(1, 0)),
            ..RECV_TEMPL
        }]
    );
}

#[test]
fn test_doesnt_accept_wrong_port() {
    let mut s = socket_established();
    s.rx_buffer = SocketBuffer::new(vec![0; 6]);
    s.assembler = Assembler::new();

    let tcp_repr = TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        dst_port: LOCAL_PORT + 1,
        ..SEND_TEMPL
    };
    assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));

    let tcp_repr = TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        src_port: REMOTE_PORT + 1,
        ..SEND_TEMPL
    };
    assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
}

#[test]
fn test_doesnt_accept_wrong_ip() {
    let mut s = socket_established();

    let tcp_repr = TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        payload: &b"abcdef"[..],
        ..SEND_TEMPL
    };

    let ip_repr = IpReprIpvX(IpvXRepr {
        src_addr: REMOTE_ADDR,
        dst_addr: LOCAL_ADDR,
        next_header: IpProtocol::Tcp,
        payload_len: tcp_repr.buffer_len(),
        hop_limit: 64,
    });
    assert!(s.socket.accepts(&mut s.cx, &ip_repr, &tcp_repr));

    let ip_repr_wrong_src = IpReprIpvX(IpvXRepr {
        src_addr: OTHER_ADDR,
        dst_addr: LOCAL_ADDR,
        next_header: IpProtocol::Tcp,
        payload_len: tcp_repr.buffer_len(),
        hop_limit: 64,
    });
    assert!(!s.socket.accepts(&mut s.cx, &ip_repr_wrong_src, &tcp_repr));

    let ip_repr_wrong_dst = IpReprIpvX(IpvXRepr {
        src_addr: REMOTE_ADDR,
        dst_addr: OTHER_ADDR,
        next_header: IpProtocol::Tcp,
        payload_len: tcp_repr.buffer_len(),
        hop_limit: 64,
    });
    assert!(!s.socket.accepts(&mut s.cx, &ip_repr_wrong_dst, &tcp_repr));
}

#[test]
fn test_tsval_disabled_in_remote_client() {
    let mut s = socket_listen();
    s.set_tsval_generator(Some(|| 1));
    assert!(s.timestamp_enabled());
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
    assert!(!s.timestamp_enabled());
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
    assert_eq!(s.state(), State::Established);
    assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
    assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
}

#[test]
fn test_tsval_disabled_in_local_server() {
    let mut s = socket_listen();
    // s.set_timestamp(false); // commented to alert if the default state changes
    assert!(!s.timestamp_enabled());
    send!(
        s,
        TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            timestamp: Some(TcpTimestampRepr::new(500, 0)),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state(), State::SynReceived);
    assert_eq!(s.tuple, Some(TUPLE));
    assert!(!s.timestamp_enabled());
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
    assert_eq!(s.state(), State::Established);
    assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
    assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
}

#[test]
fn test_tsval_disabled_in_remote_server() {
    let mut s = socket();
    s.set_tsval_generator(Some(|| 1));
    assert!(s.timestamp_enabled());
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
            timestamp: Some(TcpTimestampRepr::new(1, 0)),
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
            timestamp: None,
            ..SEND_TEMPL
        }
    );
    assert!(!s.timestamp_enabled());
    s.send_slice(b"abcdef").unwrap();
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"abcdef"[..],
            timestamp: None,
            ..RECV_TEMPL
        }]
    );
}

#[test]
fn test_tsval_disabled_in_local_client() {
    let mut s = socket();
    // s.set_timestamp(false); // commented to alert if the default state changes
    assert!(!s.timestamp_enabled());
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
            timestamp: Some(TcpTimestampRepr::new(500, 0)),
            ..SEND_TEMPL
        }
    );
    assert!(!s.timestamp_enabled());
    s.send_slice(b"abcdef").unwrap();
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"abcdef"[..],
            timestamp: None,
            ..RECV_TEMPL
        }]
    );
}

#[test]
fn test_buffer_delivery_distinguishes_unknown_and_submillisecond_rtt() {
    let mut s = socket_established();
    assert_eq!(s.buffer_delivery(), (Duration::ZERO, 0));
    s.rtte.sample(0);
    assert_eq!(s.buffer_delivery(), (Duration::from_millis(1), 0));
    s.rtte.sample(20);
    assert_eq!(s.buffer_delivery().0, s.rtte.smoothed_rtt());
    s.reset();
    assert_eq!(s.buffer_delivery(), (Duration::ZERO, 0));
}
