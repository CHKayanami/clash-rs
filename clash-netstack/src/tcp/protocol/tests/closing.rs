// Derived from smoltcp; see ../LICENSE-0BSD.txt.
use super::*;

#[test]
fn test_established_receive_partially_outside_window_fin() {
    let mut s = socket_established();

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

    // Peer decides to retransmit (perhaps because the ACK was lost)
    // and also pushed data, and sent a FIN.
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            control: TcpControl::Fin,
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        }
    );

    s.recv(|data| {
        assert_eq!(data, b"def");
        (3, ())
    })
    .unwrap();

    // We should accept the FIN, because even though the last packet was partially
    // outside the receive window, there is no hole after adding its data to the assembler.
    assert_eq!(s.state, State::CloseWait);
}

#[test]
fn test_established_fin() {
    let mut s = socket_established();
    send!(
        s,
        TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]
    );
    assert_eq!(s.state, State::CloseWait);
    sanity!(s, socket_close_wait());
}

#[test]
fn test_established_fin_after_missing() {
    let mut s = socket_established();
    send!(
        s,
        TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1 + 6,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"123456"[..],
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        })
    );
    assert_eq!(s.state, State::Established);
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
            ack_number: Some(REMOTE_SEQ + 1 + 6 + 6),
            window_len: 52,
            ..RECV_TEMPL
        })
    );
    assert_eq!(s.state, State::Established);
}

#[test]
fn test_established_send_fin() {
    let mut s = socket_established();
    s.send_slice(b"abcdef").unwrap();
    send!(
        s,
        TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::CloseWait);
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload: &b"abcdef"[..],
            ..RECV_TEMPL
        }]
    );
}

#[test]
fn test_established_close() {
    let mut s = socket_established();
    s.close();
    assert_eq!(s.state, State::FinWait1);
    sanity!(s, socket_fin_wait_1());
}

#[test]
fn test_established_abort() {
    let mut s = socket_established();
    s.abort();
    assert_eq!(s.state, State::Closed);
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }]
    );
}

#[test]
fn test_fin_wait_1_fin_ack() {
    let mut s = socket_fin_wait_1();
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::FinWait2);
    sanity!(s, socket_fin_wait_2());
}

#[test]
fn test_fin_wait_1_fin_fin() {
    let mut s = socket_fin_wait_1();
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Closing);
    sanity!(s, socket_closing());
}

#[test]
fn test_fin_wait_1_fin_with_data_queued() {
    let mut s = socket_established();
    s.remote_win_len = 6;
    s.send_slice(b"abcdef123456").unwrap();
    s.close();
    recv!(
        s,
        Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"abcdef"[..],
            ..RECV_TEMPL
        })
    );
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::FinWait1);
}

#[test]
fn test_fin_wait_1_recv() {
    let mut s = socket_fin_wait_1();
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abc"[..],
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::FinWait1);
    s.recv(|data| {
        assert_eq!(data, b"abc");
        (3, ())
    })
    .unwrap();
}

#[test]
fn test_fin_wait_1_close() {
    let mut s = socket_fin_wait_1();
    s.close();
    assert_eq!(s.state, State::FinWait1);
}

#[test]
fn test_fin_wait_2_fin() {
    let mut s = socket_fin_wait_2();
    send!(s, time 1_000, TcpRepr {
        control: TcpControl::Fin,
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1 + 1),
        ..SEND_TEMPL
    });
    assert_eq!(s.state, State::TimeWait);
    sanity!(s, socket_time_wait(false));
}

#[test]
fn test_fin_wait_2_recv() {
    let mut s = socket_fin_wait_2();
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            payload: &b"abc"[..],
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::FinWait2);
    s.recv(|data| {
        assert_eq!(data, b"abc");
        (3, ())
    })
    .unwrap();
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            ..RECV_TEMPL
        }]
    );
}

#[test]
fn test_fin_wait_2_close() {
    let mut s = socket_fin_wait_2();
    s.close();
    assert_eq!(s.state, State::FinWait2);
}

#[test]
fn test_closing_ack_fin() {
    let mut s = socket_closing();
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]
    );
    send!(s, time 1_000, TcpRepr {
        seq_number: REMOTE_SEQ + 1 + 1,
        ack_number: Some(LOCAL_SEQ + 1 + 1),
        ..SEND_TEMPL
    });
    assert_eq!(s.state, State::TimeWait);
    sanity!(s, socket_time_wait(true));
}

#[test]
fn test_closing_close() {
    let mut s = socket_closing();
    s.close();
    assert_eq!(s.state, State::Closing);
}

#[test]
fn test_time_wait_from_fin_wait_2_ack() {
    let mut s = socket_time_wait(false);
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]
    );
}

#[test]
fn test_time_wait_from_closing_no_ack() {
    let mut s = socket_time_wait(true);
    recv!(s, []);
}

#[test]
fn test_time_wait_close() {
    let mut s = socket_time_wait(false);
    s.close();
    assert_eq!(s.state, State::TimeWait);
}

#[test]
fn test_time_wait_timeout() {
    let mut s = socket_time_wait(false);
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]
    );
    assert_eq!(s.state, State::TimeWait);
    recv_nothing!(s, time 60_000);
    assert_eq!(s.state, State::Closed);
}

#[test]
fn test_close_wait_ack() {
    let mut s = socket_close_wait();
    s.send_slice(b"abcdef").unwrap();
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload: &b"abcdef"[..],
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            ..SEND_TEMPL
        }
    );
}

#[test]
fn test_close_wait_close() {
    let mut s = socket_close_wait();
    s.close();
    assert_eq!(s.state, State::LastAck);
    sanity!(s, socket_last_ack());
}

#[test]
fn test_last_ack_fin_ack() {
    let mut s = socket_last_ack();
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]
    );
    assert_eq!(s.state, State::LastAck);
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Closed);
}

#[test]
fn test_last_ack_ack_not_of_fin() {
    let mut s = socket_last_ack();
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]
    );
    assert_eq!(s.state, State::LastAck);

    // A duplicate ACK (ack_number == SND.UNA, not the FIN ACK) must elicit a
    // challenge ACK per RFC 9293 §3.10.7.4 and must keep the state in LAST-ACK.
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        })
    );
    assert_eq!(s.state, State::LastAck);

    // ACK received of fin: socket should change to Closed.
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Closed);
}

#[test]
fn test_last_ack_duplicate_ack_challenge_ack() {
    let mut s = socket_last_ack();
    // Trigger dispatch so our FIN is sent and remote_last_seq advances.
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]
    );
    assert_eq!(s.state, State::LastAck);

    // Remote re-sends an ACK for SND.UNA (not the FIN).  RFC 9293 requires a
    // challenge ACK in response so the remote can learn the current state.
    let challenge = send(
        &mut s,
        Instant::from_millis(0),
        &TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        },
    );
    assert_eq!(
        challenge,
        Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }),
        "expected challenge ACK in response to duplicate ACK in LAST-ACK"
    );
    // State must remain LAST-ACK: we have not received the FIN ACK.
    assert_eq!(s.state, State::LastAck);

    // A second duplicate in the same second is rate-limited; the FIN ACK
    // must still be correctly accepted regardless.
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Closed);
}

#[test]
fn test_last_ack_partial_ack_no_challenge_ack() {
    // Build a LAST-ACK socket that has one byte of data still unacknowledged
    // before the FIN.  We manually wire the state so we can send a partial ACK.
    let mut s = socket_last_ack();
    // Push one byte into the tx buffer to simulate data that preceded the FIN.
    let _ = s.tx_buffer.enqueue_slice(b"x");
    // Mark it as already sent (remote_last_seq is past the data byte and the FIN).
    s.remote_last_seq = LOCAL_SEQ + 1 + 1 + 1; // data(1) + FIN(1)

    // Remote ACKs just the data byte, not the FIN (partial ACK).
    // ack_number = local_seq_no + 1  =>  ack_len = 1, ack_of_fin = false.
    // Per RFC 9293, a valid partial ACK should advance SND.UNA normally;
    // no challenge ACK should be emitted.
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1), // acks the data byte, not FIN
            ..SEND_TEMPL
        }
    );
    // State remains LAST-ACK; FIN retransmission is handled by the timer.
    assert_eq!(s.state, State::LastAck);
    // SND.UNA has advanced to the partial ACK number.
    assert_eq!(s.local_seq_no, LOCAL_SEQ + 1 + 1);
}

#[test]
fn test_last_ack_close() {
    let mut s = socket_last_ack();
    s.close();
    assert_eq!(s.state, State::LastAck);
}

#[test]
fn test_remote_close() {
    let mut s = socket_established();
    send!(
        s,
        TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::CloseWait);
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]
    );
    s.close();
    assert_eq!(s.state, State::LastAck);
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Closed);
}

#[test]
fn test_local_close() {
    let mut s = socket_established();
    s.close();
    assert_eq!(s.state, State::FinWait1);
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::FinWait2);
    send!(
        s,
        TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::TimeWait);
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]
    );
}

#[test]
fn test_simultaneous_close() {
    let mut s = socket_established();
    s.close();
    assert_eq!(s.state, State::FinWait1);
    recv!(
        s,
        [TcpRepr {
            // due to reordering, this is logically located...
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Closing);
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]
    );
    // ... at this point
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::TimeWait);
    recv!(s, []);
}

#[test]
fn test_simultaneous_close_combined_fin_ack() {
    let mut s = socket_established();
    s.close();
    assert_eq!(s.state, State::FinWait1);
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::TimeWait);
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]
    );
}

#[test]
fn test_simultaneous_close_raced() {
    let mut s = socket_established();
    s.close();
    assert_eq!(s.state, State::FinWait1);

    // Socket receives FIN before it has a chance to send its own FIN
    send!(
        s,
        TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Closing);

    // FIN + ack-of-FIN
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]
    );
    assert_eq!(s.state, State::Closing);

    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::TimeWait);
    recv!(s, []);
}

#[test]
fn test_simultaneous_close_raced_with_data() {
    let mut s = socket_established();
    s.send_slice(b"abcdef").unwrap();
    s.close();
    assert_eq!(s.state, State::FinWait1);

    // Socket receives FIN before it has a chance to send its own data+FIN
    send!(
        s,
        TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Closing);

    // data + FIN + ack-of-FIN
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload: &b"abcdef"[..],
            ..RECV_TEMPL
        }]
    );
    assert_eq!(s.state, State::Closing);

    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::TimeWait);
    recv!(s, []);
}

#[test]
fn test_fin_with_data() {
    let mut s = socket_established();
    s.send_slice(b"abcdef").unwrap();
    s.close();
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"abcdef"[..],
            ..RECV_TEMPL
        }]
    )
}

#[test]
fn test_mutual_close_with_data_1() {
    let mut s = socket_established();
    s.send_slice(b"abcdef").unwrap();
    s.close();
    assert_eq!(s.state, State::FinWait1);
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"abcdef"[..],
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
            ..SEND_TEMPL
        }
    );
}

#[test]
fn test_mutual_close_with_data_2() {
    let mut s = socket_established();
    s.send_slice(b"abcdef").unwrap();
    s.close();
    assert_eq!(s.state, State::FinWait1);
    recv!(
        s,
        [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"abcdef"[..],
            ..RECV_TEMPL
        }]
    );
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::FinWait2);
    send!(
        s,
        TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
            ..SEND_TEMPL
        }
    );
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }]
    );
    assert_eq!(s.state, State::TimeWait);
}

#[test]
fn test_fin_wait_1_timeout() {
    let mut s = socket_fin_wait_1();
    s.set_timeout(Some(Duration::from_millis(1000)));
    recv!(s, time 100, Ok(TcpRepr {
        control:    TcpControl::Fin,
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        ..RECV_TEMPL
    }));
    recv!(s, time 1100, Ok(TcpRepr {
        control:    TcpControl::Rst,
        seq_number: LOCAL_SEQ + 1 + 1,
        ack_number: Some(REMOTE_SEQ + 1),
        ..RECV_TEMPL
    }));
    assert_eq!(s.state, State::Closed);
}

#[test]
fn test_last_ack_timeout() {
    let mut s = socket_last_ack();
    s.set_timeout(Some(Duration::from_millis(1000)));
    recv!(s, time 100, Ok(TcpRepr {
        control:    TcpControl::Fin,
        seq_number: LOCAL_SEQ + 1,
        ack_number: Some(REMOTE_SEQ + 1 + 1),
        ..RECV_TEMPL
    }));
    recv!(s, time 1100, Ok(TcpRepr {
        control:    TcpControl::Rst,
        seq_number: LOCAL_SEQ + 1 + 1,
        ack_number: Some(REMOTE_SEQ + 1 + 1),
        ..RECV_TEMPL
    }));
    assert_eq!(s.state, State::Closed);
}

#[test]
fn test_rx_close_fin() {
    let mut s = socket_established();
    send!(
        s,
        TcpRepr {
            control: TcpControl::Fin,
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
    assert_eq!(s.recv(|_| (0, ())), Err(RecvError::Finished));
}

#[test]
fn test_rx_close_fin_in_fin_wait_1() {
    let mut s = socket_fin_wait_1();
    send!(
        s,
        TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abc"[..],
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::Closing);
    s.recv(|data| {
        assert_eq!(data, b"abc");
        (3, ())
    })
    .unwrap();
    assert_eq!(s.recv(|_| (0, ())), Err(RecvError::Finished));
}

#[test]
fn test_rx_close_fin_in_fin_wait_2() {
    let mut s = socket_fin_wait_2();
    send!(
        s,
        TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            payload: &b"abc"[..],
            ..SEND_TEMPL
        }
    );
    assert_eq!(s.state, State::TimeWait);
    s.recv(|data| {
        assert_eq!(data, b"abc");
        (3, ())
    })
    .unwrap();
    assert_eq!(s.recv(|_| (0, ())), Err(RecvError::Finished));
}

#[test]
fn test_rx_close_fin_with_hole() {
    let mut s = socket_established();
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abc"[..],
            ..SEND_TEMPL
        }
    );
    send!(
        s,
        TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1 + 6,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"ghi"[..],
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            window_len: 61,
            ..RECV_TEMPL
        })
    );
    s.recv(|data| {
        assert_eq!(data, b"abc");
        (3, ())
    })
    .unwrap();
    s.recv(|data| {
        assert_eq!(data, b"");
        (0, ())
    })
    .unwrap();
    send!(
        s,
        TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ + 1 + 9,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );
    // Error must be `Illegal` even if we've received a FIN,
    // because we are missing data.
    assert_eq!(s.recv(|_| (0, ())), Err(RecvError::InvalidState));
}

#[test]
fn test_rx_close_rst() {
    let mut s = socket_established();
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abc"[..],
            ..SEND_TEMPL
        }
    );
    send!(
        s,
        TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ + 1 + 3,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );
    s.recv(|data| {
        assert_eq!(data, b"abc");
        (3, ())
    })
    .unwrap();
    assert_eq!(s.recv(|_| (0, ())), Err(RecvError::InvalidState));
}

#[test]
fn test_rx_close_rst_with_hole() {
    let mut s = socket_established();
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abc"[..],
            ..SEND_TEMPL
        }
    );
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 6,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"ghi"[..],
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            window_len: 61,
            ..RECV_TEMPL
        })
    );
    send!(
        s,
        TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ + 1 + 9,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        }
    );
    s.recv(|data| {
        assert_eq!(data, b"abc");
        (3, ())
    })
    .unwrap();
    assert_eq!(s.recv(|_| (0, ())), Err(RecvError::InvalidState));
}

#[test]
fn test_final_packet_in_stream_doesnt_wait_for_nagle() {
    let mut s = socket_established();
    s.remote_mss = 6;
    s.send_slice(b"abcdef0").unwrap();
    s.socket.close();

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
        payload:    &b"0"[..],
        ..RECV_TEMPL
    }), exact);
}

#[test]
fn test_established_close_on_src_ip_change() {
    let mut s = socket_established();

    // Verify socket is working normally
    s.send_slice(b"abc").unwrap();
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &b"abc"[..],
            ..RECV_TEMPL
        }]
    );

    // Simulate interface IP change - remove the socket's source IP
    // and add a different one.
    let mut new_addrs = Vec::<IpCidr>::new();
    new_addrs.push(IpCidr::new(OTHER_ADDR.into(), 24));
    s.cx.set_ip_addrs(new_addrs);

    // The socket's source IP is no longer on the interface.
    // When dispatch() runs, it should detect this and reset the socket
    // silently (no RST sent, since that would use the invalid source IP).
    s.send_slice(b"def").unwrap();
    recv_nothing!(s);
    assert_eq!(s.state, State::Closed);
}
