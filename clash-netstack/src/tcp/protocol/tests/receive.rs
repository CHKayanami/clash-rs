// Derived from smoltcp; see ../LICENSE-0BSD.txt.
use super::*;

#[test]
fn test_established_recv() {
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
    assert_eq!(s.rx_buffer.dequeue_many(6), &b"abcdef"[..]);
}

#[test]
fn test_established_sack_no_overflow_on_near_max_seqnumber() {
    let mut s = socket_established();
    s.remote_has_sack = true;
    s.remote_seq_no = TcpSeqNumber(-4);
    s.remote_last_ack = Some(TcpSeqNumber(-4));

    // Send an out-of-order segment 10 bytes past the expected sequence,
    // creating a 10-byte hole at the front of the assembler.
    send!(
        s,
        TcpRepr {
            seq_number: TcpSeqNumber(-4 + 10),
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"AAAAAAAAAA"[..],
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(TcpSeqNumber(-4)),
            window_len: 64,
            sack_ranges: [
                Some(((-4_i32 + 10) as u32, (-4_i32 + 20) as u32,)),
                None,
                None,
            ],
            ..RECV_TEMPL
        })
    );
}

#[test]
fn test_established_sliding_window_recv() {
    let mut s = socket_established();
    // Update our scaling parameters for a TCP with a scaled buffer.
    assert_eq!(s.rx_buffer.len(), 0);
    s.rx_buffer = SocketBuffer::new(vec![0; 262143]);
    s.assembler = Assembler::new();
    s.remote_win_scale = Some(0);
    s.remote_last_win_len = 65535 << 2;
    s.remote_win_shift = 2;

    // Create a TCP segment that will mostly fill an IP frame.
    let mut segment: Vec<u8> = Vec::with_capacity(1400);
    for _ in 0..100 {
        segment.extend_from_slice(b"abcdefghijklmn")
    }
    assert_eq!(segment.len(), 1400);

    // Send the frame
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &segment,
            ..SEND_TEMPL
        }
    );

    // Ensure that the received window size is shifted right by 2.
    recv!(
        s,
        [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1400),
            window_len: 65185,
            ..RECV_TEMPL
        }]
    );
}

#[test]
fn test_established_receive_partially_outside_window() {
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
    // and also pushed data.
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        }
    );

    s.recv(|data| {
        assert_eq!(data, b"def");
        (3, ())
    })
    .unwrap();
}

#[test]
fn test_recv_out_of_recv_win() {
    let mut s = socket_established();
    s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
    s.remote_mss = 32;

    // No ACKs are sent due to the ACK delay.
    send!(
        s,
        TcpRepr {
            control: TcpControl::Psh,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &[0; 32],
            ..SEND_TEMPL
        }
    );
    recv_nothing!(s);

    // RMSS+1 bytes of data has been received, so ACK is sent without delay.
    send!(
        s,
        TcpRepr {
            control: TcpControl::Psh,
            seq_number: REMOTE_SEQ + 33,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &[0; 1],
            ..SEND_TEMPL
        }
    );
    recv!(
        s,
        Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 34),
            window_len: 31,
            ..RECV_TEMPL
        })
    );

    // This frees up a byte in the receive buffer. However, the remote shouldn't be aware of
    // this since no ACKs are sent.
    s.recv_slice(&mut [0; 1]).unwrap();
    recv_nothing!(s);

    // Now, if the remote wants to send one byte outside of the receive window that we
    // previously advertised, it should not succeed.
    send!(
        s,
        TcpRepr {
            control: TcpControl::Psh,
            seq_number: REMOTE_SEQ + 34,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &[0; 32],
            ..SEND_TEMPL
        }
    );
    recv!(
        s,
        Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 65),
            window_len: 1, // The last byte isn't accepted.
            ..RECV_TEMPL
        })
    );
}

#[test]
fn test_psh_receive() {
    let mut s = socket_established();
    send!(
        s,
        TcpRepr {
            control: TcpControl::Psh,
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
}

#[test]
fn test_out_of_order() {
    let mut s = socket_established();
    send!(
        s,
        TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 3,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"def"[..],
            ..SEND_TEMPL
        },
        Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        })
    );
    s.recv(|buffer| {
        assert_eq!(buffer, b"");
        (buffer.len(), ())
    })
    .unwrap();
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
    s.recv(|buffer| {
        assert_eq!(buffer, b"abcdef");
        (buffer.len(), ())
    })
    .unwrap();
}
