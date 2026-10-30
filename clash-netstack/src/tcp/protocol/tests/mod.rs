// Derived from smoltcp commit 6b126ba1e965add8d765dffee0338756ffdfb6da.
// Copyright (C) smoltcp contributors; licensed under 0BSD.
// See the protocol directory's LICENSE-0BSD.txt.

use super::*;
use smoltcp::wire::{IpCidr, IpRepr};
use std::ops::{Deref, DerefMut};
use std::vec::Vec;

// =========================================================================================//
// Constants
// =========================================================================================//

const LOCAL_PORT: u16 = 80;
const REMOTE_PORT: u16 = 49500;
const LISTEN_END: IpListenEndpoint = IpListenEndpoint {
    addr: None,
    port: LOCAL_PORT,
};
const TUPLE: Tuple = Tuple {
    local: LOCAL_END,
    remote: REMOTE_END,
};
const LOCAL_SEQ: TcpSeqNumber = TcpSeqNumber(10000);
const REMOTE_SEQ: TcpSeqNumber = TcpSeqNumber(-10001);

        use smoltcp::wire::Ipv4Address as IpvXAddress;
        use smoltcp::wire::Ipv4Repr as IpvXRepr;
        use IpRepr::Ipv4 as IpReprIpvX;

        const LOCAL_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 1);
        const REMOTE_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 2);
        const OTHER_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 3);

        const BASE_MSS: u16 = 1460;

        const LOCAL_END: IpEndpoint = IpEndpoint {
            addr: IpAddress::Ipv4(LOCAL_ADDR),
            port: LOCAL_PORT,
        };
        const REMOTE_END: IpEndpoint = IpEndpoint {
            addr: IpAddress::Ipv4(REMOTE_ADDR),
            port: REMOTE_PORT,
        };

const SEND_IP_TEMPL: IpRepr = IpReprIpvX(IpvXRepr {
    src_addr: LOCAL_ADDR,
    dst_addr: REMOTE_ADDR,
    next_header: IpProtocol::Tcp,
    payload_len: 20,
    hop_limit: 64,
});
const SEND_TEMPL: TcpRepr<'static> = TcpRepr {
    src_port: REMOTE_PORT,
    dst_port: LOCAL_PORT,
    control: TcpControl::None,
    seq_number: TcpSeqNumber(0),
    ack_number: Some(TcpSeqNumber(0)),
    window_len: 256,
    window_scale: None,
    max_seg_size: None,
    sack_permitted: false,
    sack_ranges: [None, None, None],
    timestamp: None,
    payload: &[],
};
const _RECV_IP_TEMPL: IpRepr = IpReprIpvX(IpvXRepr {
    src_addr: LOCAL_ADDR,
    dst_addr: REMOTE_ADDR,
    next_header: IpProtocol::Tcp,
    payload_len: 20,
    hop_limit: 64,
});
const RECV_TEMPL: TcpRepr<'static> = TcpRepr {
    src_port: LOCAL_PORT,
    dst_port: REMOTE_PORT,
    control: TcpControl::None,
    seq_number: TcpSeqNumber(0),
    ack_number: Some(TcpSeqNumber(0)),
    window_len: 64,
    window_scale: None,
    max_seg_size: None,
    sack_permitted: false,
    sack_ranges: [None, None, None],
    timestamp: None,
    payload: &[],
};

// =========================================================================================//
// Helper functions
// =========================================================================================//

struct TestSocket {
    socket: Socket<'static>,
    cx: Context,
}

impl Deref for TestSocket {
    type Target = Socket<'static>;
    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

impl DerefMut for TestSocket {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.socket
    }
}

#[track_caller]
fn send(
    socket: &mut TestSocket,
    timestamp: Instant,
    repr: &TcpRepr,
) -> Option<TcpRepr<'static>> {
    socket.cx.set_now(timestamp);

    let ip_repr = IpReprIpvX(IpvXRepr {
        src_addr: REMOTE_ADDR,
        dst_addr: LOCAL_ADDR,
        next_header: IpProtocol::Tcp,
        payload_len: repr.buffer_len(),
        hop_limit: 64,
    });
    net_trace!("send: {}", repr);

    assert!(socket.socket.accepts(&mut socket.cx, &ip_repr, repr));

    match socket.socket.process(&mut socket.cx, &ip_repr, repr) {
        Some((_ip_repr, repr)) => {
            net_trace!("recv: {}", repr);
            Some(repr)
        }
        None => None,
    }
}

#[track_caller]
fn recv<F>(socket: &mut TestSocket, timestamp: Instant, mut f: F)
where
    F: FnMut(Result<TcpRepr, ()>),
{
    socket.cx.set_now(timestamp);

    let mut sent = 0;
    let result = socket
        .socket
        .dispatch(&mut socket.cx, |_, _, (ip_repr, tcp_repr)| {
            assert_eq!(ip_repr.next_header(), IpProtocol::Tcp);
            assert_eq!(ip_repr.src_addr(), LOCAL_ADDR.into());
            assert_eq!(ip_repr.dst_addr(), REMOTE_ADDR.into());
            assert_eq!(ip_repr.payload_len(), tcp_repr.buffer_len());

            net_trace!("recv: {}", tcp_repr);
            sent += 1;
            Ok(f(Ok(tcp_repr)))
        });
    match result {
        Ok(()) => assert_eq!(sent, 1, "Exactly one packet should be sent"),
        Err(e) => f(Err(e)),
    }
}

#[track_caller]
fn recv_nothing(socket: &mut TestSocket, timestamp: Instant) {
    socket.cx.set_now(timestamp);

    let mut fail = false;
    let result: Result<(), ()> = socket.socket.dispatch(&mut socket.cx, |_, _, _| {
        fail = true;
        Ok(())
    });
    if fail {
        panic!("Should not send a packet")
    }

    assert_eq!(result, Ok(()))
}

#[collapse_debuginfo(yes)]
macro_rules! send {
    ($socket:ident, $repr:expr) =>
        (send!($socket, time 0, $repr));
    ($socket:ident, $repr:expr, $result:expr) =>
        (send!($socket, time 0, $repr, $result));
    ($socket:ident, time $time:expr, $repr:expr) =>
        (send!($socket, time $time, $repr, None));
    ($socket:ident, time $time:expr, $repr:expr, $result:expr) =>
        (assert_eq!(send(&mut $socket, Instant::from_millis($time), &$repr), $result));
}

#[collapse_debuginfo(yes)]
macro_rules! recv {
    ($socket:ident, [$( $repr:expr ),*]) => ({
        $( recv!($socket, Ok($repr)); )*
        recv_nothing!($socket)
    });
    ($socket:ident, time $time:expr, [$( $repr:expr ),*]) => ({
        $( recv!($socket, time $time, Ok($repr)); )*
        recv_nothing!($socket, time $time)
    });
    ($socket:ident, $result:expr) =>
        (recv!($socket, time 0, $result));
    ($socket:ident, time $time:expr, $result:expr) =>
        (recv(&mut $socket, Instant::from_millis($time), |result| {
            // Most of the time we don't care about the PSH flag.
            let result = result.map(|mut repr| {
                repr.control = repr.control.quash_psh();
                repr
            });
            assert_eq!(result, $result)
        }));
    ($socket:ident, time $time:expr, $result:expr, exact) =>
        (recv(&mut $socket, Instant::from_millis($time), |repr| assert_eq!(repr, $result)));
}

#[collapse_debuginfo(yes)]
macro_rules! recv_nothing {
    ($socket:ident) => (recv_nothing!($socket, time 0));
    ($socket:ident, time $time:expr) => (recv_nothing(&mut $socket, Instant::from_millis($time)));
}

#[collapse_debuginfo(yes)]
macro_rules! sanity {
    ($socket1:expr, $socket2:expr) => {{
        let (s1, s2) = ($socket1, $socket2);
        assert_eq!(s1.state, s2.state, "state");
        assert_eq!(s1.tuple, s2.tuple, "tuple");
        assert_eq!(s1.local_seq_no, s2.local_seq_no, "local_seq_no");
        assert_eq!(s1.remote_seq_no, s2.remote_seq_no, "remote_seq_no");
        assert_eq!(s1.remote_last_seq, s2.remote_last_seq, "remote_last_seq");
        assert_eq!(s1.remote_last_ack, s2.remote_last_ack, "remote_last_ack");
        assert_eq!(
            s1.remote_last_win_len, s2.remote_last_win_len,
            "remote_last_win_len"
        );
        assert_eq!(s1.remote_win_len, s2.remote_win_len, "remote_win_len");
        assert_eq!(s1.timer, s2.timer, "timer");
    }};
}

fn socket() -> TestSocket {
    socket_with_buffer_sizes(64, 64)
}

fn socket_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {

    let rx_buffer = SocketBuffer::new(vec![0; rx_len]);
    let tx_buffer = SocketBuffer::new(vec![0; tx_len]);
    let mut socket = Socket::new(rx_buffer, tx_buffer);
    socket.set_ack_delay(None);
    TestSocket {
        socket,
        cx: Context::for_tests(),
    }
}

fn socket_syn_received_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
    let mut s = socket_with_buffer_sizes(tx_len, rx_len);
    s.state = State::SynReceived;
    s.tuple = Some(TUPLE);
    s.local_seq_no = LOCAL_SEQ;
    s.remote_seq_no = REMOTE_SEQ + 1;
    s.remote_last_seq = LOCAL_SEQ;
    s.remote_win_len = 256;
    s
}

fn socket_syn_received() -> TestSocket {
    socket_syn_received_with_buffer_sizes(64, 64)
}

fn socket_syn_sent_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
    let mut s = socket_with_buffer_sizes(tx_len, rx_len);
    s.state = State::SynSent;
    s.tuple = Some(TUPLE);
    s.local_seq_no = LOCAL_SEQ;
    s.remote_last_seq = LOCAL_SEQ;
    s
}

fn socket_syn_sent() -> TestSocket {
    socket_syn_sent_with_buffer_sizes(64, 64)
}

fn socket_established_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
    let mut s = socket_syn_received_with_buffer_sizes(tx_len, rx_len);
    s.state = State::Established;
    s.local_seq_no = LOCAL_SEQ + 1;
    s.remote_last_seq = LOCAL_SEQ + 1;
    s.remote_last_ack = Some(REMOTE_SEQ + 1);
    s.remote_last_win_len = (s.scaled_window() as usize) << s.remote_win_shift;
    s
}

fn socket_established() -> TestSocket {
    socket_established_with_buffer_sizes(64, 64)
}

fn socket_fin_wait_1() -> TestSocket {
    let mut s = socket_established();
    s.state = State::FinWait1;
    s
}

fn socket_fin_wait_2() -> TestSocket {
    let mut s = socket_fin_wait_1();
    s.state = State::FinWait2;
    s.local_seq_no = LOCAL_SEQ + 1 + 1;
    s.remote_last_seq = LOCAL_SEQ + 1 + 1;
    s
}

fn socket_closing() -> TestSocket {
    let mut s = socket_fin_wait_1();
    s.state = State::Closing;
    s.remote_last_seq = LOCAL_SEQ + 1 + 1;
    s.remote_seq_no = REMOTE_SEQ + 1 + 1;
    s.timer = Timer::Retransmit {
        expires_at: Instant::from_millis_const(1000),
    };
    s
}

fn socket_time_wait(from_closing: bool) -> TestSocket {
    let mut s = socket_fin_wait_2();
    s.state = State::TimeWait;
    s.remote_seq_no = REMOTE_SEQ + 1 + 1;
    if from_closing {
        s.remote_last_ack = Some(REMOTE_SEQ + 1 + 1);
    }
    s.timer = Timer::Close {
        expires_at: Instant::from_secs(1) + CLOSE_DELAY,
    };
    s
}

fn socket_close_wait() -> TestSocket {
    let mut s = socket_established();
    s.state = State::CloseWait;
    s.remote_seq_no = REMOTE_SEQ + 1 + 1;
    s.remote_last_ack = Some(REMOTE_SEQ + 1 + 1);
    s
}

fn socket_last_ack() -> TestSocket {
    let mut s = socket_close_wait();
    s.state = State::LastAck;
    s
}

fn socket_recved() -> TestSocket {
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
    s
}

// =========================================================================================//
// Tests for the CLOSED state.
// =========================================================================================//

fn growth_handshake(initial: usize) -> TestSocket {
    let mut s = socket_with_buffer_sizes(64, initial);
    s.set_receive_capacity_limit(4 * 1024 * 1024);
    assert_eq!(s.remote_win_shift, 7);
    assert_eq!(s.receive_capacity_limit(), 4 * 1024 * 1024);
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
        let reply = reply.unwrap();
        assert_eq!(reply.window_len, initial as u16);
        assert_eq!(reply.window_scale, Some(7));
    });
    assert!(!s.window_to_update(&s.cx));
    assert_eq!(s.remote_last_win_len, initial);
    let ack = s.local_seq_no + 1;
    send(
        &mut s,
        Instant::from_millis(0),
        &TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(ack),
            ..SEND_TEMPL
        },
    );
    assert_eq!(s.state(), State::Established);
    s
}

// =========================================================================================//
// Tests for the LISTEN state.
// =========================================================================================//
fn socket_listen() -> TestSocket {
    let mut s = socket();
    s.state = State::Listen;
    s.listen_endpoint = LISTEN_END;
    s
}

// =========================================================================================//
// Tests for the SYN-RECEIVED state.
// =========================================================================================//

// =========================================================================================//
// Tests for the SYN-SENT state.
// =========================================================================================//

// =========================================================================================//
// Tests for the ESTABLISHED state.
// =========================================================================================//

fn setup_rfc2018_cases() -> (TestSocket, Vec<u8>) {
    // This is a utility function used by the tests for RFC 2018 cases. It configures a socket
    // in a particular way suitable for those cases.
    //
    // RFC 2018: Assume the left window edge is 5000 and that the data transmitter sends [...]
    // segments, each containing 500 data bytes.
    let mut s = socket_established_with_buffer_sizes(4000, 4000);
    s.remote_has_sack = true;

    // create a segment that is 500 bytes long
    let mut segment: Vec<u8> = Vec::with_capacity(500);

    // move the last ack to 5000 by sending ten of them
    for _ in 0..50 {
        segment.extend_from_slice(b"abcdefghij")
    }
    for offset in (0..5000).step_by(500) {
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + offset,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + offset + 500),
                window_len: 3500,
                ..RECV_TEMPL
            }]
        );
        s.recv(|data| {
            assert_eq!(data.len(), 500);
            assert_eq!(data, segment.as_slice());
            (500, ())
        })
        .unwrap();
    }
    assert_eq!(s.remote_last_win_len, 3500);
    (s, segment)
}

// =========================================================================================//
// Tests for the FIN-WAIT-1 state.
// =========================================================================================//

// =========================================================================================//
// Tests for the FIN-WAIT-2 state.
// =========================================================================================//

// =========================================================================================//
// Tests for the CLOSING state.
// =========================================================================================//

// =========================================================================================//
// Tests for the TIME-WAIT state.
// =========================================================================================//

// =========================================================================================//
// Tests for the CLOSE-WAIT state.
// =========================================================================================//

// =========================================================================================//
// Tests for the LAST-ACK state.
// =========================================================================================//

// RFC 9293 §3.10.7.4: duplicate ACK in LAST-ACK must elicit a challenge ACK,
// not be silently dropped.

// A partial ACK in LAST-ACK (ack_len > 0 but not FIN ACK) advances SND.UNA
// without a challenge ACK; the FIN will be retransmitted by the timer.

// =========================================================================================//
// Tests for transitioning through multiple states.
// =========================================================================================//

// =========================================================================================//
// Tests for retransmission on packet loss.
// =========================================================================================//

// =========================================================================================//
// Tests for window management.
// =========================================================================================//

// =========================================================================================//
// Tests for flow control.
// =========================================================================================//

// =========================================================================================//
// Tests for zero-window probes.
// =========================================================================================//

// =========================================================================================//
// Tests for timeouts.
// =========================================================================================//

// =========================================================================================//
// Tests for keep-alive.
// =========================================================================================//

// =========================================================================================//
// Tests for time-to-live configuration.
// =========================================================================================//

// =========================================================================================//
// Tests for reassembly.
// =========================================================================================//

// =========================================================================================//
// Tests for graceful vs ungraceful rx close
// =========================================================================================//

// =========================================================================================//
// Tests for delayed ACK
// =========================================================================================//

// =========================================================================================//
// Tests for Nagle's Algorithm
// =========================================================================================//

// =========================================================================================//
// Tests for packet filtering.
// =========================================================================================//

// =========================================================================================//
// Timer tests
// =========================================================================================//

// =========================================================================================//
// Timestamp tests
// =========================================================================================//

// =========================================================================================//
// Tests for source IP address change.
// =========================================================================================//

mod buffers;
mod closing;
mod handshake;
mod receive;
mod recovery;
mod transfer;
mod windows;
