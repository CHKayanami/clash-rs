use std::{
    collections::HashMap,
    io,
    io::Cursor,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::{Buf, BufMut, BytesMut};
use futures::{Sink, Stream, ready};
use tokio::io::AsyncWrite;
use tracing::{debug, trace};

use crate::{
    common::io::{ReadExactBase, ReadExt},
    proxy::{AnyStream, datagram::UdpPacket},
    session::SocksAddr,
};

const MAX_PACKET_LENGTH: usize = 1024 << 3; // 8KB max packet length

/// Smallest legal XUDP frame body: session id (2) + status (1) + option (1).
/// The 6 bytes already consumed cover the length field plus these four, so a
/// shorter value would underflow the "rest of frame" arithmetic below.
const XUDP_MIN_FRAME_LENGTH: usize = 4;

/// Cap on live XUDP sessions. Entries are only reclaimed when the server
/// reports an End status, so without a bound a client that reaches many
/// destinations would exhaust the 16-bit session id space.
const MAX_XUDP_SESSIONS: usize = 512;

/// Idle time after which a session may be reclaimed to make room.
const XUDP_SESSION_TTL: Duration = Duration::from_secs(300);

/// A destination bound to an XUDP session id, with the last time it was used.
struct XudpSession {
    destination: SocksAddr,
    last_used: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DatagramReadState {
    WaitingLength,
    WaitingPayload(usize),

    // XUDP states
    XudpWaitingHeader,
    XudpWaitingKeepFrameAndPayloadLength {
        remaining_frame_and_len: usize,
        option: u8,
        session_id: u16,
        status: u8,
    },
    XudpWaitingPayloadLength {
        option: u8,
        session_id: u16,
        status: u8,
    },
    XudpWaitingPayload {
        payload_len: usize,
        src_addr: SocksAddr,
        session_id: u16,
        status: u8,
    },
}

pub struct OutboundDatagramVless {
    inner: AnyStream,
    remote_addr: SocksAddr,

    // Write state
    write_buf: BytesMut,
    pending_packet: Option<UdpPacket>,

    // Read state
    read_state: DatagramReadState,
    read_buf: BytesMut,
    read_pos: usize,

    // State tracking
    flushed: bool,

    // XUDP fields
    xudp: bool,
    request_written: bool,

    // Session Multiplexing fields
    next_session_id: u16,
    destination_to_session: HashMap<SocksAddr, u16>,
    session_to_destination: HashMap<u16, XudpSession>,
}

fn read_addr_port_vmess_sync(
    buf: &mut std::io::Cursor<&[u8]>,
) -> io::Result<SocksAddr> {
    if buf.remaining() < 3 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "too short"));
    }
    let port = buf.get_u16();
    let atyp = buf.get_u8();
    match atyp {
        0x01 => {
            if buf.remaining() < 4 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "too short for ipv4",
                ));
            }
            let mut ip = [0u8; 4];
            buf.copy_to_slice(&mut ip);
            Ok(SocksAddr::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(ip)),
                port,
            )))
        }
        0x03 => {
            if buf.remaining() < 16 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "too short for ipv6",
                ));
            }
            let mut ip = [0u8; 16];
            buf.copy_to_slice(&mut ip);
            Ok(SocksAddr::Ip(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(ip)),
                port,
            )))
        }
        0x02 => {
            if buf.remaining() < 1 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "too short for domain len",
                ));
            }
            let len = buf.get_u8() as usize;
            if buf.remaining() < len {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "too short for domain name",
                ));
            }
            let mut name_buf = vec![0u8; len];
            buf.copy_to_slice(&mut name_buf);
            let domain = String::from_utf8(name_buf).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid domain")
            })?;
            Ok(SocksAddr::Domain(domain, port))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid address type",
        )),
    }
}

impl OutboundDatagramVless {
    pub fn new(inner: AnyStream, remote_addr: SocksAddr, xudp: bool) -> Self {
        Self {
            inner,
            remote_addr,
            write_buf: BytesMut::new(),
            pending_packet: None,
            read_state: if xudp {
                DatagramReadState::XudpWaitingHeader
            } else {
                DatagramReadState::WaitingLength
            },
            read_buf: BytesMut::new(),
            read_pos: 0,
            flushed: true,
            xudp,
            request_written: false,
            next_session_id: 1,
            destination_to_session: HashMap::new(),
            session_to_destination: HashMap::new(),
        }
    }

    /// Reclaim sessions that have gone idle, then the least recently used, so
    /// the table stays under [`MAX_XUDP_SESSIONS`].
    fn evict_sessions(&mut self, now: Instant) {
        if self.session_to_destination.len() < MAX_XUDP_SESSIONS {
            return;
        }

        let stale: Vec<u16> = self
            .session_to_destination
            .iter()
            .filter(|(_, s)| now.duration_since(s.last_used) >= XUDP_SESSION_TTL)
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            self.remove_session(id);
        }

        while self.session_to_destination.len() >= MAX_XUDP_SESSIONS {
            let Some(oldest) = self
                .session_to_destination
                .iter()
                .min_by_key(|(_, s)| s.last_used)
                .map(|(id, _)| *id)
            else {
                break;
            };
            trace!("evicting idle XUDP session {}", oldest);
            self.remove_session(oldest);
        }
    }

    /// Pick a free session id. Bounded: the id space is 16 bits, so a full
    /// table must report an error rather than spin looking for a free slot.
    fn allocate_session_id(&mut self) -> io::Result<u16> {
        for _ in 0..=u16::MAX as u32 {
            let id = self.next_session_id;
            self.next_session_id = self.next_session_id.wrapping_add(1);
            if self.next_session_id == 0 {
                self.next_session_id = 1;
            }
            if id != 0 && !self.session_to_destination.contains_key(&id) {
                return Ok(id);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "no free XUDP session id",
        ))
    }

    fn remove_session(&mut self, session_id: u16) {
        if let Some(session) = self.session_to_destination.remove(&session_id) {
            self.destination_to_session.remove(&session.destination);
        }
    }

    /// Record a session mapping, refreshing its idle timer.
    fn touch_session(&mut self, session_id: u16, destination: SocksAddr) {
        self.destination_to_session
            .insert(destination.clone(), session_id);
        self.session_to_destination.insert(
            session_id,
            XudpSession {
                destination,
                last_used: Instant::now(),
            },
        );
    }

    fn write_packet_xudp(
        &mut self,
        payload: &[u8],
        destination: &SocksAddr,
    ) -> Result<(), io::Error> {
        self.write_buf.clear();

        if payload.len() > MAX_PACKET_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "packet too large: {} > {}",
                    payload.len(),
                    MAX_PACKET_LENGTH
                ),
            ));
        }

        let (session_id, status, dst_addr) =
            match self.destination_to_session.get(destination).copied() {
                Some(id) => {
                    if let Some(session) = self.session_to_destination.get_mut(&id) {
                        session.last_used = Instant::now();
                    }
                    (id, super::xudp::SessionStatus::Keep, None)
                }
                None => {
                    self.evict_sessions(Instant::now());
                    let id = self.allocate_session_id()?;
                    let dst_cloned = destination.clone();
                    self.touch_session(id, dst_cloned.clone());
                    (id, super::xudp::SessionStatus::New, Some(dst_cloned))
                }
            };

        let frame = super::xudp::XudpFrame {
            session_id,
            status,
            option: super::xudp::FrameOption::new().with_data(),
            dst_addr,
            payload: Vec::new(),
        };

        frame.encode_payload(payload, &mut self.write_buf)?;
        self.request_written = true;
        Ok(())
    }

    fn write_packet(&mut self, payload: &[u8]) -> Result<(), io::Error> {
        self.write_buf.clear();

        // VLESS UDP packet format is simpler than expected:
        // Just 2-byte length + payload data
        // No address encoding in the packet data phase!

        if payload.len() > MAX_PACKET_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "packet too large: {} > {}",
                    payload.len(),
                    MAX_PACKET_LENGTH
                ),
            ));
        }

        // Write length header (big-endian)
        self.write_buf.put_u16(payload.len() as u16);

        // Write payload
        self.write_buf.put_slice(payload);

        trace!("encoded VLESS UDP packet: len={}", payload.len());
        Ok(())
    }
}

impl Sink<UdpPacket> for OutboundDatagramVless {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let this = self.get_mut();

        if this.pending_packet.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "previous packet not yet sent",
            ));
        }

        if item.data.is_empty() {
            return Ok(()); // Skip empty packets
        }

        if this.xudp {
            this.write_packet_xudp(&item.data, &item.dst_addr)?;
        } else {
            this.write_packet(&item.data)?;
        }
        this.pending_packet = Some(item);
        this.flushed = false;

        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let this = self.get_mut();

        if this.write_buf.is_empty() {
            this.flushed = true;
            this.pending_packet = None;
            return Poll::Ready(Ok(()));
        }

        let mut inner = Pin::new(&mut this.inner);

        // Write the encoded packet
        while !this.write_buf.is_empty() {
            let n = ready!(inner.as_mut().poll_write(cx, &this.write_buf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write packet data",
                )));
            }
            this.write_buf.advance(n);
        }

        // Flush the underlying stream
        ready!(inner.poll_flush(cx))?;

        if let Some(packet) = &this.pending_packet {
            debug!("sent VLESS UDP packet, data_len={}", packet.data.len());
        }

        this.flushed = true;
        this.pending_packet = None;

        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl ReadExactBase for OutboundDatagramVless {
    type I = AnyStream;

    fn decompose(&mut self) -> (&mut Self::I, &mut BytesMut, &mut usize) {
        (&mut self.inner, &mut self.read_buf, &mut self.read_pos)
    }
}

impl Stream for OutboundDatagramVless {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match this.read_state.clone() {
                DatagramReadState::WaitingLength => {
                    match this.poll_read_exact(cx, 2) {
                        Poll::Ready(Ok(())) => {
                            let packet_len = u16::from_be_bytes([
                                this.read_buf[0],
                                this.read_buf[1],
                            ]) as usize;
                            this.read_buf.clear();
                            if packet_len == 0 {
                                continue;
                            }
                            if packet_len > MAX_PACKET_LENGTH {
                                debug!("packet too large: {} bytes", packet_len);
                                return Poll::Ready(None);
                            }
                            this.read_state =
                                DatagramReadState::WaitingPayload(packet_len);
                        }
                        Poll::Ready(Err(e)) => {
                            debug!("failed to read length header: {}", e);
                            return Poll::Ready(None);
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                DatagramReadState::WaitingPayload(len) => {
                    match this.poll_read_exact(cx, len) {
                        Poll::Ready(Ok(())) => {
                            let packet_data = this.read_buf.split_to(len).freeze();
                            this.read_buf.clear();
                            this.read_state = DatagramReadState::WaitingLength;
                            return Poll::Ready(Some(UdpPacket {
                                data: packet_data,
                                src_addr: this.remote_addr.clone(),
                                dst_addr: this.remote_addr.clone(),
                                inbound_user: None,
                            }));
                        }
                        Poll::Ready(Err(e)) => {
                            debug!("failed to read payload: {}", e);
                            return Poll::Ready(None);
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                DatagramReadState::XudpWaitingHeader => {
                    match this.poll_read_exact(cx, 6) {
                        Poll::Ready(Ok(())) => {
                            let length = u16::from_be_bytes([
                                this.read_buf[0],
                                this.read_buf[1],
                            ]) as usize;
                            let session_id = u16::from_be_bytes([
                                this.read_buf[2],
                                this.read_buf[3],
                            ]);
                            let status = this.read_buf[4];
                            let option = this.read_buf[5];
                            this.read_buf.clear();

                            // `length` covers session id + status + option, all
                            // of which we just consumed. Anything shorter makes
                            // the `length - 2` below underflow into a ~18 EB
                            // read — a server-controlled abort.
                            if length < XUDP_MIN_FRAME_LENGTH {
                                debug!(
                                    "XUDP invalid frame length {}, closing",
                                    length
                                );
                                return Poll::Ready(None);
                            }

                            if status == 1 || status == 2 || status == 3 {
                                if length != 4 {
                                    // Need to read (length - 4) bytes of address/network + 2 bytes of payload length.
                                    // Total to read: length - 2.
                                    this.read_state = DatagramReadState::XudpWaitingKeepFrameAndPayloadLength {
                                        remaining_frame_and_len: length - 2,
                                        option,
                                        session_id,
                                        status,
                                    };
                                } else {
                                    // Only need to read 2 bytes of payload length.
                                    this.read_state = DatagramReadState::XudpWaitingPayloadLength {
                                        option,
                                        session_id,
                                        status,
                                    };
                                }
                            } else {
                                // Ignore unexpected status and try reading next header
                                this.read_state =
                                    DatagramReadState::XudpWaitingHeader;
                            }
                        }
                        Poll::Ready(Err(e)) => {
                            debug!("XUDP failed to read header: {}", e);
                            return Poll::Ready(None);
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                DatagramReadState::XudpWaitingKeepFrameAndPayloadLength {
                    remaining_frame_and_len,
                    option,
                    session_id,
                    status,
                } => {
                    match this.poll_read_exact(cx, remaining_frame_and_len) {
                        Poll::Ready(Ok(())) => {
                            // read_buf has remaining_frame_and_len bytes.
                            // The first 1 byte is NetworkUDP (should be 2).
                            // The next is destination address.
                            // The last 2 bytes is payload length.
                            let mut cursor = Cursor::new(this.read_buf.as_ref());
                            if cursor.remaining() < 1 {
                                this.read_buf.clear();
                                return Poll::Ready(None);
                            }
                            let _network = cursor.get_u8();
                            let src_addr =
                                match read_addr_port_vmess_sync(&mut cursor) {
                                    Ok(addr) => addr,
                                    Err(e) => {
                                        debug!(
                                            "XUDP failed to parse address: {}",
                                            e
                                        );
                                        this.read_buf.clear();
                                        return Poll::Ready(None);
                                    }
                                };
                            if cursor.remaining() < 2 {
                                debug!("XUDP no payload length found");
                                this.read_buf.clear();
                                return Poll::Ready(None);
                            }
                            let payload_len = cursor.get_u16() as usize;
                            this.read_buf.clear();

                            if payload_len > MAX_PACKET_LENGTH {
                                debug!(
                                    "XUDP payload too large: {} > {}",
                                    payload_len, MAX_PACKET_LENGTH
                                );
                                return Poll::Ready(None);
                            }

                            // Save mapped session address
                            this.evict_sessions(Instant::now());
                            this.touch_session(session_id, src_addr.clone());

                            if (option & 1) == 1 {
                                this.read_state =
                                    DatagramReadState::XudpWaitingPayload {
                                        payload_len,
                                        src_addr,
                                        session_id,
                                        status,
                                    };
                            } else {
                                if status == 3 {
                                    this.remove_session(session_id);
                                }
                                this.read_state =
                                    DatagramReadState::XudpWaitingHeader;
                            }
                        }
                        Poll::Ready(Err(e)) => {
                            debug!("XUDP failed to read keep frame: {}", e);
                            return Poll::Ready(None);
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                DatagramReadState::XudpWaitingPayloadLength {
                    option,
                    session_id,
                    status,
                } => match this.poll_read_exact(cx, 2) {
                    Poll::Ready(Ok(())) => {
                        let payload_len =
                            u16::from_be_bytes([this.read_buf[0], this.read_buf[1]])
                                as usize;
                        this.read_buf.clear();

                        if payload_len > MAX_PACKET_LENGTH {
                            debug!(
                                "XUDP payload too large: {} > {}",
                                payload_len, MAX_PACKET_LENGTH
                            );
                            return Poll::Ready(None);
                        }

                        let src_addr = this
                            .session_to_destination
                            .get(&session_id)
                            .map(|s| s.destination.clone())
                            .unwrap_or_else(|| this.remote_addr.clone());

                        if (option & 1) == 1 {
                            this.read_state =
                                DatagramReadState::XudpWaitingPayload {
                                    payload_len,
                                    src_addr,
                                    session_id,
                                    status,
                                };
                        } else {
                            if status == 3 {
                                this.remove_session(session_id);
                            }
                            this.read_state = DatagramReadState::XudpWaitingHeader;
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        debug!("XUDP failed to read payload length: {}", e);
                        return Poll::Ready(None);
                    }
                    Poll::Pending => return Poll::Pending,
                },
                DatagramReadState::XudpWaitingPayload {
                    payload_len,
                    src_addr,
                    session_id,
                    status,
                } => match this.poll_read_exact(cx, payload_len) {
                    Poll::Ready(Ok(())) => {
                        let packet_data =
                            this.read_buf.split_to(payload_len).freeze();
                        this.read_buf.clear();
                        this.read_state = DatagramReadState::XudpWaitingHeader;
                        if status == 3 {
                            this.remove_session(session_id);
                        }
                        return Poll::Ready(Some(UdpPacket {
                            data: packet_data,
                            src_addr: src_addr.clone(),
                            dst_addr: this.remote_addr.clone(),
                            inbound_user: None,
                        }));
                    }
                    Poll::Ready(Err(e)) => {
                        debug!("XUDP failed to read payload: {}", e);
                        return Poll::Ready(None);
                    }
                    Poll::Pending => return Poll::Pending,
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn tcp_dest() -> SocksAddr {
        "1.2.3.4:80".parse().unwrap()
    }

    #[tokio::test]
    async fn test_vless_datagram_roundtrip() {
        let (client_raw, mut server_raw) = tokio::io::duplex(1024);
        let mut client =
            OutboundDatagramVless::new(Box::new(client_raw), tcp_dest(), false);

        // 1. Send UDP packet from client
        let test_data = b"udp payload";
        let packet = UdpPacket {
            data: bytes::Bytes::from_static(test_data),
            src_addr: tcp_dest(),
            dst_addr: tcp_dest(),
            inbound_user: None,
        };

        let handle = tokio::spawn(async move {
            client.send(packet).await.unwrap();

            // Try reading packet back
            let resp = client.next().await.unwrap();
            assert_eq!(resp.data.as_ref(), b"server reply");
        });

        // 2. Server reads encoded client packet
        let mut len_buf = [0u8; 2];
        server_raw.read_exact(&mut len_buf).await.unwrap();
        let payload_len = u16::from_be_bytes(len_buf) as usize;
        assert_eq!(payload_len, test_data.len());

        let mut payload = vec![0u8; payload_len];
        server_raw.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload, test_data);

        // 3. Server sends packet back in chunks (to test chunked TCP read state machine)
        // Length of response "server reply" is 12 (0x000c)
        server_raw.write_all(&[0x00]).await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        server_raw.write_all(&[0x0c]).await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        // payload in chunks
        server_raw.write_all(b"server ").await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        server_raw.write_all(b"reply").await.unwrap();

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_xudp_datagram_roundtrip() {
        let (client_raw, mut server_raw) = tokio::io::duplex(1024);
        let mut client =
            OutboundDatagramVless::new(Box::new(client_raw), tcp_dest(), true);

        // 1. Send UDP packet from client
        let test_data = b"xudp payload";
        let packet = UdpPacket {
            data: bytes::Bytes::from_static(test_data),
            src_addr: tcp_dest(),
            dst_addr: tcp_dest(),
            inbound_user: None,
        };

        let handle = tokio::spawn(async move {
            client.send(packet).await.unwrap();

            // Try reading packet back
            let resp = client.next().await.unwrap();
            assert_eq!(resp.data.as_ref(), b"xudp server reply");
        });

        // 2. Server reads encoded client packet (StatusNew)
        let mut len_buf = [0u8; 2];
        server_raw.read_exact(&mut len_buf).await.unwrap();
        let frame_len = u16::from_be_bytes(len_buf) as usize;

        let mut frame_header = vec![0u8; frame_len];
        server_raw.read_exact(&mut frame_header).await.unwrap();

        // frame header should be: sessionID (2), status (1), option (1), network (1), address (N)
        assert_eq!(frame_header[0], 0);
        assert_eq!(frame_header[1], 1); // session_id = 1
        assert_eq!(frame_header[2], 1); // StatusNew
        assert_eq!(frame_header[3], 1); // OptionData
        assert_eq!(frame_header[4], 2); // NetworkUDP
        // verify address parsed using read_addr_port_vmess_sync
        let mut cursor = Cursor::new(&frame_header[5..]);
        let parsed_dest = read_addr_port_vmess_sync(&mut cursor).unwrap();
        assert_eq!(parsed_dest.port(), tcp_dest().port());

        // 2-byte payload length
        let mut payload_len_buf = [0u8; 2];
        server_raw.read_exact(&mut payload_len_buf).await.unwrap();
        let payload_len = u16::from_be_bytes(payload_len_buf) as usize;
        assert_eq!(payload_len, test_data.len());

        let mut payload = vec![0u8; payload_len];
        server_raw.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload, test_data);

        // 3. Server sends packet back (StatusKeep) for session_id = 1
        let resp_payload = b"xudp server reply";
        let mut resp_frame = BytesMut::new();

        let mut addr_buf = BytesMut::new();
        tcp_dest().write_to_buf_vmess(&mut addr_buf);
        let addr_len = addr_buf.len();

        // 2-byte frame length: 5 + addr_len
        resp_frame.put_u16((5 + addr_len) as u16);
        // session ID = 1
        resp_frame.put_u16(1);
        // status: StatusKeep
        resp_frame.put_u8(2);
        // option: OptionData
        resp_frame.put_u8(1);
        // network
        resp_frame.put_u8(2);
        // address
        resp_frame.put_slice(&addr_buf);
        // 2-byte payload length
        resp_frame.put_u16(resp_payload.len() as u16);
        // payload
        resp_frame.put_slice(resp_payload);

        server_raw.write_all(&resp_frame).await.unwrap();

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_xudp_multisession_multiplexing() {
        let (client_raw, mut server_raw) = tokio::io::duplex(2048);
        let mut client =
            OutboundDatagramVless::new(Box::new(client_raw), tcp_dest(), true);

        let dest1: SocksAddr = "1.1.1.1:53".parse().unwrap();
        let dest2: SocksAddr = "8.8.8.8:53".parse().unwrap();

        let packet1 = UdpPacket {
            data: bytes::Bytes::from_static(b"dns query 1"),
            src_addr: dest1.clone(),
            dst_addr: dest1.clone(),
            inbound_user: None,
        };
        let packet2 = UdpPacket {
            data: bytes::Bytes::from_static(b"dns query 2"),
            src_addr: dest2.clone(),
            dst_addr: dest2.clone(),
            inbound_user: None,
        };

        let dest1_check = dest1.clone();
        let dest2_check = dest2.clone();
        let handle = tokio::spawn(async move {
            client.send(packet1).await.unwrap();
            client.send(packet2).await.unwrap();

            let resp1 = client.next().await.unwrap();
            let resp2 = client.next().await.unwrap();

            assert_eq!(resp1.data.as_ref(), b"dns resp 1");
            assert_eq!(resp1.src_addr, dest1_check);

            assert_eq!(resp2.data.as_ref(), b"dns resp 2");
            assert_eq!(resp2.src_addr, dest2_check);
        });

        // Drain packet 1 (StatusNew, session_id = 1)
        let mut len_buf = [0u8; 2];
        server_raw.read_exact(&mut len_buf).await.unwrap();
        let frame_len = u16::from_be_bytes(len_buf) as usize;
        let mut frame1_hdr = vec![0u8; frame_len];
        server_raw.read_exact(&mut frame1_hdr).await.unwrap();
        let session_id_1 = u16::from_be_bytes([frame1_hdr[0], frame1_hdr[1]]);
        assert_eq!(session_id_1, 1);
        let mut plen_buf = [0u8; 2];
        server_raw.read_exact(&mut plen_buf).await.unwrap();
        let plen1 = u16::from_be_bytes(plen_buf) as usize;
        let mut p1 = vec![0u8; plen1];
        server_raw.read_exact(&mut p1).await.unwrap();

        // Drain packet 2 (StatusNew, session_id = 2)
        server_raw.read_exact(&mut len_buf).await.unwrap();
        let frame_len = u16::from_be_bytes(len_buf) as usize;
        let mut frame2_hdr = vec![0u8; frame_len];
        server_raw.read_exact(&mut frame2_hdr).await.unwrap();
        let session_id_2 = u16::from_be_bytes([frame2_hdr[0], frame2_hdr[1]]);
        assert_eq!(session_id_2, 2);
        server_raw.read_exact(&mut plen_buf).await.unwrap();
        let plen2 = u16::from_be_bytes(plen_buf) as usize;
        let mut p2 = vec![0u8; plen2];
        server_raw.read_exact(&mut p2).await.unwrap();

        // Server responds to session 1
        let mut resp_frame1 = BytesMut::new();
        let mut addr_buf1 = BytesMut::new();
        dest1.write_to_buf_vmess(&mut addr_buf1);
        resp_frame1.put_u16((5 + addr_buf1.len()) as u16);
        resp_frame1.put_u16(session_id_1);
        resp_frame1.put_u8(1); // StatusNew with address
        resp_frame1.put_u8(1); // OptionData
        resp_frame1.put_u8(2); // NetworkUDP
        resp_frame1.put_slice(&addr_buf1);
        resp_frame1.put_u16(b"dns resp 1".len() as u16);
        resp_frame1.put_slice(b"dns resp 1");
        server_raw.write_all(&resp_frame1).await.unwrap();

        // Server responds to session 2
        let mut resp_frame2 = BytesMut::new();
        let mut addr_buf2 = BytesMut::new();
        dest2.write_to_buf_vmess(&mut addr_buf2);
        resp_frame2.put_u16((5 + addr_buf2.len()) as u16);
        resp_frame2.put_u16(session_id_2);
        resp_frame2.put_u8(1); // StatusNew with address
        resp_frame2.put_u8(1); // OptionData
        resp_frame2.put_u8(2); // NetworkUDP
        resp_frame2.put_slice(&addr_buf2);
        resp_frame2.put_u16(b"dns resp 2".len() as u16);
        resp_frame2.put_slice(b"dns resp 2");
        server_raw.write_all(&resp_frame2).await.unwrap();

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_xudp_datagram_status_new_response() {
        let (client_raw, mut server_raw) = tokio::io::duplex(1024);
        let mut client =
            OutboundDatagramVless::new(Box::new(client_raw), tcp_dest(), true);

        let test_data = b"xudp ping";
        let packet = UdpPacket {
            data: bytes::Bytes::from_static(test_data),
            src_addr: tcp_dest(),
            dst_addr: tcp_dest(),
            inbound_user: None,
        };

        let handle = tokio::spawn(async move {
            client.send(packet).await.unwrap();

            // Read packet back from server StatusNew response
            let resp = client.next().await.unwrap();
            assert_eq!(resp.data.as_ref(), b"xudp pong from StatusNew");
        });

        // Drain client request frame
        let mut len_buf = [0u8; 2];
        server_raw.read_exact(&mut len_buf).await.unwrap();
        let frame_len = u16::from_be_bytes(len_buf) as usize;
        let mut dummy = vec![0u8; frame_len];
        server_raw.read_exact(&mut dummy).await.unwrap();
        let mut plen_buf = [0u8; 2];
        server_raw.read_exact(&mut plen_buf).await.unwrap();
        let plen = u16::from_be_bytes(plen_buf) as usize;
        let mut dummy_p = vec![0u8; plen];
        server_raw.read_exact(&mut dummy_p).await.unwrap();

        // Server responds with StatusNew (status = 1)
        let resp_payload = b"xudp pong from StatusNew";
        let mut resp_frame = BytesMut::new();

        let mut addr_buf = BytesMut::new();
        tcp_dest().write_to_buf_vmess(&mut addr_buf);
        let addr_len = addr_buf.len();

        resp_frame.put_u16((5 + addr_len) as u16);
        resp_frame.put_u16(0); // session ID
        resp_frame.put_u8(1); // status: StatusNew (1)
        resp_frame.put_u8(1); // option: OptionData
        resp_frame.put_u8(2); // network: NetworkUDP
        resp_frame.put_slice(&addr_buf);
        resp_frame.put_u16(resp_payload.len() as u16);
        resp_frame.put_slice(resp_payload);

        server_raw.write_all(&resp_frame).await.unwrap();

        handle.await.unwrap();
    }
}
