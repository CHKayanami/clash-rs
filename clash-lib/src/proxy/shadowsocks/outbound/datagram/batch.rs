use std::array::from_fn;
use super::*;
use tokio::net::UdpSocket;
use crate::proxy::{direct::recv::recv_batch_map, utils::udp_batch::{self, DatagramSlice}};

type PacketDecoder<'a> = dyn FnMut(&mut [u8]) -> Option<(usize, SocksAddr)> + 'a;

fn poll_recv_decoded(socket: &UdpSocket, mtu: Option<usize>, cx: &mut Context<'_>,
    packets: &mut Vec<UdpPacket>, decode: &mut PacketDecoder<'_>) -> Poll<io::Result<()>> {
    loop {
        ready!(socket.poll_recv_ready(cx))?;
        let result = recv_batch_map(socket, MAX_BATCH_PACKETS, |data, _| {
            if mtu.is_some_and(|mtu| data.len() > mtu) { None } else { decode(data) }
        }, |data, _, source| packets.push(UdpPacket { data, src_addr: source, ..Default::default() }));
        match result {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            result => return Poll::Ready(result.map(|_| ())),
        }
    }
}

pub(crate) trait EncryptedTransport: DatagramSend + DatagramReceive + Unpin {
    fn send_batch(&self, cx: &mut Context<'_>, batch: &mut PacketBatch) -> Poll<BatchResult>;
    fn recv_batch(&self, cx: &mut Context<'_>, encrypted: &mut Vec<UdpPacket>,
        packets: &mut Vec<UdpPacket>, decode: &mut PacketDecoder<'_>) -> Poll<io::Result<()>>;

}

impl EncryptedTransport for ShadowsocksUdpIo {
    fn send_batch(&self, cx: &mut Context<'_>, batch: &mut PacketBatch) -> Poll<BatchResult> {
        self.state.lock().inner.poll_send_batch(cx, batch)
    }
    fn recv_batch(&self, cx: &mut Context<'_>, encrypted: &mut Vec<UdpPacket>,
        packets: &mut Vec<UdpPacket>, decode: &mut PacketDecoder<'_>) -> Poll<io::Result<()>> {
        let mut state = self.state.lock();
        if let Some(socket) = state.inner.physical_recv_socket() {
            return poll_recv_decoded(socket, None, cx, packets, decode);
        }
        if ready!(state.inner.poll_recv_batch(cx, encrypted)).is_none() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "shadowsocks transport closed")));
        }
        // Protocol chains and buffered reads own their packet storage. Keep
        // that ownership boundary; physical sockets decrypt in scratch above.
        for packet in encrypted.drain(..) {
            let mut data = packet.data.try_into_mut()
                .unwrap_or_else(|data| BytesMut::from(data.as_ref()));
            let Some((len, source)) = decode(&mut data) else { continue; };
            data.truncate(len);
            packets.push(UdpPacket { data: data.freeze(), src_addr: source, ..Default::default() });
        }
        Poll::Ready(Ok(()))
    }

}

impl EncryptedTransport for ShadowsocksUdpSocket {
    fn send_batch(&self, cx: &mut Context<'_>, batch: &mut PacketBatch) -> Poll<BatchResult> {
        let mut slices = from_fn::<_, MAX_BATCH_PACKETS, _>(|_| DatagramSlice {
            header: &[], payload: &[], destination: SocketAddr::from(([0, 0, 0, 0], 0)),
        });
        let mut count = 0;
        for packet in batch.packets() {
            if self.mtu().is_some_and(|mtu| packet.data.len() > mtu) {
                if count == 0 {
                    return Poll::Ready(BatchResult::failed(io::Error::new(io::ErrorKind::InvalidInput, "encrypted UDP packet exceeds MTU")));
                }
                break;
            }
            let SocksAddr::Ip(destination) = packet.dst_addr else { unreachable!("encrypted packet destination") };
            slices[count] = DatagramSlice { header: &[], payload: &packet.data, destination };
            count += 1;
        }
        let ipv6 = match self.local_addr() {
            Ok(address) => address.is_ipv6(),
            Err(error) => return Poll::Ready(BatchResult::failed(error)),
        };
        udp_batch::poll_send_batch(self, ipv6, cx, &slices[..count])
    }
    fn recv_batch(&self, cx: &mut Context<'_>, _: &mut Vec<UdpPacket>,
        packets: &mut Vec<UdpPacket>, decode: &mut PacketDecoder<'_>) -> Poll<io::Result<()>> {
        poll_recv_decoded(self, self.mtu(), cx, packets, decode)
    }

}

impl<S: EncryptedTransport> DatagramBatch for OutboundDatagramShadowsocks<S> {
    fn poll_send_batch(&mut self, cx: &mut Context<'_>, batch: &mut PacketBatch) -> Poll<BatchResult> {
        if self.encrypted.is_empty() && self.preparation_error.is_none() {
            if let Err(error) = ready!(Pin::new(&mut *self).poll_flush(cx)) {
                return Poll::Ready(BatchResult::failed(error));
            }
            let mut packets = batch.packets();
            if let Some(packet) = self.deferred_encrypted.take() {
                self.encrypted.push(packet).unwrap();
                packets.next().expect("deferred ciphertext belongs to the first pending packet");
            }
            for packet in packets {
                let Some(next_id) = self.ss_control.packet_id.checked_add(1) else {
                    self.preparation_error = Some(io::Error::other("packet_id overflow")); break;
                };
                let address = Address::from(&packet.dst_addr);
                // Reserve once, including for packets subsequently rejected by
                // the byte budget or the transport. Pending retains ciphertext.
                let encoded = self.inner.encode_packet(&address, &self.ss_control, &packet.data);
                self.ss_control.packet_id = next_id;
                match encoded {
                    Ok(data) => {
                        if let Err(packet) = self.encrypted.push(UdpPacket { data, dst_addr: self.remote_addr.into(),
                            ..Default::default() }) {
                            self.deferred_encrypted = Some(packet);
                            break;
                        }
                    }
                    Err(error) => { self.preparation_error = Some(error.into()); break; }
                }
            }
        }
        if self.encrypted.is_empty() {
            return Poll::Ready(BatchResult::failed(self.preparation_error.take().expect("preparation error")));
        }
        let result = ready!(self.inner.get_ref().send_batch(cx, &mut self.encrypted));
        for _ in 0..result.sent { self.encrypted.complete(); }
        if result.error.is_some() { self.encrypted.complete(); }
        let error = if result.error.is_some() { result.error }
            else if self.encrypted.is_empty() { self.preparation_error.take() } else { None };
        Poll::Ready(BatchResult { sent: result.sent, error, fatal: result.fatal })
    }

    fn poll_recv_batch(&mut self, cx: &mut Context<'_>, packets: &mut Vec<UdpPacket>) -> Poll<Option<()>> {
        // Bound invalid-packet work too, so an invalid flood cannot monopolize
        // the executor. Successful packets retain independent datagram bounds.
        for _ in 0..MAX_CONSECUTIVE_RECV_ERRORS {
            let result = ready!(self.inner.get_ref().recv_batch(cx, &mut self.encrypted_recv,
                packets, &mut |data| decode_response(&self.inner, self.ss_control.client_session_id,
                    &mut self.server_sessions, data)));
            match result {
                Ok(()) => self.consecutive_recv_errors = 0,
                Err(error) => {
                    self.consecutive_recv_errors += 1;
                    if self.consecutive_recv_errors >= MAX_CONSECUTIVE_RECV_ERRORS {
                        debug!(%error, "shadowsocks batch receive failed");
                        return Poll::Ready(None);
                    }
                    continue;
                }
            }
            if !packets.is_empty() { return Poll::Ready(Some(())); }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

fn decode_response<S: DatagramReceive>(inner: &ProxySocket<S>, client_session_id: u64,
    sessions: &mut ServerSessions, data: &mut [u8]) -> Option<(usize, SocksAddr)> {
    let (len, address, control) = match inner.decode_packet(data) {
        Ok(decoded) => decoded,
        Err(error) => { debug!(%error, "dropping invalid shadowsocks UDP packet"); return None; }
    };
    if !accept_response(control, client_session_id, sessions) { return None; }
    let source = match address {
        Address::SocketAddress(address) => address.into(),
        Address::DomainNameAddress(host, port) => SocksAddr::Domain(host.into(), port),
    };
    Some((len, source))
}
