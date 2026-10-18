use std::{io, net::SocketAddr, task::{Context, Poll}};
use tokio::net::UdpSocket;
use crate::proxy::{datagram::batch::{PacketBatch, BatchResult, MAX_BATCH_PACKETS},
    utils::udp_batch::{self, DatagramSlice}};

pub(super) enum BatchTarget { Relay(SocketAddr), Client }

pub(super) fn poll_send_socks_batch(
    socket: &UdpSocket, ipv6: bool, cx: &mut Context<'_>, batch: &PacketBatch, target: BatchTarget,
) -> Poll<BatchResult> {
    // Each header has independent storage. Payloads remain in the owned batch;
    // neither header nor payload is merged or copied into another allocation.
    let mut headers = [[0u8; 262]; MAX_BATCH_PACKETS];
    let mut slices = std::array::from_fn::<_, MAX_BATCH_PACKETS, _>(|_| DatagramSlice {
        header: &[], payload: &[], destination: SocketAddr::from(([0, 0, 0, 0], 0)),
    });
    let mut count = 0;
    for ((packet, header), slice) in batch.packets().zip(headers.iter_mut()).zip(slices.iter_mut()) {
        let (address, destination) = match target {
            BatchTarget::Relay(remote) => (&packet.dst_addr, Some(remote)),
            BatchTarget::Client => (&packet.src_addr, packet.dst_addr.clone().try_into_socket_addr()),
        };
        let len = 3 + address.size();
        if len > header.len() || destination.is_none() {
            if count > 0 { break; }
            return Poll::Ready(BatchResult::failed(io::Error::new(io::ErrorKind::InvalidInput, "invalid SOCKS UDP batch address")));
        }
        address.write_buf(&mut &mut header[3..len]);
        *slice = DatagramSlice { header: &header[..len], payload: &packet.data, destination: destination.unwrap() };
        count += 1;
    }
    udp_batch::poll_send_batch(socket, ipv6, cx, &slices[..count])
}
