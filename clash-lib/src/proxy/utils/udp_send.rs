use std::{io::{self, IoSlice}, net::SocketAddr, task::{Context, Poll}};
use futures::ready;
use socket2::{SockAddr, SockRef};
use tokio::{io::Interest, net::UdpSocket};

/// Send header and payload as one datagram without merging their allocations.
/// The caller retains both slices unchanged while this returns Pending.
pub(crate) fn poll_send_to_vectored(
    socket: &UdpSocket, cx: &mut Context<'_>, header: &[u8], payload: &[u8],
    destination: SocketAddr,
) -> Poll<io::Result<()>> {
    loop {
        ready!(socket.poll_send_ready(cx))?;
        let result = socket.try_io(Interest::WRITABLE, || {
            SockRef::from(socket).send_to_vectored(
                &[IoSlice::new(header), IoSlice::new(payload)],
                &SockAddr::from(destination),
            )
        });
        match result {
            Err(err) if matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => continue,
            result => return Poll::Ready(result.and_then(|sent| {
                if sent == header.len() + payload.len() { Ok(()) }
                else { Err(io::Error::new(io::ErrorKind::WriteZero, "partial UDP datagram send")) }
            })),
        }
    }
}
