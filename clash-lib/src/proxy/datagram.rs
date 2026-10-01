use crate::session::SocksAddr;
use std::{
    fmt::{Debug, Display, Formatter},
    sync::Arc,
};

#[derive(Clone)]
pub struct UdpPacket {
    pub data: bytes::Bytes,
    pub src_addr: SocksAddr,
    /// Logical destination for this packet. For fake-IP setups the dispatcher
    /// rewrites this to the resolved domain before forwarding, so proxy
    /// outbounds always see the intended domain rather than a fake-IP.
    pub dst_addr: SocksAddr,
    /// Authenticated user name from SS2022 EIH, propagated to the dispatcher
    /// session for per-user traffic attribution. `None` for all other
    /// protocols. Clones share the authenticated name with the inbound session.
    pub inbound_user: Option<Arc<str>>,
}

impl Default for UdpPacket {
    fn default() -> Self {
        Self {
            data: bytes::Bytes::new(),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: SocksAddr::any_ipv4(),
            inbound_user: None,
        }
    }
}

impl Debug for UdpPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpPacket")
            .field("src_addr", &self.src_addr)
            .field("dst_addr", &self.dst_addr)
            .finish()
    }
}

impl Display for UdpPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UDP Packet from {} to {} with {} bytes",
            self.src_addr,
            self.dst_addr,
            self.data.len()
        )
    }
}

impl UdpPacket {
    pub fn new(
        data: bytes::Bytes,
        src_addr: SocksAddr,
        dst_addr: SocksAddr,
    ) -> Self {
        Self {
            data,
            src_addr,
            dst_addr,
            inbound_user: None,
        }
    }
}

use futures::{Sink, Stream};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio_util::sync::PollSender;

#[allow(dead_code)]
#[derive(Debug)]
pub struct ChannelDatagram {
    rx: tokio::sync::mpsc::Receiver<UdpPacket>,
    tx: PollSender<UdpPacket>,
    pkt: Option<UdpPacket>,
}

#[allow(dead_code)]
pub type TunDatagram = ChannelDatagram;

impl ChannelDatagram {
    #[allow(dead_code)]
    pub fn new(
        tx: tokio::sync::mpsc::Sender<UdpPacket>,
        rx: tokio::sync::mpsc::Receiver<UdpPacket>,
    ) -> Self {
        Self {
            rx,
            tx: PollSender::new(tx),
            pkt: None,
        }
    }
}

impl Stream for ChannelDatagram {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

impl Sink<UdpPacket> for ChannelDatagram {
    type Error = std::io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.pkt.is_some() {
            if let Poll::Pending = self.as_mut().poll_flush(cx)? {
                return Poll::Pending;
            }
        }

        match Pin::new(&mut self.get_mut().tx).poll_reserve(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(_)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "PollSender channel closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        self.pkt = Some(item);
        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.pkt.is_none() {
            return Poll::Ready(Ok(()));
        }

        let this = self.get_mut();
        let pkt = this.pkt.take().unwrap();

        match Pin::new(&mut this.tx).send_item(pkt) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(_) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "PollSender failed to send item",
            ))),
        }
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_and_session_clones_share_domain_and_user() {
        let domain: Arc<str> = Arc::from("example.com");
        let user: Arc<str> = Arc::from("alice");
        let mut packet = UdpPacket::new(
            bytes::Bytes::from_static(b"payload"),
            SocksAddr::any_ipv4(),
            SocksAddr::Domain(domain.clone(), 443),
        );
        packet.inbound_user = Some(user.clone());
        let cloned = packet.clone();
        let SocksAddr::Domain(cloned_domain, _) = &cloned.dst_addr else {
            panic!("expected domain address");
        };
        assert!(Arc::ptr_eq(&domain, cloned_domain));
        assert!(Arc::ptr_eq(&user, cloned.inbound_user.as_ref().unwrap()));
        let session = crate::session::Session {
            destination: packet.dst_addr,
            inbound_user: packet.inbound_user,
            ..Default::default()
        };
        let cloned_session = session.clone();
        assert!(Arc::ptr_eq(
            &user,
            cloned_session.inbound_user.as_ref().unwrap()
        ));
        let SocksAddr::Domain(cloned_domain, _) = &cloned_session.destination else {
            panic!("expected domain address");
        };
        assert!(Arc::ptr_eq(&domain, cloned_domain));
    }
}
