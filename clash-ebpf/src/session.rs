use std::net::SocketAddr;

/// Information about an incoming transparently proxied connection.
#[derive(Debug)]
pub struct EbpfSession {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub protocol: TransportProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}
