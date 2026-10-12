use bytes::{BufMut, BytesMut};
use crate::session::SocksAddr;

pub mod datagram;

pub use datagram::OutboundDatagramUotV2;

/// Magic address used to signal UoT V2
pub const UDP_OVER_TCP_V2_MAGIC_HOST: &str = "sp.v2.udp-over-tcp.arpa";

/// Encodes UoT V2 Connect Request Header:
/// `isConnect(u8=1)` + `SocksAddr`
#[cfg(test)]
pub fn encode_uot_connect_request(dst_addr: &SocksAddr) -> BytesMut {
    let mut request = BytesMut::with_capacity(1 + dst_addr.size());
    request.put_u8(1); // isConnect = 1 (UoT V2 connect mode)
    dst_addr.write_buf(&mut request);
    request
}

/// Packet-address mode keeps one UDP association for all destinations.
pub fn encode_uot_packet_request() -> BytesMut {
    let mut request = BytesMut::with_capacity(8);
    request.put_u8(0);
    SocksAddr::any_ipv4().write_buf(&mut request);
    request
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_request_uses_socks_address_not_packet_address_type() {
        assert_eq!(&encode_uot_packet_request()[..], &[0, 1, 0, 0, 0, 0, 0, 0]);
    }
}
