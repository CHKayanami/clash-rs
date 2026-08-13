use bytes::{BufMut, BytesMut};
use crate::session::SocksAddr;

pub mod datagram;

pub use datagram::OutboundDatagramUotV2;

/// Magic address used to signal UoT V2 connect mode
pub const UDP_OVER_TCP_V2_MAGIC_HOST: &str = "sp.v2.udp-over-tcp.arpa";

/// Encodes UoT V2 Connect Request Header:
/// `isConnect(u8=1)` + `SocksAddr`
pub fn encode_uot_connect_request(dst_addr: &SocksAddr) -> BytesMut {
    let mut request = BytesMut::new();
    request.put_u8(1); // isConnect = 1 (UoT V2 connect mode)
    dst_addr.write_buf(&mut request);
    request
}
