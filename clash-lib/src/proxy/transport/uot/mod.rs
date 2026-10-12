use bytes::{BufMut, BytesMut};
use std::{io, time::Duration};
use tokio::{io::{AsyncRead, AsyncReadExt}, time::timeout};
use crate::session::SocksAddr;

mod codec;
pub mod datagram;

pub use datagram::OutboundDatagramUotV2;

/// Magic address used to signal UoT V2
pub const UDP_OVER_TCP_V2_MAGIC_HOST: &str = "sp.v2.udp-over-tcp.arpa";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) async fn read_uot_request(
    stream: &mut (impl AsyncRead + Unpin),
) -> io::Result<(bool, SocksAddr)> {
    timeout(REQUEST_TIMEOUT, async {
        let is_connect = stream.read_u8().await?;
        if is_connect > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData, "invalid UoT isConnect flag",
            ));
        }
        let address = SocksAddr::read_from(stream).await?;
        codec::validate_address(&address)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        Ok((is_connect == 1, address))
    }).await.map_err(|_| io::Error::new(
        io::ErrorKind::TimedOut, "UoT request header timed out",
    ))?
}

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
    use tokio::io::{duplex, AsyncWriteExt};

    #[tokio::test(start_paused = true)]
    async fn request_header_timeout_covers_partial_address() {
        let (mut writer, mut reader) = duplex(32);
        writer.write_all(&[0, 1, 192]).await.unwrap();
        let error = read_uot_request(&mut reader).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn request_headers_reject_invalid_flag_and_empty_domain() {
        for wire in [vec![2], vec![0, 3, 0, 0, 53]] {
            let (mut writer, mut reader) = duplex(32);
            writer.write_all(&wire).await.unwrap();
            let error = read_uot_request(&mut reader).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[tokio::test]
    async fn request_header_leaves_first_packet_unconsumed() {
        let (mut writer, mut reader) = duplex(32);
        let mut wire = encode_uot_packet_request();
        wire.extend_from_slice(b"packet");
        writer.write_all(&wire).await.unwrap();
        let (is_connect, target) = read_uot_request(&mut reader).await.unwrap();
        assert!(!is_connect);
        assert_eq!(target, SocksAddr::any_ipv4());
        let mut packet = [0; 6];
        reader.read_exact(&mut packet).await.unwrap();
        assert_eq!(&packet, b"packet");
    }

    #[test]
    fn packet_request_uses_socks_address_not_packet_address_type() {
        assert_eq!(&encode_uot_packet_request()[..], &[0, 1, 0, 0, 0, 0, 0, 0]);
    }
}
