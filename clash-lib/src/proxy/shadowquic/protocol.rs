use std::io;

use bytes::BytesMut;
use quinn_jls::SendStream;
use tokio::io::AsyncWriteExt;

use crate::session::SocksAddr;

pub(super) const CONNECT: u8 = 0x01;
pub(super) const ASSOCIATE_DATAGRAM: u8 = 0x03;
pub(super) const ASSOCIATE_STREAM: u8 = 0x04;

pub(super) fn payload_len(len: usize) -> io::Result<u16> {
    u16::try_from(len).map_err(|_| io::Error::new(
        io::ErrorKind::InvalidInput, "shadowquic UDP payload exceeds 65535 bytes",
    ))
}

pub(super) fn validate_addr(addr: &SocksAddr) -> io::Result<()> {
    if let SocksAddr::Domain(host, _) = addr
        && (host.is_empty() || host.len() > u8::MAX as usize)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput, "shadowquic domain length must be 1..=255",
        ));
    }
    Ok(())
}

pub(super) fn encode_addr(addr: &SocksAddr) -> io::Result<BytesMut> {
    validate_addr(addr)?;
    let mut header = BytesMut::with_capacity(addr.size());
    addr.write_buf(&mut header);
    Ok(header)
}

pub(super) async fn write_request(
    send: &mut SendStream, command: u8, addr: &SocksAddr,
) -> io::Result<()> {
    let header = encode_addr(addr)?;
    send.write_u8(command).await?;
    send.write_all(&header).await?;
    Ok(())
}
