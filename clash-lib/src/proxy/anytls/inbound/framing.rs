#![cfg(test)]

//! AnyTLS frame codec — read/write the wire format and protocol constants.

use tokio::io::{AsyncRead, AsyncReadExt};

// AnyTLS frame command bytes — same as outbound.
pub(crate) const CMD_SYN: u8 = 1;
pub(crate) const CMD_PSH: u8 = 2;
pub(crate) const CMD_SETTINGS: u8 = 4;

/// The magic hostname used by the client for UDP-over-TCP v2 sessions.
pub(crate) const UDP_OVER_TCP_V2_MAGIC_HOST: &str = "sp.v2.udp-over-tcp.arpa";

/// Read one AnyTLS frame: `CMD(1) | StreamID(u32-BE) | DataLen(u16-BE) | Data`.
pub(crate) async fn read_frame(
    reader: &mut (impl AsyncRead + Unpin),
) -> std::io::Result<(u8, u32, Vec<u8>)> {
    let command = reader.read_u8().await?;
    let stream_id = reader.read_u32().await?;
    let data_len = reader.read_u16().await? as usize;
    let mut data = vec![0u8; data_len];
    if data_len > 0 {
        reader.read_exact(&mut data).await?;
    }
    Ok((command, stream_id, data))
}
