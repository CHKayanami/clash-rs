use crate::session::SocksAddr;
use anyhow::anyhow;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use quinn_proto::{VarInt, coding::Codec};
use rand::distr::Distribution;
use std::{io::ErrorKind, str::FromStr};
use tokio_util::codec::{Decoder, Encoder};

pub struct Hy2TcpCodec;

/// Ceiling on the server's status message. Lengths arrive as a QUIC varint, so
/// without a bound a server can name any size up to 2^62 and have us allocate
/// it sight unseen.
const MAX_RESP_MSG_LEN: usize = 8 * 1024;

/// Ceiling on the server's random padding, per the same reasoning. Hysteria
/// itself pads with a few hundred bytes.
const MAX_RESP_PADDING_LEN: u64 = 64 * 1024;

/// Longest address string we will accept in a UDP packet header. A `SocksAddr`
/// domain is at most 255 bytes plus `:65535`.
const MAX_ADDR_LEN: usize = 256 + 6;

/// ### format
///
/// ```text
/// [uint8] Status (0x00 = OK, 0x01 = Error)
/// [varint] Message length
/// [bytes] Message string
/// [varint] Padding length
/// [bytes] Random padding
/// ```
#[derive(Debug)]
pub struct Hy2TcpResp {
    pub status: u8,
    pub msg: String,
}

pub async fn read_hy2_resp<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Hy2TcpResp> {
    use tokio::io::AsyncReadExt;
    let status = reader.read_u8().await?;

    let msg_len = read_varint(reader).await?;
    if msg_len > MAX_RESP_MSG_LEN as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "hysteria2 response message too long: {} > {}",
                msg_len, MAX_RESP_MSG_LEN
            ),
        ));
    }
    let mut msg_buf = vec![0u8; msg_len as usize];
    if msg_len > 0 {
        reader.read_exact(&mut msg_buf).await?;
    }
    let msg = String::from_utf8(msg_buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let padding_len = read_varint(reader).await?;
    if padding_len > MAX_RESP_PADDING_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "hysteria2 response padding too long: {} > {}",
                padding_len, MAX_RESP_PADDING_LEN
            ),
        ));
    }
    if padding_len > 0 {
        // discard in bounded chunks rather than allocating the whole run
        let mut remaining = padding_len;
        let mut pad_buf = [0u8; 1024];
        while remaining > 0 {
            let take = remaining.min(pad_buf.len() as u64) as usize;
            reader.read_exact(&mut pad_buf[..take]).await?;
            remaining -= take as u64;
        }
    }

    Ok(Hy2TcpResp { status, msg })
}

async fn read_varint<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<u64> {
    use tokio::io::AsyncReadExt;
    let b0 = reader.read_u8().await?;
    let tag = b0 >> 6;
    let first_byte_val = (b0 & 0x3f) as u64;
    match tag {
        0b00 => Ok(first_byte_val),
        0b01 => {
            let b1 = reader.read_u8().await? as u64;
            Ok((first_byte_val << 8) | b1)
        }
        0b10 => {
            let mut buf = [0u8; 3];
            reader.read_exact(&mut buf).await?;
            let val =
                ((buf[0] as u64) << 16) | ((buf[1] as u64) << 8) | (buf[2] as u64);
            Ok((first_byte_val << 24) | val)
        }
        0b11 => {
            let mut buf = [0u8; 7];
            reader.read_exact(&mut buf).await?;
            let mut val = 0u64;
            for b in buf {
                val = (val << 8) | (b as u64);
            }
            Ok((first_byte_val << 56) | val)
        }
        _ => unreachable!(),
    }
}

impl Decoder for Hy2TcpCodec {
    type Error = std::io::Error;
    type Item = Hy2TcpResp;

    fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        // Peek over a borrowed slice — `src.clone()` deep-copied the whole
        // buffer on every call just to answer "is the frame complete yet?".
        let mut peek: &[u8] = &src[..];

        if !peek.has_remaining() {
            return Ok(None);
        }
        let _status = peek.get_u8();

        let Ok(msg_len_var) = VarInt::decode(&mut peek) else {
            return Ok(None);
        };
        let msg_len = msg_len_var.into_inner();
        if msg_len > MAX_RESP_MSG_LEN as u64 {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "hysteria2 response message too long: {} > {}",
                    msg_len, MAX_RESP_MSG_LEN
                ),
            ));
        }
        let msg_len = msg_len as usize;

        if peek.remaining() < msg_len {
            return Ok(None);
        }
        peek.advance(msg_len);

        let Ok(padding_len_var) = VarInt::decode(&mut peek) else {
            return Ok(None);
        };
        let padding_len = padding_len_var.into_inner();
        if padding_len > MAX_RESP_PADDING_LEN {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "hysteria2 response padding too long: {} > {}",
                    padding_len, MAX_RESP_PADDING_LEN
                ),
            ));
        }
        let padding_len = padding_len as usize;

        if peek.remaining() < padding_len {
            return Ok(None);
        }

        // The peek above proved every field is present, so the destructive
        // pass below cannot run off the end.
        let status = src.get_u8();
        let msg_len = VarInt::decode(src)
            .map_err(|_| ErrorKind::InvalidData)?
            .into_inner() as usize;

        let msg_bytes = src.split_to(msg_len);
        let msg = String::from_utf8(msg_bytes.to_vec())
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;

        let padding_len = VarInt::decode(src)
            .map_err(|_| ErrorKind::InvalidData)?
            .into_inner() as usize;
        src.advance(padding_len);

        Ok(Some(Hy2TcpResp { status, msg }))
    }
}

#[inline]
pub fn padding(range: std::ops::RangeInclusive<u32>) -> Vec<u8> {
    let len = rand::random_range(range) as usize;
    rand::distr::Alphanumeric
        .sample_iter(rand::rng())
        .take(len)
        .collect()
}

impl Encoder<&'_ SocksAddr> for Hy2TcpCodec {
    type Error = std::io::Error;

    fn encode(
        &mut self,
        item: &'_ SocksAddr,
        buf: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        const REQ_ID: VarInt = VarInt::from_u32(0x401);

        let padding = padding(64..=512);
        let padding_var = VarInt::from_u32(padding.len() as u32);

        let addr = item.to_string().into_bytes();
        let addr_var = VarInt::from_u32(addr.len() as u32);

        buf.reserve(
            var_size(REQ_ID)
                + var_size(padding_var)
                + var_size(addr_var)
                + addr.len()
                + padding.len(),
        );

        REQ_ID.encode(buf);

        addr_var.encode(buf);
        buf.put_slice(&addr);

        padding_var.encode(buf);
        buf.put_slice(&padding);

        Ok(())
    }
}

/// Compute the number of bytes needed to encode this value
pub fn var_size(var: VarInt) -> usize {
    let x = var.into_inner();
    if x < 2u64.pow(6) {
        1
    } else if x < 2u64.pow(14) {
        2
    } else if x < 2u64.pow(30) {
        4
    } else if x < 2u64.pow(62) {
        8
    } else {
        unreachable!("malformed VarInt");
    }
}

/// ```text
/// [uint32] Session ID
/// [uint16] Packet ID
/// [uint8] Fragment ID
/// [uint8] Fragment count
/// [varint] Address length
/// [bytes] Address string (host:port)
/// [bytes] Payload
/// ```
#[derive(Clone)]
pub struct HysUdpPacket {
    pub session_id: u32,
    pub pkt_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    pub addr: SocksAddr,
    pub data: Bytes,
}

impl std::fmt::Debug for HysUdpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HysUdpPacket")
            .field("session_id", &format_args!("{:#010x}", self.session_id))
            .field("pkt_id", &self.pkt_id)
            .field("frag_id", &self.frag_id)
            .field("frag_count", &self.frag_count)
            .field("addr", &self.addr)
            .field("data_size", &self.data.len())
            .finish()
    }
}

impl HysUdpPacket {
    /// `decode` method, `encode` has been moved to Fragments
    pub fn decode(buf: &mut BytesMut) -> anyhow::Result<Self> {
        if buf.len() < 4 + 2 + 1 + 1 {
            return Err(anyhow!("packet too short"));
        }
        let session_id = buf.get_u32();
        let pkt_id = buf.get_u16();
        let frag_id = buf.get_u8();
        let frag_count = buf.get_u8();
        let addr_len = VarInt::decode(buf)
            .map_err(|_| anyhow!("malformed address length"))?
            .into_inner();
        // `split_to` panics past the end, and the length is server-controlled.
        if addr_len > MAX_ADDR_LEN as u64 || addr_len > buf.remaining() as u64 {
            return Err(anyhow!(
                "invalid address length {} (remaining {})",
                addr_len,
                buf.remaining()
            ));
        }
        let addr: Vec<u8> = buf.split_to(addr_len as usize).into();
        let data = buf.split().freeze();
        Ok(Self {
            session_id,
            pkt_id,
            frag_id,
            frag_count,
            addr: to_socksaddr(&addr)?,
            data,
        })
    }
}

fn to_socksaddr(bytes: &[u8]) -> std::io::Result<SocksAddr> {
    let addr_str = std::str::from_utf8(bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid UTF-8 in address",
        )
    })?;

    // Literal addresses (including the bracketed `[::1]:443` form) parse here.
    if let Ok(sock_addr) = std::net::SocketAddr::from_str(addr_str) {
        return Ok(SocksAddr::Ip(sock_addr));
    }

    // Split the string at ':' to get host and port
    let (host, port_str) = addr_str.rsplit_once(':').ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Address must be in host:port format",
        )
    })?;

    // Parse the port
    let port = port_str.parse::<u16>().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid port number")
    })?;

    // A host still holding a colon is an unbracketed IPv6 literal that failed
    // to parse above; calling it a domain would silently produce nonsense.
    if host.is_empty() || host.contains(':') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Malformed address host",
        ));
    }

    Ok(SocksAddr::Domain(host.to_string(), port))
}

/// Iterator over fragments of a packet
#[derive(Debug)]
pub struct Fragments<'a, P> {
    session_id: u32,
    pkt_id: u16,
    addr: (Vec<u8>, VarInt),
    frag_total: u8,
    next_frag_id: u8,
    next_frag_start: usize,
    payload: P,
    // used for fragment, not a actual field of packet
    max_pkt_size: usize,
    fixed_size: usize,
    _marker: std::marker::PhantomData<&'a P>,
}

impl<'a, P> Fragments<'a, P>
where
    P: AsRef<[u8]> + 'a,
{
    pub fn new(
        session_id: u32,
        pkt_id: u16,
        addr: SocksAddr,
        max_pkt_size: usize,
        payload: P,
    ) -> anyhow::Result<Self> {
        let addr = addr.to_string().into_bytes();
        let addr_var = VarInt::from_u32(addr.len() as u32);

        let fixed_size = 4 + 2 + 1 + 1 + addr.len() + var_size(addr_var);
        // A long destination plus a small configured `udp_mtu` made this
        // subtraction underflow.
        let Some(max_data_size) =
            max_pkt_size.checked_sub(fixed_size).filter(|n| *n > 0)
        else {
            return Err(anyhow!(
                "hysteria2 udp mtu {} too small for a {}-byte header",
                max_pkt_size,
                fixed_size
            ));
        };

        // `frag_total` is a single byte on the wire. Truncating it turned an
        // oversized packet into either silence (256 fragments -> 0) or, worse,
        // one fragment claiming to be the whole packet (257 -> 1), which the
        // peer's defragmenter accepted as complete but truncated data.
        let frag_total = payload.as_ref().len().div_ceil(max_data_size);
        if frag_total > u8::MAX as usize {
            return Err(anyhow!(
                "hysteria2 udp packet needs {} fragments, exceeding the {} the \
                 protocol allows",
                frag_total,
                u8::MAX
            ));
        }
        let frag_total = frag_total as u8;

        Ok(Self {
            session_id,
            pkt_id,
            addr: (addr, addr_var),
            frag_total,
            next_frag_id: 0,
            next_frag_start: 0,
            payload,
            max_pkt_size,
            fixed_size,
            _marker: std::marker::PhantomData,
        })
    }
}

impl<'a, P> Iterator for Fragments<'a, P>
where
    P: AsRef<[u8]> + 'a,
{
    type Item = Bytes;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_frag_id < self.frag_total {
            let max_payload_size = self.max_pkt_size - self.fixed_size;
            let next_frag_end = (self.next_frag_start + max_payload_size)
                .min(self.payload.as_ref().len());
            let payload =
                &self.payload.as_ref()[self.next_frag_start..next_frag_end];

            let mut buf = BytesMut::new();
            buf.reserve(self.fixed_size + payload.len());

            buf.put_u32(self.session_id);
            buf.put_u16(self.pkt_id);
            buf.put_u8(self.next_frag_id);
            buf.put_u8(self.frag_total);
            self.addr.1.encode(&mut buf);
            buf.put_slice(self.addr.0.as_slice());
            buf.put_slice(payload);
            let frag = buf.freeze();

            self.next_frag_id += 1;
            self.next_frag_start = next_frag_end;

            Some(frag)
        } else {
            None
        }
    }
}

impl<P> ExactSizeIterator for Fragments<'_, P>
where
    P: AsRef<[u8]>,
{
    fn len(&self) -> usize {
        self.frag_total as usize
    }
}

#[derive(Default)]
pub struct Defragger {
    pub pkt_id: u16,
    pub frags: Vec<Option<HysUdpPacket>>,
    pub cnt: u16,
}

impl Defragger {
    pub fn feed(&mut self, pkt: HysUdpPacket) -> Option<HysUdpPacket> {
        if pkt.frag_count == 1 {
            return Some(pkt);
        }
        if pkt.frag_count <= pkt.frag_id {
            tracing::warn!(
                "invalid frag, id, count: {}, {}",
                pkt.frag_id,
                pkt.frag_count
            );
            return None;
        }
        let frag_id = pkt.frag_id as usize;

        if pkt.pkt_id != self.pkt_id || pkt.frag_count as usize != self.frags.len() {
            // new packet, overwrite the old one
            // if the new packet frags is 1, should already return
            self.pkt_id = pkt.pkt_id;
            self.frags.clear();
            self.frags.resize(pkt.frag_count as usize, None);
            self.cnt = 0;
            self.frags[frag_id] = Some(pkt);
            self.cnt += 1;
        } else if frag_id < self.frags.len() && self.frags[frag_id].is_none() {
            self.frags[frag_id] = Some(pkt);
            self.cnt += 1;
            if self.cnt as usize == self.frags.len() {
                // now we have all fragments
                let frags = std::mem::take(&mut self.frags);
                let mut iters = frags.into_iter().map(|x| x.unwrap());
                let mut pkt0 = iters.next().unwrap();
                let mut data_buf = BytesMut::new();
                data_buf.extend_from_slice(&pkt0.data);
                for pkt in iters {
                    data_buf.extend_from_slice(&pkt.data);
                }
                pkt0.data = data_buf.freeze();
                return Some(pkt0);
            }
        }
        None
    }
}

#[test]
fn hy2_resp_parse() {
    let mut src = BytesMut::from(&[0x00, 0x03, 0x61, 0x62, 0x63, 0x00][..]);
    let msg = Hy2TcpCodec.decode(&mut src).unwrap().unwrap();
    assert!(msg.status == 0);
    assert!(msg.msg == "abc");

    let mut src = BytesMut::from(&[0x01, 0x00, 0x00][..]);
    let msg = Hy2TcpCodec.decode(&mut src).unwrap().unwrap();
    assert!(msg.status == 0x1);
    assert!(msg.msg.is_empty());
}

#[test]
fn test_decode_addr() {
    let socket_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 80));
    let addr = SocksAddr::Ip(socket_addr);
    let addr_bytes = addr.to_string().into_bytes();
    let decoded_addr = to_socksaddr(&addr_bytes).unwrap();
    assert_eq!(addr, decoded_addr);

    let addr = SocksAddr::Domain("example.com".to_string(), 80);
    let addr_bytes = addr.to_string().into_bytes();
    let decoded_addr = to_socksaddr(&addr_bytes).unwrap();
    assert_eq!(addr, decoded_addr);
}
