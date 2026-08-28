use byteorder::{BigEndian, ReadBytesExt};
use hmac::{KeyInit, Mac};
use std::{io::Read, ptr::copy_nonoverlapping};

use super::prelude::*;

#[derive(Clone)]
pub(crate) struct Hmac(hmac::Hmac<sha1::Sha1>);

impl std::fmt::Debug for Hmac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hmac").finish()
    }
}

impl Hmac {
    #[inline]
    pub(crate) fn new(password: &str, init_data: (&[u8], &[u8])) -> Self {
        // Note: in fact new_from_slice never returns Err.
        let mut hmac: hmac::Hmac<sha1::Sha1> =
            hmac::Hmac::new_from_slice(password.as_bytes())
                .expect("unable to build hmac instance");
        hmac.update(init_data.0);
        hmac.update(init_data.1);
        Self(hmac)
    }

    #[inline]
    pub(crate) fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    #[inline]
    pub(crate) fn finalize(&self) -> [u8; HMAC_SIZE] {
        let hmac = self.0.clone();
        let hash = hmac.finalize().into_bytes();
        let mut res = [0; HMAC_SIZE];
        unsafe {
            copy_nonoverlapping(
                hash.as_slice().as_ptr(),
                res.as_mut_ptr(),
                HMAC_SIZE,
            )
        };
        res
    }
}

pub(crate) trait CursorExt {
    fn skip(&mut self, n: usize) -> std::io::Result<()>;
    fn skip_by_u8(&mut self) -> std::io::Result<u8>;
}

impl<T> CursorExt for std::io::Cursor<T>
where
    std::io::Cursor<T>: std::io::Read,
{
    #[inline]
    fn skip(&mut self, n: usize) -> std::io::Result<()> {
        for _ in 0..n {
            self.read_u8()?;
        }
        Ok(())
    }

    #[inline]
    fn skip_by_u8(&mut self) -> std::io::Result<u8> {
        let len = self.read_u8()?;
        self.skip(len as usize)?;
        Ok(len)
    }
}

/// Modify ClientHello from rustls to embed HMAC into Session ID (Shadow-TLS V3).
pub(crate) fn modify_client_hello(
    original_frame: &[u8],
    initial_hmac: &Hmac,
) -> std::io::Result<Vec<u8>> {
    if original_frame.len() < TLS_HEADER_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ClientHello frame too short for header",
        ));
    }
    if original_frame[0] != HANDSHAKE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Expected ClientHello handshake content type",
        ));
    }

    let original_payload_len =
        u16::from_be_bytes([original_frame[3], original_frame[4]]) as usize;
    if original_frame.len() != TLS_HEADER_SIZE + original_payload_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ClientHello frame length mismatch",
        ));
    }

    let mut reader = std::io::Cursor::new(&original_frame[TLS_HEADER_SIZE..]);

    let handshake_type = reader.read_u8()?;
    if handshake_type != 0x01 {
        // HANDSHAKE_TYPE_CLIENT_HELLO
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Expected ClientHello handshake message type",
        ));
    }

    let client_hello_payload_len = {
        let b1 = reader.read_u8()? as usize;
        let b2 = reader.read_u8()? as usize;
        let b3 = reader.read_u8()? as usize;
        (b1 << 16) | (b2 << 8) | b3
    };

    let ch_protocol_ver_major = reader.read_u8()?;
    let ch_protocol_ver_minor = reader.read_u8()?;

    let mut client_random = [0u8; TLS_RANDOM_SIZE];
    reader.read_exact(&mut client_random)?;

    let original_session_id_len = reader.read_u8()? as usize;
    if original_session_id_len != 0 {
        if original_session_id_len != TLS_SESSION_ID_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Original ClientHello SessionID is not 32 bytes",
            ));
        }
        reader.skip(TLS_SESSION_ID_SIZE)?;
    }

    let remaining_offset = reader.position() as usize;
    let remaining_ch_data =
        &original_frame[TLS_HEADER_SIZE + remaining_offset..];

    // target session id length is 32
    let new_client_hello_payload_len =
        client_hello_payload_len + (TLS_SESSION_ID_SIZE - original_session_id_len);
    let new_record_payload_len = new_client_hello_payload_len + 4;

    let mut modified_frame =
        vec![0u8; TLS_HEADER_SIZE + new_record_payload_len];

    modified_frame[0] = HANDSHAKE;
    modified_frame[1] = original_frame[1];
    modified_frame[2] = original_frame[2];
    modified_frame[3..5]
        .copy_from_slice(&(new_record_payload_len as u16).to_be_bytes());

    modified_frame[5] = handshake_type;
    let len_bytes = (new_client_hello_payload_len as u32).to_be_bytes();
    modified_frame[6..9].copy_from_slice(&len_bytes[1..]);
    modified_frame[9] = ch_protocol_ver_major;
    modified_frame[10] = ch_protocol_ver_minor;
    modified_frame[11..43].copy_from_slice(&client_random);

    // session id length
    modified_frame[43] = TLS_SESSION_ID_SIZE as u8;
    // first 28 bytes random
    rand::fill(&mut modified_frame[44..72]);
    // last 4 bytes zero for hmac computation
    modified_frame[72..76].copy_from_slice(&[0, 0, 0, 0]);
    modified_frame[76..].copy_from_slice(remaining_ch_data);

    let mut hmac_ctx = initial_hmac.clone();
    hmac_ctx.update(&modified_frame[TLS_HEADER_SIZE..]);
    let hmac_tag = hmac_ctx.finalize();
    modified_frame[72..76].copy_from_slice(&hmac_tag);

    Ok(modified_frame)
}

pub(crate) struct ParsedServerHello {
    pub(crate) server_random: [u8; TLS_RANDOM_SIZE],
    pub(crate) is_tls13: bool,
}

/// Parse ServerHello and extract server_random & check if tls1.3 is supported.
pub(crate) fn parse_server_hello(frame: &[u8]) -> std::io::Result<ParsedServerHello> {
    if frame.len() < TLS_HEADER_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ServerHello frame too short for header",
        ));
    }
    if frame[0] != HANDSHAKE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Expected Handshake record",
        ));
    }

    let payload = &frame[TLS_HEADER_SIZE..];
    if payload.is_empty() || payload[0] != SERVER_HELLO {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Expected ServerHello handshake type",
        ));
    }

    if payload.len() < 1 + 3 + 2 + TLS_RANDOM_SIZE + 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ServerHello payload too short",
        ));
    }

    let mut server_random = [0u8; TLS_RANDOM_SIZE];
    server_random.copy_from_slice(&payload[1 + 3 + 2..1 + 3 + 2 + TLS_RANDOM_SIZE]);

    let is_tls13 = support_tls13(frame);

    Ok(ParsedServerHello {
        server_random,
        is_tls13,
    })
}

/// Feed TLS frame bytes into rustls::ClientConnection.
pub(crate) fn feed_rustls_client_connection(
    connection: &mut rustls::ClientConnection,
    data: &[u8],
) -> std::io::Result<()> {
    let mut cursor = std::io::Cursor::new(data);
    let mut i = 0;
    while i < data.len() {
        let n = connection.read_tls(&mut cursor).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to feed rustls client connection: {e}"),
            )
        })?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "rustls client connection did not consume all bytes: fed {}/{} bytes",
                    i,
                    data.len()
                ),
            ));
        }
        i += n;
    }
    Ok(())
}

/// Parse ServerHello and return if tls1.3 is supported.
pub(crate) fn support_tls13(frame: &[u8]) -> bool {
    if frame.len() < SESSION_ID_LEN_IDX {
        return false;
    }
    let mut cursor = std::io::Cursor::new(&frame[SESSION_ID_LEN_IDX..]);
    macro_rules! read_ok {
        ($res:expr_2021) => {
            match $res {
                Ok(r) => r,
                Err(_) => {
                    return false;
                }
            }
        };
    }

    // skip session id
    read_ok!(cursor.skip_by_u8());
    // skip cipher suites
    read_ok!(cursor.skip(2));
    // skip compression method
    read_ok!(cursor.skip(1));
    // ext length
    let cnt = read_ok!(cursor.read_u16::<BigEndian>()) as usize;
    let ext_end = cursor.position() as usize + cnt;
    if frame[SESSION_ID_LEN_IDX..].len() < ext_end {
        return false;
    }

    while (cursor.position() as usize) < ext_end {
        let ext_type = read_ok!(cursor.read_u16::<BigEndian>());
        let ext_len = read_ok!(cursor.read_u16::<BigEndian>());
        if ext_type == SUPPORTED_VERSIONS_TYPE {
            if ext_len != 2 {
                return false;
            }
            let ext_val = read_ok!(cursor.read_u16::<BigEndian>());
            let use_tls13 = ext_val == TLS_13;
            tracing::trace!("found supported_versions extension, tls1.3: {use_tls13}");
            return use_tls13;
        } else {
            read_ok!(cursor.skip(ext_len as usize));
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modify_client_hello_and_verify_hmac() {
        let initial_hmac = Hmac::new("test_password", (&[], &[]));

        // Construct a mock TLS 1.3 ClientHello record
        let mut raw_ch = Vec::new();
        // Record header (5 bytes): Handshake (0x16), TLS 1.0 (0x0301), length placeholder
        raw_ch.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x00]);

        // Handshake header: Type ClientHello (0x01), length 3 bytes placeholder
        let hs_start = raw_ch.len();
        raw_ch.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

        // Version: TLS 1.2 (0x0303)
        raw_ch.extend_from_slice(&[0x03, 0x03]);

        // Client Random: 32 bytes
        raw_ch.extend_from_slice(&[0xAA; 32]);

        // Session ID: 0 length
        raw_ch.push(0x00);

        // Cipher suites: length 2, 0x1301 (TLS_AES_128_GCM_SHA256)
        raw_ch.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);

        // Compression: 1 byte (0x00)
        raw_ch.push(0x00);

        // Extensions: empty
        raw_ch.extend_from_slice(&[0x00, 0x00]);

        // Fill lengths
        let hs_len = (raw_ch.len() - hs_start - 4) as u32;
        raw_ch[hs_start + 1] = (hs_len >> 16) as u8;
        raw_ch[hs_start + 2] = (hs_len >> 8) as u8;
        raw_ch[hs_start + 3] = hs_len as u8;

        let record_len = (raw_ch.len() - 5) as u16;
        raw_ch[3..5].copy_from_slice(&record_len.to_be_bytes());

        let modified = modify_client_hello(&raw_ch, &initial_hmac).expect("modify failed");

        // Verify session ID length is 32
        assert_eq!(modified[43], 32);

        // Verify HMAC in modified frame
        let mut verify_hmac = initial_hmac.clone();
        let mut check_buf = modified[5..].to_vec();
        // Zero the HMAC digest bytes (offset 72..76 relative to modified frame -> 67..71 relative to modified[5..])
        check_buf[67..71].copy_from_slice(&[0, 0, 0, 0]);
        verify_hmac.update(&check_buf);
        let expected_tag = verify_hmac.finalize();

        assert_eq!(&modified[72..76], &expected_tag);
    }
}
