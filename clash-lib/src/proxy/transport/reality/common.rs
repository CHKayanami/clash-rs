use std::io::{self, Error, ErrorKind};

// TLS ContentType values
pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;
pub const CONTENT_TYPE_ALERT: u8 = 0x15;
pub const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

// TLS alert levels
pub const ALERT_LEVEL_WARNING: u8 = 0x01;
pub const ALERT_DESC_CLOSE_NOTIFY: u8 = 0x00;

// TLS 1.2 version bytes used in TLS 1.3 record layer header
pub const VERSION_TLS_1_2_MAJOR: u8 = 0x03;
pub const VERSION_TLS_1_2_MINOR: u8 = 0x03;

// TLS 1.3 handshake message types
pub const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 2;
pub const HANDSHAKE_TYPE_CERTIFICATE: u8 = 11;
pub const HANDSHAKE_TYPE_CERTIFICATE_VERIFY: u8 = 15;
pub const HANDSHAKE_TYPE_FINISHED: u8 = 20;
pub const HANDSHAKE_TYPE_KEY_UPDATE: u8 = 24;

// KeyUpdate request_update values (RFC 8446 §4.6.3)
pub const KEY_UPDATE_NOT_REQUESTED: u8 = 0;
pub const KEY_UPDATE_REQUESTED: u8 = 1;

// Maximum TLS 1.3 ciphertext payload size (16,640 bytes)
pub const MAX_TLS_CIPHERTEXT_LEN: usize = 16384 + 256;

// TLS record header size
pub const TLS_RECORD_HEADER_SIZE: usize = 5;

// Maximum TLS record size (ciphertext + header)
pub const TLS_MAX_RECORD_SIZE: usize =
    MAX_TLS_CIPHERTEXT_LEN + TLS_RECORD_HEADER_SIZE;

pub const CIPHERTEXT_READ_BUF_CAPACITY: usize = TLS_MAX_RECORD_SIZE * 2;
pub const PLAINTEXT_READ_BUF_CAPACITY: usize = TLS_MAX_RECORD_SIZE * 2;

pub const OUTGOING_BUFFER_LIMIT: usize = 64 * 1024;

/// Strip TLS 1.3 content type trailer and optional padding from decrypted plaintext.
pub fn strip_content_type_with_padding(plaintext: &mut Vec<u8>) -> io::Result<u8> {
    if plaintext.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "Empty plaintext"));
    }

    // Remove trailing zeros (padding) per RFC 8446 Section 5.4
    while !plaintext.is_empty() && *plaintext.last().unwrap() == 0 {
        plaintext.pop();
    }

    if plaintext.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "Plaintext is all zeros"));
    }

    let content_type = plaintext.pop().unwrap();

    if content_type != CONTENT_TYPE_HANDSHAKE
        && content_type != CONTENT_TYPE_APPLICATION_DATA
        && content_type != CONTENT_TYPE_ALERT
    {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid content type: 0x{:02x}", content_type),
        ));
    }

    Ok(content_type)
}
