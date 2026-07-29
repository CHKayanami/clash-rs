use std::io::{self, Read, Write};

use aws_lc_rs::{agreement, digest};
use bytes::{Buf, BytesMut};
use rand::Rng;

use super::aead::{AeadKey, decrypt_handshake_message};
use super::auth::{derive_auth_key, encrypt_session_id, perform_ecdh};
use super::cipher_suite::{CipherSuite, DEFAULT_CIPHER_SUITES};
use super::client_verify::{
    constant_time_eq, extract_certificate_der, extract_certificate_verify_signature,
    extract_ed25519_public_key, verify_certificate_hmac,
    verify_certificate_verify_signature,
};
use super::common::{
    ALERT_DESC_CLOSE_NOTIFY, ALERT_LEVEL_WARNING, CIPHERTEXT_READ_BUF_CAPACITY,
    CONTENT_TYPE_ALERT, CONTENT_TYPE_APPLICATION_DATA,
    CONTENT_TYPE_CHANGE_CIPHER_SPEC, CONTENT_TYPE_HANDSHAKE,
    HANDSHAKE_TYPE_CERTIFICATE, HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
    HANDSHAKE_TYPE_FINISHED, HANDSHAKE_TYPE_KEY_UPDATE, HANDSHAKE_TYPE_SERVER_HELLO,
    KEY_UPDATE_NOT_REQUESTED, KEY_UPDATE_REQUESTED, MAX_TLS_CIPHERTEXT_LEN,
    OUTGOING_BUFFER_LIMIT, PLAINTEXT_READ_BUF_CAPACITY, TLS_MAX_RECORD_SIZE,
    TLS_RECORD_HEADER_SIZE,
};
use super::tls13_keys::{
    compute_finished_verify_data, derive_application_secrets, derive_handshake_keys,
    derive_next_traffic_secret, derive_traffic_keys,
};
use super::tls13_messages::{
    DEFAULT_ALPN_PROTOCOLS, construct_client_hello, construct_finished,
    write_record_header,
};

#[derive(Clone)]
pub struct RealityClientConfig {
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub server_name: String,
    pub cipher_suites: Vec<CipherSuite>,
}

enum HandshakeState {
    AwaitingServerHello {
        client_hello_bytes: Vec<u8>,
        client_private_key: [u8; 32],
        auth_key: [u8; 32],
    },
    ProcessingHandshake {
        client_handshake_traffic_secret: Vec<u8>,
        server_handshake_traffic_secret: Vec<u8>,
        master_secret: Vec<u8>,
        cipher_suite: CipherSuite,
        handshake_transcript_bytes: Vec<u8>,
        auth_key: [u8; 32],
        handshake_seq: u64,
        accumulated_plaintext: Vec<u8>,
        messages_found: u8,
        certificate_verified: bool,
        ed25519_public_key: Option<[u8; 32]>,
        cert_verify_offset: Option<usize>,
        finished_offset: Option<usize>,
    },
    Complete,
}

pub struct RealityClientConnection {
    config: RealityClientConfig,
    handshake_state: HandshakeState,

    app_read_key: Option<AeadKey>,
    app_read_iv: Option<Vec<u8>>,
    app_write_key: Option<AeadKey>,
    app_write_iv: Option<Vec<u8>>,
    read_seq: u64,
    write_seq: u64,
    cipher_suite: Option<CipherSuite>,

    tls_read_buffer: Box<[u8]>,
    ciphertext_read_buf: BytesMut,
    ciphertext_write_buf: Vec<u8>,
    plaintext_read_buf: BytesMut,
    plaintext_write_buf: Vec<u8>,

    /// Current application traffic secrets, kept so KeyUpdate can derive the
    /// next epoch from them.
    client_app_secret: Option<Vec<u8>>,
    server_app_secret: Option<Vec<u8>>,

    received_close_notify: bool,
    fatal_error: Option<io::ErrorKind>,
}

impl RealityClientConnection {
    pub fn new(config: RealityClientConfig) -> io::Result<Self> {
        let mut conn = RealityClientConnection {
            config,
            handshake_state: HandshakeState::AwaitingServerHello {
                client_hello_bytes: Vec::new(),
                client_private_key: [0u8; 32],
                auth_key: [0u8; 32],
            },
            app_read_key: None,
            app_read_iv: None,
            app_write_key: None,
            app_write_iv: None,
            read_seq: 0,
            write_seq: 0,
            cipher_suite: None,
            tls_read_buffer: vec![0u8; TLS_MAX_RECORD_SIZE].into_boxed_slice(),
            ciphertext_read_buf: BytesMut::with_capacity(
                CIPHERTEXT_READ_BUF_CAPACITY,
            ),
            ciphertext_write_buf: Vec::with_capacity(OUTGOING_BUFFER_LIMIT),
            plaintext_read_buf: BytesMut::with_capacity(PLAINTEXT_READ_BUF_CAPACITY),
            plaintext_write_buf: Vec::with_capacity(OUTGOING_BUFFER_LIMIT),
            client_app_secret: None,
            server_app_secret: None,
            received_close_notify: false,
            fatal_error: None,
        };

        conn.generate_client_hello()?;
        Ok(conn)
    }

    fn generate_client_hello(&mut self) -> io::Result<()> {
        let mut rng = rand::rng();

        let mut our_private_bytes = [0u8; 32];
        rng.fill_bytes(&mut our_private_bytes);

        let our_private_key = agreement::PrivateKey::from_private_key(
            &agreement::X25519,
            &our_private_bytes,
        )
        .map_err(|_| io::Error::other("Failed to create X25519 key"))?;
        let our_public_key_bytes = our_private_key
            .compute_public_key()
            .map_err(|_| io::Error::other("Failed to compute public key"))?;

        let mut client_random = [0u8; 32];
        rng.fill_bytes(&mut client_random);

        let shared_secret =
            perform_ecdh(&our_private_bytes, &self.config.public_key).map_err(
                |e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
            )?;

        let auth_key =
            derive_auth_key(&shared_secret, &client_random[0..20], b"REALITY")
                .map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                })?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| io::Error::other("System time error"))?
            .as_secs();

        let mut session_id_plaintext = [0u8; 16];
        session_id_plaintext[0] = 1;
        session_id_plaintext[1] = 8;
        session_id_plaintext[2] = 0;
        session_id_plaintext[3] = 0;
        session_id_plaintext[4..8]
            .copy_from_slice(&(timestamp as u32).to_be_bytes());
        session_id_plaintext[8..16].copy_from_slice(&self.config.short_id);

        let mut session_id_for_hello = [0u8; 32];
        session_id_for_hello[0..16].copy_from_slice(&session_id_plaintext);

        let cipher_suites = if self.config.cipher_suites.is_empty() {
            DEFAULT_CIPHER_SUITES.to_vec()
        } else {
            self.config.cipher_suites.clone()
        };
        let cipher_suite_ids: Vec<u16> =
            cipher_suites.iter().map(|cs| cs.id()).collect();
        let mut client_hello = construct_client_hello(
            &client_random,
            &session_id_for_hello,
            our_public_key_bytes.as_ref(),
            &self.config.server_name,
            &cipher_suite_ids,
            DEFAULT_ALPN_PROTOCOLS,
        )?;

        let nonce = &client_random[20..32];
        client_hello[39..71].fill(0);

        let encrypted_session_id = encrypt_session_id(
            &session_id_plaintext,
            &auth_key,
            nonce,
            &client_hello,
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        client_hello[39..71].copy_from_slice(&encrypted_session_id);

        let mut record = Vec::new();
        write_record_header(
            &mut record,
            CONTENT_TYPE_HANDSHAKE,
            (3, 3),
            client_hello.len() as u16,
        );
        record.extend_from_slice(&client_hello);
        self.ciphertext_write_buf.extend_from_slice(&record);

        self.handshake_state = HandshakeState::AwaitingServerHello {
            client_hello_bytes: client_hello,
            client_private_key: our_private_bytes,
            auth_key,
        };

        Ok(())
    }

    pub fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
        let n = rd.read(&mut self.tls_read_buffer[..])?;
        if n > 0 {
            self.ciphertext_read_buf
                .extend_from_slice(&self.tls_read_buffer[..n]);
        }
        Ok(n)
    }

    pub fn process_new_packets(&mut self) -> io::Result<usize> {
        if let Some(error_kind) = self.fatal_error {
            return Err(io::Error::new(error_kind, "connection previously failed"));
        }

        if self.received_close_notify {
            return Ok(self.plaintext_read_buf.len());
        }

        let result = self.process_new_packets_inner();

        if let Err(ref e) = result {
            match e.kind() {
                io::ErrorKind::InvalidData
                | io::ErrorKind::PermissionDenied
                | io::ErrorKind::ConnectionAborted => {
                    self.fatal_error = Some(e.kind());
                }
                _ => {}
            }
        }

        result
    }

    fn process_new_packets_inner(&mut self) -> io::Result<usize> {
        loop {
            match &self.handshake_state {
                HandshakeState::AwaitingServerHello { .. } => {
                    if !self.process_server_hello()? {
                        break;
                    }
                }
                HandshakeState::ProcessingHandshake { .. } => {
                    if !self.process_encrypted_handshake()? {
                        break;
                    }
                }
                HandshakeState::Complete => {
                    self.process_application_data()?;
                    break;
                }
            }
        }

        Ok(self.plaintext_read_buf.len())
    }

    fn process_server_hello(&mut self) -> io::Result<bool> {
        let HandshakeState::AwaitingServerHello {
            client_hello_bytes,
            client_private_key,
            auth_key,
        } = &self.handshake_state
        else {
            unreachable!()
        };

        // The header must be present before it can be parsed — indexing first
        // and range-checking afterwards panicked on any short read, which a
        // server that dribbles the ServerHello (or plain TCP segmentation)
        // triggers. The other two record readers already guard this way.
        if self.ciphertext_read_buf.len() < TLS_RECORD_HEADER_SIZE {
            return Ok(false);
        }

        let record_type = self.ciphertext_read_buf[0];
        let record_len = u16::from_be_bytes([
            self.ciphertext_read_buf[3],
            self.ciphertext_read_buf[4],
        ]) as usize;

        if record_len > MAX_TLS_CIPHERTEXT_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "TLS record too large: {} > {}",
                    record_len, MAX_TLS_CIPHERTEXT_LEN
                ),
            ));
        }

        let total_record_len = TLS_RECORD_HEADER_SIZE + record_len;
        if self.ciphertext_read_buf.len() < total_record_len {
            return Ok(false);
        }

        if record_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC {
            self.ciphertext_read_buf.advance(total_record_len);
            return self.process_server_hello();
        }

        if record_type == CONTENT_TYPE_ALERT {
            let alert_level = if record_len >= 1 {
                self.ciphertext_read_buf[TLS_RECORD_HEADER_SIZE]
            } else {
                0
            };
            let alert_desc = if record_len >= 2 {
                self.ciphertext_read_buf[TLS_RECORD_HEADER_SIZE + 1]
            } else {
                0
            };
            self.ciphertext_read_buf.advance(total_record_len);
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!(
                    "Received TLS Alert from server (level {}, description {})",
                    alert_level, alert_desc
                ),
            ));
        }

        if record_type != CONTENT_TYPE_HANDSHAKE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Expected TLS Handshake record (0x16), got 0x{:02x}",
                    record_type
                ),
            ));
        }

        let client_hello_bytes = client_hello_bytes.clone();
        let record = self.ciphertext_read_buf.split_to(total_record_len).to_vec();
        let server_hello = &record[TLS_RECORD_HEADER_SIZE..];

        if server_hello.is_empty() || server_hello[0] != HANDSHAKE_TYPE_SERVER_HELLO
        {
            let msg_type = if !server_hello.is_empty() {
                server_hello[0]
            } else {
                0
            };
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Expected ServerHello handshake message (0x02), got 0x{:02x}",
                    msg_type
                ),
            ));
        }

        if server_hello.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ServerHello handshake header too short",
            ));
        }

        let server_hello_msg_len = u32::from_be_bytes([
            0,
            server_hello[1],
            server_hello[2],
            server_hello[3],
        ]) as usize;
        let server_hello_total_len = 4 + server_hello_msg_len;

        if server_hello.len() < server_hello_total_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ServerHello handshake message truncated",
            ));
        }

        // If the TLS record contained leftover bytes beyond ServerHello (coalesced messages),
        // put the leftover bytes back into ciphertext_read_buf as a TLS record for subsequent processing.
        if server_hello.len() > server_hello_total_len {
            let leftover = &server_hello[server_hello_total_len..];
            let mut leftover_record =
                Vec::with_capacity(TLS_RECORD_HEADER_SIZE + leftover.len());
            write_record_header(
                &mut leftover_record,
                record_type,
                (3, 3),
                leftover.len() as u16,
            );
            leftover_record.extend_from_slice(leftover);

            let mut new_buf = BytesMut::with_capacity(
                leftover_record.len() + self.ciphertext_read_buf.len(),
            );
            new_buf.extend_from_slice(&leftover_record);
            new_buf.extend_from_slice(&self.ciphertext_read_buf);
            self.ciphertext_read_buf = new_buf;
        }

        let server_hello = &server_hello[..server_hello_total_len];

        // Extract server public key and cipher suite from ServerHello message
        // ServerHello structure: Handshake type (1) + length (3) + version (2) + random (32) + session_id_len (1) + session_id + cipher_suite (2) + compression (1) + ext_len (2) + extensions
        if server_hello.len() < 39 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ServerHello record too short",
            ));
        }
        let session_id_len = server_hello[38] as usize;
        let cipher_suite_offset = 39 + session_id_len;
        if cipher_suite_offset + 2 > server_hello.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ServerHello cipher suite truncated",
            ));
        }
        let cipher_suite_id = u16::from_be_bytes([
            server_hello[cipher_suite_offset],
            server_hello[cipher_suite_offset + 1],
        ]);
        let cipher_suite =
            CipherSuite::from_id(cipher_suite_id).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Server selected unsupported cipher suite: 0x{:04x}",
                        cipher_suite_id
                    ),
                )
            })?;

        // Find key_share extension in ServerHello
        let ext_offset = cipher_suite_offset + 3; // skip cipher suite (2 bytes) + compression method byte (0x00)
        if ext_offset + 2 > server_hello.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ServerHello extensions truncated",
            ));
        }
        let ext_len = u16::from_be_bytes([
            server_hello[ext_offset],
            server_hello[ext_offset + 1],
        ]) as usize;
        if ext_offset + 2 + ext_len > server_hello.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ServerHello extensions truncated",
            ));
        }
        let ext_bytes = &server_hello[ext_offset + 2..ext_offset + 2 + ext_len];

        let mut key_share_found = None;
        let mut curr = 0;
        while curr + 4 <= ext_bytes.len() {
            let ext_type =
                u16::from_be_bytes([ext_bytes[curr], ext_bytes[curr + 1]]);
            let e_len =
                u16::from_be_bytes([ext_bytes[curr + 2], ext_bytes[curr + 3]])
                    as usize;
            if curr + 4 + e_len > ext_bytes.len() {
                break;
            }
            if ext_type == 51 {
                // key_share
                let data = &ext_bytes[curr + 4..curr + 4 + e_len];
                if data.len() >= 4 + 32 {
                    // group (2) + length (2) + public_key (32)
                    let key_bytes = &data[4..36];
                    let mut server_pk = [0u8; 32];
                    server_pk.copy_from_slice(key_bytes);
                    key_share_found = Some(server_pk);
                }
                break;
            }
            curr += 4 + e_len;
        }

        let server_public_key = key_share_found.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Missing key_share in ServerHello",
            )
        })?;

        let mut full_transcript =
            digest::Context::new(cipher_suite.digest_algorithm());
        full_transcript.update(&client_hello_bytes);
        full_transcript.update(server_hello);
        let server_hello_hash = full_transcript.finish();
        let server_hello_hash_vec: Vec<u8> = server_hello_hash.as_ref().to_vec();

        let client_hello_hash_vec: Vec<u8> = {
            let mut ctx = digest::Context::new(cipher_suite.digest_algorithm());
            ctx.update(&client_hello_bytes);
            ctx.finish().as_ref().to_vec()
        };

        let peer_public_key = agreement::UnparsedPublicKey::new(
            &agreement::X25519,
            &server_public_key,
        );
        let my_private_key = agreement::PrivateKey::from_private_key(
            &agreement::X25519,
            client_private_key,
        )
        .map_err(|_| io::Error::other("Failed to create private key"))?;

        let mut tls_shared_secret = [0u8; 32];
        agreement::agree(
            &my_private_key,
            peer_public_key,
            io::Error::other("ECDH failed"),
            |key_material| {
                tls_shared_secret.copy_from_slice(key_material);
                Ok(())
            },
        )?;

        let hs_keys = derive_handshake_keys(
            cipher_suite,
            &tls_shared_secret,
            &client_hello_hash_vec,
            &server_hello_hash_vec,
        )?;

        let mut transcript_bytes = Vec::new();
        transcript_bytes.extend_from_slice(&client_hello_bytes);
        transcript_bytes.extend_from_slice(server_hello);

        self.handshake_state = HandshakeState::ProcessingHandshake {
            client_handshake_traffic_secret: hs_keys.client_handshake_traffic_secret,
            server_handshake_traffic_secret: hs_keys.server_handshake_traffic_secret,
            master_secret: hs_keys.master_secret,
            cipher_suite,
            handshake_transcript_bytes: transcript_bytes,
            auth_key: *auth_key,
            handshake_seq: 0,
            accumulated_plaintext: Vec::new(),
            messages_found: 0,
            certificate_verified: false,
            ed25519_public_key: None,
            cert_verify_offset: None,
            finished_offset: None,
        };

        Ok(true)
    }

    fn process_encrypted_handshake(&mut self) -> io::Result<bool> {
        if self.ciphertext_read_buf.len() < TLS_RECORD_HEADER_SIZE {
            return Ok(false);
        }

        let record_type = self.ciphertext_read_buf[0];
        let record_len = u16::from_be_bytes([
            self.ciphertext_read_buf[3],
            self.ciphertext_read_buf[4],
        ]) as usize;

        if record_len > MAX_TLS_CIPHERTEXT_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "TLS record too large: {} > {}",
                    record_len, MAX_TLS_CIPHERTEXT_LEN
                ),
            ));
        }

        let total_record_len = TLS_RECORD_HEADER_SIZE + record_len;
        if self.ciphertext_read_buf.len() < total_record_len {
            return Ok(false);
        }

        if record_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC {
            self.ciphertext_read_buf.advance(total_record_len);
            return self.process_encrypted_handshake();
        }

        if record_type != CONTENT_TYPE_APPLICATION_DATA {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Expected Application Data record, got 0x{:02x}",
                    record_type
                ),
            ));
        }

        let HandshakeState::ProcessingHandshake {
            client_handshake_traffic_secret,
            server_handshake_traffic_secret,
            master_secret,
            cipher_suite,
            handshake_transcript_bytes,
            auth_key,
            mut handshake_seq,
            mut accumulated_plaintext,
            mut messages_found,
            mut certificate_verified,
            mut ed25519_public_key,
            mut cert_verify_offset,
            mut finished_offset,
        } = std::mem::replace(&mut self.handshake_state, HandshakeState::Complete)
        else {
            unreachable!()
        };

        let (server_hs_key, server_hs_iv) =
            derive_traffic_keys(&server_handshake_traffic_secret, cipher_suite)?;

        let ciphertext = self.ciphertext_read_buf
            [TLS_RECORD_HEADER_SIZE..total_record_len]
            .to_vec();
        self.ciphertext_read_buf.advance(total_record_len);

        let plaintext = decrypt_handshake_message(
            cipher_suite,
            &server_hs_key,
            &server_hs_iv,
            handshake_seq,
            &ciphertext,
            record_len as u16,
        )?;

        handshake_seq += 1;

        let prev_accumulated_len = accumulated_plaintext.len();
        accumulated_plaintext.extend_from_slice(&plaintext);

        let mut offset = prev_accumulated_len;
        while offset < accumulated_plaintext.len() && messages_found < 4 {
            if offset + 4 > accumulated_plaintext.len() {
                break;
            }

            let msg_type = accumulated_plaintext[offset];
            let msg_len = u32::from_be_bytes([
                0,
                accumulated_plaintext[offset + 1],
                accumulated_plaintext[offset + 2],
                accumulated_plaintext[offset + 3],
            ]) as usize;

            if offset + 4 + msg_len > accumulated_plaintext.len() {
                break;
            }

            if msg_type == HANDSHAKE_TYPE_CERTIFICATE {
                let cert_der = extract_certificate_der(
                    &accumulated_plaintext[offset..offset + 4 + msg_len],
                )?;
                verify_certificate_hmac(cert_der, &auth_key)?;
                ed25519_public_key = Some(extract_ed25519_public_key(cert_der)?);
                certificate_verified = true;
            }

            if msg_type == HANDSHAKE_TYPE_CERTIFICATE_VERIFY {
                cert_verify_offset = Some(offset);
            }

            if msg_type == HANDSHAKE_TYPE_FINISHED {
                finished_offset = Some(offset);
            }

            messages_found += 1;
            offset += 4 + msg_len;
        }

        if messages_found < 4 {
            self.handshake_state = HandshakeState::ProcessingHandshake {
                client_handshake_traffic_secret,
                server_handshake_traffic_secret,
                master_secret,
                cipher_suite,
                handshake_transcript_bytes,
                auth_key,
                handshake_seq,
                accumulated_plaintext,
                messages_found,
                certificate_verified,
                ed25519_public_key,
                cert_verify_offset,
                finished_offset,
            };
            return Ok(true);
        }

        if !certificate_verified {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "REALITY handshake failed: Certificate message not verified",
            ));
        }

        let mut cert_verify_verified = false;
        if let (Some(public_key), Some(cv_offset)) =
            (ed25519_public_key, cert_verify_offset)
        {
            let mut cv_transcript =
                digest::Context::new(cipher_suite.digest_algorithm());
            cv_transcript.update(&handshake_transcript_bytes);
            cv_transcript.update(&accumulated_plaintext[..cv_offset]);
            let cv_transcript_hash = cv_transcript.finish();

            let cv_msg_len = u32::from_be_bytes([
                0,
                accumulated_plaintext[cv_offset + 1],
                accumulated_plaintext[cv_offset + 2],
                accumulated_plaintext[cv_offset + 3],
            ]) as usize;
            let cv_message =
                &accumulated_plaintext[cv_offset..cv_offset + 4 + cv_msg_len];
            let signature = extract_certificate_verify_signature(cv_message)?;

            verify_certificate_verify_signature(
                &public_key,
                &signature,
                cv_transcript_hash.as_ref(),
            )?;
            cert_verify_verified = true;
        }

        if !cert_verify_verified {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "REALITY handshake failed: CertificateVerify signature invalid",
            ));
        }

        // RFC 8446 §4.4.4: the server's Finished must be verified before its
        // handshake is accepted. It was previously counted towards
        // `messages_found` but never checked.
        let Some(fin_offset) = finished_offset else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "REALITY handshake failed: no server Finished message",
            ));
        };

        {
            let mut fin_transcript =
                digest::Context::new(cipher_suite.digest_algorithm());
            fin_transcript.update(&handshake_transcript_bytes);
            fin_transcript.update(&accumulated_plaintext[..fin_offset]);
            let fin_transcript_hash = fin_transcript.finish();

            let expected = compute_finished_verify_data(
                cipher_suite,
                &server_handshake_traffic_secret,
                fin_transcript_hash.as_ref(),
            )?;

            let fin_len = u32::from_be_bytes([
                0,
                accumulated_plaintext[fin_offset + 1],
                accumulated_plaintext[fin_offset + 2],
                accumulated_plaintext[fin_offset + 3],
            ]) as usize;
            let body_start = fin_offset + 4;
            if body_start + fin_len > accumulated_plaintext.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated server Finished",
                ));
            }
            let received = &accumulated_plaintext[body_start..body_start + fin_len];

            if !constant_time_eq(&expected, received) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "REALITY handshake failed: server Finished verify_data mismatch",
                ));
            }
        }

        let mut handshake_transcript =
            digest::Context::new(cipher_suite.digest_algorithm());
        handshake_transcript.update(&handshake_transcript_bytes);
        handshake_transcript.update(&accumulated_plaintext);

        let handshake_hash = handshake_transcript.finish();
        let handshake_hash_vec: Vec<u8> = handshake_hash.as_ref().to_vec();

        let client_verify_data = compute_finished_verify_data(
            cipher_suite,
            &client_handshake_traffic_secret,
            &handshake_hash_vec,
        )?;
        let client_finished = construct_finished(&client_verify_data)?;

        let (client_hs_key, client_hs_iv) =
            derive_traffic_keys(&client_handshake_traffic_secret, cipher_suite)?;
        let hs_aead_key = AeadKey::new(cipher_suite, &client_hs_key)?;

        let mut finished_payload = client_finished;
        finished_payload.push(CONTENT_TYPE_HANDSHAKE);

        let mut record_header = Vec::new();
        let cipher_len = finished_payload.len() + 16;
        write_record_header(
            &mut record_header,
            CONTENT_TYPE_APPLICATION_DATA,
            (3, 3),
            cipher_len as u16,
        );
        hs_aead_key.seal_in_place(
            &mut finished_payload,
            &client_hs_iv,
            0,
            &record_header,
        )?;

        self.ciphertext_write_buf.extend_from_slice(&record_header);
        self.ciphertext_write_buf
            .extend_from_slice(&finished_payload);

        let (client_app_secret, server_app_secret) = derive_application_secrets(
            cipher_suite,
            &master_secret,
            &handshake_hash_vec,
        )?;

        let (client_app_key_bytes, client_app_iv) =
            derive_traffic_keys(&client_app_secret, cipher_suite)?;
        let (server_app_key_bytes, server_app_iv) =
            derive_traffic_keys(&server_app_secret, cipher_suite)?;

        let client_app_key = AeadKey::new(cipher_suite, &client_app_key_bytes)?;
        let server_app_key = AeadKey::new(cipher_suite, &server_app_key_bytes)?;

        self.client_app_secret = Some(client_app_secret);
        self.server_app_secret = Some(server_app_secret);

        self.app_read_key = Some(server_app_key);
        self.app_read_iv = Some(server_app_iv);
        self.app_write_key = Some(client_app_key);
        self.app_write_iv = Some(client_app_iv);
        self.read_seq = 0;
        self.write_seq = 0;
        self.cipher_suite = Some(cipher_suite);
        self.handshake_state = HandshakeState::Complete;

        Ok(true)
    }

    fn process_application_data(&mut self) -> io::Result<()> {
        while self.ciphertext_read_buf.len() >= TLS_RECORD_HEADER_SIZE {
            let record_len = u16::from_be_bytes([
                self.ciphertext_read_buf[3],
                self.ciphertext_read_buf[4],
            ]) as usize;

            if record_len > MAX_TLS_CIPHERTEXT_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "TLS record too large: {} > {}",
                        record_len, MAX_TLS_CIPHERTEXT_LEN
                    ),
                ));
            }

            let total_record_len = TLS_RECORD_HEADER_SIZE + record_len;
            if self.ciphertext_read_buf.len() < total_record_len {
                break;
            }

            let (app_read_key, app_read_iv) =
                match (&self.app_read_key, &self.app_read_iv) {
                    (Some(key), Some(iv)) => (key, iv),
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "application keys not available",
                        ));
                    }
                };

            let mut record_slice =
                self.ciphertext_read_buf.split_to(total_record_len);
            let aad = [
                record_slice[0],
                record_slice[1],
                record_slice[2],
                record_slice[3],
                record_slice[4],
            ];

            let payload_slice = &mut record_slice[TLS_RECORD_HEADER_SIZE..];
            // An AEAD failure is fatal, full stop. This used to set a
            // `direct_bypass` flag and hand the *undecrypted* record to the
            // caller as if it were authenticated plaintext, which let anyone
            // able to flip a bit on the wire downgrade the connection to
            // cleartext and inject into it. The legitimate XTLS-splice
            // transition is signalled explicitly through `VisionOptions`, so
            // nothing depends on guessing it from a decryption error.
            let decrypted = app_read_key
                .open_in_place_slice(payload_slice, app_read_iv, self.read_seq, &aad)
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "REALITY record authentication failed (bad_record_mac)",
                    )
                })?;
            self.read_seq += 1;

            // Strip TLS 1.3 zero padding to find the real content type
            // (RFC 8446 §5.4). Reading the last byte directly treated a padded
            // record's padding as its content type and silently dropped it.
            let Some(content_end) =
                decrypted.iter().rposition(|&b| b != 0).map(|p| p + 1)
            else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TLS record with no content type (all padding)",
                ));
            };

            let content_type = decrypted[content_end - 1];
            let content = &decrypted[..content_end - 1];

            match content_type {
                CONTENT_TYPE_APPLICATION_DATA => {
                    self.plaintext_read_buf.extend_from_slice(content);
                }
                CONTENT_TYPE_HANDSHAKE => {
                    let content = content.to_vec();
                    self.process_post_handshake_message(&content)?;
                }
                CONTENT_TYPE_ALERT => {
                    if content.len() >= 2 {
                        let alert_level = content[0];
                        let alert_desc = content[1];

                        if alert_desc == ALERT_DESC_CLOSE_NOTIFY {
                            self.received_close_notify = true;
                            return Ok(());
                        } else if alert_level != ALERT_LEVEL_WARNING {
                            return Err(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                format!("Received fatal alert: {}", alert_desc),
                            ));
                        }
                    }
                }
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected TLS content type 0x{:02x}", other),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Handle handshake messages that arrive after the handshake completes.
    /// Only KeyUpdate is meaningful for this client; anything else is ignored
    /// the way a TLS 1.3 peer may ignore NewSessionTicket.
    fn process_post_handshake_message(&mut self, mut msg: &[u8]) -> io::Result<()> {
        while msg.len() >= 4 {
            let msg_type = msg[0];
            let msg_len = u32::from_be_bytes([0, msg[1], msg[2], msg[3]]) as usize;
            if msg.len() < 4 + msg_len {
                break;
            }
            let body = &msg[4..4 + msg_len];

            if msg_type == HANDSHAKE_TYPE_KEY_UPDATE {
                if body.len() != 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed KeyUpdate",
                    ));
                }
                self.apply_key_update(body[0])?;
            }

            msg = &msg[4 + msg_len..];
        }
        Ok(())
    }

    /// Rotate the read keys per RFC 8446 §7.2, and if the peer asked us to
    /// update too, rotate the write keys and answer with our own KeyUpdate.
    ///
    /// Without this, a server that rekeys a long-lived connection produced
    /// records this client could not decrypt.
    fn apply_key_update(&mut self, request_update: u8) -> io::Result<()> {
        let cipher_suite = self.cipher_suite.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "no cipher suite negotiated")
        })?;

        let server_secret = self.server_app_secret.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "no server traffic secret")
        })?;
        let next_server = derive_next_traffic_secret(server_secret, cipher_suite)?;
        let (key, iv) = derive_traffic_keys(&next_server, cipher_suite)?;
        self.app_read_key = Some(AeadKey::new(cipher_suite, &key)?);
        self.app_read_iv = Some(iv);
        self.server_app_secret = Some(next_server);
        self.read_seq = 0;

        tracing::debug!("REALITY: applied server KeyUpdate");

        if request_update == KEY_UPDATE_REQUESTED {
            // Answer before rotating our own keys: the reply must still be
            // encrypted under the current epoch.
            self.queue_key_update_message(KEY_UPDATE_NOT_REQUESTED)?;

            let client_secret =
                self.client_app_secret.as_ref().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "no client traffic secret",
                    )
                })?;
            let next_client =
                derive_next_traffic_secret(client_secret, cipher_suite)?;
            let (key, iv) = derive_traffic_keys(&next_client, cipher_suite)?;
            self.app_write_key = Some(AeadKey::new(cipher_suite, &key)?);
            self.app_write_iv = Some(iv);
            self.client_app_secret = Some(next_client);
            self.write_seq = 0;

            tracing::debug!("REALITY: sent KeyUpdate in response");
        }

        Ok(())
    }

    /// Encrypt a KeyUpdate handshake message under the current write keys and
    /// queue it ahead of any pending application data.
    fn queue_key_update_message(&mut self, request_update: u8) -> io::Result<()> {
        let cipher_suite = self.cipher_suite.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "no cipher suite negotiated")
        })?;
        let (app_write_key, app_write_iv) =
            match (&self.app_write_key, &self.app_write_iv) {
                (Some(key), Some(iv)) => (key, iv),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "application keys not available",
                    ));
                }
            };
        let _ = cipher_suite;

        // handshake header (type + 3-byte length) + body + inner content type
        let mut payload = vec![HANDSHAKE_TYPE_KEY_UPDATE, 0, 0, 1, request_update];
        payload.push(CONTENT_TYPE_HANDSHAKE);

        let mut record_header = Vec::with_capacity(TLS_RECORD_HEADER_SIZE);
        write_record_header(
            &mut record_header,
            CONTENT_TYPE_APPLICATION_DATA,
            (3, 3),
            (payload.len() + 16) as u16,
        );

        app_write_key.seal_in_place(
            &mut payload,
            app_write_iv,
            self.write_seq,
            &record_header,
        )?;
        self.write_seq += 1;

        self.ciphertext_write_buf.extend_from_slice(&record_header);
        self.ciphertext_write_buf.extend_from_slice(&payload);
        Ok(())
    }

    pub fn read_plaintext(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let to_copy = std::cmp::min(buf.len(), self.plaintext_read_buf.len());
        if to_copy > 0 {
            buf[..to_copy].copy_from_slice(&self.plaintext_read_buf[..to_copy]);
            self.plaintext_read_buf.advance(to_copy);
        }
        Ok(to_copy)
    }

    pub fn drain_plaintext_read_buf(&mut self) -> bytes::Bytes {
        self.plaintext_read_buf.split().freeze()
    }

    pub fn drain_ciphertext_read_buf(&mut self) -> bytes::Bytes {
        self.ciphertext_read_buf.split().freeze()
    }

    /// Accept at most [`OUTGOING_BUFFER_LIMIT`] bytes per call and report how
    /// many were taken, so a caller that never drains cannot grow this buffer
    /// without bound.
    pub fn write_plaintext(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len().min(OUTGOING_BUFFER_LIMIT);
        self.plaintext_write_buf.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    pub fn write_tls(&mut self, wr: &mut dyn Write) -> io::Result<usize> {
        if !matches!(self.handshake_state, HandshakeState::Complete) {
            let n = wr.write(&self.ciphertext_write_buf)?;
            self.ciphertext_write_buf.drain(..n);
            return Ok(n);
        }

        if !self.plaintext_write_buf.is_empty() {
            let (app_write_key, app_write_iv) =
                match (&self.app_write_key, &self.app_write_iv) {
                    (Some(key), Some(iv)) => (key, iv),
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Application keys not available",
                        ));
                    }
                };

            let mut offset = 0;
            let total = self.plaintext_write_buf.len();

            while offset < total {
                let chunk_size = std::cmp::min(total - offset, 16384);
                let chunk = &self.plaintext_write_buf[offset..offset + chunk_size];

                let mut payload = Vec::with_capacity(chunk_size + 1 + 16);
                payload.extend_from_slice(chunk);
                payload.push(CONTENT_TYPE_APPLICATION_DATA);

                let cipher_len = payload.len() + 16;
                let mut record_header = Vec::with_capacity(TLS_RECORD_HEADER_SIZE);
                write_record_header(
                    &mut record_header,
                    CONTENT_TYPE_APPLICATION_DATA,
                    (3, 3),
                    cipher_len as u16,
                );

                app_write_key.seal_in_place(
                    &mut payload,
                    app_write_iv,
                    self.write_seq,
                    &record_header,
                )?;
                self.write_seq += 1;

                self.ciphertext_write_buf.extend_from_slice(&record_header);
                self.ciphertext_write_buf.extend_from_slice(&payload);

                offset += chunk_size;
            }

            self.plaintext_write_buf.clear();
        }

        let n = wr.write(&self.ciphertext_write_buf)?;
        self.ciphertext_write_buf.drain(..n);
        Ok(n)
    }

    pub fn wants_write(&self) -> bool {
        if !matches!(self.handshake_state, HandshakeState::Complete) {
            !self.ciphertext_write_buf.is_empty()
        } else {
            !self.ciphertext_write_buf.is_empty()
                || !self.plaintext_write_buf.is_empty()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_server_hello_offsets() {
        let priv_key =
            agreement::PrivateKey::from_private_key(&agreement::X25519, &[5u8; 32])
                .unwrap();
        let pub_key_bytes = priv_key.compute_public_key().unwrap();
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(pub_key_bytes.as_ref());

        let config = RealityClientConfig {
            public_key,
            short_id: [0u8; 8],
            server_name: "example.com".to_string(),
            cipher_suites: vec![],
        };
        let mut conn = RealityClientConnection::new(config).unwrap();

        // Send client hello write so handshake state transitions to AwaitingServerHello
        let mut wr = Vec::new();
        conn.write_tls(&mut wr).unwrap();
        assert!(matches!(
            conn.handshake_state,
            HandshakeState::AwaitingServerHello { .. }
        ));

        // Construct mock ServerHello
        // Set last byte of random (index 37 of server_hello) to 0xFF (255)
        // With old bug, reading index 37 as session_id_len would try offset 38 + 255 = 293, causing "ServerHello cipher suite truncated"
        let mut server_hello_body = Vec::new();
        server_hello_body.push(0x02); // ServerHello
        server_hello_body.extend_from_slice(&[0, 0, 0]); // Length placeholder

        server_hello_body.extend_from_slice(&[0x03, 0x03]); // Version TLS 1.2
        let mut random = [0u8; 32];
        random[31] = 0xFF; // Last byte of random is 255
        server_hello_body.extend_from_slice(&random);

        let session_id = [0xAAu8; 32];
        server_hello_body.push(32); // Session ID len = 32
        server_hello_body.extend_from_slice(&session_id);

        server_hello_body.extend_from_slice(&[0x13, 0x01]); // CipherSuite TLS_AES_128_GCM_SHA256
        server_hello_body.push(0x00); // Compression method

        // Extensions
        let server_priv =
            agreement::PrivateKey::from_private_key(&agreement::X25519, &[7u8; 32])
                .unwrap();
        let server_pub_bytes = server_priv.compute_public_key().unwrap();

        let mut extensions = Vec::new();
        // key_share extension (type 51 = 0x0033)
        extensions.extend_from_slice(&[0x00, 0x33]);
        extensions.extend_from_slice(&[0x00, 0x24]); // len 36
        extensions.extend_from_slice(&[0x00, 0x1d]); // group x25519
        extensions.extend_from_slice(&[0x00, 0x20]); // key len 32
        extensions.extend_from_slice(server_pub_bytes.as_ref()); // public key

        server_hello_body
            .extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        server_hello_body.extend_from_slice(&extensions);

        // Fix handshake body length
        let body_len = (server_hello_body.len() - 4) as u32;
        server_hello_body[1] = ((body_len >> 16) & 0xff) as u8;
        server_hello_body[2] = ((body_len >> 8) & 0xff) as u8;
        server_hello_body[3] = (body_len & 0xff) as u8;

        // Wrap in TLS Record Header
        let mut record = Vec::new();
        write_record_header(
            &mut record,
            CONTENT_TYPE_HANDSHAKE,
            (3, 3),
            server_hello_body.len() as u16,
        );
        record.extend_from_slice(&server_hello_body);

        // Feed record into conn.ciphertext_read_buf
        conn.ciphertext_read_buf.extend_from_slice(&record);

        // Process packet
        let res = conn.process_new_packets();
        assert!(res.is_ok(), "process_new_packets failed: {:?}", res);
        assert!(matches!(
            conn.handshake_state,
            HandshakeState::ProcessingHandshake { .. }
        ));
    }
}
