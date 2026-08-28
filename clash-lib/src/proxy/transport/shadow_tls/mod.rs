use async_trait::async_trait;
use rand::{RngExt, distr::Distribution};
use std::{io, sync::Arc};
use stream::VerifiedStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use utils::{
    Hmac, feed_rustls_client_connection, modify_client_hello, parse_server_hello,
};

mod prelude;
mod stream;
mod utils;

use super::Transport;
use crate::{
    common::{errors::map_io_error, tls::GLOBAL_ROOT_STORE},
    proxy::AnyStream,
};
use prelude::*;

pub struct Client {
    host: String,
    password: String,
    strict: bool,
}

impl Client {
    pub fn new(host: String, password: String, strict: bool) -> Self {
        Self {
            host,
            password,
            strict,
        }
    }

    pub async fn wrap_shadow_tls_stream(
        &self,
        mut stream: AnyStream,
    ) -> std::io::Result<AnyStream> {
        let sni_name = rustls::pki_types::ServerName::try_from(self.host.clone())
            .map_err(map_io_error)?;

        let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(map_io_error)?
        .with_root_certificates(GLOBAL_ROOT_STORE.clone())
        .with_no_client_auth();

        let mut client_conn =
            rustls::ClientConnection::new(Arc::new(tls_config), sni_name)
                .map_err(map_io_error)?;

        let mut client_hello_buf = [0u8; 1024];
        let n = if client_conn.wants_write() {
            client_conn
                .write_tls(&mut std::io::Cursor::new(&mut client_hello_buf[..]))?
        } else {
            0
        };
        if n == 0 {
            return Err(std::io::Error::other(
                "ClientConnection did not produce ClientHello",
            ));
        }

        let hmac_handshake = Hmac::new(&self.password, (&[], &[]));
        let modified_client_hello =
            modify_client_hello(&client_hello_buf[..n], &hmac_handshake)?;

        stream.write_all(&modified_client_hello).await?;
        stream.flush().await?;

        let mut server_random_opt = None;
        let mut hmac_nop_opt = None;
        let mut authorized = false;

        let mut write_frame_buf = [0u8; 16384];
        let mut read_frame_buf = [0u8; 16384];

        while client_conn.is_handshaking() || !authorized {
            if client_conn.wants_write() {
                let mut cursor = std::io::Cursor::new(&mut write_frame_buf[..]);
                let nw = client_conn.write_tls(&mut cursor)?;
                if nw > 0 {
                    stream.write_all(&write_frame_buf[..nw]).await?;
                    stream.flush().await?;
                }
                continue;
            }

            let frame_len =
                read_tls_frame(&mut stream, &mut read_frame_buf).await?;
            let frame = &read_frame_buf[..frame_len];
            let content_type = frame[0];

            if content_type == HANDSHAKE {
                if frame.len() > TLS_HEADER_SIZE
                    && frame[TLS_HEADER_SIZE] == SERVER_HELLO
                {
                    let parsed = parse_server_hello(frame)?;
                    if !parsed.is_tls13 {
                        tracing::warn!("shadow-tls requires TLS 1.3");
                        if self.strict {
                            let _ = fake_request(&mut stream).await;
                            return Err(io::Error::other(
                                "V3 strict enabled: TLS 1.3 is not supported",
                            ));
                        }
                    }
                    let hmac_nop =
                        Hmac::new(&self.password, (&parsed.server_random, &[]));
                    server_random_opt = Some(parsed.server_random);
                    hmac_nop_opt = Some(hmac_nop);
                }
                feed_rustls_client_connection(&mut client_conn, frame)?;
                client_conn.process_new_packets().map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("rustls process_new_packets error: {e}"),
                    )
                })?;
            } else if content_type == APPLICATION_DATA {
                let payload = &frame[TLS_HEADER_SIZE..];
                if payload.len() > HMAC_SIZE
                    && let Some(ref mut hmac_nop) = hmac_nop_opt
                {
                    hmac_nop.update(&payload[HMAC_SIZE..]);
                    if hmac_nop.finalize() == payload[..HMAC_SIZE] {
                        authorized = true;
                        break;
                    }
                }
                tracing::warn!(
                    "shadow-tls verification failed on application data"
                );
                break;
            } else if content_type == 0x15 {
                // ALERT
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected alert frame from server",
                ));
            } else {
                feed_rustls_client_connection(&mut client_conn, frame)?;
                let _ = client_conn.process_new_packets();
            }
        }

        let (server_random, hmac_nop) =
            match (authorized, server_random_opt, hmac_nop_opt) {
                (true, Some(sr), Some(hn)) => (sr, hn),
                _ => {
                    if self.strict {
                        tracing::warn!(
                            "shadow-tls V3 strict enabled: traffic hijacked \
                             or TLS1.3 is not supported, perform fake request"
                        );
                        let _ = fake_request(&mut stream).await;
                        return Err(io::Error::other(
                            "V3 strict enabled: traffic hijacked or TLS1.3 \
                             is not supported, fake request",
                        ));
                    }
                    return Err(io::Error::other(
                        "shadow-tls handshake verification failed",
                    ));
                }
            };

        let hmac_client =
            Hmac::new(&self.password, (&server_random, "C".as_bytes()));
        let hmac_server =
            Hmac::new(&self.password, (&server_random, "S".as_bytes()));

        let verified_stream =
            VerifiedStream::new(stream, hmac_client, hmac_server, Some(hmac_nop));

        Ok(Box::new(verified_stream))
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(
        &self,
        stream: AnyStream,
    ) -> std::io::Result<AnyStream> {
        self.wrap_shadow_tls_stream(stream).await
    }
}

/// Read a single TLS record frame from stream into the provided buffer.
async fn read_tls_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    stream.read_exact(&mut buf[..TLS_HEADER_SIZE]).await?;

    let payload_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let total_len = TLS_HEADER_SIZE + payload_len;
    if total_len > buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS frame payload exceeds buffer size",
        ));
    }
    stream
        .read_exact(&mut buf[TLS_HEADER_SIZE..total_len])
        .await?;

    Ok(total_len)
}

/// Doing fake request.
///
/// Only used by V3 protocol.
async fn fake_request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
) -> std::io::Result<()> {
    const HEADER: &[u8; 207] = b"GET / HTTP/1.1\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36\nAccept: gzip, deflate, br\nConnection: Close\nCookie: sessionid=";
    const FAKE_REQUEST_LENGTH_RANGE: (usize, usize) = (16, 64);
    let cnt = rand::rng()
        .random_range(FAKE_REQUEST_LENGTH_RANGE.0..FAKE_REQUEST_LENGTH_RANGE.1);
    let mut buffer = Vec::with_capacity(cnt + HEADER.len() + 1);

    buffer.extend_from_slice(HEADER);
    rand::distr::Alphanumeric
        .sample_iter(rand::rng())
        .take(cnt)
        .for_each(|c| buffer.push(c));
    buffer.push(b'\n');

    stream.write_all(&buffer).await?;
    let _ = stream.shutdown().await;

    // read until eof
    let mut buf = [0u8; 1024];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
    Ok(())
}


