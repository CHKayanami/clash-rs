use std::{collections::HashMap, fmt::Debug, io, sync::Arc};

use async_trait::async_trait;
use base64::{Engine, prelude::BASE64_STANDARD};
use erased_serde::Serialize as ErasedSerialize;
use http::{HeaderMap, HeaderName, HeaderValue, header::{HOST, PROXY_AUTHORIZATION}, uri::Authority};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::{
    app::{dns::ThreadSafeDNSResolver, sniffer::PrefixedStream},
    common::io::SlideBuffer,
    impl_default_connector,
    proxy::{
        AnyOutboundDatagram, AnyStream, ConnectorType, DialWithConnector,
        HandlerCommonOptions, OutboundHandler, OutboundType,
        PlainProxyAPIResponse, transport::TransportLayer,
        utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
    },
    session::Session,
};

const MAX_RESPONSE_HEADER: usize = 16 * 1024;

#[derive(Default)]
pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
    pub headers: HashMap<String, String>,
    pub tls_client: Option<TransportLayer>,
}

pub struct Handler {
    opts: HandlerOptions,
    headers: HeaderMap,
    connector: Option<Arc<dyn RemoteConnector>>,
}

impl_default_connector!(Handler);

impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http").field("name", &self.opts.name).finish()
    }
}

impl Handler {
    pub fn new(
        opts: HandlerOptions,
        connector: Option<Arc<dyn RemoteConnector>>,
    ) -> io::Result<Self> {
        let mut headers = HeaderMap::new();
        for (name, value) in &opts.headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            let value = HeaderValue::from_str(value)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            headers.insert(name, value);
        }
        if let Some(user) = &opts.user {
            let credentials = format!("{user}:{}", opts.password.as_deref().unwrap_or_default());
            let value = format!("Basic {}", BASE64_STANDARD.encode(credentials));
            headers.insert(PROXY_AUTHORIZATION, HeaderValue::from_str(&value)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?);
        }
        Ok(Self { opts, headers, connector })
    }

    async fn handshake(&self, mut stream: AnyStream, sess: &Session) -> io::Result<AnyStream> {
        if let Some(tls) = &self.opts.tls_client {
            stream = tls.wrap(stream).await?;
        }
        let destination = sess.destination.to_string();
        let host = HeaderValue::from_str(&destination)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // Validate the request target as an authority, including IPv6 brackets.
        let authority = destination.parse::<Authority>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut request = format!("CONNECT {authority} HTTP/1.1\r\n");
        if !self.headers.contains_key(HOST) {
            request.push_str(&format!("Host: {}\r\n", host.to_str().unwrap()));
        }
        for (name, value) in &self.headers {
            request.push_str(name.as_str());
            request.push_str(": ");
            request.push_str(value.to_str()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        read_response(stream).await
    }
}

async fn read_response(stream: AnyStream) -> io::Result<AnyStream> {
    let mut stream = BufReader::new(stream);
    let mut response = Vec::new();
    loop {
        let available = stream.fill_buf().await?;
        if available.is_empty() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete HTTP CONNECT response"));
        }
        let mut consumed = 0;
        for byte in available {
            response.push(*byte);
            consumed += 1;
            if response.ends_with(b"\r\n\r\n") || response.len() >= MAX_RESPONSE_HEADER {
                break;
            }
        }
        stream.consume(consumed);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
        if response.len() >= MAX_RESPONSE_HEADER {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP CONNECT response header too large"));
        }
    }
    for line in response.split(|b| *b == b'\n').skip(1) {
        if line == b"\r" || line.is_empty() { continue; }
        let line = line.strip_suffix(b"\r").ok_or_else(||
            io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP response header"))?;
        let colon = line.iter().position(|b| *b == b':').ok_or_else(||
            io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP response header"))?;
        HeaderName::from_bytes(&line[..colon])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        HeaderValue::from_bytes(&line[colon + 1..])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    }
    let status = response.split(|b| *b == b'\n').next().unwrap();
    let mut fields = status.split(|b| *b == b' ');
    let version = fields.next().unwrap_or_default();
    let code = fields.next().unwrap_or_default();
    if !matches!(version, b"HTTP/1.0" | b"HTTP/1.1") || code.len() != 3
        || !code.iter().all(u8::is_ascii_digit)
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP CONNECT status line"));
    }
    if code[0] != b'2' {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied,
            format!("HTTP CONNECT rejected with status {}", String::from_utf8_lossy(code))));
    }
    // Reuse the prefix wrapper so buffered tunnel bytes and zero-copy support
    // survive the CONNECT handshake without retaining the response buffer.
    if stream.buffer().is_empty() {
        return Ok(stream.into_inner());
    }
    let mut prefix = SlideBuffer::new(stream.buffer().len());
    prefix.extend_from_slice(stream.buffer());
    Ok(AnyStream::new(PrefixedStream::new(prefix, stream.into_inner())))
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str { &self.opts.name }
    fn server_name(&self) -> Option<&str> { Some(&self.opts.server) }
    fn proto(&self) -> OutboundType { OutboundType::Http }
    async fn support_udp(&self) -> bool { false }
    async fn support_connector(&self) -> ConnectorType { ConnectorType::Tcp }

    async fn connect_stream(&self, sess: &Session, resolver: ThreadSafeDNSResolver) -> io::Result<AnyStream> {
        let connector = self.connector.as_ref().unwrap_or(&GLOBAL_DIRECT_CONNECTOR);
        self.connect_stream_with_connector(sess, resolver, connector.as_ref()).await
    }

    async fn connect_stream_with_connector(
        &self, sess: &Session, resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<AnyStream> {
        let stream = connector.connect_stream(
            resolver, &self.opts.server, self.opts.port, self.opts.common_opts.tfo,
            sess.iface.as_ref(),
            #[cfg(target_os = "linux")]
            sess.so_mark,
        ).await?;
        let stream = self.handshake(stream, sess).await?;
        sess.push_chain(self.name());
        Ok(stream)
    }

    async fn connect_datagram(&self, _sess: &Session, _resolver: ThreadSafeDNSResolver) -> io::Result<AnyOutboundDatagram> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "HTTP outbound does not support UDP"))
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> { Some(self) }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        let mut m: HashMap<String, Box<dyn ErasedSerialize + Send>> = HashMap::new();
        m.insert("server".to_owned(), Box::new(self.opts.server.clone()));
        m.insert("port".to_owned(), Box::new(self.opts.port));
        m.insert("tls".to_owned(), Box::new(self.opts.tls_client.is_some()));
        m.insert("headers".to_owned(), Box::new(self.opts.headers.clone()));
        if let Some(user) = &self.opts.user {
            m.insert("username".to_owned(), Box::new(user.clone()));
        }
        if let Some(password) = &self.opts.password {
            m.insert("password".to_owned(), Box::new(password.clone()));
        }
        m
    }
}

#[cfg(test)]
#[path = "outbound_tests.rs"]
mod tests;
