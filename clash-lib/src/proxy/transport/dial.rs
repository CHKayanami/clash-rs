use std::{io, sync::Arc};
use tracing::debug;
use crate::{
    app::dns::ThreadSafeDNSResolver,
    proxy::{AnyStream, HandlerCommonOptions, utils::RemoteConnector},
    session::Session,
};
use super::{TlsClient, RealityClient, Transport, TransportLayer, xhttp::{ConnectionFactory, DialFuture}};

#[derive(Clone)]
pub(crate) enum TransportSecurity { Tls(TlsClient), Reality(RealityClient) }
impl TransportSecurity {
    pub(crate) fn from_layer(layer: Option<&TransportLayer>) -> io::Result<Option<Self>> {
        match layer {
            Some(TransportLayer::Tls(client)) => Ok(Some(Self::Tls(client.clone()))),
            Some(TransportLayer::Reality(client)) => Ok(Some(Self::Reality(client.clone()))),
            None => Ok(None),
            Some(_) => Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid XHTTP security layer")),
        }
    }
    async fn wrap(&self, stream: AnyStream) -> io::Result<AnyStream> {
        match self {
            Self::Tls(client) => Transport::proxy_stream(client, stream).await,
            Self::Reality(client) => Transport::proxy_stream(client, stream).await,
        }
    }
}

pub(crate) struct TransportDialer<'a> {
    pub(crate) server: &'a str,
    pub(crate) port: u16,
    pub(crate) common: &'a HandlerCommonOptions,
    pub(crate) session: &'a Session,
    pub(crate) tls: Option<&'a TransportLayer>,
    pub(crate) resolver: ThreadSafeDNSResolver,
    pub(crate) connector: &'a dyn RemoteConnector,
}

impl TransportDialer<'_> {
    pub(crate) fn factory(&self) -> io::Result<ConnectionFactory> {
        self.endpoint_factory(self.server, self.port, TransportSecurity::from_layer(self.tls)?)
    }

    pub(crate) fn endpoint_factory(
        &self, server: &str, port: u16, security: Option<TransportSecurity>,
    ) -> io::Result<ConnectionFactory> {
        let connector = self.connector.clone_connector().ok_or_else(|| io::Error::new(
            io::ErrorKind::Unsupported, "XHTTP requires a shareable remote connector"))?;
        let key = format!("{}:{:p}:{:?}:{:?}:{server:?}:{port}:{}", self.connector.pool_key(),
            Arc::as_ptr(&self.resolver), self.session.iface, self.session.so_mark, self.common.tfo);
        let resolver = self.resolver.clone();
        let server = server.to_owned();
        let iface = self.session.iface.clone();
        let tfo = self.common.tfo;
        #[cfg(target_os = "linux")]
        let mark = self.session.so_mark;
        let dial = Arc::new(move || {
            let connector = connector.clone();
            let resolver = resolver.clone();
            let server = server.clone();
            let iface = iface.clone();
            let security = security.clone();
            Box::pin(async move {
                let stream = connector.connect_stream(resolver, &server, port, tfo, iface.as_ref(),
                    #[cfg(target_os = "linux")]
                    mark,
                ).await?;
                debug!(server, port, "XHTTP TCP connection established");
                let stream = match security { Some(security) => security.wrap(stream).await?, None => stream };
                debug!(server, port, "XHTTP transport security established");
                Ok(stream)
            }) as DialFuture
        });
        Ok(ConnectionFactory { key, dial })
    }
}

#[cfg(test)]
mod tests {
    use super::TransportDialer;
    use std::sync::Arc;
    use crate::{
        app::dns::MockClashResolver,
        proxy::{HandlerCommonOptions, utils::DirectConnector},
        session::Session,
    };

    #[test]
    fn xhttp_endpoint_pool_keys_isolate_servers_and_ports() {
        let common = HandlerCommonOptions::default();
        let session = Session::default();
        let connector = DirectConnector::new();
        let dialer = TransportDialer {
            server: "upload.example", port: 443, common: &common,
            session: &session, tls: None,
            resolver: Arc::new(MockClashResolver::new()), connector: &connector,
        };
        let upload = dialer.factory().unwrap();
        let same = dialer.endpoint_factory("upload.example", 443, None).unwrap();
        let other_server = dialer.endpoint_factory("download.example", 443, None).unwrap();
        let other_port = dialer.endpoint_factory("upload.example", 8443, None).unwrap();
        assert_eq!(upload.key, same.key);
        assert_ne!(upload.key, other_server.key);
        assert_ne!(upload.key, other_port.key);
    }
}
