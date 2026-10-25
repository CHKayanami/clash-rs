use crate::app::dns::query::IngressProfile;
use bytes::Bytes;
use ipnet::IpNet;
use crate::config::internal::config::DnsHijack;
use crate::proxy::AnyStream;
use std::{net::SocketAddr, sync::Arc};

use tracing::debug;

use crate::{
    app::{
        dispatcher::Dispatcher,
        dns::{ThreadSafeDNSResolver, exchange_with_resolver},
        net::get_default_outbound_interface,
    },
    proxy::ProxyStream,
    session::{Network, Session, Type},
};

pub(super) struct TcpContext {
    pub dispatcher: Arc<Dispatcher>,
    pub resolver: ThreadSafeDNSResolver,
    pub so_mark: Option<u32>,
    pub dns_hijack: DnsHijack,
    pub strict_route: bool,
    pub exclude_routes: Arc<Vec<IpNet>>,
}

pub(super) async fn handle_inbound_stream<S: ProxyStream + Sync + Into<AnyStream> + 'static>(
    stream: S, source: SocketAddr, destination: SocketAddr, context: Arc<TcpContext>,
) {
    let remote_ip = destination.ip();
    if context.strict_route && context.exclude_routes.iter().any(|net| net.contains(&remote_ip)) {
        debug!(
            "strict-route: rejecting tun TCP stream to excluded subnet: {}",
            destination
        );
        return;
    }

    if context.dns_hijack.is_hijacked(Network::Tcp, &destination) {
        handle_tcp_dns_hijack(stream, source, destination, context.resolver.clone()).await;
        return;
    }

    let sess = Session {
        network: Network::Tcp,
        typ: Type::Tun,
        source,
        destination: destination.into(),
        iface: get_default_outbound_interface().inspect(|x| {
            debug!(
                "selecting outbound interface: {:?} for tun TCP connection",
                x
            );
        }),
        so_mark: context.so_mark,
        ..Default::default()
    };

    debug!("new tun TCP session assigned: {}", sess);
    context.dispatcher
        .dispatch_stream(sess, AnyStream::new(stream))
        .await;
}

pub(super) async fn handle_inbound_netstack_stream(
    stream: watfaq_netstack::TcpStream, context: Arc<TcpContext>,
) {
    let source = stream.local_addr();
    let destination = stream.remote_addr();
    handle_inbound_stream(stream, source, destination, context).await;
}

async fn handle_tcp_dns_hijack<S: ProxyStream + 'static>(
    mut stream: S,
    local: SocketAddr,
    remote: SocketAddr,
    resolver: ThreadSafeDNSResolver,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    debug!("hijacking TCP DNS request from {} to {}", local, remote);

    loop {
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                if e.kind() != std::io::ErrorKind::UnexpectedEof {
                    debug!("error reading TCP DNS length prefix: {}", e);
                }
                break;
            }
        }

        let msg_len = u16::from_be_bytes(len_buf) as usize;
        let mut msg_buf = vec![0u8; msg_len];
        if let Err(e) = stream.read_exact(&mut msg_buf).await {
            debug!("error reading TCP DNS message body: {}", e);
            break;
        }

        match exchange_with_resolver(
            &resolver, Bytes::from(msg_buf), IngressProfile::Tcp, Some(local.ip()),
        ).await {
            Ok(resp_bytes) => {
                let resp_len = (resp_bytes.len() as u16).to_be_bytes();
                if let Err(e) = stream.write_all(&resp_len).await {
                    debug!(
                        "failed to write TCP DNS response length: {}",
                        e
                    );
                    break;
                }
                if let Err(e) = stream.write_all(&resp_bytes).await {
                    debug!("failed to write TCP DNS response body: {}", e);
                    break;
                }
                if let Err(e) = stream.flush().await {
                    debug!("failed to flush TCP DNS response: {}", e);
                    break;
                }
            }
            Err(e) => {
                debug!("failed to exchange TCP DNS message: {}", e);
                break;
            }
        }
    }
}
