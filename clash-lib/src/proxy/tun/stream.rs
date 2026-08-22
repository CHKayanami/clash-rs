use std::{net::SocketAddr, sync::Arc};

use tracing::debug;

use crate::{
    app::{
        dispatcher::Dispatcher,
        dns::{ThreadSafeDNSResolver, exchange_with_resolver},
        net::DEFAULT_OUTBOUND_INTERFACE,
    },
    proxy::ProxyStream,
    session::{Network, Session, Type},
};

pub(crate) async fn handle_inbound_stream<S: ProxyStream + 'static>(
    stream: S,
    source: SocketAddr,
    destination: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
    so_mark: Option<u32>,
    dns_hijack: crate::config::internal::config::DnsHijack,
    strict_route: bool,
    exclude_routes: Arc<Vec<ipnet::IpNet>>,
) {
    let remote_ip = destination.ip();
    if strict_route && exclude_routes.iter().any(|net| net.contains(&remote_ip)) {
        debug!(
            "strict-route: rejecting tun TCP stream to excluded subnet: {}",
            destination
        );
        return;
    }

    if dns_hijack.is_hijacked(Network::Tcp, &destination) {
        handle_tcp_dns_hijack(stream, source, destination, resolver).await;
        return;
    }

    let sess = Session {
        network: Network::Tcp,
        typ: Type::Tun,
        source,
        destination: destination.into(),
        iface: DEFAULT_OUTBOUND_INTERFACE
            .read()
            .await
            .clone()
            .inspect(|x| {
                debug!(
                    "selecting outbound interface: {:?} for tun TCP connection",
                    x
                );
            }),
        so_mark,
        ..Default::default()
    };

    debug!("new tun TCP session assigned: {}", sess);
    dispatcher.dispatch_stream(sess, Box::new(stream)).await;
}

pub(crate) async fn handle_inbound_netstack_stream(
    stream: watfaq_netstack::TcpStream,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
    so_mark: Option<u32>,
    dns_hijack: crate::config::internal::config::DnsHijack,
    strict_route: bool,
    exclude_routes: Arc<Vec<ipnet::IpNet>>,
) {
    let source = stream.local_addr();
    let destination = stream.remote_addr();
    handle_inbound_stream(
        stream,
        source,
        destination,
        dispatcher,
        resolver,
        so_mark,
        dns_hijack,
        strict_route,
        exclude_routes,
    )
    .await;
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

        match exchange_with_resolver(&resolver, &msg_buf, true).await {
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
