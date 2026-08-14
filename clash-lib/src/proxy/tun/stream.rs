use std::sync::Arc;

use tracing::{debug, warn};

use crate::{
    app::{
        dispatcher::Dispatcher,
        dns::{ThreadSafeDNSResolver, exchange_with_resolver},
        net::DEFAULT_OUTBOUND_INTERFACE,
    },
    session::{Network, Session, Type},
};

pub(crate) async fn handle_inbound_stream(
    stream: watfaq_netstack::TcpStream,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
    so_mark: Option<u32>,
    dns_hijack: crate::config::internal::config::DnsHijack,
) {
    if dns_hijack.is_hijacked(Network::Tcp, &stream.remote_addr()) {
        handle_tcp_dns_hijack(stream, resolver).await;
        return;
    }

    let sess = Session {
        network: Network::Tcp,
        typ: Type::Tun,
        source: stream.local_addr(),
        destination: stream.remote_addr().into(),
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

async fn handle_tcp_dns_hijack(
    mut stream: watfaq_netstack::TcpStream,
    resolver: ThreadSafeDNSResolver,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let remote = stream.remote_addr();
    let local = stream.local_addr();
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

        match hickory_proto::op::Message::from_vec(&msg_buf) {
            Ok(msg) => match exchange_with_resolver(&resolver, &msg, true).await {
                Ok(mut resp) => {
                    resp.metadata.id = msg.metadata.id;
                    match resp.to_vec() {
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
                            warn!("failed to serialize TCP DNS response: {}", e);
                            break;
                        }
                    }
                }
                Err(e) => {
                    warn!("failed to exchange TCP DNS message with resolver: {}", e);
                    break;
                }
            },
            Err(e) => {
                warn!("failed to parse TCP DNS message: {}", e);
                break;
            }
        }
    }
}
