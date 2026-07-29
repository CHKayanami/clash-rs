use crate::{
    Dispatcher,
    common::{auth::ThreadSafeAuthenticator, errors::new_io_error},
    proxy::{
        socks::{
            SOCKS5_VERSION,
            inbound::{Socks5UDPCodec, datagram::InboundUdp},
            socks5::{auth_methods, response_code, socks_command},
        },
        utils::new_udp_socket,
    },
    session::{Network, Session, SocksAddr, Type},
};

use bytes::{BufMut, BytesMut};

use std::{io, net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_util::udp::UdpFramed;
use tracing::{instrument, trace, warn};

/// A client that connects but never completes the SOCKS handshake would
/// otherwise hold its task and file descriptor forever.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Method negotiation, optional username/password auth, and the request
/// header. Returns the command byte and the requested destination.
async fn handshake(
    s: &mut TcpStream,
    authenticator: &ThreadSafeAuthenticator,
) -> io::Result<(u8, SocksAddr)> {
    let mut hdr = [0u8; 2];
    s.read_exact(&mut hdr).await?;

    if hdr[0] != SOCKS5_VERSION {
        return Err(io::Error::other("unsupported SOCKS version"));
    }

    let n_methods = hdr[1] as usize;
    if n_methods == 0 {
        return Err(io::Error::other("malformed SOCKS data"));
    }

    let mut methods = vec![0u8; n_methods];
    s.read_exact(&mut methods).await?;

    let mut response = [SOCKS5_VERSION, auth_methods::NO_METHODS];

    if authenticator.enabled() {
        if !methods.contains(&auth_methods::USER_PASS) {
            // RFC 1928: X'FF' means "no acceptable methods"
            response[1] = auth_methods::NO_METHODS;
            s.write_all(&response).await?;
            s.shutdown().await?;
            return Err(new_io_error("auth required"));
        }

        response[1] = auth_methods::USER_PASS;
        s.write_all(&response).await?;

        // +----+------+----------+------+----------+
        // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        // +----+------+----------+------+----------+
        // | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
        // +----+------+----------+------+----------+
        let mut auth_hdr = [0u8; 2];
        s.read_exact(&mut auth_hdr).await?;

        let mut user = vec![0u8; auth_hdr[1] as usize];
        s.read_exact(&mut user).await?;

        let mut plen = [0u8; 1];
        s.read_exact(&mut plen).await?;

        let mut pass = vec![0u8; plen[0] as usize];
        s.read_exact(&mut pass).await?;

        // credentials are attacker-controlled bytes and are not required to be
        // valid UTF-8 — never hand them to `from_utf8_unchecked`
        let user = String::from_utf8_lossy(&user);
        let pass = String::from_utf8_lossy(&pass);

        match authenticator.authenticate(&user, &pass) {
            // +----+--------+
            // |VER | STATUS |
            // +----+--------+
            // | 1  |   1    |
            // +----+--------+
            true => {
                s.write_all(&[0x1, response_code::SUCCEEDED]).await?;
            }
            false => {
                s.write_all(&[0x1, response_code::FAILURE]).await?;
                s.shutdown().await?;
                return Err(io::Error::other("auth failure"));
            }
        }
    } else if methods.contains(&auth_methods::NO_AUTH) {
        response[1] = auth_methods::NO_AUTH;
        s.write_all(&response).await?;
    } else {
        response[1] = auth_methods::NO_METHODS;
        s.write_all(&response).await?;
        s.shutdown().await?;
        return Err(io::Error::other("auth failure"));
    }

    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    let mut req = [0u8; 3];
    s.read_exact(&mut req).await?;
    if req[0] != SOCKS5_VERSION {
        return Err(io::Error::other("unsupported SOCKS version"));
    }

    let dst = SocksAddr::read_from(s).await?;
    Ok((req[1], dst))
}

#[instrument(skip(sess, s, dispatcher, authenticator))]
pub async fn handle_tcp(
    sess: &mut Session,
    mut s: TcpStream,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
) -> io::Result<()> {
    let (command, dst) = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        handshake(&mut s, &authenticator),
    )
    .await
    {
        Ok(res) => res?,
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "SOCKS handshake timed out",
            ));
        }
    };

    let mut buf = BytesMut::new();

    match command {
        socks_command::CONNECT => {
            trace!("Got a CONNECT request from {}", s.peer_addr()?);

            buf.clear();
            buf.put_u8(SOCKS5_VERSION);
            buf.put_u8(response_code::SUCCEEDED);
            buf.put_u8(0x0);
            let bnd = SocksAddr::from(s.local_addr()?);
            bnd.write_buf(&mut buf);
            s.write_all(&buf[..]).await?;
            sess.destination = dst;

            dispatcher
                .dispatch_stream(sess.to_owned(), Box::new(s))
                .await;

            Ok(())
        }
        socks_command::UDP_ASSOCIATE => {
            let udp_addr = SocketAddr::new(s.local_addr()?.ip(), 0);
            let udp_inbound = new_udp_socket(
                Some(udp_addr),
                None,
                #[cfg(target_os = "linux")]
                None,
                None,
            )
            .await?;

            trace!(
                "Got a UDP_ASSOCIATE request from {}, UDP assigned at {}",
                s.peer_addr()?,
                udp_inbound.local_addr()?
            );

            buf.clear();
            buf.put_u8(SOCKS5_VERSION);
            buf.put_u8(response_code::SUCCEEDED);
            buf.put_u8(0x0);
            let bnd = SocksAddr::from(udp_inbound.local_addr()?);
            bnd.write_buf(&mut buf);

            let (close_handle, close_listener) = tokio::sync::oneshot::channel();

            let framed = UdpFramed::new(udp_inbound, Socks5UDPCodec);
            // Pin the association to the client that requested it. The relay
            // socket is reachable by anything that can route to this host, so
            // without this it is an open UDP relay.
            let framed = InboundUdp::new(framed, sess.source.ip());
            let source = sess.source;
            let so_mark = sess.so_mark;
            let iface = sess.iface.clone();
            let sess = Session {
                network: Network::Udp,
                typ: Type::Socks5,
                source,
                so_mark,
                iface,
                ..Default::default()
            };

            let dispatcher_cloned = dispatcher.clone();

            tokio::spawn(async move {
                let handle = dispatcher_cloned
                    .dispatch_datagram(sess, Box::new(framed))
                    .await;
                close_listener.await.ok();
                handle.send(0).ok();
            });

            s.write_all(&buf[..]).await?;

            buf.resize(1, 0);
            match s.read(&mut buf[..]).await {
                Ok(_) => {
                    trace!("UDP association finished, closing");
                }
                Err(e) => {
                    warn!("SOCKS client closed connection: {}", e);
                }
            }

            let _ = close_handle.send(1);

            Ok(())
        }
        _ => {
            buf.clear();
            buf.put_u8(SOCKS5_VERSION);
            buf.put_u8(response_code::COMMAND_NOT_SUPPORTED);
            buf.put_u8(0x0);
            SocksAddr::any_ipv4().write_buf(&mut buf);
            s.write_all(&buf).await?;
            Err(io::Error::other("unsupported SOCKS command"))
        }
    }
}
