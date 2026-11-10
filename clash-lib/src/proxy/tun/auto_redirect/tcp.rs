use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr}, sync::Arc, time::Duration};

use socket2::Type;
use tokio::{net::{TcpListener, TcpStream}, task::JoinSet, time::sleep};
use tracing::warn;

use crate::{
    Error,
    config::internal::config::TunConfig,
    proxy::utils::{ToCanonical, get_original_destination_addr, try_create_dualstack_socket},
};
use super::super::stream::{TcpContext, handle_inbound_stream};

pub(in crate::proxy::tun) fn bind(cfg: &TunConfig) -> Result<Option<TcpListener>, Error> {
    if !cfg.auto_redirect || !cfg.enable_tcp { return Ok(None); }
    let address = if cfg.gateway_v6.is_some() {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else { IpAddr::V4(Ipv4Addr::UNSPECIFIED) };
    let (socket, dualstack) = try_create_dualstack_socket(SocketAddr::new(address, 0), Type::STREAM)?;
    if address.is_ipv6() && !dualstack {
        return Err(Error::Operation("auto-redirect requires a dual-stack TCP listener".into()));
    }
    socket.set_nonblocking(true)?;
    socket.set_tcp_nodelay(true)?;
    socket.bind(&SocketAddr::new(address, 0).into())?;
    socket.listen(1024)?;
    Ok(Some(TcpListener::from_std(socket.into())?))
}

pub(in crate::proxy::tun) async fn run(listener: TcpListener, context: Arc<TcpContext>) -> Result<(), Error> {
    let mut connections = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            accepted = accept(&listener) => accepted,
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result { warn!("auto-redirect TCP relay failed: {error}"); }
                continue;
            }
        };
        let (stream, source) = accepted;
        let destination = match get_original_destination_addr(&stream) {
            Ok(address) => address.to_canonical(),
            Err(error) => {
                warn!("auto-redirect failed to read original TCP destination: {error}");
                continue;
            }
        };
        // SO_ORIGINAL_DST also succeeds for ordinary connections. Reject a
        // connection addressed directly to this listener to prevent recursion.
        let local = match stream.local_addr() {
            Ok(address) => address.to_canonical(),
            Err(error) => {
                warn!("auto-redirect failed to read local TCP address: {error}");
                continue;
            }
        };
        if destination == local { continue; }
        let context = context.clone();
        connections.spawn(handle_inbound_stream(stream, source.to_canonical(), destination, context));
    }
}

// A connection abort or descriptor exhaustion must not stop UDP/ICMP or the
// device stage. Back off after errors so EMFILE cannot turn into a busy loop.
async fn accept(listener: &TcpListener) -> (TcpStream, SocketAddr) {
    loop {
        match listener.accept().await {
            Ok(connection) => return connection,
            Err(error) => {
                warn!("auto-redirect TCP accept failed; retrying: {error}");
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use tokio::time::timeout;
    use super::*;

    #[tokio::test]
    async fn auto_redirect_listener_inherits_tcp_nodelay() {
        let cfg = TunConfig { auto_redirect: true, ..Default::default() };
        let listener = bind(&cfg).unwrap().unwrap();
        let address = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), listener.local_addr().unwrap().port());
        let _client = TcpStream::connect(address).await.unwrap();
        let (stream, _) = accept(&listener).await;
        assert!(stream.nodelay().unwrap());
    }

    // Run in a dedicated test process with prlimit --nofile=128:128.
    #[tokio::test]
    #[ignore = "requires a dedicated process with RLIMIT_NOFILE <= 256"]
    async fn auto_redirect_tcp_accept_recovers_after_emfile() {
        let limits = fs::read_to_string("/proc/self/limits").unwrap();
        let line = limits.lines().find(|line| line.starts_with("Max open files")).unwrap();
        let limit: usize = line.split_whitespace().nth(3).unwrap().parse().unwrap();
        assert!(limit <= 256, "run with prlimit --nofile=128:128");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let mut files = Vec::new();
        loop {
            match File::open("/dev/null") {
                Ok(file) => files.push(file),
                Err(error) => {
                    assert_eq!(error.raw_os_error(), Some(libc::EMFILE));
                    break;
                }
            }
        }
        // Prove accept itself sees EMFILE before testing the retry path.
        assert_eq!(listener.accept().await.unwrap_err().raw_os_error(), Some(libc::EMFILE));
        let release = tokio::spawn(async move {
            sleep(Duration::from_millis(250)).await;
            drop(files);
        });
        timeout(Duration::from_secs(3), accept(&listener)).await.unwrap();
        release.await.unwrap();
    }
}
