mod dns;
mod routes;
mod monitor;

use std::{io::{self, Write}, os::unix::net::UnixStream, sync::Arc};

use tokio::{sync::oneshot, task::spawn_blocking};
use tokio_util::sync::CancellationToken;
use tracing::info;
use tun_rs::AsyncDevice;

use crate::{Error, app::net::{get_outbound_interface,
    update_default_outbound_interface_if_changed, macos::register_tun},
    config::internal::config::TunConfig, runner::ServiceContext};
use dns::Dns;
use monitor::Monitor;
use routes::{Plan, Routes, SystemRoutes};

/// Cancelling the runner stops the worker; dropping this guard also handles
/// packet-pipeline failure. The tracked worker owns all native state and fully
/// cleans it up before the service context finishes draining its tasks.
pub(super) struct PlatformGuard(CancellationToken);

impl Drop for PlatformGuard {
    fn drop(&mut self) { self.0.cancel(); }
}

pub(super) async fn start(
    cfg: TunConfig,
    device: Arc<AsyncDevice>,
    manage_network: bool,
    ctx: &ServiceContext,
    cancellation: &CancellationToken,
) -> Result<PlatformGuard, Error> {
    let name = device.name()?;
    let token = cancellation.child_token();
    let guard = PlatformGuard(token.clone());
    let (ready_tx, ready_rx) = oneshot::channel();
    let (wake_reader, mut wake_writer) = UnixStream::pair()?;
    let wake_token = token.clone();
    ctx.spawn(async move {
        wake_token.cancelled().await;
        // One byte on an otherwise empty stream cannot fill its send buffer.
        let _ = wake_writer.write_all(&[1]);
    });
    // Core Foundation objects remain on this worker thread. No native object
    // crosses an await point, and no unsafe Send/Sync implementation is needed.
    let worker = spawn_blocking(move || {
        // Keep the utun file description open until DNS and route guards have
        // dropped. This local is declared first, so it is dropped last, even
        // when setup fails or the packet pipeline exits concurrently.
        let _device = device;
        // Publish the exclusion before installing any session-owned service;
        // keep it through native DNS and route cleanup, including reload overlap.
        let _interface = register_tun(name.clone());
        let setup = || -> io::Result<_> {
            let monitor = Monitor::new(wake_reader)?;
            let mut plan = Plan::new(&cfg, &name);
            let mut routes = Routes::new(SystemRoutes::new()?);
            if manage_network { routes.reconcile(&mut plan)?; }
            let dns = if manage_network {
                dns::server(&cfg).map(|address| Dns::new(&name, address,
                    cfg.gateway.addr())).transpose()?
            } else { None };
            Ok((monitor, routes, dns, plan))
        };
        let (monitor, mut routes, _dns, mut plan) = match setup() {
            Ok(state) => state,
            Err(error) => {
                let _ = ready_tx.send(Err(Error::Io(error)));
                return Ok(());
            }
        };
        if ready_tx.send(Ok(())).is_err() { return Ok(()); }
        monitor.run(&token, || {
            if manage_network { routes.reconcile(&mut plan)?; }
            if cfg.route_all || cfg.auto_detect_interface {
                if let Some(iface) = get_outbound_interface() {
                    if update_default_outbound_interface_if_changed(iface.clone()) {
                        info!("macOS default outbound interface changed to {}", iface.name);
                    }
                }
            }
            Ok(())
        })
    });
    let context = ctx.clone();
    ctx.spawn(async move {
        match worker.await {
            Ok(Ok(())) => {}
            result => context.report_fatal(format!("macOS TUN network monitor failed: {result:?}")),
        }
    });
    ready_rx.await.map_err(|_| Error::Operation(
        "macOS TUN platform worker exited during initialization".to_owned()
    ))??;
    Ok(guard)
}
