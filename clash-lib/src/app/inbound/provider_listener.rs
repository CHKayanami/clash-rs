use std::{collections::{HashMap, HashSet}, sync::Arc};

use tokio::{sync::watch, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::network_listener::build_network_listeners;
use crate::{
    Error, Result,
    app::dispatcher::Dispatcher,
    common::auth::ThreadSafeAuthenticator,
    config::internal::listener::{InboundOpts, InboundUser},
    runner::ServiceContext,
};

pub(super) struct ProviderHandleEntry {
    pub handle: Option<JoinHandle<()>>,
    pub stop_token: CancellationToken,
    users_tx: Option<watch::Sender<Vec<InboundUser>>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, create_components, setup_default_crypto_provider};
    use crate::app::remote_content_manager::providers::{
        file_vehicle::Vehicle, inbound_provider::InboundSetProvider,
    };
    use crate::common::auth::PlainAuthenticator;
    use std::{net::TcpListener, time::Duration};
    use tokio::sync::{Mutex, mpsc};

    #[tokio::test]
    async fn periodic_failure_restores_old_listeners_and_retries_same_content() {
        setup_default_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let config = Config::Str("mode: direct\ntun:\n  enable: false\n".into())
            .try_parse().unwrap();
        let components = create_components(
            dir.path().to_path_buf(), config, None, None, None,
        ).await.unwrap();
        let runtime = Arc::new(ProviderRuntime {
            dispatcher: components.dispatcher.clone(),
            authenticator: Arc::new(PlainAuthenticator::new(vec![])),
            cancellation_token: CancellationToken::new(),
            context: None,
        });
        let old_port = TcpListener::bind("127.0.0.1:0").unwrap();
        let old_address = old_port.local_addr().unwrap();
        let new_port = TcpListener::bind("127.0.0.1:0").unwrap();
        let new_address = new_port.local_addr().unwrap();
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let occupied_address = occupied.local_addr().unwrap();
        drop(old_port);
        let path = dir.path().join("provider.yaml");
        let listener = |name: &str, typ: &str, port: u16| format!(
            "  - name: {name}\n    type: {typ}\n    listen: 127.0.0.1\n    port: {port}\n"
        );
        std::fs::write(&path, format!("listeners:\n{}",
            listener("old", "socks", old_address.port()))).unwrap();
        let handles = Arc::new(Mutex::new(Handles::new()));
        let update_handles = handles.clone();
        let update_runtime = runtime.clone();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let provider = InboundSetProvider::new(
            "rollback".into(), Duration::from_millis(100),
            Arc::new(Vehicle::new(path.to_str().unwrap())),
            move |opts| {
                let handles = update_handles.clone();
                let runtime = update_runtime.clone();
                let tx = tx.clone();
                Box::pin(async move {
                    let mut guard = handles.lock().await;
                    let (next, result) = runtime.update(
                        std::mem::take(&mut *guard), opts,
                    ).await;
                    *guard = next;
                    tx.send(result.is_ok()).unwrap();
                    result
                })
            },
        ).unwrap();
        provider.initialize().await.unwrap();
        assert_eq!(rx.recv().await, Some(true));
        assert!(TcpListener::bind(old_address).is_err());
        {
            let mut guard = handles.lock().await;
            let opt = guard.keys().next().unwrap().clone();
            let original_token = guard.values().next().unwrap().stop_token.clone();
            let (next, result) = runtime.update(
                std::mem::take(&mut *guard), vec![opt.clone(), opt],
            ).await;
            *guard = next;
            assert!(result.unwrap_err().to_string().contains("duplicate"));
            assert!(!original_token.is_cancelled());
            assert_eq!(guard.len(), 1);
            assert!(TcpListener::bind(old_address).is_err());
        }
        let opt = handles.lock().await.keys().next().unwrap().clone();
        let (empty, result) = runtime.update(
            Handles::new(), vec![opt.clone(), opt],
        ).await;
        assert!(result.unwrap_err().to_string().contains("duplicate"));
        assert!(empty.is_empty());
        drop(new_port);
        // Change the protocol on the same port, then fail after another new
        // listener has started. Rollback must restore the removed old listener.
        std::fs::write(&path, format!("listeners:\n{}{}{}",
            listener("replacement", "mixed", old_address.port()),
            listener("new", "socks", new_address.port()),
            listener("conflict", "socks", occupied_address.port()),
        )).unwrap();
        assert_eq!(tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await.unwrap(), Some(false));
        {
            let guard = handles.lock().await;
            assert_eq!(guard.len(), 1);
            assert_eq!(guard.keys().next().unwrap().common_opts().name, "old");
            assert!(TcpListener::bind(old_address).is_err());
            let _released = TcpListener::bind(new_address).unwrap();
        }
        drop(occupied);
        assert_eq!(tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match rx.recv().await {
                    Some(true) => break,
                    Some(false) => {},
                    None => panic!("provider update channel closed before success"),
                }
            }
        }).await, Ok(()));
        assert_eq!(handles.lock().await.len(), 3);
        assert!(TcpListener::bind(new_address).is_err());
        provider.stop().await;
        stop(std::mem::take(&mut *handles.lock().await)).await;
        let _old_released = TcpListener::bind(old_address).unwrap();
        let _new_released = TcpListener::bind(new_address).unwrap();
        let _conflict_released = TcpListener::bind(occupied_address).unwrap();
    }
}

pub(super) struct ProviderRuntime {
    pub dispatcher: Arc<Dispatcher>,
    pub authenticator: ThreadSafeAuthenticator,
    pub cancellation_token: CancellationToken,
    pub context: Option<ServiceContext>,
}

type Handles = HashMap<InboundOpts, ProviderHandleEntry>;

fn users(opts: &InboundOpts) -> Option<&Vec<InboundUser>> {
    match opts {
        #[cfg(feature = "shadowsocks")]
        InboundOpts::Shadowsocks { users, .. } => Some(users),
        InboundOpts::Anytls { users, .. } => Some(users),
        _ => None,
    }
}

async fn stop(handles: Handles) {
    for entry in handles.values() {
        entry.stop_token.cancel();
    }
    for (opts, entry) in handles {
        if let Some(handle) = entry.handle
            && let Err(error) = handle.await
        {
            warn!("provider inbound '{}' stopped with error: {error}",
                opts.common_opts().name);
        }
    }
}

impl ProviderRuntime {
    async fn start(&self, opts: &InboundOpts) -> Result<ProviderHandleEntry> {
        let (users_tx, users_rx) = match users(opts) {
            Some(users) => {
                let (tx, rx) = watch::channel(users.clone());
                (Some(tx), Some(rx))
            }
            None => (None, None),
        };
        let runners = build_network_listeners(
            opts, self.dispatcher.clone(), self.authenticator.clone(), users_rx,
        ).await?;
        let stop_token = self.cancellation_token.child_token();
        let task_stop_token = stop_token.clone();
        let name = opts.common_opts().name.clone();
        let critical_name = format!("provider_inbound_{name}");
        let task = async move {
            tokio::select! {
                _ = futures::future::try_join_all(runners) => {
                    warn!("Provider inbound {name} exited unexpectedly");
                }
                _ = task_stop_token.cancelled() => {
                    info!("Provider inbound {name} closed");
                }
            }
        };
        let handle = if let Some(ctx) = &self.context {
            ctx.spawn_critical_with_token(critical_name, stop_token.clone(), task)
        } else {
            tokio::spawn(task)
        };
        Ok(ProviderHandleEntry { handle: Some(handle), stop_token, users_tx })
    }

    pub async fn update(&self, mut old: Handles, opts: Vec<InboundOpts>)
        -> (Handles, Result<()>)
    {
        let mut seen = HashSet::with_capacity(opts.len());
        for opt in &opts {
            if !seen.insert(opt) {
                return (old, Err(Error::Operation(format!(
                    "duplicate provider inbound '{}'", opt.common_opts().name
                ))));
            }
        }
        let mut retained = Handles::new();
        let mut added = Vec::new();
        let mut reused = Vec::new();
        for opt in opts {
            if let Some((previous, entry)) = old.remove_entry(&opt) {
                retained.insert(previous, entry);
                reused.push(opt);
            } else {
                added.push(opt);
            }
        }
        let removed: Vec<_> = old.keys().cloned().collect();
        stop(old).await;
        let mut started = Handles::new();
        for opt in added {
            match self.start(&opt).await {
                Ok(entry) => { started.insert(opt, entry); }
                Err(error) => {
                    stop(started).await;
                    for previous in removed {
                        match self.start(&previous).await {
                            Ok(entry) => { retained.insert(previous, entry); }
                            Err(restore_error) => {
                                let error = Error::Operation(format!(
                                    "provider update failed: {error}; rollback failed: {restore_error}"
                                ));
                                if let Some(ctx) = &self.context {
                                    ctx.report_fatal(error.to_string());
                                }
                                return (retained, Err(error));
                            }
                        }
                    }
                    return (retained, Err(error));
                }
            }
        }
        // Commit user changes only after every new listener is ready. Keep the
        // old keys and user lists intact until then so rollback needs no undo.
        for opt in reused {
            if let Some((_, entry)) = retained.remove_entry(&opt) {
                if let (Some(users), Some(tx)) = (users(&opt), &entry.users_tx) {
                    let _ = tx.send(users.clone());
                }
                started.insert(opt, entry);
            }
        }
        (started, Ok(()))
    }
}
