//! Validate the combined node, group and named-dialer graph before publication.

use crate::{Error, config::internal::proxy::OutboundProxyProtocol, proxy::OutboundNode};
use std::collections::{HashMap, HashSet};

fn identity(handler: &OutboundNode) -> usize {
    handler.identity()
}

pub(super) async fn validate(
    handlers: &HashMap<String, OutboundNode>,
) -> Result<(), Error> {
    let mut pending: Vec<_> = handlers.values().cloned().collect();
    let mut graph = HashMap::new();
    while let Some(handler) = pending.pop() {
        let id = identity(&handler);
        if graph.contains_key(&id) { continue; }
        let mut children = if let Some(group) = handler.as_group() {
            group.get_proxies().await
        } else { Vec::new() };
        if let Some(name) = handler.support_dialer() {
            let dialer = handler.dialer_dependency().or_else(|| handlers.get(name).cloned()).ok_or_else(|| Error::InvalidConfig(format!(
                "missing dialer-proxy: {} -> {name}", handler.name()
            )))?;
            children.push(dialer);
        }
        // Retain each handler so pointer identities cannot be reused while a
        // provider publishes a new generation during validation.
        graph.insert(id, (handler, children.iter().map(identity).collect::<Vec<_>>()));
        pending.extend(children);
    }
    let mut colors = HashMap::new();
    for &root in graph.keys() {
        let mut stack = vec![(root, false)];
        while let Some((id, exiting)) = stack.pop() {
            if exiting { colors.insert(id, 2); continue; }
            match colors.get(&id) {
                Some(2) => continue,
                Some(1) => return Err(Error::InvalidConfig(format!(
                    "cyclic group/dialer-proxy dependency at {}", graph[&id].0.name()
                ))),
                _ => {}
            }
            colors.insert(id, 1);
            stack.push((id, true));
            stack.extend(graph[&id].1.iter().map(|&child| (child, false)));
        }
    }
    Ok(())
}

/// Reject cycles among plain nodes even before groups become available.
pub(super) fn validate_plain(outbounds: &[OutboundProxyProtocol]) -> Result<(), Error> {
    let edges: HashMap<_, _> = outbounds.iter()
        .map(|node| (node.name(), node.dialer_proxy())).collect();
    let mut finished = HashSet::new();
    for &root in edges.keys() {
        let mut path = HashSet::new();
        let mut current = root;
        while !finished.contains(current) {
            if !path.insert(current) {
                return Err(Error::InvalidConfig(format!("cyclic dialer-proxy dependency at {current}")));
            }
            match edges.get(current).copied().flatten() {
                Some(next) if edges.contains_key(next) => current = next,
                _ => break,
            }
        }
        finished.extend(path);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::proxy::utils::ProviderSnapshot;
    use super::validate;
    use crate::{
        app::outbound::manager::OutboundManager,
        config::internal::proxy::OutboundProxyProtocol,
        proxy::{OutboundNode, direct, mocks::MockDummyProxyProvider, selector},
    };
    use arc_swap::ArcSwap;
    use std::{collections::HashMap, sync::Arc};

    #[tokio::test]
    async fn mixed_group_and_dialer_cycle_is_rejected() {
        let registry = Arc::new(ArcSwap::from_pointee(HashMap::new()));
        let config: OutboundProxyProtocol = yaml_serde::from_str(
            "type: socks5\nname: exit\nserver: 127.0.0.1\nport: 1080\ndialer-proxy: entry\n"
        ).unwrap();
        let exit = OutboundManager::load_plain_outbounds(vec![config], &registry).unwrap().remove(0);
        let snapshot = Arc::new(vec![exit.clone()]);
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_proxies().returning(move || snapshot.clone());
        let entry = selector::Handler::new(selector::HandlerOptions {
            name: "entry".to_owned(), ..Default::default()
        }, vec![Arc::new(provider)], None).await;
        let handlers = HashMap::from([
            ("exit".to_owned(), exit),
            ("entry".to_owned(), OutboundNode::group(Arc::new(entry))),
        ]);
        assert!(validate(&handlers).await.unwrap_err().to_string().contains("cyclic"));
    }

    #[tokio::test]
    async fn provider_local_dialer_dependency_is_validated() {
        let registry = Arc::new(ArcSwap::from_pointee(HashMap::new()));
        let local = Arc::new(ArcSwap::from_pointee(ProviderSnapshot::default()));
        let config: OutboundProxyProtocol = yaml_serde::from_str(
            "type: socks5\nname: exit\nserver: 127.0.0.1\nport: 1080\ndialer-proxy: local-entry\n"
        ).unwrap();
        let exit = OutboundManager::load_provider_outbounds(vec![config], &registry, Some(&local)).unwrap().remove(0);
        local.store(Arc::new(ProviderSnapshot::new(vec![OutboundNode::protocol(Arc::new(direct::Handler::new("local-entry")))])));
        validate(&HashMap::from([("exit".to_owned(), exit)])).await.unwrap();
    }

    #[cfg(feature = "shadowsocks")]
    #[tokio::test]
    async fn shadowsocks_provider_local_dialer_dependency_is_validated() {
        let registry = Arc::new(ArcSwap::from_pointee(HashMap::new()));
        let local = Arc::new(ArcSwap::from_pointee(ProviderSnapshot::default()));
        let config: OutboundProxyProtocol = yaml_serde::from_str(
            "type: ss\nname: exit\nserver: 127.0.0.1\nport: 8388\ncipher: aes-128-gcm\npassword: test-only\ndialer-proxy: local-entry\n"
        ).unwrap();
        let exit = OutboundManager::load_provider_outbounds(vec![config], &registry, Some(&local)).unwrap().remove(0);
        let entry = OutboundNode::protocol(Arc::new(direct::Handler::new("local-entry")));
        local.store(Arc::new(ProviderSnapshot::new(vec![entry.clone()])));
        assert!(exit.dialer_dependency().unwrap().ptr_eq(&entry));
        let handlers = HashMap::from([("exit".to_owned(), exit.clone())]);
        validate(&handlers).await.unwrap();
        let mut snapshot = ProviderSnapshot::default();
        snapshot.entries.insert("local-entry".to_owned(), exit);
        local.store(Arc::new(snapshot));
        assert!(validate(&handlers).await.unwrap_err().to_string().contains("cyclic"));
    }
}
