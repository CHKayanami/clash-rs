use crate::{
    app::remote_content_manager::providers::proxy_provider::ArcProxyProvider,
    proxy::AnyOutboundHandler,
};
use std::collections::HashSet;

pub async fn get_proxies_from_providers(
    providers: &Vec<ArcProxyProvider>,
    touch: bool,
) -> Vec<AnyOutboundHandler> {
    let mut provider_proxies = Vec::with_capacity(providers.len());
    for provider in providers {
        if touch {
            provider.touch().await;
        }

        provider_proxies.push(provider.proxies().await);
    }

    let mut proxy_names = HashSet::new();
    let mut proxies = Vec::new();
    for list in &provider_proxies {
        for p in list {
            if proxy_names.insert(p.name()) {
                proxies.push(p.clone());
            }
        }
    }
    proxies
}
