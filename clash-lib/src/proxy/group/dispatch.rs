//! Static dispatch for group selection policies and API inspection.
use super::{GroupHandler, GroupProxyAPIResponse, UdpPolicy};
use crate::{proxy::{OutboundNode, OutboundType}, session::Session};
use erased_serde::Serialize;
use std::{collections::{HashMap, HashSet}, io, time::Duration};

use std::sync::{Arc, Weak};

use crate::proxy::group::selector::Handler as SelectorHandler;
use crate::proxy::group::fallback::Handler as FallbackHandler;
use crate::proxy::group::urltest::Handler as UrlTestHandler;
use crate::proxy::group::loadbalance::Handler as LoadBalanceHandler;
use crate::proxy::group::smart::Handler as SmartHandler;
#[cfg(test)]
use crate::proxy::group::outbound_tests::RetryGroup as RetryHandler;

use crate::proxy::common::handler_enum;

handler_enum!(ProxyGroup, WeakProxyGroup, $;
    Selector(SelectorHandler),
    Fallback(FallbackHandler),
    UrlTest(UrlTestHandler),
    LoadBalance(LoadBalanceHandler),
    Smart(SmartHandler),
    #[cfg(test)]
    Retry(RetryHandler),
);

impl ProxyGroup {
    pub fn name(&self) -> &str { dispatch!(self, h, GroupHandler::name(h.as_ref())) }
    pub fn proto(&self) -> OutboundType { dispatch!(self, h, GroupHandler::proto(h.as_ref())) }
    pub fn udp_policy(&self) -> UdpPolicy { dispatch!(self, h, GroupHandler::udp_policy(h.as_ref())) }
    pub fn retry_delay(&self, attempt: u32) -> Duration { dispatch!(self, h, GroupHandler::retry_delay(h.as_ref(), attempt)) }

    pub async fn select(&self, sess: &Session, excluded: &HashSet<String>) -> io::Result<Option<OutboundNode>> {
        match self {
            Self::Selector(h) => h.select(sess, excluded).await,
            Self::Fallback(h) => h.select(sess, excluded).await,
            Self::UrlTest(h) => h.select(sess, excluded).await,
            Self::LoadBalance(h) => h.select(sess, excluded).await,
            // Keep the large Smart state out of every group's selection future.
            Self::Smart(h) => Box::pin(h.select(sess, excluded)).await,
            #[cfg(test)]
            Self::Retry(h) => h.select(sess, excluded).await,
        }
    }
    pub async fn attempts(&self, sess: &Session) -> u32 {
        dispatch!(self, h, GroupHandler::attempts(h.as_ref(), sess).await)
    }
    pub async fn record_result(&self, sess: &Session, proxy: &str, elapsed: Duration, success: bool) {
        dispatch!(self, h, GroupHandler::record_result(h.as_ref(), sess, proxy, elapsed, success).await)
    }
    pub async fn get_proxies(&self) -> Vec<OutboundNode> {
        dispatch!(self, h, GroupProxyAPIResponse::get_proxies(h.as_ref()).await)
    }
    pub async fn get_active_proxy(&self) -> Option<OutboundNode> {
        dispatch!(self, h, GroupProxyAPIResponse::get_active_proxy(h.as_ref()).await)
    }
    pub fn get_latency_test_url(&self) -> Option<String> {
        dispatch!(self, h, GroupProxyAPIResponse::get_latency_test_url(h.as_ref()))
    }
    pub async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        dispatch!(self, h, GroupProxyAPIResponse::as_map(h.as_ref()).await)
    }
}
