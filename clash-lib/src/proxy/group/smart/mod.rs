//! Smart proxy group implementation
//!
//! This module provides an intelligent proxy group that automatically selects
//! the best proxy based on performance metrics, site preferences, traffic
//! patterns, and adaptive learning algorithms.
//!
//! - [`penalty`] - Proxy penalty system for performance tracking
//! - [`stats`] - Statistics collection and performance metrics
//! - [`state`] - Centralized state management

use super::UdpPolicy;
use std::{cmp::Ordering, collections::HashSet, time::Duration};
use super::GroupHandler;
use std::{io, sync::Arc};
use tracing::{debug, info};
use parking_lot::Mutex;

use crate::{
    app::remote_content_manager::{
        ProxyManager, providers::proxy_provider::ArcProxyProvider,
    },
    proxy::{
        OutboundNode, HandlerCommonOptions, OutboundType,
        utils::provider_helper::Providers,
    },
    session::Session,
};

pub mod penalty;
pub mod state;
pub mod stats;

use crate::proxy::group::GroupProxyAPIResponse;
pub use state::SmartState;
use stats::SiteStats;

#[derive(Default, Clone)]
pub struct HandlerOptions {
    /// Common proxy handler options
    pub common_opts: HandlerCommonOptions,
    /// Name of this proxy group
    pub name: String,
    /// Whether UDP is supported
    pub udp: bool,
    /// Maximum retries for failed connections
    pub max_retries: Option<u32>,
    /// Bandwidth consideration weight
    pub bandwidth_weight: Option<f64>,
}

/// Smart proxy group handler
pub struct Handler {
    /// Configuration options
    opts: HandlerOptions,
    /// Proxy providers for obtaining available proxies
    providers: Providers,
    /// Proxy manager for health checks and metrics
    proxy_manager: ProxyManager,
    /// Centralized state management
    smart_state: Arc<Mutex<SmartState>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmartHandler")
            .field("name", &self.opts.name)
            .field("udp", &self.opts.udp)
            .field("max_retries", &self.opts.max_retries)
            .finish()
    }
}

impl Handler {
    #[cfg(feature = "allocation-tests")]
    pub(crate) fn measurement_fixture(proxy_manager: ProxyManager) -> Self {
        Self {
            opts: HandlerOptions::default(),
            providers: Providers::new(Vec::new()),
            proxy_manager,
            smart_state: Arc::new(Mutex::new(SmartState::new())),
        }
    }

    /// Create a new smart proxy group handler with persistence support
    /// Load persisted stats and build the handler.
    ///
    /// This used to be a sync fn that spawned an OS thread, stood up a second
    /// Tokio runtime inside it just to `block_on` the cache read, and then
    /// blocked the calling thread on a rendezvous channel — all while running
    /// on a Tokio worker, with three `expect`s on the way. Every caller is
    /// async, so load the cache with a normal `.await` instead.
    pub async fn new_with_cache(
        opts: HandlerOptions,
        providers: Vec<ArcProxyProvider>,
        proxy_manager: ProxyManager,
        cache_store: crate::app::profile::ThreadSafeCacheFile,
    ) -> Self {
        let group_name = opts.name.clone();

        // Load persisted smart stats from cache
        let stored_data = cache_store.get_smart_stats(&group_name);
        if stored_data.is_some() {
            info!("{} successfully loaded smart stats from cache", group_name);
        } else {
            info!(
                "{} no smart stats found in cache, initializing new state",
                group_name
            );
        }
        let smart_state = SmartState::new_with_imported_data(stored_data);

        let handler = Self {
            opts,
            providers: Providers::new(providers),
            proxy_manager,
            smart_state: Arc::new(Mutex::new(smart_state)),
        };

        // Set up periodic persistence for smart_stats
        let cache_store_clone = cache_store;
        let group_name_clone = group_name;
        let weak_state = Arc::downgrade(&handler.smart_state);

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let Some(state) = weak_state.upgrade() else { break; };
                let data_to_save = { state.lock().export_data() };

                cache_store_clone
                    .set_smart_stats(&group_name_clone, data_to_save);
            }
        });

        handler
    }

    /// Get all available proxies from providers
    ///
    /// # Arguments
    /// * `touch` - Whether to update provider statistics
    ///
    /// # Returns
    /// Vector of available proxy handlers
    fn get_proxies(&self, touch: bool) -> Arc<Vec<OutboundNode>> {
        self.providers.get_proxies(touch)
    }

    /// Smart proxy selection considering all available metrics
    ///
    /// Implements comprehensive proxy selection algorithm that considers:
    /// - Site preferences and stickiness
    /// - Historical performance metrics
    /// - Traffic pattern analysis
    /// - Custom weight configuration
    /// - Penalty scores
    /// - Real-time health status
    ///
    /// # Arguments
    /// * `sess` - Session information for the connection
    ///
    /// # Returns
    /// Selected proxy handler, or None if no suitable proxy available
    async fn pick_smart(
        &self,
        sess: &Session,
        excluded: Option<&HashSet<String>>,
    ) -> Option<OutboundNode> {
        let proxies = self.get_proxies(false);
        if proxies.is_empty() {
            debug!("{} no proxies available", self.name());
            return None;
        }

        let site = sess.destination.host_cow();
        let dest_ip = sess.destination.ip().map(|ip| ip.to_string());

        debug!(
            "{} selecting proxy for site: {}, ip: {:?}",
            self.name(),
            site,
            dest_ip
        );

        let traffic_stats = {
            let mut state = self.smart_state.lock();
            state.cleanup_stale();
            state.get_traffic_stats(sess)
        };
        if traffic_stats.is_some() {
            debug!(
                "{} using traffic pattern analysis for session {}",
                self.name(), SmartState::generate_session_id(sess)
            );
        }
        let site_tuning = self.proxy_manager.get_site_tuning(sess, traffic_stats.as_ref()).await;
        let histories = {
            let state = self.smart_state.lock();
            let summary = |stats: &SiteStats| {
                (
                    stats.get_delay_score(),
                    stats.success_rate(),
                    stats.get_trend(),
                    stats.latency_stability(),
                )
            };
            proxies.iter()
                .filter(|proxy| {
                    !excluded.is_some_and(|names| names.contains(proxy.name()))
                })
                .map(|proxy| {
                    let name = proxy.name();
                    let site_stats = state.get_site_stats(name, &site).map(summary);
                    let ip_stats = dest_ip.as_ref()
                        .and_then(|ip| state.get_site_stats(name, ip))
                        .map(summary);
                    let penalty = state.get_penalty(name)
                        .map_or(0.0, |p| p.value());
                    (proxy.clone(), site_stats, ip_stats, penalty)
                })
                .collect::<Vec<_>>()
        };

        let mut best: Option<(f64, OutboundNode)> = None;

        for (proxy, site_stats, ip_stats, penalty_score) in histories {
            let name = proxy.name();

            // Get basic metrics from proxy manager
            let (alive, last_delay) = self.proxy_manager.alive_and_last_delay(name);
            let delay = if alive { last_delay } else { None }
                .map(|d| d.as_millis_f64())
                .unwrap_or(9999.0);
            let (packet_loss, rtt) = self.proxy_manager.delay_metrics(name)
                .unwrap_or((1.0, 9999.0));

            debug!(
                "{} proxy {} metrics - delay: {:.1}ms, loss: {:.1}%, rtt: {:.1}ms, \
                 alive: {}",
                self.name(),
                name,
                delay,
                packet_loss * 100.0,
                rtt,
                alive
            );

            // Use traffic-aware tuning parameters
            let delay_weight = site_tuning.delay_weight.unwrap_or(1.0);
            let packet_loss_weight =
                site_tuning.packet_loss_weight.unwrap_or(1000.0);
            let rtt_weight = site_tuning.rtt_weight.unwrap_or(1.0);
            let alive_penalty = site_tuning.alive_penalty.unwrap_or(5000.0);
            let bandwidth_weight = self.opts.bandwidth_weight.unwrap_or(0.0);

            debug!(
                "{} using tuning weights - delay: {:.2}, loss: {:.1}, rtt: {:.2}, \
                 alive_penalty: {:.1}, bandwidth: {:.2}",
                self.name(),
                delay_weight,
                packet_loss_weight,
                rtt_weight,
                alive_penalty,
                bandwidth_weight
            );

            if let Some((sd, sr, st, stability)) = site_stats {
                debug!(
                    "{} proxy {} site history - avg delay: {:.1}ms, success rate: \
                     {:.1}%, trend: {}, stability: {:.2}",
                    self.name(),
                    name,
                    sd,
                    sr * 100.0,
                    match st {
                        1 => "improving",
                        -1 => "degrading",
                        _ => "stable",
                    },
                    stability
                );
            }

            if let Some((id, ir, it, stability)) = ip_stats {
                debug!(
                    "{} proxy {} IP history - avg delay: {:.1}ms, success rate: \
                     {:.1}%, trend: {}, stability: {:.2}",
                    self.name(),
                    name,
                    id,
                    ir * 100.0,
                    match it {
                        1 => "improving",
                        -1 => "degrading",
                        _ => "stable",
                    },
                    stability
                );
            }

            debug!(
                "{} proxy {} current penalty score: {:.1}",
                self.name(),
                name,
                penalty_score
            );

            // Calculate comprehensive score with trend consideration
            let site_delay = site_stats
                .map(|(d, r, t, _)| {
                    let trend_multiplier = match t {
                        1 => 0.9,  // Improving trend gets 10% bonus
                        -1 => 1.1, // Degrading trend gets 10% penalty
                        _ => 1.0,  // Stable trend no change
                    };
                    d * (2.0 - r) * trend_multiplier
                })
                .unwrap_or(delay);

            let ip_delay = ip_stats
                .map(|(d, r, t, _)| {
                    let trend_multiplier = match t {
                        1 => 0.9,  // Improving trend gets 10% bonus
                        -1 => 1.1, // Degrading trend gets 10% penalty
                        _ => 1.0,  // Stable trend no change
                    };
                    d * (2.0 - r) * trend_multiplier
                })
                .unwrap_or(delay);

            // Calculate stability penalty factor
            let stability_penalty = site_stats
                .map(|(_, _, _, s)| s * 0.5) // Each point of stability adds 0.5 to score
                .unwrap_or(0.0)
                + ip_stats.map(|(_, _, _, s)| s * 0.5).unwrap_or(0.0);

            let mut base_score = ((site_delay + ip_delay) / 2.0) * delay_weight
                + packet_loss * packet_loss_weight
                + rtt * rtt_weight
                + stability_penalty // Add stability penalty
                + if alive { 0.0 } else { alive_penalty }
                + penalty_score;

            // Apply bandwidth consideration if enabled
            if bandwidth_weight > 0.0 {
                // Simple heuristic: lower delay suggests better bandwidth
                let bandwidth_score = delay * 0.1;
                base_score += bandwidth_score * bandwidth_weight;
            }

            // TODO: custom weight multiplier
            let final_score = base_score;

            debug!(
                "{} proxy {} final score: {:.1}",
                self.name(),
                name,
                final_score
            );

            // Strict comparison preserves provider order for equal scores.
            // Incomparable scores do not displace the current candidate.
            if best.as_ref().is_none_or(|(score, _)| {
                final_score.partial_cmp(score) == Some(Ordering::Less)
            }) {
                best = Some((final_score, proxy));
            }
        }

        let (_, selected_proxy) = best?;
        debug!("{} selected proxy: {}", self.name(), selected_proxy.name());
        Some(selected_proxy)
    }

    /// Calculate optimal retry count based on site history
    fn calculate_max_retries(&self, state: &SmartState, site: &str) -> u32 {
        if let Some(max) = self.opts.max_retries.filter(|max| *max > 0) {
            return max;
        }

        let (total, count) = state.site_stats.values()
            .filter_map(|stats| stats.get(site))
            .fold((0.0, 0usize), |(total, count), stats| {
                (total + stats.success_rate(), count + 1)
            });
        let avg_success_rate = if count > 0 { total / count as f64 } else { 0.5 };

        (3.0 * (2.0 - avg_success_rate)).round().clamp(2.0, 6.0) as u32
    }
}

impl GroupHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Smart
    }

    fn udp_policy(&self) -> UdpPolicy {
        if self.opts.udp { UdpPolicy::Enabled } else { UdpPolicy::Disabled }
    }

    async fn select(
        &self,
        sess: &Session,
        excluded: &HashSet<String>,
    ) -> io::Result<Option<OutboundNode>> {
        Ok(self.pick_smart(sess, Some(excluded)).await)
    }

    async fn attempts(&self, sess: &Session) -> u32 {
        let mut state = self.smart_state.lock();
        state.start_traffic_tracking(sess);
        state.record_request(sess);
        self.calculate_max_retries(&state, sess.destination.host_cow().as_ref())
    }

    fn retry_delay(&self, attempt: u32) -> Duration {
        let delay = 100u64 << attempt.saturating_sub(1).min(6);
        Duration::from_millis(delay.min(5000))
    }

    async fn record_result(
        &self,
        sess: &Session,
        proxy: &str,
        elapsed: Duration,
        success: bool,
    ) {
        let mut state = self.smart_state.lock();
        let site = sess.destination.host_cow();
        let ip = sess.destination.ip().map(|ip| ip.to_string());
        let delay = if success { elapsed.as_secs_f64() * 1000.0 } else { 9999.0 };
        state.record_connection_result(proxy, &site, ip.as_deref(), delay, success);
        if success {
            state.record_traffic(sess, 500, 500);
        } else {
            state.record_request(sess);
        }
    }
}

impl GroupProxyAPIResponse for Handler {
    async fn get_proxies(&self) -> Vec<OutboundNode> {
        Handler::get_proxies(self, false).to_vec()
    }

    async fn get_active_proxy(&self) -> Option<OutboundNode> {
        None
    }

    fn get_latency_test_url(&self) -> Option<String> {
        self.opts.common_opts.url.clone()
    }

    fn icon(&self) -> Option<String> {
        self.opts.common_opts.icon.clone()
    }
}

#[cfg(test)]
mod unit_tests {
    use crate::proxy::AnyStream;
    use super::*;
    use crate::proxy::{
        mocks::{MockDummyOutboundHandler, MockDummyProxyProvider},
        utils::test_utils::noop::NoopResolver,
    };

    #[tokio::test]
    async fn selection_preserves_score_order_ties_and_exclusions() {
        let proxies = Arc::new(["slow", "first-fast", "second-fast"].map(|name| {
            let mut proxy = MockDummyOutboundHandler::new();
            proxy.expect_name().return_const(name.to_owned());
            OutboundNode::protocol(Arc::new(proxy))
        }).to_vec());
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_proxies().returning(move || proxies.clone());
        let manager = ProxyManager::new(Arc::new(NoopResolver), None);
        for (name, delay) in [("slow", 100), ("first-fast", 10), ("second-fast", 10)] {
            manager.report_delay(name, true, Duration::from_millis(delay)).await;
        }
        let mut handler = Handler {
            opts: HandlerOptions::default(),
            providers: Providers::new(vec![Arc::new(provider)]),
            proxy_manager: manager,
            smart_state: Arc::new(Mutex::new(SmartState::new())),
        };
        let sess = Session::default();
        let mut excluded = HashSet::new();
        assert_eq!(handler.select(&sess, &excluded).await.unwrap().unwrap().name(), "first-fast");
        excluded.insert("first-fast".to_owned());
        assert_eq!(handler.select(&sess, &excluded).await.unwrap().unwrap().name(), "second-fast");
        excluded.insert("second-fast".to_owned());
        assert_eq!(handler.select(&sess, &excluded).await.unwrap().unwrap().name(), "slow");
        excluded.insert("slow".to_owned());
        assert!(handler.select(&sess, &excluded).await.unwrap().is_none());
        excluded.clear();
        // Equal infinite scores also preserve provider order.
        handler.opts.bandwidth_weight = Some(f64::INFINITY);
        assert_eq!(handler.select(&sess, &excluded).await.unwrap().unwrap().name(), "slow");
    }

    #[tokio::test]
    async fn result_history_controls_adaptive_retry_budget() {
        let handler = Handler {
            opts: HandlerOptions::default(),
            providers: Providers::new(Vec::new()),
            proxy_manager: ProxyManager::new(Arc::new(NoopResolver), None),
            smart_state: Arc::new(Mutex::new(SmartState::new())),
        };
        let sess = Session::default();
        assert_eq!(handler.attempts(&sess).await, 5);
        handler.record_result(&sess, "healthy", Duration::from_millis(10), true).await;
        assert_eq!(handler.attempts(&sess).await, 3);
        handler.record_result(&sess, "broken", Duration::ZERO, false).await;
        assert_eq!(handler.attempts(&sess).await, 5);
        let state = handler.smart_state.lock();
        let site = sess.destination.host_cow();
        assert_eq!(state.get_site_stats("healthy", &site).unwrap().success_rate(), 1.0);
        assert_eq!(state.get_site_stats("broken", &site).unwrap().success_rate(), 0.0);
        assert!(state.get_penalty("broken").unwrap().value() > 0.0);
    }

    #[tokio::test]
    async fn retry_tries_another_member_after_a_connection_failure() {
        let mut failing = MockDummyOutboundHandler::new();
        failing.expect_name().return_const("fast-but-broken".to_owned());
        failing.expect_connect_stream().returning(|_, _| {
            Err(io::Error::other("connection failed"))
        });

        let mut working = MockDummyOutboundHandler::new();
        working.expect_name().return_const("slower-but-working".to_owned());
        working.expect_connect_stream().returning(|_, _| {
            let (stream, _peer) = tokio::io::duplex(64);
            Ok(AnyStream::new(stream))
        });

        let proxies: Arc<Vec<OutboundNode>> = Arc::new(vec![
            OutboundNode::protocol(Arc::new(failing)),
            OutboundNode::protocol(Arc::new(working)),
        ]);
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_proxies().returning(move || proxies.clone());

        let resolver = Arc::new(NoopResolver);
        let manager = ProxyManager::new(resolver.clone(), None);
        manager
            .report_delay("fast-but-broken", true, std::time::Duration::from_millis(1))
            .await;
        manager
            .report_delay("slower-but-working", true, std::time::Duration::from_secs(60))
            .await;

        let handler = Handler {
            opts: HandlerOptions {
                name: "smart".to_owned(),
                max_retries: Some(2),
                ..Default::default()
            },
            providers: Providers::new(vec![Arc::new(provider)]),
            proxy_manager: manager,
            smart_state: Arc::new(Mutex::new(SmartState::new())),
        };
        let sess = Session::default();
        OutboundNode::group(Arc::new(handler)).connect_stream(&sess, resolver).await.unwrap();
        assert!(sess.proxy_chain.snapshot().contains(&"smart".to_owned()));
    }
}

#[cfg(feature = "shadowsocks")]
#[cfg(all(test, docker_test))]
mod tests {
    use super::*;
    use crate::{
        SystemResolver,
        profile::ThreadSafeCacheFile,
        proxy::{
            mocks::MockDummyProxyProvider,
            utils::test_utils::{
                Suite,
                consts::*,
                docker_runner::{
                    DockerTestRunner, DockerTestRunnerBuilder, alloc_docker_port,
                },
                run_test_suites_and_cleanup,
            },
        },
        tests::initialize,
    };
    use tempfile::tempdir;

    // Constants for the mock Shadowsocks server
    const PASSWORD: &str = "FzcLbKs2dY9mhL_smart";
    const CIPHER: &str = "aes-256-gcm";

    // Helper function to get a Shadowsocks Docker runner
    async fn get_ss_runner(port: u16) -> anyhow::Result<DockerTestRunner> {
        let host = format!("0.0.0.0:{}", port);
        DockerTestRunnerBuilder::new()
            .image(IMAGE_SS_RUST)
            .port(port)
            .entrypoint(&["ssserver"])
            .cmd(&["-s", &host, "-m", CIPHER, "-k", PASSWORD, "-U"])
            .build()
            .await
    }

    #[tokio::test]
    async fn test_smart_group_smoke() -> anyhow::Result<()> {
        initialize();
        let ss_port = alloc_docker_port();

        let docker_runner = get_ss_runner(ss_port).await?;

        let ss_opts = crate::proxy::shadowsocks::outbound::HandlerOptions {
            name: "test-ss-for-smart".to_owned(),
            common_opts: Default::default(),
            server: docker_runner
                .container_ip()
                .unwrap_or(LOCAL_ADDR.to_owned()),
            port: ss_port,
            password: PASSWORD.to_owned(),
            cipher: CIPHER.to_owned(),
            plugin: Default::default(),
            udp: true,
        };
        let ss_handler: OutboundNode =
            OutboundNode::protocol(Arc::new(crate::proxy::shadowsocks::outbound::Handler::new(ss_opts, None)));

        let mut provider = MockDummyProxyProvider::new();
        provider.expect_touch().returning(|| ());
        provider.expect_healthcheck().returning(|| ());
        provider
            .expect_proxies()
            .returning(move || Arc::new(vec![ss_handler.clone()]));
        let thread_safe_provider: ArcProxyProvider = Arc::new(provider);

        // Setup HandlerOptions for Smart group
        let smart_opts = super::HandlerOptions {
            common_opts: Default::default(),
            name: "test-smart-group".to_string(),
            udp: true,
            max_retries: Some(3),
            bandwidth_weight: Some(0.1),
        };

        let temp_dir_hdl = tempdir()?;
        let cache_path = temp_dir_hdl.path().join("smart_test_cache.db");
        let cache_store = ThreadSafeCacheFile::new(
            cache_path.to_str().expect("Cache path is not valid UTF-8"),
            false,
        )?;

        let resolver = SystemResolver::new(false).map_err(|e| {
            anyhow::anyhow!("Failed to create system resolver: {}", e)
        })?;
        let thread_safe_resolver = Arc::new(resolver);

        let proxy_manager = ProxyManager::new(thread_safe_resolver.clone(), None);

        let smart_handler_instance = super::Handler::new_with_cache(
            smart_opts,
            vec![thread_safe_provider],
            proxy_manager,
            cache_store,
        )
        .await;
        let any_smart_handler: OutboundNode = OutboundNode::group(Arc::new(smart_handler_instance));

        run_test_suites_and_cleanup(any_smart_handler, docker_runner, Suite::all())
            .await
    }
}
