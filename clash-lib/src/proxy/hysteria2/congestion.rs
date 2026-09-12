use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use quinn_proto::congestion::{
    Controller, ControllerFactory, ControllerMetrics,
};

#[cfg(test)]
const INITIAL_PACKET_SIZE_IPV4: u16 = 1252;
const INITIAL_RTT: Duration = Duration::from_millis(333);

/// Brutal 拥塞控制配置工厂（对齐 honk 与 quinn ControllerFactory 范式）
#[derive(Debug, Clone)]
pub struct BrutalConfig {
    /// 目标发送速率（字节/秒）
    bytes_per_second: u64,
}

impl BrutalConfig {
    pub fn new(bytes_per_second: u64) -> Self {
        Self { bytes_per_second }
    }
}

impl ControllerFactory for BrutalConfig {
    fn build(
        self: Arc<Self>,
        _now: Instant,
        current_mtu: u16,
    ) -> Box<dyn Controller> {
        Box::new(Brutal {
            rate: self.bytes_per_second,
            rtt: INITIAL_RTT,
            mtu: current_mtu,
        })
    }
}

/// Brutal 恒定速率发送端（完全无锁实现）
///
/// quinn 的令牌桶 Pacer 以 `window / RTT` 速率补充令牌。
/// 通过将拥塞窗口设置为 `rate × RTT`（即 BDP），并显式在 `metrics().pacing_rate` 中报告目标速率，
/// 即可让 quinn 内置的 Pacer 以恒定速率平滑发包，且在发生网络丢包或拥塞事件时不降速。
pub struct Brutal {
    /// 目标发送速率（字节/秒）
    rate: u64,
    /// 最新平滑 RTT 估计（初始使用 RFC 9002 规范的 333ms）
    rtt: Duration,
    /// 最大报文大小（MTU）
    mtu: u16,
}

impl Brutal {
    /// 构造 Brutal 控制器，`rate_bytes_per_sec` 为字节/秒
    #[cfg(test)]
    pub fn new(rate_bytes_per_sec: u64) -> Self {
        Self {
            rate: rate_bytes_per_sec,
            rtt: INITIAL_RTT,
            mtu: INITIAL_PACKET_SIZE_IPV4,
        }
    }

    /// 带宽时延积（Bandwidth-Delay Product），以微秒精度计算避免溢出与精度丢失
    pub fn bdp(&self) -> u64 {
        (u128::from(self.rate).saturating_mul(self.rtt.as_micros()) / 1_000_000)
            .min(u128::from(u64::MAX)) as u64
    }
}

impl Controller for Brutal {
    fn initial_window(&self) -> u64 {
        10 * u64::from(self.mtu)
    }

    fn window(&self) -> u64 {
        self.bdp().max(self.initial_window())
    }

    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &quinn_proto::RttEstimator,
    ) {
        self.rtt = rtt.get();
    }

    /// Brutal 核心语义：忽略网络拥塞和丢包事件，不降低发送速率
    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
    }

    fn metrics(&self) -> ControllerMetrics {
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.window();
        metrics.pacing_rate = Some(self.rate.saturating_mul(8));
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Brutal {
            rate: self.rate,
            rtt: self.rtt,
            mtu: self.mtu,
        })
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_brutal_bdp_calculation() {
        // 100 Mbps = 12,500,000 Bytes/s
        let rate = 12_500_000;
        let mut brutal = Brutal::new(rate);

        // 初始 RTT = 333ms
        // BDP = 12_500_000 * 0.333 = 4_162_500
        assert_eq!(brutal.bdp(), 4_162_500);
        assert_eq!(brutal.window(), 4_162_500);

        // 设置 RTT 为 50ms = 50,000us
        // BDP = 12_500_000 * 0.05 = 625_000
        brutal.rtt = Duration::from_millis(50);
        assert_eq!(brutal.bdp(), 625_000);
        assert_eq!(brutal.window(), 625_000);

        // 极低 RTT (如 1ms) 时，窗口保底为 initial_window (10 * 1252 = 12520)
        brutal.rtt = Duration::from_micros(500);
        assert_eq!(brutal.bdp(), 6250);
        assert_eq!(brutal.window(), 12520);
    }

    #[test]
    fn test_brutal_metrics() {
        let rate = 12_500_000; // 100 Mbps in Bytes/s
        let brutal = Brutal::new(rate);
        let metrics = brutal.metrics();

        assert_eq!(metrics.congestion_window, brutal.window());
        // 目标 pacing_rate 必须为 100,000,000 bps
        assert_eq!(metrics.pacing_rate, Some(100_000_000));
    }

    #[test]
    fn test_brutal_congestion_event_ignored() {
        let rate = 12_500_000;
        let mut brutal = Brutal::new(rate);
        let win_before = brutal.window();

        // 模拟丢包拥塞事件，窗口不得减小
        brutal.on_congestion_event(Instant::now(), Instant::now(), false, 65535);
        assert_eq!(brutal.window(), win_before);
    }

    #[test]
    fn test_brutal_config_factory() {
        let config = Arc::new(BrutalConfig::new(12_500_000));
        let controller = config.build(Instant::now(), 1400);

        assert_eq!(controller.initial_window(), 14000);
        let metrics = controller.metrics();
        assert_eq!(metrics.pacing_rate, Some(100_000_000));
    }
}

