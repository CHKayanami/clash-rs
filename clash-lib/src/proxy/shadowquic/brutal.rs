/*
Adapted from ShadowQUIC.

MIT License

Copyright (c) 2025 spongebob888

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

use std::any::Any;
use std::sync::Arc;
use std::time::Instant;

use brutal_core::{BrutalConfigCore, BrutalCore};
use quinn_jls::congestion::{Controller, ControllerFactory};
use quinn_proto_jls::RttEstimator;
use super::config::BrutalParams;

#[derive(Debug)]
pub(super) struct BrutalConfig(BrutalConfigCore);

impl BrutalConfig {
    pub fn new(params: &BrutalParams) -> Self {
        Self(BrutalConfigCore::new(
            params.bandwidth,
            params.min_window,
            params.cwnd_gain,
            params.min_ack_rate,
            params.min_sample_count,
            params.ack_compensate,
        ))
    }
}

impl ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Brutal(BrutalCore::new(self.0.clone(), now, current_mtu)))
    }
}

#[derive(Debug, Clone)]
struct Brutal(BrutalCore);

impl Controller for Brutal {
    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }

    fn initial_window(&self) -> u64 {
        self.0.initial_window()
    }

    fn window(&self) -> u64 {
        self.0.window_cached()
    }

    fn on_sent(&mut self, _now: Instant, bytes: u64, _last_packet_number: u64) {
        self.0.on_sent(bytes);
    }

    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.0.on_ack_bytes(bytes, rtt.get());
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        _in_flight: u64,
        _app_limited: bool,
        _largest_packet_num_acked: Option<u64>,
    ) {
        self.0.on_end_acks(now);
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _is_ecn: bool,
        lost_bytes: u64,
    ) {
        self.0.on_loss_bytes(lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.0.on_mtu_update(new_mtu);
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }
}
