//! Adapt syscall batch size to observed packet pressure, not elapsed time or
//! an assumed payload size. The maximum matches the native message array.
use super::MAX_GRO_PACKETS;
pub(in crate::proxy::direct) struct ReceiveBudget { packets: usize }
impl Default for ReceiveBudget {
    fn default() -> Self { Self { packets: 8 } }
}
impl ReceiveBudget {
    pub fn limit(&self) -> usize { self.packets }
    pub fn observe(&mut self, requested: usize, count: usize) {
        if count == requested { self.packets = (self.packets * 2).min(MAX_GRO_PACKETS); }
        else if count * 2 < requested { self.packets = (self.packets / 2).max(8); }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_batches_expand_and_sparse_batches_reduce_requested_messages() {
        let mut budget = ReceiveBudget::default();
        assert_eq!(budget.limit(), 8);
        for _ in 0..8 { let n = budget.limit(); budget.observe(n, n); }
        assert_eq!(budget.limit(), MAX_GRO_PACKETS);
        budget.observe(MAX_GRO_PACKETS, 1);
        assert_eq!(budget.limit(), MAX_GRO_PACKETS / 2);
        budget.observe(budget.limit(), 0);
        assert_eq!(budget.limit(), 8);
        budget.observe(8, 8);
        assert_eq!(budget.limit(), 16);
    }
}
