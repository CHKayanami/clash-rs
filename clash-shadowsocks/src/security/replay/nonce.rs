use std::{
    collections::{HashSet, VecDeque},
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const CAPACITY: usize = 16_384;
const RETENTION: Duration = Duration::from_secs(60);

#[derive(Default)]
pub(super) struct Nonces(Mutex<NonceSet>);

#[derive(Default)]
struct NonceSet {
    salts: HashSet<Arc<[u8]>>,
    expiry: VecDeque<(Instant, Arc<[u8]>)>,
}

impl Nonces {
    pub(super) fn check_and_set(&self, nonce: &[u8]) -> io::Result<()> {
        self.0.lock().expect("nonce cache lock poisoned")
            .insert(nonce, Instant::now(), CAPACITY)
    }
}

impl NonceSet {
    fn insert(&mut self, nonce: &[u8], now: Instant, capacity: usize) -> io::Result<()> {
        while self.expiry.front().is_some_and(|(expiry, _)| *expiry <= now) {
            let (_, salt) = self.expiry.pop_front().expect("expired salt");
            self.salts.remove(&salt);
        }
        if self.salts.contains(nonce) {
            return Err(io::Error::other("detected repeated nonce (iv/salt)"));
        }
        if self.salts.len() >= capacity {
            return Err(io::Error::other("nonce replay cache capacity exhausted"));
        }
        let salt: Arc<[u8]> = Arc::from(nonce);
        self.salts.insert(salt.clone());
        self.expiry.push_back((now + RETENTION, salt));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saturation_preserves_live_salts_until_retention_expires() {
        let mut set = NonceSet::default();
        let now = Instant::now();
        assert!(set.insert(b"first", now, 2).is_ok());
        assert!(set.insert(b"second", now, 2).is_ok());
        assert!(set.insert(b"third", now + RETENTION / 2, 2).is_err());
        assert!(set.insert(b"first", now + RETENTION / 2, 2).is_err());
        assert!(set.insert(b"third", now + RETENTION, 2).is_ok());
        assert!(set.insert(b"first", now + RETENTION, 2).is_ok());
    }
}
