use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use shadowsocks::security::replay::PacketWindow;

// A valid SS2022 timestamp can be 30 seconds in the future and is accepted
// until 30 seconds afterwards. Keep windows longer than that entire interval
// so expiring one cannot make an old authenticated packet valid again.
const SESSION_TTL: Duration = Duration::from_secs(120);
const MAX_SERVER_SESSIONS: usize = 64;

#[derive(Default)]
pub(super) struct ServerSessions {
    windows: HashMap<u64, (PacketWindow, Instant)>,
}

impl ServerSessions {
    pub(super) fn check_and_set(
        &mut self,
        session_id: u64,
        packet_id: u64,
        now: Instant,
    ) -> bool {
        if self.windows.len() >= MAX_SERVER_SESSIONS
            && !self.windows.contains_key(&session_id)
        {
            self.windows.retain(|_, (_, last_seen)| {
                now.duration_since(*last_seen) < SESSION_TTL
            });
            // Do not evict live windows: that would allow replays simply
            // by alternating enough authenticated server sessions.
            if self.windows.len() >= MAX_SERVER_SESSIONS {
                return true;
            }
        }
        let (window, last_seen) = self.windows
            .entry(session_id)
            .or_insert_with(|| (PacketWindow::new(), now));
        if window.check_and_set(packet_id) {
            return true;
        }
        *last_seen = now;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alternating_sessions_preserve_replay_windows() {
        let mut sessions = ServerSessions::default();
        let now = Instant::now();
        assert!(!sessions.check_and_set(1, 10, now));
        assert!(!sessions.check_and_set(2, 10, now));
        for _ in 0..4 {
            assert!(sessions.check_and_set(1, 10, now));
            assert!(sessions.check_and_set(2, 10, now));
        }
        assert!(!sessions.check_and_set(1, 9, now));
        assert!(!sessions.check_and_set(2, 11, now));
    }

    #[test]
    fn session_limit_retains_live_windows_and_reclaims_expired_ones() {
        let mut sessions = ServerSessions::default();
        let now = Instant::now();
        for id in 0..MAX_SERVER_SESSIONS as u64 {
            assert!(!sessions.check_and_set(id, 0, now));
        }
        assert!(sessions.check_and_set(100, 0, now));
        assert!(sessions.check_and_set(0, 0, now));
        let later = now + SESSION_TTL;
        assert!(!sessions.check_and_set(0, 1, later));
        assert!(!sessions.check_and_set(100, 0, later));
        assert!(sessions.check_and_set(0, 1, later));
        assert_eq!(sessions.windows.len(), 2);
    }
}
