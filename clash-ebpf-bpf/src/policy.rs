use aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_REDIRECT};
use clash_ebpf_common::{RedirectEntry, UdpReplyEntry};
use network_types::ip::Ipv4Hdr;

#[inline(always)]
pub fn tcp_socket_policy_update(verdict: i32) -> Option<u32> {
    match verdict {
        TC_ACT_OK => Some(3),
        TC_ACT_REDIRECT => Some(2),
        // A dropped packet leaves the socket decision available for retransmission.
        _ => None,
    }
}

pub const UDP_CONN_TIMEOUT_NS: u64 = 120_000_000_000;

/// network-types exposes host-order flags and offset separately.
#[inline(always)]
pub fn ipv4_is_fragment(iph: &Ipv4Hdr) -> bool {
    iph.frag_flags() & 1 != 0 || iph.frag_offset() != 0
}

pub const REDIRECT_REFRESH_NS: u64 = 1_000_000_000;

#[inline(always)]
pub fn udp_reply_expired(last_seen_ns: u64, now: u64) -> bool {
    now.saturating_sub(last_seen_ns) > UDP_CONN_TIMEOUT_NS + REDIRECT_REFRESH_NS
}

#[inline(always)]
pub fn udp_reply_refresh_due(last_seen_ns: u64, now: u64) -> bool {
    now.saturating_sub(last_seen_ns) >= REDIRECT_REFRESH_NS
}

#[inline(always)]
pub fn udp_reply_route(entry: &UdpReplyEntry, now: u64) -> Option<RedirectEntry> {
    if udp_reply_expired(entry.last_seen_ns, now) { None }
    else { Some(entry.route) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aya_ebpf::bindings::TC_ACT_SHOT;
    use clash_ebpf_common::{RedirectTuple, UdpReplyKey};

    #[test]
    fn tcp_socket_policy_is_only_cached_for_pass_or_redirect() {
        assert_eq!(tcp_socket_policy_update(TC_ACT_SHOT), None);
        assert_eq!(tcp_socket_policy_update(TC_ACT_OK), Some(3));
        assert_eq!(tcp_socket_policy_update(TC_ACT_REDIRECT), Some(2));
    }

    #[test]
    fn udp_return_key_ignores_remote_but_preserves_client_socket_and_family() {
        let mut first = RedirectTuple { src_ip: [1; 16], src_port: 1234,
            dst_ip: [2; 16], dst_port: 3478, proto: 17, ip_version: 4,
            ..Default::default() };
        let key = UdpReplyKey::from_request(&first);
        first.dst_port += 1;
        assert_eq!(key, UdpReplyKey::from_request(&first));
        first.dst_ip = [3; 16];
        assert_eq!(key, UdpReplyKey::from_request(&first));
        first.src_port += 1;
        assert_ne!(key, UdpReplyKey::from_request(&first));
        first.src_port -= 1; first.ip_version = 6;
        assert_ne!(key, UdpReplyKey::from_request(&first));
        first.ip_version = 4; first.src_ip = [4; 16];
        assert_ne!(key, UdpReplyKey::from_request(&first));
        assert_eq!(core::mem::size_of::<UdpReplyKey>(), 24);
        assert_eq!(core::mem::size_of::<UdpReplyEntry>(), 40);
    }

    #[test]
    fn udp_reply_refresh_is_due_at_the_refresh_interval() {
        let last_seen = 10;
        let boundary = last_seen + REDIRECT_REFRESH_NS;
        assert!(!udp_reply_refresh_due(last_seen, boundary - 1));
        assert!(udp_reply_refresh_due(last_seen, boundary));
    }

    #[test]
    fn udp_reply_route_expires_after_the_timeout_and_refresh_interval() {
        let entry = UdpReplyEntry { last_seen_ns: 10, ..Default::default() };
        let boundary = entry.last_seen_ns + UDP_CONN_TIMEOUT_NS + REDIRECT_REFRESH_NS;
        assert_eq!(udp_reply_route(&entry, boundary), Some(entry.route));
        assert_eq!(udp_reply_route(&entry, boundary + 1), None);
    }

    #[test]
    fn stale_packet_timestamps_cannot_expire_or_rewind_a_newer_route() {
        let last_seen = 2 * REDIRECT_REFRESH_NS;
        assert!(!udp_reply_expired(last_seen, REDIRECT_REFRESH_NS));
        assert!(!udp_reply_refresh_due(last_seen, REDIRECT_REFRESH_NS));
    }

    #[test]
    fn ipv4_fragment_detection_covers_all_offsets_and_flags() {
        let mut iph: Ipv4Hdr = unsafe { core::mem::zeroed() };
        // MF requires bypass even on the first fragment. DF alone does not.
        for flags in 0..8 {
            for offset in 0..=0x1fff {
                iph.set_frags(flags, offset);
                assert_eq!(
                    ipv4_is_fragment(&iph),
                    flags & 1 != 0 || offset != 0,
                    "flags={flags}, offset={offset}"
                );
            }
        }
    }

}
