use clash_ebpf_common::{RedirectEntry, UdpReplyEntry};
use network_types::ip::Ipv4Hdr;

pub const UDP_CONN_TIMEOUT_NS: u64 = 120_000_000_000;

/// network-types exposes host-order flags and offset separately.
#[inline(always)]
pub fn ipv4_is_fragment(iph: &Ipv4Hdr) -> bool {
    iph.frag_flags() & 1 != 0 || iph.frag_offset() != 0
}

pub const REDIRECT_REFRESH_NS: u64 = 1_000_000_000;

#[inline(always)]
pub fn udp_reply_expired(entry: &UdpReplyEntry, now: u64) -> bool {
    now.saturating_sub(entry.last_seen_ns)
        > UDP_CONN_TIMEOUT_NS + REDIRECT_REFRESH_NS
}

/// Separate packet routing metadata from per-target conntrack decisions.
#[inline(always)]
pub fn udp_reply_update(old: Option<&UdpReplyEntry>, route: RedirectEntry,
    now: u64,
) -> Option<UdpReplyEntry> {
    let mut out = UdpReplyEntry::default();
    udp_reply_update_into(old, route, now, &mut out).then_some(out)
}

#[inline(always)]
pub fn udp_reply_update_into(old: Option<&UdpReplyEntry>, route: RedirectEntry,
    now: u64, out: &mut UdpReplyEntry,
) -> bool {
    // Keep this update from rewinding the timestamp it observed.
    let now = old.map_or(now, |old| now.max(old.last_seen_ns));
    let mut new = UdpReplyEntry { last_seen_ns: now, route, ambiguous: 0, _pad: [0; 3] };
    if let Some(old) = old.filter(|old| !udp_reply_expired(old, now)) {
        new.ambiguous = old.ambiguous;
        if old.route.ifindex != route.ifindex || old.route.from_wan != route.from_wan {
            // A reply has no original ingress interface to disambiguate this.
            new.ambiguous = 1;
        }
        if new.ambiguous == old.ambiguous
            && old.route == route
            && now.saturating_sub(old.last_seen_ns) < REDIRECT_REFRESH_NS {
            return false;
        }
    }
    *out = new;
    true
}

#[inline(always)]
pub fn udp_reply_route(entry: &UdpReplyEntry, now: u64) -> Option<RedirectEntry> {
    if entry.ambiguous != 0 || udp_reply_expired(entry, now) { None }
    else { Some(entry.route) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clash_ebpf_common::{RedirectTuple, UdpReplyKey};

    #[test]
    fn udp_return_key_is_independent_of_peer_and_preserves_client_and_family() {
        let mut first = RedirectTuple { src_ip: [1; 16], src_port: 1234,
            dst_ip: [2; 16], dst_port: 3478, proto: 17, ip_version: 4,
            ..Default::default() };
        let key = UdpReplyKey::from_request(&first);
        first.dst_ip = [3; 16]; first.dst_port = 3479;
        assert_eq!(key, UdpReplyKey::from_request(&first));
        first.src_port += 1;
        assert_ne!(key, UdpReplyKey::from_request(&first));
        first.src_port -= 1; first.ip_version = 6;
        assert_ne!(key, UdpReplyKey::from_request(&first));
        first.ip_version = 4; first.src_ip = [4; 16];
        assert_ne!(key, UdpReplyKey::from_request(&first));
        assert_eq!(core::mem::size_of::<UdpReplyKey>(), 24);
        assert_eq!(core::mem::size_of::<UdpReplyEntry>(), 32);
    }

    #[test]
    fn udp_reply_activity_refreshes_client_route_without_a_target_flow() {
        for from_wan in [0, 1] {
            let route = RedirectEntry { ifindex: 3, from_wan, smac: [1; 6],
                dmac: [2; 6], ..Default::default() };
            let mut entry = udp_reply_update(None, route, 10).unwrap();
            assert_eq!(udp_reply_route(&entry, 11), Some(entry.route));
            assert!(udp_reply_update(Some(&entry), route, 11).is_none());
            // Replies keep the association route alive beyond its original age.
            for i in 1..=3 {
                let now = 10 + i * UDP_CONN_TIMEOUT_NS;
                let current = udp_reply_route(&entry, now).unwrap();
                entry = udp_reply_update(Some(&entry), current, now).unwrap();
            }
            assert!(udp_reply_route(&entry,
                entry.last_seen_ns + UDP_CONN_TIMEOUT_NS + REDIRECT_REFRESH_NS + 1).is_none());
        }
    }

    #[test]
    fn conflicting_client_routes_disable_only_the_fallback_until_expiration() {
        let route = RedirectEntry { ifindex: 3, from_wan: 1, ..Default::default() };
        for conflicting in [RedirectEntry { ifindex: 4, ..route },
            RedirectEntry { from_wan: 0, ..route }] {
            let first = udp_reply_update(None, route, 10).unwrap();
            let conflict = udp_reply_update(Some(&first), conflicting, 11).unwrap();
            assert!(udp_reply_route(&conflict, 12).is_none());
            let now = 11 + UDP_CONN_TIMEOUT_NS + REDIRECT_REFRESH_NS + 1;
            let replacement = udp_reply_update(Some(&conflict), route, now).unwrap();
            assert_eq!(udp_reply_route(&replacement, now), Some(replacement.route));
        }
    }

    #[test]
    fn stale_packet_timestamps_cannot_expire_or_rewind_a_newer_route() {
        let route = RedirectEntry { ifindex: 3, from_wan: 1, ..Default::default() };
        let current = udp_reply_update(None, route, 2 * REDIRECT_REFRESH_NS).unwrap();
        assert!(udp_reply_route(&current, REDIRECT_REFRESH_NS).is_some());
        assert!(udp_reply_update(Some(&current), route, REDIRECT_REFRESH_NS).is_none());
        let conflict = udp_reply_update(Some(&current), RedirectEntry { ifindex: 4, ..route },
            REDIRECT_REFRESH_NS).unwrap();
        assert_eq!(conflict.ambiguous, 1);
        assert_eq!(conflict.last_seen_ns, current.last_seen_ns);
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
