use clash_ebpf_common::RedirectEntry;
use network_types::ip::Ipv4Hdr;

pub const UDP_CONN_TIMEOUT_NS: u64 = 120_000_000_000;

/// network-types exposes host-order flags and offset separately.
#[inline(always)]
pub fn ipv4_is_fragment(iph: &Ipv4Hdr) -> bool {
    iph.frag_flags() & 1 != 0 || iph.frag_offset() != 0
}

pub const REDIRECT_REFRESH_NS: u64 = 1_000_000_000;

/// Update complete values atomically only when metadata or UDP age changes.
#[inline(always)]
pub fn redirect_entry_needs_update(
    old: Option<&RedirectEntry>,
    new: &RedirectEntry,
    is_udp: bool,
    now: u64,
) -> bool {
    let Some(old) = old else {
        return true;
    };
    old.ifindex != new.ifindex
        || old.from_wan != new.from_wan
        || old.smac != new.smac
        || old.dmac != new.dmac
        || (is_udp && now.wrapping_sub(old.last_seen_ns) >= REDIRECT_REFRESH_NS)
}

#[derive(Debug, PartialEq, Eq)]
pub enum RedirectTrackingAction {
    Reset,
    Expired,
    Redirect,
    Untracked,
}

/// Preserve the proxy decision for an active flow, but allow a reused tuple
/// to be classified again on a new TCP SYN or after UDP inactivity.
#[inline(always)]
pub fn redirect_tracking_action(
    entry: Option<&RedirectEntry>,
    is_udp: bool,
    is_pure_syn: bool,
    now: u64,
) -> RedirectTrackingAction {
    if is_pure_syn {
        return RedirectTrackingAction::Reset;
    }
    match entry {
        Some(entry)
            if is_udp
                && now.wrapping_sub(entry.last_seen_ns)
                    > UDP_CONN_TIMEOUT_NS + REDIRECT_REFRESH_NS =>
        {
            RedirectTrackingAction::Expired
        }
        Some(_) => RedirectTrackingAction::Redirect,
        None => RedirectTrackingAction::Untracked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_refresh_preserves_metadata_and_limits_udp_writes() {
        let old = RedirectEntry {
            last_seen_ns: 10,
            ..Default::default()
        };
        let mut new = old;
        assert!(redirect_entry_needs_update(None, &new, false, 0));
        assert!(!redirect_entry_needs_update(
            Some(&old),
            &new,
            false,
            u64::MAX
        ));
        assert!(!redirect_entry_needs_update(Some(&old), &new, true, 11));
        assert!(redirect_entry_needs_update(
            Some(&old),
            &new,
            true,
            10 + REDIRECT_REFRESH_NS
        ));
        new.ifindex = 3;
        assert!(redirect_entry_needs_update(Some(&old), &new, false, 0));
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

    #[test]
    fn existing_proxy_flow_survives_until_a_new_syn() {
        let entry = RedirectEntry {
            last_seen_ns: 1,
            ..RedirectEntry::default()
        };
        assert_eq!(
            redirect_tracking_action(Some(&entry), false, false, u64::MAX),
            RedirectTrackingAction::Redirect
        );
        assert_eq!(
            redirect_tracking_action(Some(&entry), false, true, 2),
            RedirectTrackingAction::Reset
        );
        // A direct-only old flow must also be reset, with no redirect entry.
        assert_eq!(
            redirect_tracking_action(None, false, true, 2),
            RedirectTrackingAction::Reset
        );
        assert_eq!(
            redirect_tracking_action(None, false, false, 3),
            RedirectTrackingAction::Untracked
        );
    }

    #[test]
    fn udp_tuple_can_be_reclassified_after_inactivity() {
        let mut entry = RedirectEntry {
            last_seen_ns: 10,
            ..RedirectEntry::default()
        };
        assert_eq!(
            redirect_tracking_action(
                Some(&entry),
                true,
                false,
                10 + UDP_CONN_TIMEOUT_NS + REDIRECT_REFRESH_NS
            ),
            RedirectTrackingAction::Redirect
        );
        assert_eq!(
            redirect_tracking_action(
                Some(&entry),
                true,
                false,
                11 + UDP_CONN_TIMEOUT_NS + REDIRECT_REFRESH_NS
            ),
            RedirectTrackingAction::Expired
        );
        // Continued proxy traffic refreshes the entry in the packet handlers.
        entry.last_seen_ns += UDP_CONN_TIMEOUT_NS;
        assert_eq!(
            redirect_tracking_action(
                Some(&entry),
                true,
                false,
                entry.last_seen_ns + 1
            ),
            RedirectTrackingAction::Redirect
        );
    }
}
