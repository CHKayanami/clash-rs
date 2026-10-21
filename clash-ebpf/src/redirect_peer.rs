//! Startup eligibility for ingress-to-ingress namespace redirection.
use std::fs;
use tracing::{debug, info};
use crate::netlink::{LinkPairKind, NlSock};

fn safe_kernel(release: &str) -> bool {
    // Known upstream CVE-2025-37959 fixes. Unknown vendor backports remain
    // disabled; merely accepting the helper does not prove this fix exists.
    if release.contains("-rc") { return false; }
    let version = release.split('-').next().unwrap_or("").trim_end_matches('+');
    let mut parts = version.split('.');
    let parsed = (parts.next().and_then(|s| s.parse::<u32>().ok()),
        parts.next().and_then(|s| s.parse::<u32>().ok()),
        parts.next().and_then(|s| s.parse::<u32>().ok()));
    let (Some(major), Some(minor), Some(patch)) = parsed else { return false; };
    major > 6 || (major == 6 && (minor >= 15
        || (minor == 14 && patch >= 7)
        || (minor == 12 && patch >= 29)
        || (minor == 6 && patch >= 91)
        || (minor == 1 && patch >= 139)))
}

pub(crate) fn kernel_supported() -> bool {
    match fs::read_to_string("/proc/sys/kernel/osrelease") {
        Ok(release) if safe_kernel(release.trim()) => true,
        Ok(release) => {
            debug!(kernel = release.trim(), "Kernel lacks a known redirect_peer fix; using ordinary redirect");
            false
        }
        Err(error) => {
            debug!(%error, "Cannot detect redirect_peer kernel support; using ordinary redirect");
            false
        }
    }
}

pub(crate) fn detect(nl: &mut NlSock, kind: LinkPairKind, name: &str) -> bool {
    if !kernel_supported() { return false; }
    if kind == LinkPairKind::Netkit {
        match nl.netkit_redirect_peer_ready(name) {
            Ok(true) => {}
            Ok(false) => {
                debug!("Netkit scrub=NONE readback unavailable; using ordinary redirect");
                return false;
            }
            Err(error) => {
                debug!(%error, "Cannot read netkit scrub configuration; using ordinary redirect");
                return false;
            }
        }
    }
    // The actual TC programs must still pass verifier loading before hooks
    // are attached. The paired endpoint is subsequently moved into daens.
    info!(?kind, "Enabled bpf_redirect_peer for LAN ingress");
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_known_fixed_kernel_branches_are_enabled() {
        for version in ["6.1.139", "6.6.91-openwrt", "6.12.29", "6.14.7", "6.15.0", "7.2.7-100.fc43.x86_64"] {
            assert!(safe_kernel(version), "{version}");
        }
        for version in ["5.10.240", "6.1.138", "6.6.90", "6.12.28", "6.13.12", "6.14.6", "6.15", "6.15.0-rc1", "unknown"] {
            assert!(!safe_kernel(version), "{version}");
        }
    }
}

#[cfg(test)]
#[path = "redirect_peer_tests.rs"]
mod integration;
