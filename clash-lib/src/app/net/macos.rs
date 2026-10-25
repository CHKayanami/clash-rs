use core_foundation::{base::{CFType, TCFType}, dictionary::CFDictionary,
    string::CFString};
use system_configuration::dynamic_store::SCDynamicStoreBuilder;

use super::{OutboundInterface, get_interface_by_name};
#[cfg(feature = "tun")]
use super::get_default_outbound_interface;
#[cfg(feature = "tun")]
use std::{collections::HashMap, sync::LazyLock};
#[cfg(feature = "tun")]
use parking_lot::RwLock;

#[cfg(feature = "tun")]
static OWN_TUNS: LazyLock<RwLock<HashMap<String, usize>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

#[cfg(feature = "tun")]
pub(crate) struct TunInterfaceGuard(String);

#[cfg(feature = "tun")]
pub(crate) fn register_tun(name: String) -> TunInterfaceGuard {
    *OWN_TUNS.write().entry(name.clone()).or_default() += 1;
    TunInterfaceGuard(name)
}

#[cfg(feature = "tun")]
impl Drop for TunInterfaceGuard {
    fn drop(&mut self) {
        let mut names = OWN_TUNS.write();
        let count = names.get_mut(&self.0).expect("registered TUN interface");
        *count -= 1;
        if *count == 0 { names.remove(&self.0); }
    }
}

#[cfg(feature = "tun")]
fn is_own_tun(name: &str) -> bool { OWN_TUNS.read().contains_key(name) }

/// configd's primary service follows the actual default network, including
/// transitions between Wi-Fi and Ethernet. Do not guess from interface names.
pub(super) fn default_interface() -> Option<OutboundInterface> {
    let store = SCDynamicStoreBuilder::new("ClashRS default interface").build()?;
    for family in ["IPv4", "IPv6"] {
        let Some(value) = store.get(format!("State:/Network/Global/{family}").as_str()) else {
            continue;
        };
        let Some(dict) = value.downcast::<CFDictionary>() else {
            continue;
        };
        // SAFETY: the property-list downcast validated the dictionary type.
        // Property-list dictionaries have CFString keys and CFType values;
        // the get rule retains the dictionary for this local wrapper's lifetime.
        let dict = unsafe {
            CFDictionary::<CFString, CFType>::wrap_under_get_rule(
                dict.as_concrete_TypeRef()
            )
        };
        let Some(name) = dict.find(CFString::new("PrimaryInterface"))
            .and_then(|value| value.downcast::<CFString>()) else {
            continue;
        };
        let name = name.to_string();
        #[cfg(feature = "tun")]
        if is_own_tun(&name) { continue; }
        if let Some(iface) = get_interface_by_name(&name) {
            return Some(iface);
        }
    }
    // configd may temporarily elect our supplemental service. Keep a still
    // present upstream interface instead of binding sockets back to our TUN.
    #[cfg(feature = "tun")]
    if let Some(previous) = get_default_outbound_interface()
        && !is_own_tun(&previous.name)
    {
        return get_interface_by_name(&previous.name);
    }
    None
}

#[cfg(all(test, feature = "tun"))]
mod tests {
    use super::*;

    #[test]
    fn own_interface_exclusion_survives_overlapping_generations() {
        let name = "clash-test-tun-exclusion".to_owned();
        let first = register_tun(name.clone());
        let second = register_tun(name.clone());
        assert!(is_own_tun(&name));
        assert!(!is_own_tun("another-vpn-utun"));
        drop(first);
        assert!(is_own_tun(&name));
        drop(second);
        assert!(!is_own_tun(&name));
    }
}
