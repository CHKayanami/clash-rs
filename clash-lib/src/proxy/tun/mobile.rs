use crate::{Error, config::config::TunConfig};
use url::Url;

pub(super) fn validate(cfg: &TunConfig) -> Result<u16, Error> {
    let device = Url::parse(&cfg.device_id)
        .map_err(|e| Error::InvalidConfig(format!("mobile TUN device: {e}")))?;
    let fd = device.host_str().and_then(|host| host.parse::<i32>().ok());
    if device.scheme() != "fd" || fd.is_none_or(|fd| fd < 0) {
        return Err(Error::InvalidConfig("mobile TUN requires a valid fd:// descriptor".into()));
    }
    if cfg.route_all || cfg.auto_detect_interface || !cfg.routes.is_empty()
        || !cfg.route_exclude_address.is_empty() {
        return Err(Error::InvalidConfig(
            "mobile TUN routes and outbound network must be configured by the VPN host; disable auto-route and auto-detect-interface".into(),
        ));
    }
    let mtu = cfg.mtu.unwrap_or(1500);
    let minimum = if cfg.gateway_v6.is_some() { 1280 } else { 68 };
    if mtu < minimum {
        return Err(Error::InvalidConfig(format!("mobile TUN MTU must be at least {minimum}")));
    }
    Ok(mtu)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> TunConfig {
        TunConfig { enable: true, device_id: "fd://42".into(), ..Default::default() }
    }

    #[test]
    fn host_mtu_is_used_without_device_ioctl() {
        let mut cfg = config();
        assert_eq!(validate(&cfg).unwrap(), 1500);
        cfg.mtu = Some(9000);
        assert_eq!(validate(&cfg).unwrap(), 9000);
        cfg.mtu = Some(0);
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_invalid_descriptors_and_host_route_conflicts() {
        let mut cfg = config();
        for device in ["fd://", "fd://-1", "fd://4294967295", "dev://tun0"] {
            cfg.device_id = device.into();
            assert!(validate(&cfg).is_err(), "{device}");
        }
        cfg = config();
        cfg.route_all = true;
        assert!(validate(&cfg).is_err());
        cfg = config();
        cfg.auto_detect_interface = true;
        assert!(validate(&cfg).is_err());
        cfg = config();
        cfg.routes.push("0.0.0.0/0".parse().unwrap());
        assert!(validate(&cfg).is_err());
    }
}
