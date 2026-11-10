use crate::Error;
use url::Url;
#[cfg(windows)]
use uuid::Uuid;

// Auto-redirect uses complete packet/conntrack mark values. Zero is unknown.
pub(crate) const AUTO_REDIRECT_INPUT_MARK: u32 = 0x163;
pub(crate) const AUTO_REDIRECT_BYPASS_MARK: u32 = 0x164;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TunDevice {
    FileDescriptor(u32),
    Interface {
        name: String,
        #[cfg(windows)]
        guid: Option<u128>,
    },
}

/// Shared by conversion and initialization, including URL scheme normalization.
pub(crate) fn parse_device_id(value: &str) -> Result<TunDevice, Error> {
    let parsed = Url::parse(value);
    let url = match parsed {
        Ok(url) => url,
        Err(error) if value.contains("://") => return Err(Error::InvalidConfig(
            format!("invalid tun device URL {value:?}: {error}"),
        )),
        Err(_) => return Ok(TunDevice::Interface {
            name: value.to_owned(),
            #[cfg(windows)]
            guid: None,
        }),
    };
    if !matches!(url.scheme(), "dev" | "fd") {
        return Err(Error::InvalidConfig(format!("invalid tun device scheme: {}", url.scheme())));
    }
    if !url.username().is_empty() || url.password().is_some() || url.port().is_some()
        || !url.path().is_empty() || url.fragment().is_some()
    {
        return Err(Error::InvalidConfig(
            "tun device URL must contain only a scheme, device host and supported query options".into(),
        ));
    }
    let host = url.host_str().ok_or_else(|| Error::InvalidConfig(
        "tun device URL requires a host".into(),
    ))?;
    match url.scheme() {
        "fd" => {
            if url.query().is_some() {
                return Err(Error::InvalidConfig("tun fd URL does not support query options".into()));
            }
            let fd: i32 = host.parse().map_err(|error| Error::InvalidConfig(
                format!("invalid tun fd {host:?}: {error}"),
            ))?;
            if fd < 0 { return Err(Error::InvalidConfig("tun fd must be nonnegative".into())); }
            Ok(TunDevice::FileDescriptor(fd as u32))
        }
        "dev" => {
            #[cfg(windows)]
            let guid = url.query_pairs().find(|(key, _)| key == "guid")
                .map(|(_, value)| Uuid::parse_str(&value).map(|guid| guid.as_u128()))
                .transpose().map_err(|error| Error::InvalidConfig(format!("invalid tun guid: {error}")))?;
            Ok(TunDevice::Interface {
                name: host.to_owned(),
                #[cfg(windows)]
                guid,
            })
        }
        _ => unreachable!(),
    }
}

/// Use literal Linux interface names, never nft patterns or escaped strings.
/// IFNAMSIZ is 16 including NUL; the limit applies to bytes, not characters.
pub(crate) fn validate_interface_name(name: &str) -> Result<(), Error> {
    if name.is_empty() || name.len() > 15 || matches!(name, "." | "..")
        || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    {
        return Err(Error::InvalidConfig(format!(
            "invalid tun interface name {name:?}: expected 1-15 ASCII bytes (letters, digits, '_', '.', '-')",
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_device_urls_use_one_parser() {
        for value in ["tun0", "dev://tun0", "DEV://tun0"] {
            let parsed = parse_device_id(value).unwrap();
            assert!(matches!(parsed, TunDevice::Interface { name, .. } if name == "tun0"));
        }
        for value in ["fd://3", "FD://3"] {
            assert_eq!(parse_device_id(value).unwrap(), TunDevice::FileDescriptor(3));
        }
        for value in ["dev://", "fd://", "fd://-1", "http://tun0", "dev:/tun0",
            "dev://tun0/path", "dev://user@tun0", "dev://tun0:12", "fd://3?x=1", "dev://tun0#fragment"]
        {
            assert!(parse_device_id(value).is_err(), "{value}");
        }
    }

    #[test]
    fn tun_interface_names_are_literal_and_bounded() {
        for name in ["eth0", "br-lan", "eth0.100", "veth_123", "123456789012345"] {
            assert!(validate_interface_name(name).is_ok());
        }
        for name in ["", ".", "..", "1234567890123456", "a\"; flush ruleset; \"",
            "a\"", "a\\", "a;", "eth*", "a/b", "a:b", "a b", "a\n", "é"]
        {
            assert!(validate_interface_name(name).is_err(), "{name:?}");
        }
    }
}
