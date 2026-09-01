use crate::app::net::OutboundInterface;
use anyhow::anyhow;
use bytes::{Buf, BufMut};
use serde::{Serialize, Serializer};
use std::{
    fmt::{Debug, Display, Formatter},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
};
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SocksAddr {
    Ip(SocketAddr),
    Domain(Arc<str>, u16),
}

impl Serialize for SocksAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeTupleVariant;
        match self {
            SocksAddr::Ip(addr) => {
                let mut s = serializer.serialize_tuple_variant("SocksAddr", 0, "Ip", 1)?;
                s.serialize_field(addr)?;
                s.end()
            }
            SocksAddr::Domain(domain, port) => {
                let mut s = serializer.serialize_tuple_variant("SocksAddr", 1, "Domain", 2)?;
                s.serialize_field(domain.as_ref())?;
                s.serialize_field(port)?;
                s.end()
            }
        }
    }
}

impl FromStr for SocksAddr {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut s = s.to_string();
        if !s.contains(':') {
            s = format!("{s}:80");
        }
        match SocketAddr::from_str(&s) {
            Ok(v) => Ok(Self::Ip(v)),
            Err(_) => {
                let tokens: Vec<_> = s.split(':').collect();
                if tokens.len() == 2 {
                    let port: u16 = tokens.get(1).unwrap().parse()?;
                    Ok(Self::Domain(tokens.first().unwrap().to_string().into(), port))
                } else {
                    Err(anyhow!("SocksAddr parse error, value: {s}"))
                }
            }
        }
    }
}
#[test]
fn test_from_str() {
    assert_eq!(
        SocksAddr::from_str("127.0.0.1").unwrap(),
        SocksAddr::Ip(SocketAddr::V4("127.0.0.1:80".parse().unwrap()))
    );
    assert!(SocksAddr::from_str("127.0.0.1:80").is_ok());
    assert!(SocksAddr::from_str("hosta.com").is_ok());
    assert!(SocksAddr::from_str("hosta.com:443").is_ok());
    assert!(SocksAddr::from_str("hosta.:com:443").is_err());
}

impl Default for SocksAddr {
    fn default() -> Self {
        Self::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0))
    }
}

impl Display for SocksAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                SocksAddr::Ip(ip) => ip.to_string(),
                SocksAddr::Domain(host, port) => format!("{host}:{port}"),
            }
        )
    }
}

pub struct SocksAddrType;

impl SocksAddrType {
    pub const DOMAIN: u8 = 0x3;
    pub const V4: u8 = 0x1;
    pub const V6: u8 = 0x4;
}

impl SocksAddr {
    pub fn any_ipv4() -> Self {
        Self::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0))
    }

    pub fn any_ipv6() -> Self {
        Self::Ip(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
            0,
        ))
    }

    pub fn write_buf<T: BufMut>(&self, buf: &mut T) {
        match self {
            Self::Ip(addr) => match addr {
                SocketAddr::V4(addr) => {
                    buf.put_u8(SocksAddrType::V4);
                    buf.put_slice(&addr.ip().octets());
                    buf.put_u16(addr.port());
                }
                SocketAddr::V6(addr) => {
                    buf.put_u8(SocksAddrType::V6);
                    buf.put_slice(&addr.ip().octets());
                    buf.put_u16(addr.port());
                }
            },
            Self::Domain(domain, port) => {
                buf.put_u8(SocksAddrType::DOMAIN);
                buf.put_u8(domain.len() as u8);
                buf.put_slice(domain.as_bytes());
                buf.put_u16(*port);
            }
        }
    }

    pub fn is_domain(&self) -> bool {
        match self {
            SocksAddr::Ip(_) => false,
            SocksAddr::Domain(..) => true,
        }
    }

    pub fn domain_name(domain: impl Into<Arc<str>>, port: u16) -> Self {
        Self::Domain(domain.into(), port)
    }

    pub fn domain(&self) -> Option<&str> {
        match self {
            SocksAddr::Ip(_) => None,
            SocksAddr::Domain(domain, _) => Some(domain.as_ref()),
        }
    }

    pub fn must_into_socket_addr(self) -> SocketAddr {
        let self_clone = self.clone();
        self.try_into_socket_addr()
            .unwrap_or_else(|| panic!("not a socket address: {self_clone:?}"))
    }

    pub fn try_into_socket_addr(self) -> Option<SocketAddr> {
        match self {
            SocksAddr::Ip(addr) => Some(addr),
            SocksAddr::Domain(..) => None,
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            SocksAddr::Ip(addr) => Some(addr.ip()),
            SocksAddr::Domain(host, _) => host.parse().ok(),
        }
    }


    pub fn host_cow(&self) -> std::borrow::Cow<'_, str> {
        match self {
            SocksAddr::Ip(ip) => std::borrow::Cow::Owned(ip.ip().to_string()),
            SocksAddr::Domain(domain, _) => std::borrow::Cow::Borrowed(domain.as_ref()),
        }
    }

    pub fn host(&self) -> String {
        match self {
            SocksAddr::Ip(ip) => ip.ip().to_string(),
            SocksAddr::Domain(domain, _) => domain.to_string(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            SocksAddr::Ip(ip) => ip.port(),
            SocksAddr::Domain(_, port) => *port,
        }
    }

    pub fn size(&self) -> usize {
        match self {
            // SOCKS5 ATYP
            SocksAddr::Ip(ip) => match ip {
                SocketAddr::V4(_) => 1 + 4 + 2, // ATYP + IPv4 len + port len
                SocketAddr::V6(_) => 1 + 16 + 2,
            },
            SocksAddr::Domain(domain, _) => 1 + 1 + domain.len() + 2,
        }
    }

    pub fn peek_read(buf: &[u8]) -> io::Result<Self> {
        let mut cur = io::Cursor::new(buf);
        Self::peek_cursor(&mut cur)
    }

    #[inline]
    fn peek_cursor<T: AsRef<[u8]>>(cur: &mut io::Cursor<T>) -> io::Result<Self> {
        if cur.remaining() < 2 {
            return Err(io::Error::other("invalid buf"));
        }

        let atyp = cur.get_u8();
        match atyp {
            SocksAddrType::V4 => {
                if cur.remaining() < 4 + 2 {
                    return Err(io::Error::other("invalid buf"));
                }
                let addr = Ipv4Addr::from(cur.get_u32());
                let port = cur.get_u16();
                Ok(Self::Ip((addr, port).into()))
            }
            SocksAddrType::V6 => {
                if cur.remaining() < 16 + 2 {
                    return Err(io::Error::other("invalid buf"));
                }
                let addr = Ipv6Addr::from(cur.get_u128());
                let port = cur.get_u16();
                Ok(Self::Ip((addr, port).into()))
            }
            SocksAddrType::DOMAIN => {
                let domain_len = cur.get_u8() as usize;
                if cur.remaining() < domain_len {
                    return Err(io::Error::other("invalid buf"));
                }
                let mut buf = vec![0u8; domain_len];
                cur.copy_to_slice(&mut buf);
                let port = cur.get_u16();
                let domain_name =
                    String::from_utf8(buf).map_err(|_x| invalid_domain())?;
                Ok(Self::Domain(domain_name.into(), port))
            }
            _ => Err(invalid_atyp()),
        }
    }

    pub async fn read_from<T: AsyncRead + Unpin>(r: &mut T) -> io::Result<Self> {
        match r.read_u8().await? {
            SocksAddrType::V4 => {
                let ip = Ipv4Addr::from(r.read_u32().await?);
                let port = r.read_u16().await?;
                Ok(Self::Ip((ip, port).into()))
            }
            SocksAddrType::V6 => {
                let ip = Ipv6Addr::from(r.read_u128().await?);
                let port = r.read_u16().await?;
                Ok(Self::Ip((ip, port).into()))
            }
            SocksAddrType::DOMAIN => {
                let domain_len = r.read_u8().await? as usize;
                let mut buf = vec![0u8; domain_len];
                let n = r.read_exact(&mut buf).await?;
                if n != domain_len {
                    return Err(io::Error::other("invalid domain length"));
                }
                let domain = String::from_utf8(buf).map_err(|_| invalid_domain())?;
                let port = r.read_u16().await?;
                Ok(Self::Domain(domain.into(), port))
            }
            _ => Err(invalid_atyp()),
        }
    }
}

impl From<(IpAddr, u16)> for SocksAddr {
    fn from(value: (IpAddr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(Ipv4Addr, u16)> for SocksAddr {
    fn from(value: (Ipv4Addr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(Ipv6Addr, u16)> for SocksAddr {
    fn from(value: (Ipv6Addr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<SocketAddr> for SocksAddr {
    fn from(value: SocketAddr) -> Self {
        Self::Ip(value)
    }
}

impl TryFrom<(String, u16)> for SocksAddr {
    type Error = io::Error;

    fn try_from(value: (String, u16)) -> Result<Self, Self::Error> {
        if let Ok(ip) = value.0.parse::<IpAddr>() {
            return Ok(Self::from((ip, value.1)));
        }
        if value.0.len() > 0xff {
            return Err(io::Error::other("domain too long"));
        }
        Ok(Self::Domain(value.0.into(), value.1))
    }
}

impl TryFrom<(&str, u16)> for SocksAddr {
    type Error = io::Error;

    fn try_from(value: (&str, u16)) -> Result<Self, Self::Error> {
        if let Ok(ip) = value.0.parse::<IpAddr>() {
            return Ok(Self::from((ip, value.1)));
        }
        if value.0.len() > 0xff {
            return Err(io::Error::other("domain too long"));
        }
        Ok(Self::Domain(Arc::from(value.0), value.1))
    }
}

impl TryFrom<(Arc<str>, u16)> for SocksAddr {
    type Error = io::Error;

    fn try_from(value: (Arc<str>, u16)) -> Result<Self, Self::Error> {
        if let Ok(ip) = value.0.parse::<IpAddr>() {
            return Ok(Self::from((ip, value.1)));
        }
        if value.0.len() > 0xff {
            return Err(io::Error::other("domain too long"));
        }
        Ok(Self::Domain(value.0, value.1))
    }
}

impl TryFrom<&[u8]> for SocksAddr {
    type Error = io::Error;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.is_empty() {
            return Err(insuff_bytes());
        }

        match buf[0] {
            SocksAddrType::V4 => {
                if buf.len() < 1 + 4 + 2 {
                    // ATYP + DST.ADDR + DST.PORT
                    return Err(insuff_bytes());
                }

                let mut ip_bytes = [0u8; 4];
                ip_bytes.copy_from_slice(&buf[1..5]);
                let ip = Ipv4Addr::from(ip_bytes);
                let mut port_bytes = [0u8; 2];
                port_bytes.copy_from_slice(&buf[5..7]);
                let port = u16::from_be_bytes(port_bytes);
                Ok(Self::Ip((ip, port).into()))
            }

            SocksAddrType::V6 => {
                if buf.len() < 1 + 16 + 2 {
                    // ATYP + DST.ADDR + DST.PORT
                    return Err(insuff_bytes());
                }

                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&buf[1..17]);
                let ip = Ipv6Addr::from(ip_bytes);
                let mut port_bytes = [0u8; 2];
                port_bytes.copy_from_slice(&buf[17..19]);
                let port = u16::from_be_bytes(port_bytes);
                Ok(Self::Ip((ip, port).into()))
            }

            SocksAddrType::DOMAIN => {
                if buf.is_empty() {
                    return Err(insuff_bytes());
                }
                let domain_len = buf[1] as usize;
                if buf.len() < 1 + domain_len + 2 {
                    return Err(insuff_bytes());
                }
                let domain = String::from_utf8((buf[2..domain_len + 2]).to_vec())
                    .map_err(|e| io::Error::other(format!("invalid domain: {e}")))?;
                let mut port_bytes = [0u8; 2];
                (port_bytes).copy_from_slice(&buf[domain_len + 2..domain_len + 4]);
                let port = u16::from_be_bytes(port_bytes);
                Ok(Self::Domain(domain.into(), port))
            }

            _ => Err(io::Error::other("invalid ATYP")),
        }
    }
}

impl TryFrom<SocksAddr> for SocketAddr {
    type Error = io::Error;

    fn try_from(s: SocksAddr) -> Result<Self, Self::Error> {
        match s {
            SocksAddr::Ip(ip) => Ok(ip),
            SocksAddr::Domain(..) => Err(io::Error::other("cannot convert")),
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug, Serialize)]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug, Serialize)]
pub enum Type {
    Http,
    HttpConnect,
    Socks5,
    #[cfg(feature = "tun")]
    Tun,
    #[cfg(feature = "ebpf")]
    Ebpf,
    #[cfg(all(target_os = "linux", feature = "tproxy"))]
    Tproxy,

    #[cfg(all(target_os = "linux", feature = "redir"))]
    Redir,
    Tunnel,
    Shadowsocks,
    Anytls,
    Ignore,
    RouteProbe,
}

impl Display for Network {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Network::Tcp => "TCP",
            Network::Udp => "UDP",
        })
    }
}

use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(10_000_000);

pub fn generate_session_id() -> u64 {
    NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed)
}

pub struct Session {
    /// Unique trace ID for the session request lifecycle.
    pub id: u64,
    /// The network type, representing either TCP or UDP.
    pub network: Network,
    /// The type of the inbound connection.
    pub typ: Type,
    /// The socket address of the remote peer of an inbound connection.
    pub source: SocketAddr,
    /// The proxy target address of a proxy connection.
    pub destination: SocksAddr,
    /// The locally resolved IP address of the destination domain.
    pub resolved_ip: Option<IpAddr>,
    /// The packet mark SO_MARK
    pub so_mark: Option<u32>,
    /// The bind interface
    pub iface: Option<OutboundInterface>,
    /// ISO 3166-1 alpha-2 country code from country mmdb. Only for display.
    pub country: Option<String>,
    /// ASN org name from ASN mmdb. Only for display.
    pub asn: Option<String>,
    /// The local process that owns this connection, resolved lazily by
    /// `Router::match_route` and only when a PROCESS-NAME/PROCESS-PATH rule is
    /// actually reached. `None` means "not looked up yet or lookup failed".
    pub process_name: Option<String>,
    /// Traffic statistics for intelligent proxy selection
    pub traffic_stats: Option<crate::app::remote_content_manager::TrafficStats>,
    /// Authenticated user name from SS2022 EIH (FAC user_id as string).
    /// Set by the Shadowsocks inbound before dispatch; used for per-user
    /// traffic attribution.
    pub inbound_user: Option<String>,
    /// Domain name sniffed from TLS SNI / HTTP Host / QUIC SNI
    pub sniffed_domain: Option<String>,
    /// Domain name mapped from DNS reverse lookup or Fake-IP
    pub mapped_domain: Option<String>,
    /// Original destination address before sniffing or DNS mapping override
    pub orig_destination: Option<SocksAddr>,
    /// Custom UDP session idle timeout
    pub udp_timeout: Option<std::time::Duration>,
    /// Proxy chain traversed during dispatch
    pub proxy_chain: ProxyChain,
}

#[derive(Default, Clone, Debug)]
pub struct ProxyChain(Arc<parking_lot::RwLock<Vec<String>>>);

impl Serialize for ProxyChain {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.snapshot().serialize(serializer)
    }
}

impl ProxyChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&self, s: String) {
        self.0.write().push(s);
    }

    pub fn snapshot(&self) -> Vec<String> {
        self.0.read().clone()
    }
}

impl Session {
    pub fn push_chain(&self, name: &str) {
        self.proxy_chain.push(name.to_owned());
    }
}

struct DestinationIpHelper<'a>(Option<IpAddr>, Option<&'a str>);

impl Serialize for DestinationIpHelper<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match (self.0, self.1) {
            (Some(ip), Some(asn)) => {
                serializer.collect_str(&format_args!("{ip}({asn})"))
            }
            (Some(ip), None) => serializer.collect_str(&ip),
            (None, _) => serializer.serialize_str(""),
        }
    }
}

impl Serialize for Session {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;

        let mut count = 10;
        if self.inbound_user.is_some() {
            count += 1;
        }
        if self.sniffed_domain.is_some() {
            count += 1;
        }
        if self.mapped_domain.is_some() {
            count += 1;
        }

        let mut map = serializer.serialize_map(Some(count))?;
        map.serialize_entry("id", &self.id)?;
        map.serialize_entry("network", &self.network)?;
        map.serialize_entry("type", &self.typ)?;
        map.serialize_entry("sourceIP", &self.source.ip())?;
        map.serialize_entry("sourcePort", &self.source.port())?;

        let dest_ip_helper = DestinationIpHelper(
            self.resolved_ip.or_else(|| self.destination.ip()),
            self.asn.as_deref(),
        );
        map.serialize_entry("destinationIP", &dest_ip_helper)?;
        map.serialize_entry("destinationPort", &self.destination.port())?;

        let dest_host = self.destination.host_cow();
        let display_host = self
            .sniffed_domain
            .as_deref()
            .or(self.mapped_domain.as_deref())
            .unwrap_or_else(|| dest_host.as_ref());
        map.serialize_entry("host", display_host)?;
        map.serialize_entry("asn", &self.asn)?;
        map.serialize_entry("country", &self.country)?;
        map.serialize_entry("traffic_stats", &self.traffic_stats)?;

        if let Some(ref user) = self.inbound_user {
            map.serialize_entry("inboundUser", user)?;
        }
        if let Some(ref sniffed) = self.sniffed_domain {
            map.serialize_entry("sniffedDomain", sniffed)?;
        }
        if let Some(ref mapped) = self.mapped_domain {
            map.serialize_entry("mappedDomain", mapped)?;
        }

        map.end()
    }
}

impl Default for Session {
    fn default() -> Self {
        Self {
            id: generate_session_id(),
            network: Network::Tcp,
            typ: Type::Http,
            source: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
            destination: SocksAddr::any_ipv4(),
            resolved_ip: None,
            so_mark: None,
            iface: None,
            country: None,
            asn: None,
            process_name: None,
            traffic_stats: None,
            inbound_user: None,
            sniffed_domain: None,
            mapped_domain: None,
            orig_destination: None,
            udp_timeout: None,
            proxy_chain: ProxyChain::default(),
        }
    }
}

impl Display for Session {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.resolved_ip {
            Some(ip) => write!(
                f,
                "[#{}] [{}] {} -> {}[{}]",
                self.id, self.network, self.source, self.destination, ip
            ),
            None => write!(
                f,
                "[#{}] [{}] {} -> {}",
                self.id, self.network, self.source, self.destination,
            ),
        }
    }
}

impl Debug for Session {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("network", &self.network)
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("sniffed_domain", &self.sniffed_domain)
            .field("mapped_domain", &self.mapped_domain)
            .field("packet_mark", &self.so_mark)
            .field("iface", &self.iface)
            .field("country", &self.country)
            .field("asn", &self.asn)
            .finish()
    }
}

impl Clone for Session {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            network: self.network,
            typ: self.typ,
            source: self.source,
            destination: self.destination.clone(),
            resolved_ip: self.resolved_ip,
            so_mark: self.so_mark,
            iface: self.iface.clone(),
            country: self.country.clone(),
            asn: self.asn.clone(),
            process_name: self.process_name.clone(),
            traffic_stats: self.traffic_stats.clone(),
            inbound_user: self.inbound_user.clone(),
            sniffed_domain: self.sniffed_domain.clone(),
            mapped_domain: self.mapped_domain.clone(),
            orig_destination: self.orig_destination.clone(),
            udp_timeout: self.udp_timeout,
            proxy_chain: self.proxy_chain.clone(),
        }
    }
}

fn invalid_domain() -> io::Error {
    io::Error::other("invalid domain")
}

fn invalid_atyp() -> io::Error {
    io::Error::other("invalid address type")
}

fn insuff_bytes() -> io::Error {
    io::Error::other("insufficient bytes")
}

#[test]
fn test_session_id() {
    let s1 = Session::default();
    let s2 = Session::default();

    assert!(s1.id >= 10_000_000);
    assert!(s2.id > s1.id);

    let s1_cloned = s1.clone();
    assert_eq!(s1_cloned.id, s1.id);

    let display_str = s1.to_string();
    assert!(display_str.contains(&format!("[#{}]", s1.id)));
}

#[test]
fn test_session_serialize() {
    let mut s = Session::default();
    s.resolved_ip = Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    s.asn = Some("Cloudflare".to_string());
    s.inbound_user = Some("alice".to_string());
    s.sniffed_domain = Some("example.com".to_string());

    let val: serde_json::Value = serde_json::to_value(&s).unwrap();
    assert_eq!(val["destinationIP"], "1.1.1.1(Cloudflare)");
    assert_eq!(val["inboundUser"], "alice");
    assert_eq!(val["sniffedDomain"], "example.com");

    s.asn = None;
    let val2: serde_json::Value = serde_json::to_value(&s).unwrap();
    assert_eq!(val2["destinationIP"], "1.1.1.1");

    s.resolved_ip = None;
    s.destination = SocksAddr::Domain("example.com".into(), 80);
    let val3: serde_json::Value = serde_json::to_value(&s).unwrap();
    assert_eq!(val3["destinationIP"], "");

    // Test host priority: sniffed_domain > mapped_domain > destination.host_cow()
    let mut s_prio = Session::default();
    s_prio.destination = SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443));
    let v1: serde_json::Value = serde_json::to_value(&s_prio).unwrap();
    assert_eq!(v1["host"], "1.2.3.4");

    s_prio.mapped_domain = Some("mapped.apple.com".to_string());
    let v2: serde_json::Value = serde_json::to_value(&s_prio).unwrap();
    assert_eq!(v2["host"], "mapped.apple.com");
    assert_eq!(v2["mappedDomain"], "mapped.apple.com");

    s_prio.sniffed_domain = Some("sniffed.apple.com".to_string());
    let v3: serde_json::Value = serde_json::to_value(&s_prio).unwrap();
    assert_eq!(v3["host"], "sniffed.apple.com");
    assert_eq!(v3["sniffedDomain"], "sniffed.apple.com");
    assert_eq!(v3["mappedDomain"], "mapped.apple.com");
}
