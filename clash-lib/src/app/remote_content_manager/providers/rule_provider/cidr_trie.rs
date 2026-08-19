use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ip_network_table_deps_treebitmap::IpLookupTable;

#[derive(Default)]
pub struct CidrTrie {
    v4: IpLookupTable<Ipv4Addr, ()>,
    v6: IpLookupTable<Ipv6Addr, ()>,
}

impl CidrTrie {
    #[inline]
    pub fn new() -> Self {
        Self {
            v4: IpLookupTable::new(),
            v6: IpLookupTable::new(),
        }
    }

    /// Directly insert structured IpNet without string allocation or re-parsing
    #[inline]
    pub fn insert_net(&mut self, net: ipnet::IpNet) {
        match net {
            ipnet::IpNet::V4(v4) => {
                self.v4
                    .insert(v4.trunc().addr(), v4.prefix_len() as _, ());
            }
            ipnet::IpNet::V6(v6) => {
                self.v6
                    .insert(v6.trunc().addr(), v6.prefix_len() as _, ());
            }
        }
    }

    pub fn insert(&mut self, cidr: &str) -> bool {
        if let Ok(net) = cidr.parse::<ipnet::IpNet>() {
            self.insert_net(net);
            true
        } else {
            false
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    #[inline]
    pub fn contains_v4(&self, ip: Ipv4Addr) -> bool {
        self.v4.longest_match(ip).is_some()
    }

    #[inline]
    pub fn contains_v6(&self, ip: Ipv6Addr) -> bool {
        self.v6.longest_match(ip).is_some()
    }

    #[inline]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.contains_v4(v4),
            IpAddr::V6(v6) => self.contains_v6(v6),
        }
    }

    pub fn iter_nets(&self) -> impl Iterator<Item = ipnet::IpNet> + '_ {
        let v4_iter = self.v4.iter().filter_map(|(ip, mask, _)| {
            ipnet::Ipv4Net::new(ip, mask as u8).ok().map(ipnet::IpNet::V4)
        });
        let v6_iter = self.v6.iter().filter_map(|(ip, mask, _)| {
            ipnet::Ipv6Net::new(ip, mask as u8).ok().map(ipnet::IpNet::V6)
        });
        v4_iter.chain(v6_iter)
    }

    pub fn get_ip_cidrs(&self) -> Vec<ipnet::IpNet> {
        self.iter_nets().collect()
    }
}

impl Extend<ipnet::IpNet> for CidrTrie {
    fn extend<T: IntoIterator<Item = ipnet::IpNet>>(&mut self, iter: T) {
        for net in iter {
            self.insert_net(net);
        }
    }
}
