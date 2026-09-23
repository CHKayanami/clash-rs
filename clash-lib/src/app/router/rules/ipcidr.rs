use crate::{app::router::rules::RuleMatcher, session::Session};

#[derive(Clone)]
pub struct IpCidr {
    pub ipnet: ipnet::IpNet,
    pub target: String,
    pub match_src: bool,
    pub no_resolve: bool,
}

impl std::fmt::Display for IpCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.target,
            if self.match_src { "src" } else { "dst" },
            self.ipnet
        )
    }
}

impl RuleMatcher for IpCidr {
    fn apply(&self, sess: &Session) -> bool {
        if self.match_src {
            self.ipnet.contains(&sess.source.ip())
        } else {
            let ip = sess.resolved_ip.or(sess.destination.ip());

            if let Some(ip) = ip {
                self.ipnet.contains(&ip)
            } else {
                false
            }
        }
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn should_resolve_ip(&self) -> bool {
        !self.match_src && !self.no_resolve
    }

    fn payload(&self) -> String {
        self.ipnet.to_string()
    }

    fn type_name(&self) -> &str {
        if self.match_src {
            "SrcIPCIDR"
        } else {
            "IPCIDR"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn test_should_resolve_ip() {
        let dst_cidr: ipnet::IpNet = "192.168.1.0/24".parse().unwrap();
        let rule_dst = IpCidr {
            ipnet: dst_cidr,
            target: "DIRECT".to_string(),
            match_src: false,
            no_resolve: false,
        };
        assert!(rule_dst.should_resolve_ip());

        let rule_dst_no_resolve = IpCidr {
            ipnet: dst_cidr,
            target: "DIRECT".to_string(),
            match_src: false,
            no_resolve: true,
        };
        assert!(!rule_dst_no_resolve.should_resolve_ip());

        // SRC-IP-CIDR should NEVER resolve destination IP
        let rule_src = IpCidr {
            ipnet: dst_cidr,
            target: "DIRECT".to_string(),
            match_src: true,
            no_resolve: false,
        };
        assert!(!rule_src.should_resolve_ip());

        let rule_src_no_resolve = IpCidr {
            ipnet: dst_cidr,
            target: "DIRECT".to_string(),
            match_src: true,
            no_resolve: true,
        };
        assert!(!rule_src_no_resolve.should_resolve_ip());
    }

    #[test]
    fn test_src_ip_cidr_matching() {
        let rule = IpCidr {
            ipnet: "10.0.0.0/8".parse().unwrap(),
            target: "DIRECT".to_string(),
            match_src: true,
            no_resolve: false,
        };

        let mut sess = Session {
            source: "10.1.2.3:12345".parse::<SocketAddr>().unwrap(),
            destination: crate::session::SocksAddr::Domain("example.com".into(), 80),
            ..Default::default()
        };

        assert!(rule.apply(&sess));

        sess.source = "192.168.1.1:12345".parse::<SocketAddr>().unwrap();
        assert!(!rule.apply(&sess));
    }
}
