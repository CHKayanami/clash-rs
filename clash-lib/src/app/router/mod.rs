use super::{
    dns::ThreadSafeDNSResolver,
    remote_content_manager::providers::{
        file_vehicle, http_vehicle,
        rule_provider::RuleProviderImpl,
    },
};
use crate::{
    Error,
    app::router::rules::{
        domain::Domain, domain_keyword::DomainKeyword, domain_suffix::DomainSuffix,
        final_::Final, ipcidr::IpCidr, ruleset::RuleSet,
    },
    config::internal::{config::RuleProviderDef, rule::RuleType},
    print_and_exit,
    proxy::utils::OutboundHandlerRegistry,
    session::Session,
};

use std::{collections::HashMap, io, path::PathBuf, sync::Arc, time::Duration};

use futures::future::join_all;
use hyper::Uri;
use rules::domain_regex::DomainRegex;
use tracing::{error, info, trace};

mod rules;

use crate::common::{geodata::GeoDataLookup, mmdb::MmdbLookup};
pub use rules::{Rule, RuleMatcher};
pub use rules::geodata::GeoSiteMatcher;
pub use super::remote_content_manager::providers::rule_provider::ThreadSafeRuleProvider;

pub struct Router {
    rules: Vec<Rule>,
    dns_resolver: ThreadSafeDNSResolver,

    country_mmdb: Option<MmdbLookup>,
    asn_mmdb: Option<MmdbLookup>,
    geodata: Option<GeoDataLookup>,
    rule_providers: HashMap<String, ThreadSafeRuleProvider>,
}

pub type ArcRouter = Arc<Router>;

#[deprecated(
    note = "ThreadSafeRouter has been renamed to ArcRouter; use ArcRouter instead"
)]
pub type ThreadSafeRouter = ArcRouter;

const MATCH: &str = "MATCH";

pub const DEFAULT_RULE_PROVIDER_INIT_TIMEOUT: Duration = Duration::from_secs(30);

impl Router {
    pub async fn new(
        rules: Vec<RuleType>,
        rule_providers: HashMap<String, RuleProviderDef>,
        dns_resolver: ThreadSafeDNSResolver,
        system_resolver: Option<ThreadSafeDNSResolver>,
        outbound_registry: Option<OutboundHandlerRegistry>,
        country_mmdb: Option<MmdbLookup>,
        asn_mmdb: Option<MmdbLookup>,
        geodata: Option<GeoDataLookup>,
        cwd: String,
    ) -> Result<Self, Error> {
        Self::new_with_timeout(
            rules,
            rule_providers,
            dns_resolver,
            system_resolver,
            outbound_registry,
            country_mmdb,
            asn_mmdb,
            geodata,
            cwd,
            DEFAULT_RULE_PROVIDER_INIT_TIMEOUT,
        )
        .await
    }

    pub async fn new_with_timeout(
        rules: Vec<RuleType>,
        rule_providers: HashMap<String, RuleProviderDef>,
        dns_resolver: ThreadSafeDNSResolver,
        system_resolver: Option<ThreadSafeDNSResolver>,
        outbound_registry: Option<OutboundHandlerRegistry>,
        country_mmdb: Option<MmdbLookup>,
        asn_mmdb: Option<MmdbLookup>,
        geodata: Option<GeoDataLookup>,
        cwd: String,
        provider_init_timeout: Duration,
    ) -> Result<Self, Error> {
        let mut rule_provider_registry = HashMap::new();

        Self::load_rule_providers(
            rule_providers,
            &mut rule_provider_registry,
            dns_resolver.clone(),
            system_resolver,
            outbound_registry,
            country_mmdb.clone(),
            geodata.clone(),
            cwd,
            provider_init_timeout,
        )
        .await?;

        let parsed_rules = rules
            .into_iter()
            .map(|r| {
                map_rule_type(
                    r,
                    country_mmdb.clone(),
                    geodata.clone(),
                    Some(&rule_provider_registry),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            rules: parsed_rules,
            dns_resolver,

            country_mmdb,
            asn_mmdb,
            geodata,
            rule_providers: rule_provider_registry,
        })
    }

    pub fn get_rule_providers(&self) -> &HashMap<String, ThreadSafeRuleProvider> {
        &self.rule_providers
    }

    pub fn geodata(&self) -> Option<&GeoDataLookup> {
        self.geodata.as_ref()
    }

    /// Quick check if a domain routes to DIRECT.
    pub async fn is_domain_direct(&self, domain: &str) -> bool {
        self.is_domain_direct_with_ips(domain, &[]).await
    }

    /// Quick check if a domain routes to DIRECT, utilizing pre-resolved IPs to avoid redundant DNS lookups.
    pub async fn is_domain_direct_with_ips(&self, domain: &str, ips: &[std::net::IpAddr]) -> bool {
        let mut sess = Session {
            id: 0,
            typ: crate::session::Type::RouteProbe,
            destination: crate::session::SocksAddr::Domain(domain.into(), 80),
            resolved_ip: ips.first().copied(),
            ..Default::default()
        };
        let (outbound, _) = self.match_route(&mut sess).await;
        outbound.eq_ignore_ascii_case("DIRECT")
    }

    /// Quick check if an IP address routes to DIRECT.
    pub async fn is_ip_direct(&self, ip: std::net::IpAddr) -> bool {
        let mut sess = Session {
            id: 0,
            typ: crate::session::Type::RouteProbe,
            destination: crate::session::SocksAddr::Ip(std::net::SocketAddr::new(ip, 80)),
            ..Default::default()
        };
        let (outbound, _) = self.match_route(&mut sess).await;
        outbound.eq_ignore_ascii_case("DIRECT")
    }

    /// this mutates the session, attaching resolved IP and ASN
    pub async fn match_route(
        &self,
        sess: &mut Session,
    ) -> (&str, Option<&Rule>) {
        // whether a DNS lookup has been *attempted* for this session — not
        // whether it succeeded. A domain that fails to resolve must not be
        // retried once per remaining IP rule.
        let mut sess_resolved = false;
        let mut process_resolved = false;

        // Pre-loop GeoIP/ASN resolution: if the session already has an IP address,
        // populate its geo metadata once to avoid repeated MaxMind lookups inside the rule loop.
        if let Some(ip) = sess.resolved_ip.or(sess.destination.ip()) {
            Self::populate_geo_for_ip(ip, &self.country_mmdb, &self.asn_mmdb, sess);
        }

        for r in self.rules.iter() {
            // Resolve IP when needed
            if sess.destination.is_domain()
                && r.should_resolve_ip()
                && sess.resolved_ip.is_none()
                && !sess_resolved
            {
                sess_resolved = true;

                if let Ok(Some(ip)) = self
                    .dns_resolver
                    .resolve(sess.destination.domain().unwrap(), false)
                    .await
                {
                    sess.resolved_ip = Some(ip);
                    // Populate geo metadata exactly once for the newly resolved IP
                    Self::populate_geo_for_ip(
                        ip,
                        &self.country_mmdb,
                        &self.asn_mmdb,
                        sess,
                    );
                }
            }

            // Resolve the owning process when needed. The lookup walks the OS
            // socket table and blocks, so it runs on the blocking pool, and at
            // most once per session no matter how many process rules follow.
            if r.should_resolve_process() && !process_resolved {
                process_resolved = true;

                let probe = sess.clone();
                sess.process_name = tokio::task::spawn_blocking(move || {
                    rules::process::find_process_name(&probe)
                })
                .await
                .unwrap_or_else(|e| {
                    trace!("process name lookup failed: {}", e);
                    None
                });
            }

            if r.apply(sess) {
                info!(
                    "matched {} to target {}[{}]",
                    &sess,
                    r.target(),
                    r.type_name()
                );
                return (r.target(), Some(r));
            }
        }

        (MATCH, None)
    }

    /// Look up country code and ASN for an IP address.
    /// Uses `country_mmdb` for the ISO 3166-1 alpha-2 country code.
    /// For ASN, preserves the original strategy: try
    /// `asn_mmdb.lookup_country()` first (simplified/fast path, e.g.
    /// Country.mmdb), fall back to `asn_mmdb.lookup_asn()` for the org
    /// name.
    fn populate_geo_for_ip(
        ip: std::net::IpAddr,
        country_mmdb: &Option<MmdbLookup>,
        asn_mmdb: &Option<MmdbLookup>,
        sess: &mut Session,
    ) {
        // Preserve existing geo metadata — avoids overriding prior enrichment
        if sess.country.is_some() && sess.asn.is_some() {
            return;
        }

        if sess.country.is_none()
            && let Some(country_mmdb) = country_mmdb
        {
            match country_mmdb.lookup_country(ip) {
                Ok(country) => {
                    trace!("country for {} is {:?}", ip, country.country_code);
                    sess.country = Some(country.country_code);
                }
                Err(e) => {
                    trace!("failed to lookup country for {}: {}", ip, e);
                }
            }
        }

        if sess.asn.is_none()
            && let Some(asn_mmdb) = asn_mmdb
        {
            // try simplified mmdb first (e.g. Country.mmdb doubles as a fast
            // country-code lookup on the asn_mmdb slot)
            if let Ok(country) = asn_mmdb.lookup_country(ip) {
                sess.asn = Some(country.country_code);
                return;
            }
            // fall back to full ASN lookup
            match asn_mmdb.lookup_asn(ip) {
                Ok(asn) => {
                    trace!("asn for {} is {:?}", ip, asn);
                    sess.asn = Some(asn.asn_name);
                }
                Err(e) => {
                    trace!("failed to lookup ASN for {}: {}", ip, e);
                }
            }
        }
    }

    async fn load_rule_providers(
        rule_providers: HashMap<String, RuleProviderDef>,
        rule_provider_registry: &mut HashMap<String, ThreadSafeRuleProvider>,
        resolver: ThreadSafeDNSResolver,
        system_resolver: Option<ThreadSafeDNSResolver>,
        outbound_registry: Option<OutboundHandlerRegistry>,
        mmdb: Option<MmdbLookup>,
        geodata: Option<GeoDataLookup>,
        cwd: String,
        provider_init_timeout: Duration,
    ) -> Result<(), Error> {
        for (name, provider) in rule_providers.into_iter() {
            match provider {
                RuleProviderDef::Http(http) => {
                    let resolver_to_use = if http.proxy.is_some() {
                        resolver.clone()
                    } else {
                        system_resolver.clone().unwrap_or_else(|| resolver.clone())
                    };

                    let vehicle = http_vehicle::Vehicle::new(
                        http.url.parse::<Uri>().unwrap_or_else(|_| {
                            print_and_exit!("invalid provider url: {}", http.url)
                        }),
                        http.path,
                        Some(cwd.clone()),
                        resolver_to_use,
                        http.proxy,
                        outbound_registry.clone(),
                        http.header,
                    );

                    // Default to yaml if not specified
                    let format = http.format.unwrap_or_default();
                    let provider = RuleProviderImpl::new(
                        name.clone(),
                        http.behavior,
                        format,
                        Some(Duration::from_secs(http.interval)),
                        Some(Arc::new(vehicle)),
                        mmdb.clone(),
                        geodata.clone(),
                        http.inline_rules,
                    );

                    rule_provider_registry.insert(name, Arc::new(provider));
                }
                RuleProviderDef::File(file) => {
                    let vehicle = file_vehicle::Vehicle::new(
                        PathBuf::from(cwd.clone())
                            .join(&file.path)
                            .to_str()
                            .unwrap(),
                    );

                    // Default to yaml if not specified
                    let format = file.format.unwrap_or_default();
                    let provider = RuleProviderImpl::new(
                        name.clone(),
                        file.behavior,
                        format,
                        Some(Duration::from_secs(file.interval.unwrap_or_default())),
                        Some(Arc::new(vehicle)),
                        mmdb.clone(),
                        geodata.clone(),
                        file.inline_rules,
                    );

                    rule_provider_registry.insert(name, Arc::new(provider));
                }
                RuleProviderDef::Inline(inline) => {
                    let provider = RuleProviderImpl::new(
                        name.clone(),
                        inline.behavior,
                        Default::default(), /* format really doesn't matter for
                                             * inline rules */
                        None,
                        None,
                        mmdb.clone(),
                        geodata.clone(),
                        Some(inline.inline_rules),
                    );

                    rule_provider_registry.insert(name, Arc::new(provider));
                }
            }
        }

        let tasks: Vec<_> = rule_provider_registry
            .values()
            .cloned()
            .map(|p| async move {
                info!("initializing rule provider {}", p.name());
                match tokio::time::timeout(provider_init_timeout, p.initialize()).await {
                    Ok(Ok(_)) => {
                        info!("rule provider {} initialized", p.name());
                        Ok(())
                    }
                    Ok(Err(err)) => {
                        error!(
                            "failed to initialize rule provider {}: {}",
                            p.name(),
                            err
                        );
                        Err((p.name().to_string(), err))
                    }
                    Err(_) => {
                        let err = io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("rule provider {} initialization timed out", p.name()),
                        );
                        error!("{}", err);
                        Err((p.name().to_string(), err))
                    }
                }
            })
            .collect();

        let results = join_all(tasks).await;
        let mut failed = Vec::new();
        for res in results {
            if let Err((name, err)) = res {
                failed.push((name, err));
            }
        }
        if !failed.is_empty() {
            let failed_info: Vec<String> = failed
                .into_iter()
                .map(|(name, err)| format!("{name}: {err}"))
                .collect();
            error!("failed to initialize rule providers: {}", failed_info.join("; "));
            return Err(Error::InvalidConfig(format!(
                "failed to initialize rule provider(s): {}",
                failed_info.join("; ")
            )));
        }

        Ok(())
    }

    /// API handlers
    pub fn get_all_rules(&self) -> &Vec<Rule> {
        &self.rules
    }
}

pub fn map_rule_type(
    rule_type: RuleType,
    mmdb: Option<MmdbLookup>,
    geodata: Option<GeoDataLookup>,
    rule_provider_registry: Option<&HashMap<String, ThreadSafeRuleProvider>>,
) -> Result<Rule, Error> {
    match rule_type {
        RuleType::Domain { domain, target } => {
            Ok(Rule::Domain(Domain { domain, target }))
        }
        RuleType::DomainRegex { regex, target } => {
            Ok(Rule::DomainRegex(DomainRegex { regex, target }))
        }
        RuleType::DomainSuffix {
            domain_suffix,
            target,
        } => Ok(Rule::DomainSuffix(DomainSuffix {
            suffix: domain_suffix,
            target,
        })),
        RuleType::DomainKeyword {
            domain_keyword,
            target,
        } => Ok(Rule::DomainKeyword(DomainKeyword {
            keyword: domain_keyword,
            target,
        })),
        RuleType::IpCidr {
            ipnet,
            target,
            no_resolve,
        } => Ok(Rule::IpCidr(IpCidr {
            ipnet,
            target,
            no_resolve,
            match_src: false,
        })),
        RuleType::SrcCidr {
            ipnet,
            target,
            no_resolve,
        } => Ok(Rule::IpCidr(IpCidr {
            ipnet,
            target,
            no_resolve,
            match_src: true,
        })),

        RuleType::GeoIP {
            target,
            country_code,
            no_resolve,
        } => Ok(Rule::GeoIP(rules::geoip::GeoIP {
            target,
            country_code,
            no_resolve,
            mmdb: mmdb.clone(),
        })),
        RuleType::GeoSite {
            target,
            country_code,
        } => {
            let res = rules::geodata::GeoSiteMatcher::new(
                country_code,
                target,
                geodata.as_ref(),
            )?;
            Ok(Rule::GeoSite(res))
        }
        RuleType::SRCPort { target, port } => Ok(Rule::Port(rules::port::Port {
            port,
            target,
            is_src: true,
        })),
        RuleType::DSTPort { target, port } => Ok(Rule::Port(rules::port::Port {
            port,
            target,
            is_src: false,
        })),
        RuleType::ProcessName {
            process_name,
            target,
        } => Ok(Rule::Process(rules::process::Process {
            name: process_name,
            target,
            name_only: true,
        })),
        RuleType::ProcessPath {
            process_path,
            target,
        } => Ok(Rule::Process(rules::process::Process {
            name: process_path,
            target,
            name_only: false,
        })),
        RuleType::RuleSet {
            rule_set,
            target,
            no_resolve,
        } => match rule_provider_registry {
            Some(rule_provider_registry) => {
                let provider = rule_provider_registry
                    .get(&rule_set)
                    .ok_or_else(|| Error::InvalidConfig(format!("rule provider {} not found", rule_set)))?;
                Ok(Rule::RuleSet(RuleSet::new(
                    rule_set,
                    target,
                    provider.clone(),
                    no_resolve,
                )))
            }
            None => Err(Error::InvalidConfig(format!(
                "nested RULE-SET is not supported: {rule_set}"
            ))),
        },
        RuleType::Network { network, target } => {
            Ok(Rule::Network(rules::network::NetworkRule { network, target }))
        }
        RuleType::Composite {
            operator,
            expression,
            target,
        } => {
            let rule = rules::composite::CompositeRule::new(
                &operator,
                &expression,
                &target,
                mmdb,
                geodata,
                rule_provider_registry,
            )?;
            Ok(Rule::Composite(rule))
        }
        RuleType::Match { target } => Ok(Rule::Final(Final { target })),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use anyhow::Ok;

    use crate::{
        app::{
            dns::{MockClashResolver, SystemResolver},
            remote_content_manager::providers::rule_provider::RuleSetBehavior,
        },
        common::{
            geodata::{DEFAULT_GEOSITE_DOWNLOAD_URL, GeoData},
            http::new_http_client,
            mmdb::{DEFAULT_COUNTRY_MMDB_DOWNLOAD_URL, Mmdb},
        },
        config::internal::{
            config::{InlineRuleProvider, RuleProviderDef},
            rule::RuleType,
        },
        session::Session,
        tests::initialize,
    };

    #[tokio::test]
    async fn test_route_match() {
        initialize();

        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_resolve().returning(|host, _| {
            if host == "china.com" {
                Ok(Some("114.114.114.114".parse().unwrap()))
            } else if host == "t.me" {
                Ok(Some("149.154.0.1".parse().unwrap()))
            } else if host == "git.io" {
                Ok(Some("8.8.8.8".parse().unwrap()))
            } else {
                Ok(None)
            }
        });
        let mock_resolver = Arc::new(mock_resolver);

        let real_resolver = Arc::new(SystemResolver::new(false).unwrap());

        let client = new_http_client(real_resolver.clone(), None).unwrap();

        let temp_dir = tempfile::tempdir().unwrap();

        let mmdb = Mmdb::new(
            temp_dir.path().join("mmdb.mmdb"),
            DEFAULT_COUNTRY_MMDB_DOWNLOAD_URL.to_string(),
            client,
        )
        .await
        .unwrap();

        let client = new_http_client(real_resolver.clone(), None).unwrap();

        let geodata = GeoData::new(
            temp_dir.path().join("geodata.geodata"),
            DEFAULT_GEOSITE_DOWNLOAD_URL.to_string(),
            client,
        )
        .await
        .unwrap();

        let router = super::Router::new(
            vec![
                RuleType::GeoIP {
                    target: "DIRECT".to_string(),
                    country_code: "CN".to_string(),
                    no_resolve: false,
                },
                RuleType::DomainRegex {
                    regex: regex::Regex::new(r"^regex").unwrap(),
                    target: "regex-match".to_string(),
                },
                RuleType::DomainSuffix {
                    domain_suffix: "t.me".to_string(),
                    target: "DS".to_string(),
                },
                RuleType::IpCidr {
                    ipnet: "149.154.0.0/16".parse().unwrap(),
                    target: "IC".to_string(),
                    no_resolve: false,
                },
                RuleType::DomainSuffix {
                    domain_suffix: "git.io".to_string(),
                    target: "DS2".to_string(),
                },
            ],
            Default::default(),
            mock_resolver,
            None,
            None,
            Some(Arc::new(mmdb)),
            None,
            Some(Arc::new(geodata)),
            temp_dir.path().to_str().unwrap().to_string(),
        )
        .await
        .unwrap();

        let cases = vec![
            ("china.com", "DIRECT", "should resolve and match IP"),
            ("regex", "regex-match", "should match regex"),
            ("t.me", "DS", "should match domain"),
            (
                "git.io",
                "DS2",
                "should still match domain after previous rule resolved IP and non \
                 match",
            ),
            (
                "no-match",
                "MATCH",
                "should fallback to MATCH when nothing matched",
            ),
            ("149.154.0.1", "IC", "should match CIDR"),
        ];

        for (domain, target, desc) in cases {
            assert_eq!(
                router
                    .match_route(&mut Session {
                        destination: crate::session::SocksAddr::Domain(
                             domain.into(),
                            1111
                        ),
                        ..Default::default()
                    })
                    .await
                    .0,
                target,
                "{}",
                desc
            );
        }
    }

    #[tokio::test]
    async fn test_network_rule() {
        initialize();
        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_resolve().returning(|_, _| Ok(None));
        let mock_resolver = Arc::new(mock_resolver);

        let router = super::Router::new(
            vec![
                RuleType::Network {
                    network: crate::session::Network::Tcp,
                    target: "TCP-PROXY".to_string(),
                },
                RuleType::Network {
                    network: crate::session::Network::Udp,
                    target: "UDP-PROXY".to_string(),
                },
            ],
            Default::default(),
            mock_resolver,
            None,
            None,
            None,
            None,
            None,
            std::env::temp_dir().to_str().unwrap().to_string(),
        )
        .await
        .unwrap();

        // Test TCP network rule
        let mut tcp_session = Session {
            network: crate::session::Network::Tcp,
            destination: crate::session::SocksAddr::Domain(
                "example.com".into(),
                443,
            ),
            ..Default::default()
        };
        assert_eq!(
            router.match_route(&mut tcp_session).await.0,
            "TCP-PROXY",
            "should match TCP network rule"
        );

        // Test UDP network rule
        let mut udp_session = Session {
            network: crate::session::Network::Udp,
            destination: crate::session::SocksAddr::Domain(
                "example.com".into(),
                53,
            ),
            ..Default::default()
        };
        assert_eq!(
            router.match_route(&mut udp_session).await.0,
            "UDP-PROXY",
            "should match UDP network rule"
        );
    }

    #[tokio::test]
    async fn test_router_rule_provider_initialization() {
        initialize();
        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_resolve().returning(|_, _| Ok(None));
        let mock_resolver = Arc::new(mock_resolver);

        let mut providers = HashMap::new();
        providers.insert(
            "test_provider".to_string(),
            RuleProviderDef::Inline(InlineRuleProvider {
                path: "rules/test".to_string(),
                behavior: RuleSetBehavior::Domain,
                inline_rules: vec!["custom.domain.com".to_string()],
            }),
        );

        let router = super::Router::new(
            vec![
                RuleType::RuleSet {
                    rule_set: "test_provider".to_string(),
                    target: "RULESET-HIT".to_string(),
                    no_resolve: true,
                },
            ],
            providers,
            mock_resolver,
            None,
            None,
            None,
            None,
            None,
            std::env::temp_dir().to_str().unwrap().to_string(),
        )
        .await
        .unwrap();

        let provider = router.get_rule_providers().get("test_provider").unwrap();
        // Provider must already be initialized upon Router::new return
        assert_eq!(provider.count(), 1);

        let mut sess = Session {
            destination: crate::session::SocksAddr::Domain("custom.domain.com".into(), 80),
            ..Default::default()
        };
        assert_eq!(router.match_route(&mut sess).await.0, "RULESET-HIT");
    }

    #[tokio::test]
    async fn test_router_failed_rule_provider_returns_err() {
        initialize();
        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_resolve().returning(|_, _| Ok(None));
        let mock_resolver = Arc::new(mock_resolver);

        use crate::config::internal::config::FileRuleProvider;

        let mut providers = HashMap::new();
        providers.insert(
            "broken_provider".to_string(),
            RuleProviderDef::File(FileRuleProvider {
                path: "non_existent_file_xyz_123.yaml".to_string(),
                behavior: RuleSetBehavior::Domain,
                interval: None,
                format: None,
                inline_rules: None,
            }),
        );

        let res = super::Router::new(
            vec![],
            providers,
            mock_resolver,
            None,
            None,
            None,
            None,
            None,
            std::env::temp_dir().to_str().unwrap().to_string(),
        )
        .await;

        assert!(res.is_err(), "Router::new should fail when provider fails to load");
    }

    #[tokio::test]
    async fn test_router_unknown_rule_set_returns_err() {
        initialize();
        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_resolve().returning(|_, _| Ok(None));
        let mock_resolver = Arc::new(mock_resolver);

        let res = super::Router::new(
            vec![
                RuleType::RuleSet {
                    rule_set: "non_existent_provider".to_string(),
                    target: "HIT".to_string(),
                    no_resolve: true,
                },
            ],
            HashMap::new(),
            mock_resolver,
            None,
            None,
            None,
            None,
            None,
            std::env::temp_dir().to_str().unwrap().to_string(),
        )
        .await;

        assert!(res.is_err(), "Router::new should fail when rule set is not found");
    }

    #[tokio::test]
    async fn test_domain_regex_with_parentheses_in_router() {
        initialize();
        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_resolve().returning(|_, _| Ok(None));
        let mock_resolver = Arc::new(mock_resolver);

        // A rule with parentheses like DOMAIN-REGEX,^foo(bar)\.com$,PROXY
        // followed by a fallback DIRECT rule
        let rule1 = RuleType::try_from("DOMAIN-REGEX,^foo(bar)\\.com$,PROXY".to_string()).unwrap();
        let rule2 = RuleType::try_from("MATCH,DIRECT".to_string()).unwrap();

        let router = super::Router::new(
            vec![rule1, rule2],
            HashMap::new(),
            mock_resolver,
            None,
            None,
            None,
            None,
            None,
            std::env::temp_dir().to_str().unwrap().to_string(),
        )
        .await
        .unwrap();

        // Matching domain hits PROXY
        let mut sess1 = Session {
            destination: crate::session::SocksAddr::Domain("foobar.com".into(), 80),
            ..Default::default()
        };
        assert_eq!(router.match_route(&mut sess1).await.0, "PROXY");

        // Non-matching domain must fall through to DIRECT (NOT get rejected!)
        let mut sess2 = Session {
            destination: crate::session::SocksAddr::Domain("other.com".into(), 80),
            ..Default::default()
        };
        assert_eq!(router.match_route(&mut sess2).await.0, "DIRECT");
    }

    #[tokio::test]
    async fn test_lowercase_composite_rule_in_router() {
        initialize();
        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_resolve().returning(|_, _| Ok(None));
        let mock_resolver = Arc::new(mock_resolver);

        let rule = RuleType::try_from("and,((DOMAIN,example.com),(NETWORK,TCP)),COMPOSITE-HIT".to_string()).unwrap();

        let router = super::Router::new(
            vec![rule],
            HashMap::new(),
            mock_resolver,
            None,
            None,
            None,
            None,
            None,
            std::env::temp_dir().to_str().unwrap().to_string(),
        )
        .await
        .unwrap();

        let mut sess = Session {
            network: crate::session::Network::Tcp,
            destination: crate::session::SocksAddr::Domain("example.com".into(), 80),
            ..Default::default()
        };
        assert_eq!(router.match_route(&mut sess).await.0, "COMPOSITE-HIT");
    }

    #[tokio::test]
    async fn test_domain_regex_with_commas_in_router() {
        initialize();
        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_resolve().returning(|_, _| Ok(None));
        let mock_resolver = Arc::new(mock_resolver);

        let rule = RuleType::try_from("DOMAIN-REGEX,^foo,bar$,REGEX-HIT".to_string()).unwrap();

        let router = super::Router::new(
            vec![rule],
            HashMap::new(),
            mock_resolver,
            None,
            None,
            None,
            None,
            None,
            std::env::temp_dir().to_str().unwrap().to_string(),
        )
        .await
        .unwrap();

        let mut sess = Session {
            destination: crate::session::SocksAddr::Domain("foo,bar".into(), 80),
            ..Default::default()
        };
        assert_eq!(router.match_route(&mut sess).await.0, "REGEX-HIT");
    }

    #[tokio::test]
    async fn test_router_rule_provider_timeout_returns_err() {
        initialize();
        use httpmock::{Method::GET, MockServer};
        use std::{
            result::Result::{Err, Ok},
            time::Duration,
        };

        let server = MockServer::start();
        let _mock = server.mock(|when, then| {
            when.method(GET).path("/slow_provider.yaml");
            then.delay(Duration::from_millis(500))
                .status(200)
                .body("payload:\n  - DOMAIN,example.com");
        });

        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_resolve().returning(|_, _| Ok(None));
        let mock_resolver = Arc::new(mock_resolver);

        use crate::config::internal::config::HttpRuleProvider;

        let mut providers = HashMap::new();
        providers.insert(
            "timeout_provider".to_string(),
            RuleProviderDef::Http(HttpRuleProvider {
                url: server.url("/slow_provider.yaml"),
                path: "cache/slow_provider.yaml".to_string(),
                interval: 3600,
                behavior: RuleSetBehavior::Domain,
                format: Some(crate::app::remote_content_manager::providers::rule_provider::RuleSetFormat::Yaml),
                proxy: None,
                header: None,
                inline_rules: None,
            }),
        );

        let temp_dir = tempfile::tempdir().unwrap();

        let res = super::Router::new_with_timeout(
            vec![],
            providers,
            mock_resolver,
            None,
            None,
            None,
            None,
            None,
            temp_dir.path().to_str().unwrap().to_string(),
            Duration::from_millis(50),
        )
        .await;

        match res {
            Ok(_) => panic!("Router::new should fail when provider times out"),
            Err(err) => {
                let err_msg = err.to_string();
                assert!(
                    err_msg.contains("timed out"),
                    "Error should mention timed out, got: {err_msg}"
                );
            }
        }
    }
}
