use std::{collections::HashMap, fmt::Display, sync::Arc, time::Duration};

use async_trait::async_trait;
use erased_serde::Serialize as ESerialize;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use super::cidr_trie::CidrTrie;
use crate::{
    Error,
    app::{
        remote_content_manager::providers::{
            Provider, ProviderType, ProviderVehicleType, ThreadSafeProviderVehicle,
            fetcher::Fetcher,
        },
        router::{RuleMatcher, map_rule_type},
    },
    common::{
        errors::map_io_error, geodata::GeoDataLookup, mmdb::MmdbLookup,
        succinct_set, trie,
    },
    config::internal::rule::RuleType,
    session::Session,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ProviderScheme {
    pub payload: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleSetFormat {
    #[default]
    Yaml,
    Text,
    Mrs,
}

impl Display for RuleSetFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleSetFormat::Yaml => write!(f, "yaml"),
            RuleSetFormat::Text => write!(f, "text"),
            RuleSetFormat::Mrs => write!(f, "mrs"),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RuleSetBehavior {
    /// Rule contents will be built into a DomainSet
    Domain,
    /// Rule contents will be built into a IpCidr Trie
    Ipcidr,
    /// Classical line based rules
    Classical,
}

impl Display for RuleSetBehavior {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleSetBehavior::Domain => write!(f, "Domain"),
            RuleSetBehavior::Ipcidr => write!(f, "IPCIDR"),
            RuleSetBehavior::Classical => write!(f, "Classical"),
        }
    }
}

pub enum RuleContent {
    // the left will converted into a right
    Domain(succinct_set::DomainSet),
    Ipcidr(Box<CidrTrie>),
    Classical(Vec<Box<dyn RuleMatcher>>),
}

struct Inner {
    content: RuleContent,
}

/// Invoked after a [`RuleProvider`]'s contents are replaced. See
/// [`RuleProvider::on_change`]. `Arc` rather than `Box` so the subscriber list
/// can be cloned out before dispatch, keeping the lock un-held while callbacks
/// run.
pub type RuleSetChangeCallback = Arc<dyn Fn() + Send + Sync + 'static>;

/// Clone the subscriber list out before dispatching so the lock is not held
/// while callbacks run — a callback that registered another one would otherwise
/// deadlock on the non-reentrant `RwLock`.
fn notify_subscribers(subscribers: &std::sync::RwLock<Vec<RuleSetChangeCallback>>) {
    let callbacks = match subscribers.read() {
        Ok(guard) => guard.clone(),
        Err(_) => return,
    };
    for cb in callbacks {
        cb();
    }
}

#[async_trait]
pub trait RuleProvider: Provider {
    fn search(&self, sess: &Session) -> bool;
    fn behavior(&self) -> RuleSetBehavior;
    fn format(&self) -> RuleSetFormat;
    /// Whether matching against this provider needs the destination domain to
    /// be resolved to an IP first. Always true for IPCIDR providers; for
    /// classical ones it depends on the rules currently loaded.
    fn should_resolve_ip(&self) -> bool;
    /// Whether matching needs [`Session::process_name`] populated. Only
    /// classical providers can carry PROCESS-NAME/PROCESS-PATH rules.
    fn should_resolve_process(&self) -> bool;
    /// Number of entries currently loaded, for the `/rules` API.
    fn count(&self) -> usize;
    /// Register `cb` to run right after this provider's contents are replaced,
    /// by either a periodic refresh or a manual update. Callers that memoize
    /// [`RuleProvider::search`] results use this to drop their caches instead of
    /// serving verdicts computed against rules that no longer exist (see
    /// `FakeDns::should_skip`).
    ///
    /// Callbacks run synchronously on the updating task, so they must be cheap
    /// and must not block. They are invoked after the content lock is released,
    /// so calling back into the provider is safe. Registrations are never
    /// removed — callbacks are expected to live as long as the process.
    fn on_change(&self, cb: RuleSetChangeCallback);
    /// Returns up to `limit` rules as strings. Only Classical providers return
    /// non-empty results; Domain/IPCIDR data structures don't support
    /// enumeration.
    async fn list_rules(&self, limit: usize) -> Vec<String> {
        let _ = limit;
        vec![]
    }
    /// Returns all IP/CIDR subnets contained in this provider if it is an IPCIDR provider.
    fn get_ip_cidrs(&self) -> Vec<ipnet::IpNet> {
        vec![]
    }
}

pub type ThreadSafeRuleProvider = Arc<dyn RuleProvider + Send + Sync>;

type RuleUpdater =
    Box<dyn Fn(RuleContent) -> BoxFuture<'static, ()> + Send + Sync + 'static>;
type RuleParser =
    Box<dyn Fn(&[u8]) -> anyhow::Result<RuleContent> + Send + Sync + 'static>;

pub struct RuleProviderImpl {
    name: String,
    fetcher: Option<Fetcher<RuleUpdater, RuleParser>>,
    inner: Arc<std::sync::RwLock<Inner>>,
    behavior: RuleSetBehavior,
    format: RuleSetFormat,
    inline_rules: Option<Vec<String>>,
    /// Notified on every content swap. See [`RuleProvider::on_change`].
    subscribers: Arc<std::sync::RwLock<Vec<RuleSetChangeCallback>>>,

    mmdb: Option<MmdbLookup>,
    geodata: Option<GeoDataLookup>,
}

impl RuleProviderImpl {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        behavior: RuleSetBehavior,
        format: RuleSetFormat,
        // InlineRuleProvider doesn't have an interval and vehicle
        interval: Option<Duration>,
        vehicle: Option<ThreadSafeProviderVehicle>,
        mmdb: Option<MmdbLookup>,
        geodata: Option<GeoDataLookup>,
        inline_rules: Option<Vec<String>>,
    ) -> Self {
        let inner = Arc::new(std::sync::RwLock::new(Inner {
            content: match behavior {
                RuleSetBehavior::Domain => {
                    RuleContent::Domain(succinct_set::DomainSet::default())
                }
                RuleSetBehavior::Ipcidr => {
                    RuleContent::Ipcidr(Box::new(CidrTrie::new()))
                }
                RuleSetBehavior::Classical => RuleContent::Classical(vec![]),
            },
        }));

        let inner_clone = inner.clone();
        let subscribers: Arc<std::sync::RwLock<Vec<RuleSetChangeCallback>>> =
            Arc::new(std::sync::RwLock::new(Vec::new()));
        let subscribers_clone = subscribers.clone();

        let n = name.clone();
        let updater: RuleUpdater =
            Box::new(move |input: RuleContent| -> BoxFuture<'static, ()> {
                let n = n.clone(); // Clone name for the async block
                let inner: Arc<std::sync::RwLock<Inner>> = inner_clone.clone();
                let subscribers = subscribers_clone.clone();
                Box::pin(async move {
                    {
                        let mut inner = inner.write().unwrap();
                        trace!("updated rules for provider: {}", n);
                        inner.content = input;
                    }
                    // Notify only after the content lock is released, so a
                    // callback that reads the provider back cannot deadlock.
                    notify_subscribers(&subscribers);
                })
            });

        let n_parser = name.clone(); // Clone name specifically for the parser closure
        let current_behavior = behavior;
        let current_format = format;
        let inline_rules_clone = inline_rules.clone();
        let mmdb_clone = mmdb.clone();
        let geodata_clone = geodata.clone();
        let parser: RuleParser =
            Box::new(move |input: &[u8]| -> anyhow::Result<RuleContent> {
                match current_format {
                    RuleSetFormat::Yaml => {
                        let scheme: ProviderScheme = serde_yaml::from_slice(input)
                            .map_err(|x| {
                            Error::InvalidConfig(format!(
                                "rule provider parse error (yaml) {n_parser}: {x}"
                            ))
                        })?;

                        // Fn: we need to clone the values anyway to avoid moving
                        // `inline_rules` from the "Environment"
                        let mut payload =
                            inline_rules_clone.clone().unwrap_or_default();
                        payload.extend(scheme.payload);

                        // For Yaml, we still need to convert Vec<String> to
                        // RuleContent
                        make_rules(
                            current_behavior,
                            payload,
                            mmdb_clone.clone(),
                            geodata_clone.clone(),
                        )
                        .map_err(anyhow::Error::new)
                    }
                    RuleSetFormat::Text => {
                        let text = std::str::from_utf8(input).map_err(|e| {
                            Error::InvalidConfig(format!(
                                "invalid utf-8 in text rule provider {n_parser}: \
                                 {e}"
                            ))
                        })?;

                        let mut payload: Vec<String> = text
                            .lines()
                            .map(str::trim)
                            .filter(|line| {
                                !line.is_empty()
                                    && !line.starts_with('#')
                                    && !line.starts_with("//")
                            })
                            .map(String::from)
                            .collect();

                        if let Some(inline) = inline_rules_clone.clone() {
                            payload.extend(inline);
                        }

                        // For Text, we also convert Vec<String> to RuleContent
                        make_rules(
                            current_behavior,
                            payload,
                            mmdb_clone.clone(),
                            geodata_clone.clone(),
                        )
                        .map_err(anyhow::Error::new)
                    }
                    RuleSetFormat::Mrs => {
                        if matches!(current_behavior, RuleSetBehavior::Classical) {
                            return Err(anyhow::Error::new(Error::InvalidConfig(
                                format!(
                                    "MRS format is not supported for classical \
                                     behavior in rule provider {n_parser}"
                                ),
                            )));
                        }
                        // Parse MRS format using the updated function signature.
                        // It directly returns the required RuleContent.
                        super::mrs::rules_mrs_parse(input, current_behavior)
                    }
                }
            });

        let fetcher = if let Some(interval) = interval
            && let Some(vehicle) = vehicle
        {
            Some(Fetcher::new(
                name.clone(),
                interval,
                vehicle,
                parser,
                Some(updater),
            ))
        } else {
            None
        };

        Self {
            name,
            fetcher,
            inner,
            behavior,
            format,
            inline_rules,
            subscribers,

            mmdb,
            geodata,
        }
    }
}

#[async_trait]
impl RuleProvider for RuleProviderImpl {
    fn search(&self, sess: &Session) -> bool {
        let inner = self.inner.read().unwrap();
        match &inner.content {
            RuleContent::Domain(set) => set.has(&sess.destination.host()),
            // mirror the standalone IP-CIDR rule: prefer the locally resolved
            // IP, and never fall back to a placeholder address — doing so made
            // every domain connection match a provider containing 0.0.0.0/8.
            RuleContent::Ipcidr(trie) => sess
                .resolved_ip
                .or(sess.destination.ip())
                .is_some_and(|ip| trie.contains(ip)),
            RuleContent::Classical(rules) => {
                for rule in rules.iter() {
                    if rule.apply(sess) {
                        return true;
                    }
                }
                false
            }
        }
    }

    fn behavior(&self) -> RuleSetBehavior {
        self.behavior
    }

    fn format(&self) -> RuleSetFormat {
        self.format
    }

    fn should_resolve_ip(&self) -> bool {
        match self.behavior {
            RuleSetBehavior::Domain => false,
            RuleSetBehavior::Ipcidr => true,
            RuleSetBehavior::Classical => {
                let inner = self.inner.read().unwrap();
                match &inner.content {
                    RuleContent::Classical(rules) => {
                        rules.iter().any(|r| r.should_resolve_ip())
                    }
                    _ => false,
                }
            }
        }
    }

    fn should_resolve_process(&self) -> bool {
        let inner = self.inner.read().unwrap();
        match &inner.content {
            RuleContent::Classical(rules) => {
                rules.iter().any(|r| r.should_resolve_process())
            }
            _ => false,
        }
    }

    fn count(&self) -> usize {
        let inner = self.inner.read().unwrap();
        match &inner.content {
            RuleContent::Domain(set) => set.len(),
            RuleContent::Ipcidr(trie) => trie.len(),
            RuleContent::Classical(rules) => rules.len(),
        }
    }

    fn on_change(&self, cb: RuleSetChangeCallback) {
        if let Ok(mut subscribers) = self.subscribers.write() {
            subscribers.push(cb);
        }
    }

    async fn list_rules(&self, limit: usize) -> Vec<String> {
        let inner = self.inner.read().unwrap();
        match &inner.content {
            RuleContent::Classical(rules) => rules
                .iter()
                .take(limit)
                .map(|r| format!("{},{}", r.type_name(), r.payload()))
                .collect(),
            _ => vec![],
        }
    }

    fn get_ip_cidrs(&self) -> Vec<ipnet::IpNet> {
        let inner = self.inner.read().unwrap();
        match &inner.content {
            RuleContent::Ipcidr(trie) => trie.get_ip_cidrs(),
            _ => vec![],
        }
    }
}

#[async_trait]
impl Provider for RuleProviderImpl {
    fn name(&self) -> &str {
        &self.name
    }

    fn vehicle_type(&self) -> ProviderVehicleType {
        if let Some(fetcher) = &self.fetcher {
            fetcher.vehicle_type()
        } else {
            ProviderVehicleType::Inline
        }
    }

    fn typ(&self) -> ProviderType {
        ProviderType::Rule
    }

    async fn initialize(&self) -> std::io::Result<()> {
        debug!("initializing rule provider {}", self.name());

        if let Some(fetcher) = &self.fetcher {
            trace!("initializing rule provider {} with fetcher", self.name());
            let ele = fetcher.initial().await.map_err(map_io_error)?;
            if let Some(updater) = fetcher.on_update.as_ref() {
                updater(ele).await; // Directly pass RuleContent
            }
        } else {
            trace!("initializing inline rule provider {}", self.name());
            let rules = make_rules(
                self.behavior,
                self.inline_rules.clone().unwrap_or_default(),
                self.mmdb.clone(),
                self.geodata.clone(),
            );

            match rules {
                Ok(content) => {
                    {
                        let mut inner = self.inner.write().unwrap();
                        inner.content = content;
                    }
                    notify_subscribers(&self.subscribers);
                }
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "failed to initialize inline rule provider {}: {}",
                            self.name(),
                            e
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    async fn update(&self) -> std::io::Result<()> {
        if let Some(fetcher) = &self.fetcher {
            let (ele, same) = fetcher.update().await.map_err(map_io_error)?;
            debug!("rule provider {} updated. same? {}", self.name(), same);
            if !same && let Some(updater) = fetcher.on_update.as_ref() {
                updater(ele).await; // Directly pass RuleContent
            }
        } else {
            trace!("no fetcher for rule provider {}", self.name());
        }

        Ok(())
    }

    async fn as_map(&self) -> HashMap<String, Box<dyn ESerialize + Send>> {
        let mut m: HashMap<String, Box<dyn ESerialize + Send>> = HashMap::new();

        m.insert("name".to_owned(), Box::new(self.name().to_string()));
        m.insert("type".to_owned(), Box::new(self.typ().to_string()));
        m.insert(
            "vehicleType".to_owned(),
            Box::new(self.vehicle_type().to_string()),
        );

        if let Some(fetcher) = &self.fetcher {
            m.insert("updatedAt".to_owned(), Box::new(fetcher.updated_at().await));
        }

        m.insert("behavior".to_owned(), Box::new(self.behavior().to_string()));
        m.insert("format".to_owned(), Box::new(self.format().to_string()));

        m
    }
}

// --- make_rules is needed for Yaml and Text formats ---
fn make_rules(
    behavior: RuleSetBehavior,
    rules: Vec<String>, // Input is Vec<String> for Yaml/Text
    mmdb: Option<MmdbLookup>,
    geodata: Option<GeoDataLookup>,
) -> Result<RuleContent, Error> {
    match behavior {
        RuleSetBehavior::Domain => {
            let s = make_domain_rules(rules)?;
            Ok(RuleContent::Domain(s.into()))
        }
        RuleSetBehavior::Ipcidr => {
            Ok(RuleContent::Ipcidr(Box::new(make_ip_cidr_rules(rules)?)))
        }
        RuleSetBehavior::Classical => Ok(RuleContent::Classical(
            make_classical_rules(rules, mmdb, geodata)?,
        )),
    }
}

fn make_domain_rules(rules: Vec<String>) -> Result<trie::StringTrie<bool>, Error> {
    let mut trie = trie::StringTrie::new();
    for rule in rules {
        trie.insert(&rule, Arc::new(true));
    }
    Ok(trie)
}

fn make_ip_cidr_rules(rules: Vec<String>) -> Result<CidrTrie, Error> {
    let mut trie = CidrTrie::new();
    for rule in rules {
        trie.insert(&rule);
    }
    Ok(trie)
}

fn make_classical_rules(
    rules: Vec<String>,
    mmdb: Option<MmdbLookup>,
    geodata: Option<GeoDataLookup>,
) -> Result<Vec<Box<dyn RuleMatcher>>, Error> {
    let mut rv = vec![];
    for rule in rules {
        let parts = rule.split(',').map(str::trim).collect::<Vec<&str>>();

        // the rule inside RULE-SET is slightly different from the rule in
        // config the target is always empty as it's held in the
        // RULE-SET container let's parse it manually
        let rule_type = match parts.as_slice() {
            [proto, payload] => RuleType::new(proto, payload, "", None),
            [proto, payload, params @ ..] => {
                RuleType::new(proto, payload, "", Some(params.to_vec()))
            }
            _ => Err(Error::InvalidConfig(format!("invalid rule line: {rule}"))),
        }?;

        let rule_matcher =
            map_rule_type(rule_type, mmdb.clone(), geodata.clone(), None);
        rv.push(rule_matcher);
    }
    Ok(rv)
}

#[cfg(test)]
mod tests {
    use crate::{
        app::remote_content_manager::providers::{
            MockProviderVehicle, Provider, ProviderVehicleType,
            rule_provider::{
                RuleProviderImpl, RuleSetBehavior, RuleSetFormat,
                provider::RuleProvider,
            },
        },
        common::{geodata::MockGeoDataLookupTrait, mmdb::MockMmdbLookupTrait},
        session::{Session, SocksAddr},
    };
    use std::{path::Path, sync::Arc, time::Duration};
    use tokio_test::assert_ok;

    #[tokio::test]
    async fn test_inline_provider() {
        let mock_mmdb = MockMmdbLookupTrait::new();
        let mock_geodata = MockGeoDataLookupTrait::new();

        let provider = RuleProviderImpl::new(
            "test".to_string(),
            RuleSetBehavior::Classical,
            RuleSetFormat::Text,
            None,
            None,
            Some(Arc::new(mock_mmdb)),
            Some(Arc::new(mock_geodata)),
            Some(vec!["DOMAIN-SUFFIX, google.com".to_owned()]),
        );

        assert_ok!(provider.initialize().await);

        let sess = Session {
            destination: SocksAddr::Domain("test.google.com".to_owned(), 443),
            ..Default::default()
        };
        assert!(provider.search(&sess));
    }

    #[tokio::test]
    async fn test_file_provider_with_inline_rules() {
        let mock_mmdb = MockMmdbLookupTrait::new();
        let mock_geodata = MockGeoDataLookupTrait::new();
        let mut mock_vehicle = MockProviderVehicle::new();

        let mock_file = std::env::temp_dir().join(format!(
            "{}-{}",
            "mock_provider_vehicle",
            uuid::Uuid::new_v4()
        ));
        if Path::new(mock_file.to_str().unwrap()).exists() {
            std::fs::remove_file(&mock_file).unwrap();
        }
        std::fs::write(&mock_file, "twitter.com").unwrap();

        mock_vehicle
            .expect_path()
            .return_const(mock_file.to_str().unwrap().to_owned());
        mock_vehicle
            .expect_read()
            .returning(|| Ok("twitter.com".into()));
        mock_vehicle
            .expect_typ()
            .return_const(ProviderVehicleType::File);

        let provider = RuleProviderImpl::new(
            "test".to_string(),
            RuleSetBehavior::Domain,
            RuleSetFormat::Text,
            Some(Duration::from_secs(5)),
            Some(Arc::new(mock_vehicle)),
            Some(Arc::new(mock_mmdb)),
            Some(Arc::new(mock_geodata)),
            Some(vec!["+.google.com".to_owned()]),
        );

        assert_ok!(provider.initialize().await);

        assert!(provider.search(&Session {
            destination: SocksAddr::Domain("test.google.com".to_owned(), 443),
            ..Default::default()
        }));
    }
}
