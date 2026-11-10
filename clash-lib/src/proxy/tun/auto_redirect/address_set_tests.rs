use std::{collections::HashMap, fs, process::Command, sync::Arc, time::Duration};

use tempfile::tempdir;
use tracing::Instrument;
use tracing_test::traced_test;
use tokio::time::{sleep, timeout};

use crate::{
    app::remote_content_manager::providers::{
        file_vehicle::Vehicle,
        rule_provider::{RuleProviderImpl, RuleSetBehavior, RuleSetFormat, ThreadSafeRuleProvider},
    },
    config::internal::config::TunConfig,
};
use super::{AutoRedirect, address_sets::RouteAddressSets};

// Execute in a fresh user/network namespace: unshare -Urn <binary> <name> --ignored.
#[tokio::test]
#[traced_test]
#[ignore = "requires nftables and an isolated network namespace"]
async fn nftables_address_sets_follow_provider_updates() {
    super::test_interface();
    let directory = tempdir().unwrap();
    let path = directory.path().join("networks.txt");
    fs::write(&path, "198.18.0.0/16\nfd01::/16\n").unwrap();
    let provider: ThreadSafeRuleProvider = Arc::new(RuleProviderImpl::new(
        "networks".into(), RuleSetBehavior::Ipcidr, RuleSetFormat::Text,
        Some(Duration::ZERO), Some(Arc::new(Vehicle::new(path.to_str().unwrap()))),
        None, None, None,
    ));
    provider.initialize().await.unwrap();
    let cfg = TunConfig { auto_redirect: true,
        route_address_set: vec!["networks".into()],
        route_exclude_address_set: vec!["networks".into()],
        ..Default::default() };
    let registry = HashMap::from([("networks".into(), provider.clone())]);
    let sets = RouteAddressSets::new(&cfg, &registry).unwrap();
    let updates = sets.subscribe();
    let guard = Arc::new(AutoRedirect::start(&sets.snapshot(&cfg), "tun0", None).unwrap().unwrap());
    let table = guard.table.clone();
    let task = tokio::spawn(sets.clone().run(cfg.clone(), guard.clone(), updates).in_current_span());
    let listing = || {
        let output = Command::new("nft").args(["list", "table", "inet", &table]).output().unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap()
    };
    assert!(listing().contains("198.18.0.0/16"));
    fs::write(&path, "203.0.113.0/24\nffff::/16\n").unwrap();
    provider.update().await.unwrap();
    timeout(Duration::from_secs(5), async {
        loop {
            let rules = listing();
            if rules.contains("203.0.113.0/24") && rules.contains("ffff::/16") {
                assert!(!rules.contains("198.18.0.0/16"));
                assert!(!rules.contains("fd01::/16"));
                break;
            }
            assert!(!task.is_finished(), "address set watcher exited unexpectedly");
            sleep(Duration::from_millis(20)).await;
        }
    }).await.unwrap();
    // A failed update must leave the watcher alive. Wait for its warning before
    // restoring the table so this genuinely exercises a failed nft transaction.
    super::nft(&format!("delete table inet {table}\n")).unwrap();
    fs::write(&path, "192.0.2.0/24\n").unwrap();
    provider.update().await.unwrap();
    timeout(Duration::from_secs(5), async {
        while !logs_contain("TUN address set update failed") {
            sleep(Duration::from_millis(20)).await;
        }
    }).await.unwrap();
    assert!(!task.is_finished());
    super::nft(&super::rules(&sets.snapshot(&cfg), "tun0", &table, None).unwrap()).unwrap();
    fs::write(&path, "\n").unwrap();
    provider.update().await.unwrap();
    timeout(Duration::from_secs(5), async {
        loop {
            let rules = listing();
            if !rules.contains("203.0.113.0/24") && !rules.contains("ffff::/16")
                && !rules.contains("192.0.2.0/24") {
                assert!(rules.contains("ip daddr @route4"));
                break;
            }
            assert!(!task.is_finished());
            sleep(Duration::from_millis(20)).await;
        }
    }).await.unwrap();
    task.abort();
    let _ = task.await;
    guard.close().unwrap();
    drop(guard);
    assert!(!Command::new("nft").args(["list", "table", "inet", &table])
        .output().unwrap().status.success());
}
