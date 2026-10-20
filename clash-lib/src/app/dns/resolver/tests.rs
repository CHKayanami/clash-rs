use super::*;
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::time::{Duration, sleep, timeout};
use crate::app::profile::FakeIpOperation;
use crate::config::def::Config as DefConfig;
use super::router::config::RequestAction;

fn fake_config(persist: bool) -> Config {
    let def: DefConfig = yaml_serde::from_str(&format!(r#"
profile:
  store-fake-ip: {persist}
dns2:
  enable: true
  upstreams:
    - {{tag: fake, type: fakeip}}
  routing:
    request:
      - {{fallback: fake}}
"#)).unwrap();
    Config::try_from(&def).unwrap()
}

#[tokio::test]
async fn dns2_factory_propagates_initialization_errors() {
    let mut cfg = fake_config(false);
    cfg.dns2.as_mut().unwrap().request_fallback = RequestAction::Route("missing".into());
    let error = new(cfg, None, None,
        Arc::new(ArcSwap::from_pointee(HashMap::new())), None, None,
    ).await.err().unwrap();
    assert!(error.to_string().contains("unknown dns2 upstream 'missing'"));
}

#[tokio::test]
async fn dns2_honors_fakeip_persistence_for_restore_and_new_mappings() {
    for persist in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let store = ThreadSafeCacheFile::new(
            dir.path().join("cache.db").to_str().unwrap(), false,
        ).unwrap();
        let retained: IpAddr = "198.18.0.42".parse().unwrap();
        store.apply_fake_ip_batch(&[FakeIpOperation::Put {
            ip: retained.to_string(), host: "retained.example".into(),
            host_key: "retained.example#v4".into(),
        }]).unwrap();
        let before = store.get_fake_ip_tables().unwrap();
        let resolver = new(fake_config(persist), Some(store.clone()), None,
            Arc::new(ArcSwap::from_pointee(HashMap::new())), None, None,
        ).await.unwrap();
        assert_eq!(resolver.reverse_lookup(retained),
            persist.then(|| "retained.example".to_string()));
        let allocated = resolver.resolve("new.example", true).await.unwrap().unwrap();
        assert_eq!(resolver.reverse_lookup(allocated), Some("new.example".into()));
        drop(resolver);
        if persist {
            timeout(Duration::from_secs(2), async {
                loop {
                    let (hosts, _) = store.get_fake_ip_tables().unwrap();
                    if hosts.get("new.example#v4") == Some(&allocated.to_string()) {
                        break;
                    }
                    sleep(Duration::from_millis(5)).await;
                }
            }).await.unwrap();
        } else {
            assert_eq!(store.get_fake_ip_tables().unwrap(), before);
        }
    }
}
