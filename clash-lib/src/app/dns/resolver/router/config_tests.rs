use super::*;

fn config(yaml: &str) -> Result<RouterConfig, Error> {
    let def: DefDns2Config = yaml_serde::from_str(yaml).unwrap();
    RouterConfig::from_def(&def, true)
}

#[test]
fn rejects_invalid_upstream_definitions() {
    for (yaml, field) in [
        ("upstreams: [{tag: '', type: local}]", "tag"),
        ("upstreams: [{tag: same, type: local}, {tag: same, type: local}]", "unique"),
        ("upstreams: [{tag: dns, type: remtoe}]", "type"),
        ("upstreams: [{tag: dns, type: remote}]", "server"),
        ("upstreams: [{tag: dns, type: remote, server: []}]", "server"),
        ("upstreams: [{tag: dns, type: remote, server: [system]}]", "server"),
        ("default-nameserver: [dns.example]", "default-nameserver"),
        ("default-nameserver: [https://dns.example/dns-query]", "default-nameserver"),
        ("default-nameserver: [system]", "default-nameserver"),
    ] {
        let error = config(yaml).unwrap_err().to_string();
        assert!(error.contains(field), "{yaml}: {error}");
    }
}

#[test]
fn rejects_unknown_request_and_response_upstream_references() {
    for routing in [
        "request: [{fallback: missing}]",
        "request: [{domain: [example.com], upstream: missing}]",
        "response: [{from-upstream: missing, action: accept}]",
        "response: [{domain: [example.com], upstream: missing}]",
    ] {
        let error = config(&format!(
            "upstreams: [{{tag: known, type: local}}]\nrouting:\n  {routing}\n",
        )).unwrap_err().to_string();
        assert!(error.contains("unknown dns2 upstream 'missing'"), "{error}");
    }
}

#[test]
fn accepts_known_references_and_ip_bootstrap_servers() {
    let cfg = config(r#"
default-nameserver: [192.0.2.53, "tls://[2001:db8::53]:853"]
upstreams:
  - {tag: real, type: remote, server: [192.0.2.53]}
  - {tag: local, type: local}
  - {tag: fake, type: fakeip}
routing:
  request:
    - {domain: [example.com], upstream: real}
    - {fallback: fake}
  response:
    - {from-upstream: real, upstream: local}
    - {fallback: accept}
"#).unwrap();
    assert_eq!(cfg.upstreams.len(), 3);
    assert_eq!(cfg.default_nameserver.len(), 2);
}
