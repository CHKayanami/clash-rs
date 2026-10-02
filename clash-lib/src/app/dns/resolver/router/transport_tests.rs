use super::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures::future::join_all;
use parking_lot::RwLock;
use tokio::net::UdpSocket;
use tokio::sync::Notify;

use crate::app::dns::config::{DNSNetMode, NameServer};
use crate::app::dns::response::build_dns_nxdomain;
use crate::app::dns::query::IngressProfile;
use crate::app::dns::singleflight::MAX_WAITERS_PER_FLIGHT;
use crate::app::dns::upstream_pool::UpstreamEntry;
use crate::app::dns::wire::{extract_ips_from_dns_response, skip_dns_name};

impl DnsCachePolicy {
    pub(crate) fn calculate_effective_ttl(
        &self,
        override_ttl: Option<u32>,
        raw_resp: &[u8],
    ) -> u32 {
        ResponseMetadata::parse(raw_resp)
            .map_or(0, |metadata| self.effective_ttl(override_ttl, &metadata))
    }

}

fn rewrite_ttl(wire: &mut [u8], ttl: u32) {
    let counts = [u16::from_be_bytes([wire[6], wire[7]]),
        u16::from_be_bytes([wire[8], wire[9]]), u16::from_be_bytes([wire[10], wire[11]])];
    let mut cursor = 12;
    assert!(skip_dns_name(wire, &mut cursor));
    cursor += 4;
    for (section, count) in counts.into_iter().enumerate() {
        for _ in 0..count {
            assert!(skip_dns_name(wire, &mut cursor));
            let rtype = u16::from_be_bytes([wire[cursor], wire[cursor + 1]]);
            let length = usize::from(u16::from_be_bytes([wire[cursor + 8], wire[cursor + 9]]));
            if rtype != 41 {
                let field = &mut wire[cursor + 4..cursor + 8];
                let old = u32::from_be_bytes(field.try_into().unwrap());
                field.copy_from_slice(&if section == 0 { ttl } else { old.min(ttl) }.to_be_bytes());
            }
            cursor += 10 + length;
        }
    }
}

fn query() -> (Vec<u8>, QueryContext) {
    let wire = build_dns_query_wire(&DnsName::from_domain("negative.test").unwrap(), QType::A);
    let query = QueryContext::parse(&wire).unwrap();
    (wire, query)
}

fn negative_response(query: &[u8], rcode: u8, soa_ttl: u32, minimum: u32) -> Vec<u8> {
    let mut wire = build_dns_nxdomain(query);
    wire[3] = (wire[3] & 0xf0) | rcode;
    wire[8..10].copy_from_slice(&1u16.to_be_bytes());
    wire.extend_from_slice(&[0xc0, 0x0c, 0, 6, 0, 1]);
    wire.extend_from_slice(&soa_ttl.to_be_bytes());
    wire.extend_from_slice(&22u16.to_be_bytes());
    wire.extend_from_slice(&[0, 0]); // MNAME and RNAME are the root.
    for value in [1, 2, 3, 4, minimum] {
        wire.extend_from_slice(&value.to_be_bytes());
    }
    wire
}

async fn remote(socket: &UdpSocket, ttl: Option<u32>, policy: DnsCachePolicy) -> CachedTransport {
    let ns = NameServer {
        net: DNSNetMode::Udp,
        host: url::Host::Ipv4("127.0.0.1".parse().unwrap()),
        port: socket.local_addr().unwrap().port(),
        path: None, interface: None, proxy: None,
    };
    let entry = UpstreamEntry::from_nameserver(&ns, None).unwrap();
    let mut pool = UpstreamPool::new(HashMap::from([("server".into(), entry)]),
        Arc::new(RwLock::new(HashMap::new())), None, None, None, None);
    let mutable_pool = Arc::get_mut(&mut pool).unwrap();
    mutable_pool.dns_query_timeout = Duration::from_millis(200);
    mutable_pool.dns_dial_timeout = Duration::from_millis(200);
    CachedTransport::new_remote("remote".into(), ttl, vec!["server".into()], pool,
        DnsCache::new(128), policy)
}

#[test]
fn negative_policy_uses_soa_and_excludes_errors_and_truncation() {
    let (wire, context) = query();
    let policy = DnsCachePolicy::new(600, 3600);
    for code in [0, 3] {
        for (soa_ttl, minimum, expected) in [
            (3600, 1799, 1799), (1800, 3600, 1800), (3600, 7200, 1800),
        ] {
            let response = negative_response(&wire, code, soa_ttl, minimum);
            assert_eq!(policy.calculate_effective_ttl(None, &response), expected);
            assert_eq!(policy.calculate_effective_ttl(Some(7200), &response), expected);
        }
        let response = negative_response(&wire, code, 100, 20);
        ResponseTemplate::validate(&context, &response).unwrap();
        assert_eq!(policy.calculate_effective_ttl(Some(300), &response), 20);
        assert_eq!(policy.calculate_effective_ttl(Some(0), &response), 0);
    }
    for code in [2, 5] {
        let response = negative_response(&wire, code, 100, 20);
        assert_eq!(policy.calculate_effective_ttl(Some(300), &response), 0);
    }
    assert_eq!(policy.calculate_effective_ttl(None, &build_dns_nxdomain(&wire)), 0);
    let mut response = negative_response(&wire, 3, 100, 0);
    assert_eq!(policy.calculate_effective_ttl(None, &response), 5);
    assert_eq!(policy.calculate_effective_ttl(Some(0), &response), 0);
    response[2] |= 2;
    assert_eq!(policy.calculate_effective_ttl(None, &response), 0);
}

#[tokio::test]
async fn zero_ttl_negative_is_cached_for_five_seconds_without_stale_retention() {
    for code in [0, 3] {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let transport = remote(&socket, None, DnsCachePolicy::new(600, 3600)).await;
        let task = tokio::spawn(async move {
            let mut buf = [0; 512];
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            socket.send_to(&negative_response(&buf[..len], code, 0, 0), peer).await.unwrap();
        });
        let (wire, query) = query();
        let result = transport.exchange(&wire, &query).await.unwrap();
        assert_eq!(result.ttl, 5);
        task.await.unwrap();
        // The endpoint no longer responds: repeated queries must use the cache.
        for _ in 0..3 {
            let cached = transport.exchange(&wire, &query).await.unwrap();
            assert!(!cached.is_fresh);
        }
        let now = Instant::now();
        assert!(matches!(transport.cache.lookup_scoped(&transport.tag, &query,
            now + Duration::from_secs(3)), CacheLookup::Hit(_, _)));
        assert!(matches!(transport.cache.lookup_scoped(&transport.tag, &query,
            now + Duration::from_secs(6)), CacheLookup::Miss));
    }
}

#[test]
fn cname_followed_by_nodata_uses_negative_cache_policy() {
    let (wire, context) = query();
    let mut response = negative_response(&wire, 0, 100, 20);
    let authority_start = response.len() - 34;
    let mut cname = vec![0xc0, 0x0c, 0, 5, 0, 1];
    cname.extend_from_slice(&5u32.to_be_bytes());
    let target = [6, b't', b'a', b'r', b'g', b'e', b't', 4, b't', b'e', b's', b't', 0];
    cname.extend_from_slice(&(target.len() as u16).to_be_bytes());
    cname.extend_from_slice(&target);
    response.splice(authority_start..authority_start, cname);
    response[6..8].copy_from_slice(&1u16.to_be_bytes());
    ResponseTemplate::validate(&context, &response).unwrap();
    let metadata = ResponseMetadata::parse(&response).unwrap();
    assert!(metadata.negative);
    assert_eq!(metadata.cache_ttl, Some(5));
    assert_eq!(DnsCachePolicy::new(600, 3600).calculate_effective_ttl(Some(300), &response), 5);
}

#[test]
fn compressed_soa_names_and_truncated_rdata_are_handled() {
    let (wire, context) = query();
    let mut response = negative_response(&wire, 3, 100, 20);
    let rdata_start = response.len() - 22;
    response[rdata_start - 2..rdata_start].copy_from_slice(&24u16.to_be_bytes());
    response.splice(rdata_start..rdata_start + 2, [0xc0, 0x0c, 0xc0, 0x0c]);
    ResponseTemplate::validate(&context, &response).unwrap();
    assert_eq!(ResponseMetadata::parse(&response).unwrap().cache_ttl, Some(20));
    response.pop();
    assert!(ResponseMetadata::parse(&response).is_none());
}

#[test]
fn soa_compression_rejects_self_and_out_of_bounds_pointers() {
    let (wire, _) = query();
    let mut response = negative_response(&wire, 3, 100, 20);
    let rdata_start = response.len() - 22;
    response[rdata_start - 2..rdata_start].copy_from_slice(&24u16.to_be_bytes());
    response.splice(rdata_start..rdata_start + 2, [0xc0, 0x0c, 0xc0, 0x0c]);
    assert!(ResponseMetadata::parse(&response).is_some());
    for target in [rdata_start as u16, 0x3fff] {
        let mut invalid = response.clone();
        let pointer = (0xc000 | target).to_be_bytes();
        invalid[rdata_start..rdata_start + 2].copy_from_slice(&pointer);
        assert!(ResponseMetadata::parse(&invalid).is_none());
    }
    // Reuse the name-parse state across SOAs in a message larger than 512 bytes.
    let mut soa = response[response.len() - 36..].to_vec();
    let minimum_start = soa.len() - 4;
    soa[minimum_start..].copy_from_slice(&10u32.to_be_bytes());
    response[8..10].copy_from_slice(&21u16.to_be_bytes());
    for _ in 0..20 { response.extend_from_slice(&soa); }
    assert_eq!(ResponseMetadata::parse(&response).unwrap().cache_ttl, Some(10));
    let last_rdata = response.len() - 24;
    let pointer = (0xc000 | last_rdata as u16).to_be_bytes();
    response[last_rdata..last_rdata + 2].copy_from_slice(&pointer);
    assert!(ResponseMetadata::parse(&response).is_none());
}

#[test]
fn cached_rewrite_matches_full_rewrite_and_preserves_opt() {
    let (wire, context) = query();
    let ips = ["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()];
    let mut response = build_dns_ip_response(&wire, &ips, 300).unwrap();
    let negative = negative_response(&wire, 3, 100, 20);
    response[8..10].copy_from_slice(&1u16.to_be_bytes());
    let authority_start = response.len();
    response.extend_from_slice(&negative[negative.len() - 34..]);
    response[10..12].copy_from_slice(&2u16.to_be_bytes());
    response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
    response.extend_from_slice(&30u32.to_be_bytes());
    response.extend_from_slice(&[0, 4, 192, 0, 2, 2]);
    let opt_start = response.len();
    response.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0]);
    let template = ResponseTemplate::validate(&context, &response).unwrap();
    let mut malformed_soa = response.clone();
    malformed_soa[authority_start + 12] = 0x40;
    assert!(ResponseMetadata::parse(&malformed_soa).is_none());
    let mut question_end = 12;
    assert!(skip_dns_name(&response, &mut question_end));
    question_end += 4;
    let mut mixed = response.clone();
    mixed[question_end + 22..question_end + 26].copy_from_slice(&301u32.to_be_bytes());
    let mut rewritten = mixed.clone();
    let (mixed_template, _, _) = ResponseTemplate::validate_with_ttl(&context, &mut rewritten, |_| 300).unwrap();
    let mut expected = mixed;
    rewrite_ttl(&mut expected, 300);
    assert_eq!(mixed_template.render(&context).unwrap(), expected);
    for ttl in [0, 60, 300, 600] {
        let mut expected = response.clone();
        rewrite_ttl(&mut expected, ttl);
        let cached = template.render_cached(&context, ttl).unwrap();
        assert_eq!(cached.wire, expected);
        assert_eq!(cached.answer_ips.as_ref(), ips.as_slice());
        assert!(Arc::ptr_eq(&cached.answer_ips, &template.answer_ips()));
        assert_eq!(&cached.wire[opt_start..], &response[opt_start..]);
    }
    // An extended error RCODE must not expose answer IPs to response routing.
    response[opt_start + 5] = 1;
    let metadata = ResponseMetadata::parse(&response).unwrap();
    assert_eq!(metadata.cache_ttl, None);
    let error_template = ResponseTemplate::validate(&context, &response).unwrap();
    assert!(error_template.render_cached(&context, 60).unwrap().answer_ips.is_empty());
}

#[test]
fn truncated_records_and_invalid_address_lengths_are_rejected() {
    for (qtype, ip, length) in [(QType::A, "192.0.2.1", 4u16),
        (QType::AAAA, "2001:db8::1", 16)] {
        let wire = build_dns_query_wire(&DnsName::from_domain("parse.test").unwrap(), qtype);
        let response = build_dns_ip_response(&wire, &[ip.parse().unwrap()], 60).unwrap();
        for end in 0..response.len() {
            assert!(ResponseMetadata::parse(&response[..end]).is_none());
        }
        let mut invalid = response;
        let length_offset = invalid.len() - usize::from(length) - 2;
        invalid[length_offset..length_offset + 2].copy_from_slice(&(length - 1).to_be_bytes());
        invalid.pop();
        assert!(ResponseMetadata::parse(&invalid).is_none());
    }
}

#[tokio::test]
async fn negative_cache_expires_without_stale_retention_and_ages_soa_ttl() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let transport = remote(&socket, Some(300), DnsCachePolicy::new(600, 3600)).await;
    let task = tokio::spawn(async move {
        let mut buf = [0; 512];
        let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
        socket.send_to(&negative_response(&buf[..len], 3, 3600, 7200), peer).await.unwrap();
    });
    let (wire, query) = query();
    let result = transport.exchange(&wire, &query).await.unwrap();
    assert_eq!(result.ttl, 1800);
    assert_eq!(ResponseMetadata::parse(&result.wire).unwrap().cache_ttl, Some(1800));
    let cached = transport.exchange(&wire, &query).await.unwrap();
    assert!(!cached.is_fresh);
    let mut position = 12;
    assert!(skip_dns_name(&cached.wire, &mut position));
    position += 4;
    assert!(skip_dns_name(&cached.wire, &mut position));
    let soa_ttl = u32::from_be_bytes(cached.wire[position + 4..position + 8].try_into().unwrap());
    assert!(soa_ttl <= 1800);
    match transport.cache.lookup_scoped(&transport.tag, &query, Instant::now() + Duration::from_secs(1801)) {
        CacheLookup::Miss => {}
        _ => panic!("negative responses must not be served stale"),
    }
    task.await.unwrap();
}

#[tokio::test]
async fn server_errors_are_not_cached() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let transport = remote(&socket, None, DnsCachePolicy::default()).await;
    let task = tokio::spawn(async move {
        let mut buf = [0; 512];
        for _ in 0..2 {
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            socket.send_to(&negative_response(&buf[..len], 2, 100, 20), peer).await.unwrap();
        }
    });
    let (wire, query) = query();
    for _ in 0..2 {
        assert!(transport.exchange(&wire, &query).await.unwrap().is_fresh);
        assert!(matches!(transport.cache.lookup_scoped(&transport.tag, &query, Instant::now()), CacheLookup::Miss));
    }
    task.await.unwrap();
}

#[tokio::test]
async fn endpoint_failure_is_shared_without_waiter_fanout() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let transport = remote(&socket, None, DnsCachePolicy::default()).await;
    let task = tokio::spawn(async move {
        let mut buf = [0; 512];
        loop {
            socket.recv_from(&mut buf).await.unwrap(); // Deliberately silent.
        }
    });
    let (wire, query) = query();
    let results = join_all((0..32).map(|_| transport.exchange(&wire, &query))).await;
    assert!(results.iter().all(Result::is_err));
    let counters = transport.singleflight.counters();
    assert_eq!(counters.leaders, 1);
    assert_eq!(counters.waiters, 31);
    assert_eq!(transport.singleflight.active_len(), 0);
    task.abort();
}

#[tokio::test]
async fn saturation_rejects_without_bypassing_singleflight() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let transport = remote(&socket, None, DnsCachePolicy::default()).await;
    let (wire, query) = query();
    let key = FlightKey::Query(query.canonical_wire_arc());
    let leader = transport.singleflight.acquire(key.clone());
    let waiters: Vec<_> = (0..MAX_WAITERS_PER_FLIGHT)
        .map(|_| transport.singleflight.acquire(key.clone())).collect();
    assert!(transport.exchange(&wire, &query).await.err().unwrap().to_string().contains("capacity"));
    assert!(tokio::time::timeout(Duration::from_millis(20), socket.readable()).await.is_err());
    drop(waiters);
    drop(leader);
}

#[tokio::test]
async fn cancelled_leader_retries_once_through_singleflight() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let transport = remote(&socket, None, DnsCachePolicy::default()).await;
    let (wire, query) = query();
    let key = FlightKey::Query(query.canonical_wire_arc());
    let leader = transport.singleflight.acquire(key);
    let entered = Arc::new(Notify::new());
    let counter = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn({
        let counter = counter.clone();
        async move {
            let mut buf = [0; 512];
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            counter.fetch_add(1, Ordering::Relaxed);
            let response = build_dns_ip_response(&buf[..len], &["192.0.2.1".parse().unwrap()], 60).unwrap();
            socket.send_to(&response, peer).await.unwrap();
        }
    });
    let exchanges = async {
        entered.notify_one();
        join_all((0..16).map(|_| transport.exchange(&wire, &query))).await
    };
    let cancel = async {
        entered.notified().await;
        tokio::task::yield_now().await;
        drop(leader);
    };
    let (results, ()) = tokio::join!(exchanges, cancel);
    assert!(results.iter().all(Result::is_ok));
    assert_eq!(counter.load(Ordering::Relaxed), 1);
    task.await.unwrap();
}

#[test]
fn unified_validation_preserves_ttl_policy_and_coalesced_results() {
    let (query_wire, context) = query();
    let positive = build_dns_ip_response(&query_wire,
        &["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()], 300).unwrap();
    let mut cname_negative = negative_response(&query_wire, 0, 100, 20);
    let authority_start = cname_negative.len() - 34;
    cname_negative.splice(authority_start..authority_start,
        [0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 0, 0, 2, 0xc0, 0x0c]);
    cname_negative[6..8].copy_from_slice(&1u16.to_be_bytes());
    let responses = [(positive, Some(300), false, None),
        (cname_negative, Some(0), true, Some(20)),
        (negative_response(&query_wire, 3, 100, 20), Some(20), true, Some(20)),
        (negative_response(&query_wire, 0, 0, 0), Some(0), true, Some(0)),
        (build_dns_nxdomain(&query_wire), None, true, None)];
    for (response, initial_ttl, negative, soa_limit) in responses {
        let metadata = ResponseMetadata::parse(&response).unwrap();
        assert_eq!(metadata.cache_ttl, initial_ttl);
        assert_eq!(metadata.negative, negative);
        for ttl in [0, 5, 60, 600] {
            let mut wire = response.clone();
            let (template, is_negative, effective) = ResponseTemplate::validate_with_ttl(&context, &mut wire, |_| ttl).unwrap();
            assert_eq!(effective, ttl);
            assert_eq!(is_negative, negative);
            let mut expected_wire = response.clone();
            if initial_ttl.is_some() { rewrite_ttl(&mut expected_wire, ttl); }
            assert_eq!(wire, expected_wire);
            assert_eq!(template.render(&context).unwrap(), expected_wire);
            let expected_ttl = if negative { soa_limit.map(|limit: u32| limit.min(ttl)) }
                else { initial_ttl.map(|_| ttl) };
            assert_eq!(template.cache_ttl(), expected_ttl);
            assert_eq!(template.answer_ips().as_ref(), extract_ips_from_dns_response(&response));
            let result = ExchangeResult::coalesced(&template, &context).unwrap();
            assert_eq!(result.ttl, expected_ttl.unwrap_or(0));
            assert!(Arc::ptr_eq(&result.answer_ips, &template.answer_ips()));
            let udp = QueryContext::parse_with_profile(&query_wire,
                IngressProfile::Udp { advertised_size: query_wire.len() as u16 }).unwrap();
            let truncated = ExchangeResult::coalesced(&template, &udp).unwrap();
            assert_eq!(truncated.ttl, 0);
            assert!(truncated.answer_ips.is_empty());
        }
    }
}
