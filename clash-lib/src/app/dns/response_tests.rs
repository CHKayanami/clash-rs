use bytes::Bytes;
use crate::app::dns::query::IngressProfile;
use super::*;
use crate::app::dns::query::{DnsName, build_dns_query_wire};
use crate::app::dns::wire::{extract_ips_from_dns_response, extract_ips_with_ttl};

#[test]
fn cached_udp_render_preserves_record_boundaries_and_visible_addresses() {
    let query = build_dns_query_wire(&DnsName::from_domain("cached.test").unwrap(), QType::A);
    let context = QueryContext::parse(Bytes::copy_from_slice(&query), IngressProfile::Internal).unwrap();
    let ips = ["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap(),
        "192.0.2.2".parse().unwrap()];
    let mut response = build_dns_ip_response(&QueryContext::parse(Bytes::copy_from_slice(&query), IngressProfile::Internal).unwrap(), &ips, 300).unwrap();
    let cname = [0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 1, 44, 0, 2, 0xc0, 0x0c];
    response.splice(query.len()..query.len(), cname);
    response[6..8].copy_from_slice(&4u16.to_be_bytes());
    // Include an uncompressed owner name to exercise non-constant TTL offsets.
    response[8..10].copy_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&[3, b'a', b'u', b't', 0, 0, 16, 0, 1]);
    response.extend_from_slice(&90u32.to_be_bytes());
    response.extend_from_slice(&[0, 2, 1, b'x']);
    response[10..12].copy_from_slice(&1u16.to_be_bytes());
    let opt_start = response.len();
    response.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0]);
    let template = ResponseTemplate::validate(&context, &response).unwrap();
    let shared_ips = template.answer_ips();
    assert_eq!(shared_ips.as_ref(), ips.as_slice());
    let mut caller_wire = query.clone();
    caller_wire[..2].copy_from_slice(&0x1234u16.to_be_bytes());
    for limit in 0..=response.len() + 1 {
        let caller = QueryContext::parse(Bytes::copy_from_slice(&caller_wire), IngressProfile::Udp { advertised_size: limit as u16 }).unwrap();
        let rendered = template.render_cached(&caller, 7).unwrap();
        assert_eq!(&rendered.wire[..2], &[0x12, 0x34]);
        assert_eq!(rendered.answer_ips.as_ref(), extract_ips_from_dns_response(&rendered.wire));
        assert!(extract_ips_with_ttl(&rendered.wire).iter().all(|(_, ttl)| *ttl == 7));
        assert_eq!(rendered.wire[2] & 2 != 0, limit < response.len());
        if rendered.answer_ips.len() == ips.len() {
            assert!(Arc::ptr_eq(&rendered.answer_ips, &shared_ips));
        }
        // Plain rendering and the optimized path must make the same truncation decision.
        let plain = template.render(&caller).unwrap();
        assert_eq!(plain.len(), rendered.wire.len());
        assert_eq!(&plain[6..12], &rendered.wire[6..12]);
        if rendered.wire.len() == response.len() {
            assert_eq!(&rendered.wire[opt_start..], &response[opt_start..]);
        }
    }
    // TTL edits apply to the caller's copy, never the cached binary template.
    assert_eq!(template.render(&context).unwrap(), response);
}

#[test]
fn cached_error_templates_do_not_expose_answer_addresses() {
    let query = build_dns_query_wire(&DnsName::from_domain("error.test").unwrap(), QType::A);
    let context = QueryContext::parse(Bytes::copy_from_slice(&query), IngressProfile::Internal).unwrap();
    for extended in [false, true] {
        let mut response = build_dns_ip_response(&QueryContext::parse(Bytes::copy_from_slice(&query), IngressProfile::Internal).unwrap(), &["192.0.2.1".parse().unwrap()], 60).unwrap();
        if extended {
            response[10..12].copy_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&[0, 0, 41, 4, 208, 1, 0, 0, 0, 0, 0]);
        } else {
            response[3] |= 2;
        }
        let template = ResponseTemplate::validate(&context, &response).unwrap();
        assert!(template.answer_ips().is_empty());
        for limit in [query.len(), response.len() - 1, response.len()] {
            let caller = QueryContext::parse(Bytes::copy_from_slice(&query), IngressProfile::Udp { advertised_size: limit as u16 }).unwrap();
            assert!(template.render_cached(&caller, 30).unwrap().answer_ips.is_empty());
        }
    }
}

#[test]
fn impossible_record_counts_are_rejected_before_metadata_allocation() {
    let query = build_dns_query_wire(&DnsName::from_domain("counts.test").unwrap(), QType::A);
    let context = QueryContext::parse(Bytes::copy_from_slice(&query), IngressProfile::Internal).unwrap();
    let mut response = build_dns_nodata(&query);
    for count in response[6..12].chunks_exact_mut(2) {
        count.copy_from_slice(&u16::MAX.to_be_bytes());
    }
    assert_eq!(ResponseTemplate::validate(&context, &response).unwrap_err(), ResponseError::MalformedRecord);
}

#[test]
fn layout_buffers_are_moved_and_reused_when_building_a_template() {
    let query = build_dns_query_wire(&DnsName::from_domain("move.test").unwrap(), QType::A);
    let context = QueryContext::parse(Bytes::copy_from_slice(&query), IngressProfile::Internal).unwrap();
    let ips = ["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()];
    let wire = Bytes::from(build_dns_ip_response(&QueryContext::parse(Bytes::copy_from_slice(&query), IngressProfile::Internal).unwrap(), &ips, 60).unwrap());
    let layout = validate_layout(Some(&context), &wire).unwrap();
    let records_ptr = layout.records.as_ptr();
    let indices_ptr = layout.answer_records.as_ptr();
    let wire_ptr = wire.as_ptr();
    let template = ResponseTemplate::from_layout(&context, wire, layout);
    assert_eq!(template.records.as_ptr(), records_ptr);
    assert_eq!(template.answer_ip_ends.as_ptr(), indices_ptr);
    assert_eq!(template.wire.as_ptr(), wire_ptr);
    assert_eq!(template.answer_ips.as_ref(), ips.as_slice());
    assert_eq!(template.answer_ip_ends, vec![template.records[0].wire.end,
        template.records[1].wire.end]);
}

#[test]
fn validation_rejects_malformed_addresses_and_soa_names() {
    let query = build_dns_query_wire(&DnsName::from_domain("check.test").unwrap(), QType::A);
    let context = QueryContext::parse(Bytes::copy_from_slice(&query), IngressProfile::Internal).unwrap();
    let mut bad_address = build_dns_ip_response(&QueryContext::parse(Bytes::copy_from_slice(&query), IngressProfile::Internal).unwrap(), &["192.0.2.1".parse().unwrap()], 60).unwrap();
    let length_offset = bad_address.len() - 6;
    bad_address[length_offset..length_offset + 2].copy_from_slice(&3u16.to_be_bytes());
    bad_address.pop();
    let mut bad_soa = build_dns_nxdomain(&query);
    bad_soa[8..10].copy_from_slice(&1u16.to_be_bytes());
    bad_soa.extend_from_slice(&[0xc0, 0x0c, 0, 6, 0, 1, 0, 0, 0, 60, 0, 22]);
    let pointer = (0xc000 | bad_soa.len() as u16).to_be_bytes();
    bad_soa.extend_from_slice(&pointer);
    bad_soa.extend_from_slice(&[0; 20]);
    for response in [bad_address, bad_soa] {
        assert_eq!(ResponseTemplate::validate(&context, &response).unwrap_err(), ResponseError::MalformedRecord);
    }
}

#[test]
fn questions_match_without_decoding_temporary_names() {
    let mut query = build_dns_query_wire(&DnsName::from_domain("question.test").unwrap(), QType::A);
    query[4..6].copy_from_slice(&2u16.to_be_bytes());
    let second = query.len();
    query.extend_from_slice(&[0xc0, 0x0c, 0, 28, 0, 1]);
    let context = QueryContext::parse(Bytes::copy_from_slice(&query), IngressProfile::Internal).unwrap();
    let response = build_dns_nodata(&query);
    ResponseTemplate::validate(&context, &response).unwrap();
    for offset in [second + 1, second + 3, second + 5] {
        let mut invalid = response.clone();
        invalid[offset] ^= 1;
        assert_eq!(ResponseTemplate::validate(&context, &invalid).unwrap_err(), ResponseError::QuestionMismatch);
    }
    // Fixed Question and RR headers must still reject every truncated prefix.
    let single = build_dns_query_wire(&DnsName::from_domain("fields.test").unwrap(), QType::A);
    let context = QueryContext::parse(Bytes::copy_from_slice(&single), IngressProfile::Internal).unwrap();
    let response = build_dns_ip_response(&QueryContext::parse(Bytes::copy_from_slice(&single), IngressProfile::Internal).unwrap(), &["192.0.2.1".parse().unwrap()], 60).unwrap();
    for end in 0..response.len() {
        assert!(ResponseTemplate::validate(&context, &response[..end]).is_err());
    }
}
