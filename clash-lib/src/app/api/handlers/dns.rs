use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
};
use http::StatusCode;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::app::api::AppState;
use crate::app::dns::{DnsCacheUpstreamStat, ThreadSafeDNSResolver};
use crate::app::dns::query::{DnsName, QType, QueryContext};
use crate::app::dns::wire::parse_dns_response_records;

#[derive(Clone)]
struct DNSState {
    resolver: ThreadSafeDNSResolver,
}

pub fn routes(resolver: ThreadSafeDNSResolver) -> Router<Arc<AppState>> {
    let state = DNSState { resolver };
    Router::new()
        .route("/query", get(query_dns))
        .route("/upstreams", get(get_dns_upstreams))
        .route("/cache", get(get_dns_cache).delete(delete_dns_cache))
        .with_state(state)
}

#[derive(Deserialize)]
struct DnsQuery {
    name: String,
    #[serde(rename = "type")]
    typ: Option<String>,
}

async fn query_dns(
    State(state): State<DNSState>,
    q: Query<DnsQuery>,
) -> impl IntoResponse {
    if let crate::app::dns::ResolverKind::System = state.resolver.kind() {
        return (StatusCode::BAD_REQUEST, "Clash resolver is not enabled.")
            .into_response();
    }
    let name = match DnsName::from_domain(&q.name) {
        Some(n) => n,
        None => return (StatusCode::BAD_REQUEST, "Invalid domain name").into_response(),
    };

    let qtype = match q.typ.as_deref().unwrap_or("A").to_uppercase().as_str() {
        "A" => QType::A,
        "AAAA" => QType::AAAA,
        "CNAME" => QType::CNAME,
        "TXT" => QType::TXT,
        "PTR" => QType::PTR,
        "MX" => QType::MX,
        "NS" => QType::NS,
        "SRV" => QType::SRV,
        "SOA" => QType::SOA,
        _ => QType::A,
    };

    let query = QueryContext::new(name, qtype);
    match state.resolver.exchange(&query, None).await {
        Ok(response) => {
            let mut resp = Map::new();
            let rcode = if response.len() >= 4 {
                response[3] & 0x0F
            } else {
                0
            };
            resp.insert("Status".to_owned(), rcode.into());

            let mut question_data = Map::new();
            question_data.insert("name".to_owned(), q.name.clone().into());
            question_data.insert("qtype".to_owned(), qtype.get().into());
            question_data.insert("qclass".to_owned(), 1.into());
            resp.insert("Question".to_owned(), vec![Value::Object(question_data)].into());

            let records = parse_dns_response_records(&response);
            if !records.is_empty() {
                let answers: Vec<Value> = records
                    .into_iter()
                    .map(|r| {
                        let mut data = Map::new();
                        let record_name = if r.name.is_empty() { q.name.clone() } else { r.name };
                        data.insert("name".to_owned(), record_name.into());
                        data.insert("type".to_owned(), r.rtype.into());
                        data.insert("ttl".to_owned(), r.ttl.into());
                        data.insert("data".to_owned(), r.data.into());
                        Value::Object(data)
                    })
                    .collect();
                resp.insert("Answer".to_owned(), answers.into());
            }

            Json(resp).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_dns_upstreams(State(state): State<DNSState>) -> impl IntoResponse {
    let upstreams = state.resolver.list_upstreams();
    let mut resp = Map::new();
    resp.insert(
        "upstreams".to_string(),
        serde_json::to_value(upstreams).unwrap_or(Value::Array(vec![])),
    );
    Json(resp).into_response()
}

#[derive(Deserialize)]
struct DnsCacheQuery {
    upstream: Option<String>,
    #[serde(alias = "wildcard", alias = "pattern", alias = "match")]
    name: Option<String>,
}

#[derive(Deserialize)]
struct DnsCacheDeleteQuery {
    upstream: Option<String>,
    #[serde(alias = "wildcard", alias = "pattern", alias = "match")]
    name: Option<String>,
}

async fn get_dns_cache(
    State(state): State<DNSState>,
    Query(q): Query<DnsCacheQuery>,
) -> impl IntoResponse {
    let upstream = match q.upstream.as_deref() {
        Some(u) if !u.trim().is_empty() => u.trim(),
        _ => {
            return (StatusCode::BAD_REQUEST, "Upstream parameter is required")
                .into_response();
        }
    };

    let pattern = q.name.as_deref().unwrap_or("*");
    let pattern = if pattern.trim().is_empty() {
        "*"
    } else {
        pattern.trim()
    };

    let stat = state
        .resolver
        .search_cache_by_upstream(pattern, upstream)
        .unwrap_or_else(|| DnsCacheUpstreamStat {
            name: upstream.to_string(),
            count: 0,
            upstream_type: None,
            items: Vec::new(),
        });

    let mut resp = Map::new();
    resp.insert(
        "upstream".to_string(),
        serde_json::to_value(stat).unwrap_or(Value::Null),
    );
    Json(resp).into_response()
}

async fn delete_dns_cache(
    State(state): State<DNSState>,
    Query(q): Query<DnsCacheDeleteQuery>,
) -> impl IntoResponse {
    let upstream = match q.upstream.as_deref() {
        Some(u) if !u.trim().is_empty() => u.trim(),
        _ => {
            return (StatusCode::BAD_REQUEST, "Upstream parameter is required")
                .into_response();
        }
    };

    let pattern = q.name.as_deref().unwrap_or("*");
    let pattern = if pattern.trim().is_empty() {
        "*"
    } else {
        pattern.trim()
    };

    let deleted = state.resolver.clear_cache_by_upstream(pattern, upstream);
    let mut resp = Map::new();
    resp.insert("deleted".to_string(), deleted.into());
    resp.insert("upstream".to_string(), upstream.into());
    resp.insert(
        "message".to_string(),
        format!("Deleted {} cache entries from upstream '{}'", deleted, upstream).into(),
    );
    Json(resp).into_response()
}
