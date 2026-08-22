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
use crate::app::dns::ThreadSafeDNSResolver;
use crate::app::dns::query::{DnsName, QType};
use crate::app::dns::wire::parse_dns_response_records;

#[derive(Clone)]
struct DNSState {
    resolver: ThreadSafeDNSResolver,
}

pub fn routes(resolver: ThreadSafeDNSResolver) -> Router<Arc<AppState>> {
    let state = DNSState { resolver };
    Router::new()
        .route("/query", get(query_dns))
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

    let mut msg = vec![
        0x00, 0x00, // ID
        0x01, 0x00, // Flags: RD=1
        0x00, 0x01, // QDCOUNT=1
        0x00, 0x00, // ANCOUNT=0
        0x00, 0x00, // NSCOUNT=0
        0x00, 0x00, // ARCOUNT=0
    ];
    msg.extend_from_slice(name.as_wire());
    msg.extend_from_slice(&qtype.get().to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN

    match state.resolver.exchange(&msg).await {
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
