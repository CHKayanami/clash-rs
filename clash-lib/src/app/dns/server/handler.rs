use crate::app::dns::ThreadSafeDNSResolver;
use hickory_proto::{op::Message, rr::RecordType};
use tracing::debug;

pub async fn exchange_with_resolver<'a>(
    resolver: &'a ThreadSafeDNSResolver,
    req: &'a Message,
    _enhanced: bool,
) -> Result<Message, watfaq_dns::DNSError> {
    // if req.queries.first().map(|q| q.query_type())
    // == Some(hickory_proto::rr::RecordType::AAAA)
    // || !resolver.fake_ip_enabled()
    // 1. 获取查询类型，如果没有查询请求，直接返回格式错误
    let query = req.queries.first().ok_or_else(|| {
        watfaq_dns::DNSError::InvalidOpQuery("malformed query message".to_string())
    })?;

    let qtype = query.query_type();

    // 2. 核心路由分支：判断是否走 Fake IP
    // 只有当开启了 Fake IP，且请求类型是 A 或 AAAA 时才在本地截获
    let is_fake_ip_eligible = resolver.fake_ip_enabled()
        && (qtype == RecordType::A || qtype == RecordType::AAAA);
    if !is_fake_ip_eligible {
        return match resolver.exchange(req).await {
            Ok(m) => Ok(m),
            Err(e) => {
                debug!("dns resolve error: {}", e);
                Err(watfaq_dns::DNSError::QueryFailed(e.to_string()))
            }
        };
    }

    return match resolver.exchange_all(req).await {
        Ok(m) => Ok(m),
        Err(e) => {
            debug!("self dns resolve error: {}", e);
            Err(watfaq_dns::DNSError::QueryFailed(e.to_string()))
        }
    };
}
