const MAX_DNS_MESSAGE_SIZE_U64: u64 = 65_535;

pub const MAX_DNS_MESSAGE_SIZE: usize = 65_535;

#[derive(Debug, thiserror::Error)]
#[error("{transport} DNS response size {attempted} exceeds protocol maximum {maximum}")]
pub struct DnsMessageTooLarge {
    transport: &'static str,
    attempted: u64,
    maximum: usize,
}

pub struct DnsMessageBody {
    transport: &'static str,
    bytes: Vec<u8>,
}

impl DnsMessageBody {
    pub fn new(
        transport: &'static str,
        content_length: Option<usize>,
    ) -> anyhow::Result<Self> {
        if let Some(attempted) = content_length.filter(|length| *length > MAX_DNS_MESSAGE_SIZE) {
            return Err(DnsMessageTooLarge {
                transport,
                attempted: u64::try_from(attempted).unwrap_or(u64::MAX),
                maximum: MAX_DNS_MESSAGE_SIZE,
            }
            .into());
        }
        Ok(Self {
            transport,
            bytes: Vec::with_capacity(content_length.unwrap_or(512)),
        })
    }

    pub fn push(&mut self, chunk: &[u8]) -> anyhow::Result<()> {
        let attempted = self
            .bytes
            .len()
            .checked_add(chunk.len())
            .ok_or(DnsMessageTooLarge {
                transport: self.transport,
                attempted: u64::MAX,
                maximum: MAX_DNS_MESSAGE_SIZE,
            })?;
        if attempted > MAX_DNS_MESSAGE_SIZE {
            return Err(DnsMessageTooLarge {
                transport: self.transport,
                attempted: u64::try_from(attempted).unwrap_or(u64::MAX),
                maximum: MAX_DNS_MESSAGE_SIZE,
            }
            .into());
        }
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

pub fn doh_content_length(
    transport: &'static str,
    headers: &http::HeaderMap,
) -> anyhow::Result<Option<usize>> {
    let Some(value) = headers.get(http::header::CONTENT_LENGTH) else {
        return Ok(None);
    };
    let parsed = value
        .to_str()
        .map_err(|error| anyhow::anyhow!("{transport} invalid Content-Length: {error}"))?
        .parse::<u64>()
        .map_err(|error| anyhow::anyhow!("{transport} invalid Content-Length: {error}"))?;
    if parsed > MAX_DNS_MESSAGE_SIZE_U64 {
        return Err(DnsMessageTooLarge {
            transport,
            attempted: parsed,
            maximum: MAX_DNS_MESSAGE_SIZE,
        }
        .into());
    }
    usize::try_from(parsed)
        .map(Some)
        .map_err(|error| anyhow::anyhow!("{transport} invalid Content-Length: {error}"))
}
