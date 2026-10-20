use std::{fmt, io, time::Duration};

use serde::{Deserialize, Deserializer, Serialize, de::Error as DeError};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CongestionControl {
    #[default]
    Bbr,
    Cubic,
    NewReno,
    Brutal(BrutalParams),
    Bbr3,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct BrutalParams {
    #[serde(deserialize_with = "deserialize_bandwidth")]
    pub bandwidth: u64,
    pub min_window: u64,
    pub cwnd_gain: f64,
    pub min_ack_rate: f64,
    pub min_sample_count: u64,
    pub ack_compensate: bool,
}

impl Default for BrutalParams {
    fn default() -> Self {
        Self {
            bandwidth: 10_000_000,
            min_window: 16 * 1024,
            cwnd_gain: 1.10,
            min_ack_rate: 0.8,
            min_sample_count: 50,
            ack_compensate: false,
        }
    }
}

// ShadowQUIC bandwidth suffixes use binary multipliers and bits per second.
fn deserialize_bandwidth<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Bandwidth {
        Integer(u64),
        Float(f64),
        Text(String),
    }
    let value = match Bandwidth::deserialize(deserializer)? {
        Bandwidth::Integer(value) => return Ok(value),
        Bandwidth::Float(value) => value,
        Bandwidth::Text(value) => {
            let text = value.trim();
            let (number, multiplier) = match text.as_bytes().last() {
                Some(b'k' | b'K') => (&text[..text.len() - 1], 1024.0),
                Some(b'm' | b'M') => (&text[..text.len() - 1], 1024.0 * 1024.0),
                Some(b'g' | b'G') => (&text[..text.len() - 1], 1024.0 * 1024.0 * 1024.0),
                Some(b'0'..=b'9') => (text, 1.0),
                _ => return Err(D::Error::custom("invalid bandwidth suffix")),
            };
            number.trim().parse::<f64>().map_err(D::Error::custom)? * multiplier
        }
    };
    if !value.is_finite() || value < 0.0 || value >= u64::MAX as f64 {
        return Err(D::Error::custom("bandwidth is outside the u64 range"));
    }
    Ok(value.round() as u64)
}

#[derive(Clone)]
pub struct HandlerOptions {
    pub addr: String,
    pub username: String,
    pub password: String,
    pub server_name: String,
    pub alpn: Vec<String>,
    pub initial_mtu: u16,
    pub min_mtu: u16,
    pub congestion_control: CongestionControl,
    pub zero_rtt: bool,
    pub over_stream: bool,
    pub keep_alive_interval: u32,
    pub gso: bool,
    pub mtu_discovery: bool,
}

impl fmt::Debug for HandlerOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandlerOptions")
            .field("addr", &self.addr)
            .field("server_name", &self.server_name)
            .field("over_stream", &self.over_stream)
            .finish_non_exhaustive()
    }
}

impl Default for HandlerOptions {
    fn default() -> Self {
        Self {
            addr: String::new(),
            username: String::new(),
            password: String::new(),
            server_name: String::new(),
            alpn: vec!["h3".into()],
            initial_mtu: 1300,
            min_mtu: 1290,
            congestion_control: CongestionControl::default(),
            zero_rtt: true,
            over_stream: false,
            keep_alive_interval: 0,
            gso: true,
            mtu_discovery: true,
        }
    }
}

impl HandlerOptions {
    pub(crate) fn validate(&self) -> io::Result<()> {
        if self.min_mtu < 1200 || self.initial_mtu < self.min_mtu {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "shadowquic requires initial-mtu >= min-mtu >= 1200",
            ));
        }
        if let CongestionControl::Brutal(params) = &self.congestion_control
            && (params.bandwidth == 0 || params.min_window == 0
                || !params.cwnd_gain.is_finite() || params.cwnd_gain <= 0.0
                || !params.min_ack_rate.is_finite()
                || params.min_ack_rate <= 0.0 || params.min_ack_rate > 1.0
                || params.min_sample_count == 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput, "invalid shadowquic brutal parameters",
            ));
        }
        Ok(())
    }

    pub(super) fn keep_alive(&self) -> Option<Duration> {
        (self.keep_alive_interval != 0)
            .then(|| Duration::from_millis(self.keep_alive_interval.into()))
    }
}
