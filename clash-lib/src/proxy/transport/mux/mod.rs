use serde::{Deserialize, Serialize};

use crate::config::utils::deserialize_usize;

pub mod h2mux;
pub use h2mux::H2MuxPool;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum MuxProtocol {
    #[default]
    #[serde(rename = "h2mux", alias = "h2_mux", alias = "h2")]
    H2Mux,
    #[serde(rename = "smux")]
    Smux,
    #[serde(rename = "yamux")]
    Yamux,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct MuxOption {
    #[serde(default, alias = "enabled")]
    pub enable: bool,
    #[serde(default)]
    pub protocol: MuxProtocol,
    #[serde(default, alias = "max_connections", deserialize_with = "deserialize_usize")]
    pub max_connections: usize,
    #[serde(default, alias = "min_streams", deserialize_with = "deserialize_usize")]
    pub min_streams: usize,
    #[serde(default, alias = "max_streams", deserialize_with = "deserialize_usize")]
    pub max_streams: usize,
    #[serde(default)]
    pub padding: bool,
    #[serde(default)]
    pub statistic: bool,
}

impl MuxOption {
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.enable && self.protocol != MuxProtocol::H2Mux {
            return Err(crate::Error::InvalidConfig(format!(
                "unsupported multiplex protocol '{:?}', currently only 'h2mux' is supported",
                self.protocol
            )));
        }
        Ok(())
    }
}
