//! AnyTLS padding scheme implementation
//!
//! Provides configurable packet padding to obfuscate TLS-in-TLS fingerprints.
//! Based on the AnyTLS protocol specification.

use md5::{Digest, Md5};
use rand::RngExt;
use std::sync::Arc;

use super::types::StringMap;

/// Check mark constant - indicates "stop if no more data" in padding scheme
pub const CHECK_MARK: i32 = -1;

/// Default padding scheme from the AnyTLS specification
pub const DEFAULT_PADDING_SCHEME: &str = r#"stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000"#;

/// PaddingFactory generates padding sizes according to the configured scheme
#[derive(Debug, Clone)]
pub struct PaddingFactory {
    /// Parsed scheme as key-value map
    scheme: StringMap,
    /// Raw scheme bytes (for transmission)
    #[allow(dead_code)]
    raw_scheme: Vec<u8>,
    /// Stop padding after this many packets
    stop: u32,
    /// MD5 hash of the scheme
    md5: String,
}

impl PaddingFactory {
    /// Create a new PaddingFactory from raw scheme bytes
    pub fn new(raw_scheme: &[u8]) -> Result<Self, String> {
        let scheme = StringMap::from_bytes(raw_scheme);

        let stop = scheme
            .get("stop")
            .ok_or_else(|| "missing 'stop' in padding scheme".to_string())?
            .parse::<u32>()
            .map_err(|_| "invalid 'stop' value in padding scheme".to_string())?;

        let mut hasher = Md5::new();
        hasher.update(raw_scheme);
        let md5_result: [u8; 16] = hasher.finalize().into();
        let md5 = md5_result
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        Ok(Self {
            scheme,
            raw_scheme: raw_scheme.to_vec(),
            stop,
            md5,
        })
    }

    /// Create the default padding factory
    pub fn default_factory() -> Arc<Self> {
        Arc::new(
            Self::new(DEFAULT_PADDING_SCHEME.as_bytes())
                .expect("default padding scheme should be valid"),
        )
    }

    /// Get the stop value (number of packets to pad)
    pub fn stop(&self) -> u32 {
        self.stop
    }

    /// Get the MD5 hash of the scheme
    pub fn md5(&self) -> &str {
        &self.md5
    }

    /// Get the raw scheme bytes
    #[allow(dead_code)]
    pub fn raw_scheme(&self) -> &[u8] {
        &self.raw_scheme
    }

    /// Generate record payload sizes for a given packet number
    ///
    /// Returns a vector of sizes, where CHECK_MARK (-1) indicates
    /// "stop processing if no more payload data"
    ///
    /// # Arguments
    /// * `pkt` - The packet number (0-indexed)
    pub fn generate_record_payload_sizes(&self, pkt: u32) -> Vec<i32> {
        let key = pkt.to_string();
        let Some(spec) = self.scheme.get(&key) else {
            return Vec::new();
        };

        let mut sizes = Vec::new();
        let parts: Vec<&str> = spec.split(',').collect();

        for part in parts {
            let part = part.trim();

            if part == "c" {
                sizes.push(CHECK_MARK);
                continue;
            }

            if let Some((min_str, max_str)) = part.split_once('-') {
                let min_val: i64 = match min_str.trim().parse() {
                    Ok(v) if v > 0 => v,
                    _ => continue,
                };
                let max_val: i64 = match max_str.trim().parse() {
                    Ok(v) if v > 0 => v,
                    _ => continue,
                };

                let (min_val, max_val) =
                    (min_val.min(max_val), min_val.max(max_val));

                // Saturate rather than truncate: `as i32` on a large value can
                // land on -1, which is `CHECK_MARK` and would be read back as a
                // scheme directive rather than a size.
                let clamp = |v: i64| v.clamp(0, i32::MAX as i64) as i32;

                if min_val == max_val {
                    sizes.push(clamp(min_val));
                } else {
                    let mut rng = rand::rng();
                    let size = rng.random_range(min_val..=max_val);
                    sizes.push(clamp(size));
                }
            }
        }

        sizes
    }
}

impl Default for PaddingFactory {
    fn default() -> Self {
        Self::new(DEFAULT_PADDING_SCHEME.as_bytes())
            .expect("default padding scheme should be valid")
    }
}
