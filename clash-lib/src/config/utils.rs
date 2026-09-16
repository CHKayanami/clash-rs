use serde::Deserialize;

use std::{fmt::Display, str::FromStr};

pub fn deserialize_u64<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: FromStr + serde::Deserialize<'de>,
    <T as FromStr>::Err: Display,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrNum<T> {
        String(String),
        Num(T),
    }

    match StringOrNum::<T>::deserialize(deserializer)? {
        StringOrNum::String(s) => s.parse().map_err(serde::de::Error::custom),
        StringOrNum::Num(n) => Ok(n),
    }
}

pub fn deserialize_opt_string_or_seq<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrSeq {
        String(String),
        Seq(Vec<String>),
    }

    let opt = Option::<StringOrSeq>::deserialize(deserializer)?;
    Ok(opt.map(|s| match s {
        StringOrSeq::String(s) => vec![s],
        StringOrSeq::Seq(seq) => seq,
    }))
}

pub fn deserialize_map_string_or_seq<'de, D>(
    deserializer: D,
) -> Result<Option<std::collections::HashMap<String, Vec<String>>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrSeq {
        String(String),
        Seq(Vec<String>),
    }

    let map =
        Option::<std::collections::HashMap<String, StringOrSeq>>::deserialize(
            deserializer,
        )?;
    Ok(map.map(|m| {
        m.into_iter()
            .map(|(k, v)| {
                let v = match v {
                    StringOrSeq::String(s) => vec![s],
                    StringOrSeq::Seq(seq) => seq,
                };
                (k, v)
            })
            .collect()
    }))
}

pub fn deserialize_usize<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrNum {
        String(String),
        Num(usize),
    }

    match Option::<StringOrNum>::deserialize(deserializer)? {
        None => Ok(0),
        Some(StringOrNum::String(s)) => {
            let s = s.trim();
            if s.is_empty() {
                Ok(0)
            } else {
                s.parse().map_err(serde::de::Error::custom)
            }
        }
        Some(StringOrNum::Num(n)) => Ok(n),
    }
}

pub fn parse_bandwidth_to_mbps(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    if let Ok(val) = s.parse::<u64>() {
        return Ok(val);
    }
    if let Ok(val) = s.parse::<f64>() {
        return Ok(val.max(0.0).round() as u64);
    }

    let num_end = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    let (num_str, unit_str) = s.split_at(num_end);
    let val: f64 = num_str
        .trim()
        .parse()
        .map_err(|e| format!("invalid number in bandwidth '{s}': {e}"))?;

    let unit = unit_str.trim().to_lowercase();
    let mbps = match unit.as_str() {
        "" | "mbps" | "mbit" | "m" => val,
        "kbps" | "kbit" | "k" => val / 1_000.0,
        "gbps" | "gbit" | "g" => val * 1_000.0,
        "bps" | "bit" => val / 1_000_000.0,
        // 以 Byte 为单位的速率 (B/s)，按 1 Byte = 8 bits 换算为 Mbps。
        "b/s" => (val * 8.0) / 1_000_000.0,
        "kb/s" | "kib/s" => (val * 8.0) / 1_000.0,
        "mb/s" | "mib/s" => val * 8.0,
        "gb/s" | "gib/s" => val * 8.0 * 1_000.0,
        _ => return Err(format!("unknown bandwidth unit in '{s}'")),
    };

    Ok(mbps.max(0.0).round() as u64)
}

pub fn deserialize_opt_bandwidth_mbps<'de, D>(
    deserializer: D,
) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum BandwidthVal {
        Num(u64),
        Float(f64),
        Str(String),
    }

    let opt = Option::<BandwidthVal>::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(BandwidthVal::Num(n)) => Ok(Some(n)),
        Some(BandwidthVal::Float(f)) => Ok(Some(f.max(0.0).round() as u64)),
        Some(BandwidthVal::Str(s)) => {
            parse_bandwidth_to_mbps(&s).map(Some).map_err(serde::de::Error::custom)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bandwidth() {
        assert_eq!(parse_bandwidth_to_mbps("1000 Mbps").unwrap(), 1000);
        assert_eq!(parse_bandwidth_to_mbps("1000 mbps").unwrap(), 1000);
        assert_eq!(parse_bandwidth_to_mbps("1000Mbps").unwrap(), 1000);
        assert_eq!(parse_bandwidth_to_mbps("50 MB/s").unwrap(), 400);
        assert_eq!(parse_bandwidth_to_mbps("1 Gbps").unwrap(), 1000);
        assert_eq!(parse_bandwidth_to_mbps("100").unwrap(), 100);
        assert_eq!(parse_bandwidth_to_mbps("125000 kbps").unwrap(), 125);
    }

    #[test]
    fn test_deserialize_usize() {
        #[derive(Deserialize)]
        struct TestMux {
            #[serde(deserialize_with = "deserialize_usize")]
            val: usize,
        }

        let from_str: TestMux = serde_yaml::from_str("val: '8'").unwrap();
        assert_eq!(from_str.val, 8);

        let from_num: TestMux = serde_yaml::from_str("val: 8").unwrap();
        assert_eq!(from_num.val, 8);

        let from_null: TestMux = serde_yaml::from_str("val: ~").unwrap();
        assert_eq!(from_null.val, 0);

        let from_null_word: TestMux = serde_yaml::from_str("val: null").unwrap();
        assert_eq!(from_null_word.val, 0);

        let from_empty_str: TestMux = serde_yaml::from_str("val: ''").unwrap();
        assert_eq!(from_empty_str.val, 0);
    }
}

