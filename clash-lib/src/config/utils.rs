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

