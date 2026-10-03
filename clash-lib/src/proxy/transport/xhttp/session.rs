use std::{collections::HashSet, io, ops::RangeInclusive};
use uuid::Uuid;
use crate::config::internal::proxy::XHttpOpt;
use super::range::{invalid, range};

pub(super) struct SessionId {
    table: Option<Vec<u8>>,
    uuid: bool,
    length: RangeInclusive<u32>,
}

impl SessionId {
    pub(super) fn new(opts: &XHttpOpt) -> io::Result<Self> {
        let configured = opts.session_table.as_deref().unwrap_or("");
        let table = match configured {
            "" | "uuid" => None,
            "ALPHABET" => Some("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
            "Alphabet" => Some("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"),
            "BASE36" => Some("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
            "Base62" => Some("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"),
            "HEX" => Some("0123456789ABCDEF"),
            "alphabet" => Some("abcdefghijklmnopqrstuvwxyz"),
            "base36" => Some("0123456789abcdefghijklmnopqrstuvwxyz"),
            "hex" => Some("0123456789abcdef"),
            "number" => Some("0123456789"),
            other => Some(other),
        }.map(|table| table.as_bytes().to_vec());
        let length = range(opts.session_length.as_deref(), 16..=32, 1..=256, "session length")?;
        if let Some(table) = &table {
            if !table.iter().all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(byte)) {
                return Err(invalid("XHTTP session table must contain URL-safe ASCII characters"));
            }
            let distinct = table.iter().copied().collect::<HashSet<_>>().len();
            let possibilities: f64 = length.clone().map(|length| (distinct as f64).powi(length as i32)).sum();
            if possibilities < 2_147_483_648.0 {
                return Err(invalid("XHTTP session table/length provides too few unique IDs"));
            }
        }
        Ok(Self { table, uuid: configured == "uuid", length })
    }

    pub(super) fn generate(&self) -> String {
        match &self.table {
            None if self.uuid => Uuid::new_v4().to_string(),
            None => Uuid::new_v4().simple().to_string(),
            Some(table) => (0..rand::random_range(self.length.clone()))
                .map(|_| table[rand::random_range(0..table.len())] as char).collect(),
        }
    }
}
