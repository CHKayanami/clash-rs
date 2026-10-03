use std::{fmt::Display, io, ops::RangeInclusive};

pub(super) fn invalid(message: impl Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_string())
}

pub(super) fn range(
    value: Option<&str>, default: RangeInclusive<u32>,
    limit: RangeInclusive<u32>, name: &str,
) -> io::Result<RangeInclusive<u32>> {
    let (from, to) = match value.map(str::trim).filter(|value| !value.is_empty()) {
        None => (*default.start(), *default.end()),
        Some(value) => {
            let (from, to) = value.split_once('-').unwrap_or((value, value));
            let from = from.trim().parse().map_err(|_| invalid(format!("invalid XHTTP {name} range")))?;
            let to = to.trim().parse().map_err(|_| invalid(format!("invalid XHTTP {name} range")))?;
            (from, to)
        }
    };
    if from > to || !limit.contains(&from) || !limit.contains(&to) {
        return Err(invalid(format!("XHTTP {name} is outside {limit:?}")));
    }
    Ok(from..=to)
}
