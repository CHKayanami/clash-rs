use super::{MAX_SNIFF_BUFFER_SIZE, http::HTTP_METHODS};

pub(super) struct Prefetch {
    tls_enabled: bool,
    http_enabled: bool,
    http_scan: usize,
    tls: TlsPrefix,
}

impl Prefetch {
    pub(super) fn new(tls_enabled: bool, http_enabled: bool) -> Self {
        Self { tls_enabled, http_enabled, http_scan: 0, tls: TlsPrefix::default() }
    }

    pub(super) fn required_len(&mut self, data: &[u8]) -> usize {
        if data.is_empty() { return 1; }
        if data[0] == 0x16 {
            return if self.tls_enabled {
                self.tls.required_len(data).min(MAX_SNIFF_BUFFER_SIZE)
            } else { data.len() };
        }
        if !self.http_enabled { return data.len(); }
        if !HTTP_METHODS.iter().any(|method| data.starts_with(method)) {
            return HTTP_METHODS.iter().filter(|method| method.starts_with(data))
                .map(|method| method.len()).min().unwrap_or(data.len());
        }
        // Keep the three boundary bytes needed for a split CRLF CRLF marker.
        let remaining = &data[self.http_scan..];
        if remaining.windows(4).any(|part| part == b"\r\n\r\n")
            || remaining.windows(2).any(|part| part == b"\n\n")
        {
            return data.len();
        }
        self.http_scan = data.len().saturating_sub(3);
        MAX_SNIFF_BUFFER_SIZE
    }
}

#[derive(Default)]
struct TlsPrefix {
    record_start: usize,
    cursor: usize,
    record_end: usize,
    header: [u8; 4],
    header_len: usize,
    remaining: Option<usize>,
}

impl TlsPrefix {
    fn required_len(&mut self, data: &[u8]) -> usize {
        loop {
            if self.cursor == self.record_end {
                self.record_start = self.record_end;
                let start = self.record_start;
                if data.len() > start && data[start] != 0x16
                    || data.len() > start + 1 && data[start + 1] != 0x03
                { return data.len(); }
                if data.len() < start + 5 { return start + 5; }
                let length = u16::from_be_bytes([data[start + 3], data[start + 4]])
                    as usize;
                self.cursor = start + 5;
                self.record_end = self.cursor + length;
                if length == 0 { continue; }
            }
            if self.header_len < 4 {
                let take = (4 - self.header_len)
                    .min(self.record_end - self.cursor)
                    .min(data.len().saturating_sub(self.cursor));
                self.header[self.header_len..self.header_len + take]
                    .copy_from_slice(&data[self.cursor..self.cursor + take]);
                self.header_len += take;
                self.cursor += take;
                if self.header_len < 4 {
                    if self.cursor == self.record_end { continue; }
                    return self.record_end.min(self.cursor + 4 - self.header_len);
                }
                if self.header[0] != 0x01 { return data.len(); }
                self.remaining = Some((usize::from(self.header[1]) << 16)
                    | (usize::from(self.header[2]) << 8)
                    | usize::from(self.header[3]));
            }
            let remaining = self.remaining.as_mut().unwrap();
            let take = (*remaining).min(self.record_end - self.cursor)
                .min(data.len().saturating_sub(self.cursor));
            *remaining -= take;
            self.cursor += take;
            if *remaining == 0 { return data.len(); }
            if self.cursor == self.record_end { continue; }
            return self.record_end.min(self.cursor + *remaining);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::sniffer::tests::build_multi_record_tls_client_hello;

    #[test]
    fn stops_when_the_enabled_protocol_cannot_match() {
        assert_eq!(Prefetch::new(true, false).required_len(b"G"), 1);
        assert_eq!(Prefetch::new(false, true).required_len(&[0x16]), 1);
        assert_eq!(Prefetch::new(true, true).required_len(b"SSH-"), 4);
        assert_eq!(Prefetch::new(true, true).required_len(b"GE"), 4);
    }

    #[test]
    fn http_markers_split_across_reads() {
        for marker in [b"\r\n\r\n".as_slice(), b"\n\n"] {
            let mut state = Prefetch::new(false, true);
            let mut data = b"GET / HTTP/1.1\r\nHost: example.com".to_vec();
            assert_eq!(state.required_len(&data), MAX_SNIFF_BUFFER_SIZE);
            for (index, byte) in marker.iter().enumerate() {
                data.push(*byte);
                let required = state.required_len(&data);
                assert_eq!(required, if index + 1 == marker.len() {
                    data.len()
                } else { MAX_SNIFF_BUFFER_SIZE });
            }
        }
    }

    #[test]
    fn tls_records_and_handshake_header_can_be_split_at_every_byte() {
        for split in 1..=40 {
            let data = build_multi_record_tls_client_hello("example.com", split);
            let mut state = Prefetch::new(true, false);
            for length in 1..data.len() {
                assert!(state.required_len(&data[..length]) > length);
            }
            assert_eq!(state.required_len(&data), data.len());
        }
    }
}
