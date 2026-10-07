//! Relay server in local and server side implementations.

pub use self::socks5::Address;

pub mod socks5;
pub mod tcprelay;
pub mod udprelay;

#[cfg(feature = "aead-cipher-2022")]
use bytes::BufMut;

/// AEAD 2022 maximum padding length
#[cfg(feature = "aead-cipher-2022")]
const AEAD2022_MAX_PADDING_SIZE: usize = 900;

/// Get a properly AEAD 2022 padding size according to payload's length
#[cfg(feature = "aead-cipher-2022")]
fn get_aead_2022_padding_size(payload: &[u8]) -> usize {
    use std::cell::RefCell;

    use rand::{RngExt, rngs::SmallRng};

    thread_local! {
        static PADDING_RNG: RefCell<SmallRng> = RefCell::new(rand::make_rng());
    }

    if payload.is_empty() {
        PADDING_RNG.with(|rng| rng.borrow_mut().random_range::<usize, _>(1..=AEAD2022_MAX_PADDING_SIZE))
    } else {
        0
    }
}

#[cfg(feature = "aead-cipher-2022")]
fn write_aead_2022_padding<B: BufMut>(buf: &mut B, size: usize) {
    use rand::RngExt;

    assert!(size <= AEAD2022_MAX_PADDING_SIZE);
    if size > 0 {
        let mut padding = [0_u8; AEAD2022_MAX_PADDING_SIZE];
        let padding = &mut padding[..size];
        rand::rng().fill(padding);
        buf.put_slice(padding);
    }
}

#[cfg(all(test, feature = "aead-cipher-2022"))]
mod tests {
    use super::*;

    #[test]
    fn empty_payload_always_has_padding() {
        for _ in 0..4096 {
            let size = get_aead_2022_padding_size(&[]);
            assert!((1..=AEAD2022_MAX_PADDING_SIZE).contains(&size));
        }
        assert_eq!(get_aead_2022_padding_size(b"payload"), 0);
    }
}
