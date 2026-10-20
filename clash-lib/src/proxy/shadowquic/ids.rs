use std::io;

const WORD_BITS: usize = u64::BITS as usize;
const WORDS: usize = (u16::MAX as usize + 1) / WORD_BITS;
const CAPACITY: usize = u16::MAX as usize + 1;

// Allocate the 8 KiB bitmap only when the first UDP destination is registered.
// Advance through the entire ID space before reusing IDs released by sessions.
#[derive(Default)]
pub(super) struct ContextIds {
    words: Option<Box<[u64; WORDS]>>,
    next_id: usize,
    used: usize,
}

impl ContextIds {
    pub fn allocate(&mut self) -> io::Result<u16> {
        if self.used == CAPACITY {
            return Err(io::Error::other("shadowquic UDP context IDs exhausted"));
        }
        let words = self.words.get_or_insert_with(|| Box::new([0; WORDS]));
        let first_word = self.next_id / WORD_BITS;
        let first_bit = self.next_id % WORD_BITS;
        for offset in 0..=WORDS {
            let index = (first_word + offset) % WORDS;
            let mut free = !words[index];
            if offset == 0 {
                free &= u64::MAX << first_bit;
            } else if offset == WORDS {
                free &= (1u64 << first_bit) - 1;
            }
            if free != 0 {
                let bit = free.trailing_zeros() as usize;
                words[index] |= 1u64 << bit;
                let id = index * WORD_BITS + bit;
                self.next_id = (id + 1) % CAPACITY;
                self.used += 1;
                return Ok(id as u16);
            }
        }
        unreachable!("context ID count must agree with the bitmap")
    }

    pub fn release(&mut self, id: u16) {
        let Some(words) = &mut self.words else { return };
        let index = id as usize / WORD_BITS;
        let mask = 1u64 << (id as usize % WORD_BITS);
        if words[index] & mask != 0 {
            words[index] &= !mask;
            self.used -= 1;
        }
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.used == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn released_id_is_not_reused_until_the_cursor_wraps() {
        let mut ids = ContextIds::default();
        assert!(ids.words.is_none());
        assert_eq!(ids.allocate().unwrap(), 0);
        assert_eq!(ids.allocate().unwrap(), 1);
        ids.release(0);
        assert_eq!(ids.allocate().unwrap(), 2);
    }
}
