use core::net::Ipv6Addr;

#[repr(C)]
#[derive(Copy, Clone)]
pub union In6Addr {
    pub u6_addr8: [u8; 16],
    pub u6_addr16: [u16; 8],
    pub u6_addr32: [u32; 4],
    pub u6_addr64: [u64; 2],
}

/// IPv4-mapped IPv6 prefix ::ffff/96.
#[allow(unused)]
const V4_MAPPED_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];

impl In6Addr {
    /// The all-zeros address `::`.
    pub const fn zero() -> Self {
        Self { u6_addr64: [0, 0] }
    }

    /// Build an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) from an IPv4 address.
    ///
    /// `ipv4_be` must be in network byte order (big-endian), i.e. the `u32` form.
    pub const fn from_ipv4_mapped(ipv4_be: u32) -> Self {
        Self {
            u6_addr32: [
                0,
                0,
                0x0000FFFF_u32.to_be(), // ::ffff stored as network-order bytes
                ipv4_be.to_be(),        // store IPv4 bytes in network order
            ],
        }
    }

    /// Build from a 4-byte array (big-endian bytes, e.g. `[192, 168, 1, 1]`).
    pub const fn from_ipv4_bytes(octets: [u8; 4]) -> Self {
        Self::from_ipv4_mapped(u32::from_be_bytes(octets))
    }

    /// Returns `true` if this is an IPv4-mapped address (`::ffff/96`).
    pub fn is_v4_mapped(&self) -> bool {
        unsafe {
            self.u6_addr32[0] == 0
                && self.u6_addr32[1] == 0
                && self.u6_addr16[4] == 0
                && self.u6_addr16[5] == u16::to_be(0xffff)
        }
    }

    /// Returns `true` if this is an IPv4-compatible address (`::/96`, deprecated but
    /// may still be seen in the kernel).
    pub fn is_v4_compat(&self) -> bool {
        unsafe {
            self.u6_addr32[0] == 0
                && self.u6_addr32[1] == 0
                && self.u6_addr32[2] == 0
                && self.u6_addr32[3] != 0
        }
    }

    /// Modify only the low 32 bits (IPv4 part), keeping the prefix unchanged.
    /// The current address must already be v4-mapped or v4-compat.
    pub fn set_ipv4(&mut self, ipv4_be: u32) {
        unsafe {
            // Store the IPv4 bytes in network byte order.
            self.u6_addr32[3] = ipv4_be.to_be();
        }
    }

    /// Clear the address and set it to a new IPv4-mapped address.
    pub fn remap_ipv4(&mut self, ipv4_be: u32) {
        *self = Self::from_ipv4_mapped(ipv4_be);
    }

    /// Get a reference to the 16-byte array without requiring `unsafe` on the caller's side.
    pub fn as_bytes(&self) -> &[u8; 16] {
        unsafe { &self.u6_addr8 }
    }

    /// Construct from a standard `core::net::Ipv6Addr`.
    pub fn from_ipv6_addr(ipv6: Ipv6Addr) -> Self {
        Self {
            u6_addr8: ipv6.octets(),
        }
    }
}

impl Default for In6Addr {
    fn default() -> Self {
        Self::zero()
    }
}

/// Indexing delegates to the underlying `u6_addr8` byte array.
impl core::ops::Index<usize> for In6Addr {
    type Output = u8;
    fn index(&self, i: usize) -> &u8 {
        unsafe { &self.u6_addr8[i] }
    }
}

impl core::ops::IndexMut<usize> for In6Addr {
    fn index_mut(&mut self, i: usize) -> &mut u8 {
        unsafe { &mut self.u6_addr8[i] }
    }
}

impl In6Addr {
    /// Copy bytes from `src` into the address (up to 16 bytes).
    pub fn copy_from_slice(&mut self, src: &[u8]) {
        unsafe {
            self.u6_addr8[..src.len()].copy_from_slice(src);
        }
    }
}

impl core::ops::Index<core::ops::Range<usize>> for In6Addr {
    type Output = [u8];
    fn index(&self, r: core::ops::Range<usize>) -> &[u8] {
        unsafe { &self.u6_addr8[r] }
    }
}

impl core::ops::IndexMut<core::ops::Range<usize>> for In6Addr {
    fn index_mut(&mut self, r: core::ops::Range<usize>) -> &mut [u8] {
        unsafe { &mut self.u6_addr8[r] }
    }
}

impl AsRef<[u8; 16]> for In6Addr {
    fn as_ref(&self) -> &[u8; 16] {
        unsafe { &self.u6_addr8 }
    }
}

impl core::ops::Deref for In6Addr {
    type Target = [u8; 16];
    fn deref(&self) -> &[u8; 16] {
        unsafe { &self.u6_addr8 }
    }
}

impl AsRef<[u8]> for In6Addr {
    fn as_ref(&self) -> &[u8] {
        unsafe { &self.u6_addr8 }
    }
}

/// Debug output in `::ffff:c0a8:0101` style.
impl core::fmt::Debug for In6Addr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        unsafe {
            if self.is_v4_mapped() {
                let bytes = self.u6_addr32[3].to_be_bytes();
                write!(
                    f,
                    "::ffff:{}.{}.{}.{}",
                    bytes[0], bytes[1], bytes[2], bytes[3]
                )
            } else {
                write!(
                    f,
                    "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
                    u16::from_be(self.u6_addr16[0]),
                    u16::from_be(self.u6_addr16[1]),
                    u16::from_be(self.u6_addr16[2]),
                    u16::from_be(self.u6_addr16[3]),
                    u16::from_be(self.u6_addr16[4]),
                    u16::from_be(self.u6_addr16[5]),
                    u16::from_be(self.u6_addr16[6]),
                    u16::from_be(self.u6_addr16[7]),
                )
            }
        }
    }
}
