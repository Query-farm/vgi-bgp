//! Encode an IP address / prefix into DuckDB's internal `INET` physical layout.
//!
//! DuckDB's core `INET` type is, on the Arrow boundary, a
//! `STRUCT(ip_type UTINYINT, address HUGEINT, mask USMALLINT)`. The worker emits
//! exactly that struct so a scanned `prefix` / `peer_ip` / `next_hop` column is a
//! zero-cost `::INET` cast away from the native type — `prefix::INET <<= …`,
//! `&&`, and prefix joins against `vgi-netflow` / geoip then work without parsing
//! a string. This module produces the three field values for one address.
//!
//! ## Encoding (validated against DuckDB 1.5's `inet` extension)
//!
//! - `ip_type`: `1` for IPv4, `2` for IPv6.
//! - `address`: the 128-bit DuckDB `HUGEINT` storage value. For IPv4 it is the
//!   32 address bits as an unsigned integer in the low bits. For IPv6 it is the
//!   128 address bits as a big-endian integer with the **sign bit flipped**
//!   (`value XOR 2^127`) — how DuckDB maps the unsigned 128-bit address onto the
//!   signed `HUGEINT` while preserving ordering. The returned `address_le` is
//!   that `i128` in **little-endian** bytes, the order DuckDB reads a `HUGEINT`
//!   Arrow buffer in.
//! - `mask`: the prefix length in bits (`/24`, `/64`, …).

use std::net::IpAddr;

/// The three field values of one DuckDB `INET` struct cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InetVal {
    /// `1` = IPv4, `2` = IPv6.
    pub ip_type: u8,
    /// The DuckDB `HUGEINT` address value, little-endian `i128` bytes.
    pub address_le: [u8; 16],
    /// Prefix length in bits.
    pub mask: u16,
}

/// The `ip_type` discriminant DuckDB's `inet` extension uses for IPv4.
const IP_TYPE_V4: u8 = 1;
/// The `ip_type` discriminant DuckDB's `inet` extension uses for IPv6.
const IP_TYPE_V6: u8 = 2;

/// Encode a bare [`IpAddr`] as an `INET` host address (mask defaults to the full
/// width: `/32` for IPv4, `/128` for IPv6).
pub fn encode_ip(ip: IpAddr) -> InetVal {
    match ip {
        IpAddr::V4(_) => encode(ip, 32),
        IpAddr::V6(_) => encode(ip, 128),
    }
}

/// Encode an address + prefix length into the DuckDB `INET` field triple.
pub fn encode(ip: IpAddr, mask: u16) -> InetVal {
    match ip {
        IpAddr::V4(v4) => {
            // IPv4: the 4 octets as a big-endian u32 in the low bits; high bits 0.
            let addr = u32::from_be_bytes(v4.octets()) as i128;
            InetVal {
                ip_type: IP_TYPE_V4,
                address_le: addr.to_le_bytes(),
                mask,
            }
        }
        IpAddr::V6(v6) => {
            // IPv6: the 16 network-order bytes as a big-endian u128, then flip the
            // sign bit (XOR 2^127) to match DuckDB's signed HUGEINT mapping.
            let be = u128::from_be_bytes(v6.octets());
            let flipped = be ^ (1u128 << 127);
            InetVal {
                ip_type: IP_TYPE_V6,
                address_le: (flipped as i128).to_le_bytes(),
                mask,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    #[test]
    fn ipv4_low_bits() {
        // 203.0.113.5 = 0xCB007105 = 3405803781 in the low 32 bits.
        let v = encode(IpAddr::from_str("203.0.113.5").unwrap(), 24);
        assert_eq!(v.ip_type, 1);
        assert_eq!(v.mask, 24);
        assert_eq!(i128::from_le_bytes(v.address_le), 0xCB00_7105);
    }

    #[test]
    fn ipv4_full_range() {
        let v = encode(IpAddr::from_str("255.255.255.255").unwrap(), 32);
        assert_eq!(i128::from_le_bytes(v.address_le), 0xFFFF_FFFF);
    }

    #[test]
    fn ipv6_sign_bit_flipped() {
        // `::` -> 0 XOR 2^127 = 2^127, as i128 that is i128::MIN (-2^127).
        let v = encode(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
        assert_eq!(v.ip_type, 2);
        assert_eq!(i128::from_le_bytes(v.address_le), i128::MIN);
        // `::1` -> 1 XOR 2^127 = i128::MIN + 1.
        let v1 = encode(IpAddr::from_str("::1").unwrap(), 128);
        assert_eq!(i128::from_le_bytes(v1.address_le), i128::MIN + 1);
    }

    #[test]
    fn ipv6_top_byte_flip() {
        // 2001:db8::1 — top byte 0x20 becomes 0xa0 (0x20 ^ 0x80) in the stored
        // big-endian value; little-endian byte[15] therefore holds 0xa0.
        let v = encode(IpAddr::from_str("2001:db8::1").unwrap(), 64);
        assert_eq!(v.address_le[15], 0xa0);
        assert_eq!(v.address_le[0], 0x01); // low byte of the address
    }

    #[test]
    fn default_masks() {
        assert_eq!(encode_ip(IpAddr::from_str("10.0.0.1").unwrap()).mask, 32);
        assert_eq!(encode_ip(IpAddr::from_str("::1").unwrap()).mask, 128);
    }
}
