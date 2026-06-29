//! BGP community string decode helpers.
//!
//! The `communities` column emits each community as a canonical string (e.g.
//! `"65001:100"` standard, `"65001:1:2"` large, `"NO_EXPORT"` well-known). These
//! helpers back the `bgp.community_parse` and `bgp.is_large_community` scalars so
//! a community string can be split in SQL without a regex.

/// Parse a **standard** BGP community (`"<asn>:<value>"`, two 16-bit-ish integer
/// parts) into its `(asn, value)` pair. Returns `None` for anything that is not
/// a plain two-part numeric community — a large community (`a:b:c`), a
/// well-known mnemonic (`NO_EXPORT`), or an extended community — so the scalar
/// can yield a NULL struct for those.
pub fn community_parse(raw: &str) -> Option<(u32, u32)> {
    let mut parts = raw.trim().split(':');
    let asn = parts.next()?.parse::<u32>().ok()?;
    let value = parts.next()?.parse::<u32>().ok()?;
    // A third part means this is a large community, not a standard one.
    if parts.next().is_some() {
        return None;
    }
    Some((asn, value))
}

/// Whether `raw` is a **large** community (RFC 8092): exactly three
/// colon-separated unsigned-integer parts, `"<global>:<data1>:<data2>"`.
pub fn is_large_community(raw: &str) -> bool {
    let parts: Vec<&str> = raw.trim().split(':').collect();
    parts.len() == 3 && parts.iter().all(|p| p.parse::<u32>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard() {
        assert_eq!(community_parse("65001:100"), Some((65001, 100)));
        assert_eq!(community_parse(" 174:21000 "), Some((174, 21000)));
    }

    #[test]
    fn not_standard() {
        assert_eq!(community_parse("65001:1:2"), None); // large
        assert_eq!(community_parse("NO_EXPORT"), None); // well-known
        assert_eq!(community_parse("65001"), None); // single
        assert_eq!(community_parse("a:b"), None); // non-numeric
    }

    #[test]
    fn large() {
        assert!(is_large_community("65001:1:2"));
        assert!(is_large_community("4200000000:1:1"));
        assert!(!is_large_community("65001:100")); // standard
        assert!(!is_large_community("NO_EXPORT"));
        assert!(!is_large_community("1:2:x"));
    }
}
