//! AS-path helper functions, pure over a decoded path of ASNs.
//!
//! These back the `bgp.path_length`, `bgp.origin_asn`, `bgp.as_path_prepends`,
//! and `bgp.path_contains` scalars. The worker hands each one the `as_path`
//! column value — a `LIST(UINTEGER)` — as a `&[u32]`, so all the logic lives
//! here, decoupled from Arrow and unit-tested directly. A path is stored in
//! path order: index 0 is the most recent (neighbor) AS, the last element is the
//! origin AS that announced the prefix.

/// Number of AS hops in the path (its length). `[]` → 0.
pub fn path_length(path: &[u32]) -> i64 {
    path.len() as i64
}

/// The origin AS — the last (right-most) ASN in the path, which announced the
/// prefix. `None` for an empty path.
pub fn origin_asn(path: &[u32]) -> Option<u32> {
    path.last().copied()
}

/// Number of AS-path *prepends*: extra occurrences of an ASN that immediately
/// repeats its predecessor (a router padding its own ASN to deprioritize a
/// route). Equivalent to `len - number_of_runs` — e.g. `[1,1,1,2]` has two
/// prepends (two of the three `1`s are padding), `[1,2,3]` has none.
pub fn as_path_prepends(path: &[u32]) -> i64 {
    let mut prepends = 0i64;
    for w in path.windows(2) {
        if w[0] == w[1] {
            prepends += 1;
        }
    }
    prepends
}

/// Whether `asn` appears anywhere in the path.
pub fn path_contains(path: &[u32], asn: u32) -> bool {
    path.contains(&asn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_and_origin() {
        assert_eq!(path_length(&[]), 0);
        assert_eq!(path_length(&[7018, 174, 13335]), 3);
        assert_eq!(origin_asn(&[7018, 174, 13335]), Some(13335));
        assert_eq!(origin_asn(&[]), None);
    }

    #[test]
    fn prepends() {
        assert_eq!(as_path_prepends(&[1, 2, 3]), 0);
        assert_eq!(as_path_prepends(&[1, 1, 1, 2]), 2);
        assert_eq!(as_path_prepends(&[5, 5, 6, 6, 6]), 3);
        assert_eq!(as_path_prepends(&[]), 0);
        assert_eq!(as_path_prepends(&[9]), 0);
    }

    #[test]
    fn contains() {
        assert!(path_contains(&[7018, 174, 13335], 174));
        assert!(!path_contains(&[7018, 174, 13335], 666));
        assert!(!path_contains(&[], 1));
    }
}
