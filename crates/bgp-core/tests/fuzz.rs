//! Untrusted-input hardening: the MRT decoder must NEVER panic on arbitrary or
//! truncated bytes — a malformed dump may only ever surface as a per-record
//! error, never crash the whole query. These `proptest` cases drive random byte
//! strings, truncated prefixes of the real fixtures, and bit-flipped fixtures
//! through the record loop and assert it always terminates without panicking.

use std::io::Cursor;

use bgp_core::decode::{next_record, Decoder};
use proptest::prelude::*;

/// Drive `bytes` through the full record loop. Returns the number of rows
/// produced. Must always terminate and never panic, whatever the input.
fn drain(bytes: &[u8]) -> usize {
    let mut r = Cursor::new(bytes);
    let mut dec = Decoder::new();
    let mut rows = 0usize;
    // A hard cap so a pathological "many tiny records" input can't loop forever
    // in the test (the worker itself streams unbounded, but the parser always
    // advances or errors, so this only bounds test runtime).
    for _ in 0..100_000 {
        match next_record(&mut r) {
            Ok(Some(rec)) => rows += dec.record_rows(rec).len(),
            Ok(None) => break,
            Err(_) => break,
        }
    }
    rows
}

/// Read the fixtures once for the truncation/mutation strategies.
fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("../../data/{name}")).unwrap_or_default()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Arbitrary bytes never panic the parser.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = drain(&bytes);
    }

    /// Every truncation prefix of a real RIB fixture is safe (covers a torn
    /// header, a torn body, and the exact boundary cases).
    #[test]
    fn truncated_rib_never_panics(cut in 0usize..512) {
        let data = fixture("rib.mrt");
        let n = cut.min(data.len());
        let _ = drain(&data[..n]);
    }

    /// Single-byte mutations of a real updates fixture are safe.
    #[test]
    fn mutated_updates_never_panics(idx in 0usize..512, xor in 1u8..=255) {
        let mut data = fixture("updates.mrt");
        if !data.is_empty() {
            let i = idx % data.len();
            data[i] ^= xor;
            let _ = drain(&data);
        }
    }

    /// Random bytes appended to a valid stream are safe (trailing garbage).
    #[test]
    fn valid_then_garbage_never_panics(garbage in proptest::collection::vec(any::<u8>(), 0..256)) {
        let mut data = fixture("updates.mrt");
        data.extend_from_slice(&garbage);
        let _ = drain(&data);
    }
}
