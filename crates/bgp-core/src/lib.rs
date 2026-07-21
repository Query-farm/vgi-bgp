//! `bgp-core` — the pure-compute core of the `vgi-bgp` worker.
//!
//! No Arrow, no VGI: just MRT decode (via `bgpkit-parser`) into flat row structs,
//! the AS-path / BGP-community helper functions, and the DuckDB `INET` physical
//! encoder. Everything here is directly unit-testable and `proptest`-fuzzable;
//! the `bgp-worker` crate is a thin Arrow/VGI adapter on top.
//!
//! ## Modules
//! - [`decode`] — sequential MRT stream → [`decode::MrtRow`] /
//!   [`decode::PeerRow`], with byte-offset resume and per-record error capture.
//! - [`inet`] — IP / prefix → DuckDB `INET` struct fields.
//! - [`aspath`] — `path_length` / `origin_asn` / `as_path_prepends` /
//!   `path_contains`.
//! - [`community`] — `community_parse` / `is_large_community`.

#![forbid(unsafe_code)]

pub mod aspath;
pub mod community;
pub mod decode;
pub mod inet;

pub use decode::{Decoder, MrtRow, MsgType, PeerRow};
pub use inet::{encode as encode_inet, encode_ip, InetVal};

/// The worker's own build version (the `bgp-core` crate version, which the
/// workspace keeps in lockstep with `bgp-worker`). Published as the catalog's
/// `implementation_version` so an agent reads it from `vgi_catalogs()`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
