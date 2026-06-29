//! Deterministic golden-fixture generator for `vgi-bgp`.
//!
//! Builds small synthetic MRT files from hand-written `BgpElem`s using
//! `bgpkit-parser`'s encoder, so the unit tests (`bgp-core/tests/golden.rs`) and
//! the haybarn SQLLogic E2E (`test/sql/*.test`) run against checked-in,
//! reproducible bytes — no network archive download.
//!
//! Regenerate with:
//! ```sh
//! cargo run --quiet --manifest-path data/fixtures/Cargo.toml
//! ```
//! (a tiny throwaway crate that depends on `bgpkit-parser` with the `parser`
//! feature and contains this file as `src/main.rs`). The produced files:
//!
//! - `data/rib.mrt`        — a TABLE_DUMP_V2 RIB snapshot: a PEER_INDEX_TABLE
//!   plus IPv4 and IPv6 prefixes, several peers, large communities.
//! - `data/updates.mrt`    — a BGP4MP update batch: announcements + a withdrawal,
//!   IPv4 + IPv6, standard and large communities.
//! - `data/updates.mrt.gz` — gzip of `updates.mrt` (exercises transparent
//!   decompression).
//! - `data/truncated.mrt`  — `rib.mrt` with its final record chopped mid-body
//!   (exercises the per-record error/truncated-tail path).

use std::net::IpAddr;
use std::str::FromStr;

use bgpkit_parser::encoder::{MrtRibEncoder, MrtUpdatesEncoder};
use bgpkit_parser::models::{
    Asn, AsPath, Community, ElemType, LargeCommunity, MetaCommunity, NetworkPrefix, Origin,
};
use bgpkit_parser::BgpElem;

fn elem(
    ts: f64,
    etype: ElemType,
    peer_ip: &str,
    peer_asn: u32,
    prefix: &str,
    path: &[u32],
    next_hop: Option<&str>,
    communities: Vec<MetaCommunity>,
) -> BgpElem {
    let origin = path.last().copied();
    BgpElem {
        timestamp: ts,
        elem_type: etype,
        peer_ip: IpAddr::from_str(peer_ip).unwrap(),
        peer_asn: Asn::new_32bit(peer_asn),
        prefix: NetworkPrefix::from_str(prefix).unwrap(),
        next_hop: next_hop.map(|n| IpAddr::from_str(n).unwrap()),
        as_path: if path.is_empty() {
            None
        } else {
            Some(AsPath::from_sequence(path))
        },
        origin_asns: origin.map(|o| vec![Asn::new_32bit(o)]),
        origin: Some(Origin::IGP),
        local_pref: Some(100),
        med: Some(0),
        communities: if communities.is_empty() {
            None
        } else {
            Some(communities)
        },
        atomic: false,
        ..Default::default()
    }
}

fn std_comm(asn: u16, value: u16) -> MetaCommunity {
    MetaCommunity::Plain(Community::Custom(Asn::new_16bit(asn), value))
}

fn large_comm(global: u32, d1: u32, d2: u32) -> MetaCommunity {
    MetaCommunity::Large(LargeCommunity::new(global, [d1, d2]))
}

fn main() {
    let ts = 1_751_155_200.0; // 2025-06-29T00:00:00Z

    // ---- RIB snapshot (TABLE_DUMP_V2) ----
    let mut rib = MrtRibEncoder::new();
    // IPv4 prefix seen by two peers, one with a prepended path + large community.
    rib.process_elem(&elem(
        ts,
        ElemType::ANNOUNCE,
        "192.0.2.1",
        65001,
        "203.0.113.0/24",
        &[65001, 64500, 64500, 64512],
        Some("192.0.2.1"),
        vec![std_comm(65001, 100), large_comm(65001, 1, 2)],
    ));
    rib.process_elem(&elem(
        ts,
        ElemType::ANNOUNCE,
        "198.51.100.7",
        65002,
        "203.0.113.0/24",
        &[65002, 64513, 64512],
        Some("198.51.100.7"),
        vec![std_comm(65002, 200)],
    ));
    // IPv6 prefix.
    rib.process_elem(&elem(
        ts,
        ElemType::ANNOUNCE,
        "2001:db8::1",
        65001,
        "2001:db8:abcd::/48",
        &[65001, 64500, 64600],
        Some("2001:db8::1"),
        vec![large_comm(65001, 7, 9)],
    ));
    std::fs::write("data/rib.mrt", rib.export_bytes()).unwrap();

    // ---- BGP4MP updates batch ----
    let mut upd = MrtUpdatesEncoder::new();
    upd.process_elem(&elem(
        ts,
        ElemType::ANNOUNCE,
        "192.0.2.1",
        65001,
        "203.0.113.0/24",
        &[65001, 64500, 64512],
        Some("192.0.2.1"),
        vec![std_comm(65001, 100), large_comm(65001, 1, 2)],
    ));
    upd.process_elem(&elem(
        ts + 1.0,
        ElemType::ANNOUNCE,
        "2001:db8::1",
        65001,
        "2001:db8:abcd::/48",
        &[65001, 64600],
        Some("2001:db8::1"),
        vec![],
    ));
    upd.process_elem(&elem(
        ts + 2.0,
        ElemType::WITHDRAW,
        "192.0.2.1",
        65001,
        "203.0.113.0/24",
        &[],
        None,
        vec![],
    ));
    let upd_bytes = upd.export_bytes();
    std::fs::write("data/updates.mrt", &upd_bytes).unwrap();

    // gzip of the updates file.
    {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&upd_bytes).unwrap();
        std::fs::write("data/updates.mrt.gz", enc.finish().unwrap()).unwrap();
    }

    // truncated: rib.mrt with the last 8 bytes chopped off (mid tail record).
    let rib_bytes = std::fs::read("data/rib.mrt").unwrap();
    let cut = rib_bytes.len().saturating_sub(8);
    std::fs::write("data/truncated.mrt", &rib_bytes[..cut]).unwrap();

    eprintln!("wrote fixtures: rib.mrt updates.mrt updates.mrt.gz truncated.mrt");
}
