//! The `bgp` VGI worker.
//!
//! A standalone binary DuckDB launches and talks to over Apache Arrow IPC. It
//! decodes **MRT** routing dumps (RouteViews / RIPE RIS archives — `BGP4MP`
//! updates and `TABLE_DUMP_V2` RIB snapshots) into rows under catalog `bgp`,
//! schema `main`, so route-leak / hijack / RIB-diff analysis is a SQL JOIN
//! against `vgi-threatintel` / `vgi-netflow` instead of an ETL-to-Parquet step:
//!
//! - `bgp.main.read_rib(src)` — scan a TABLE_DUMP_V2 RIB snapshot into rows
//! - `bgp.main.read_updates(src)` — scan a BGP4MP update stream into rows
//! - `bgp.main.peers(src)` — list the distinct peers / collectors in a file
//! - `bgp.main.path_length/origin_asn/as_path_prepends/path_contains` — AS-path
//!   helpers; `bgp.main.community_parse/is_large_community` — community decode
//!
//! Prefixes and peer IPs reuse DuckDB's core `INET` type (cast with `::INET`) so
//! containment joins work natively. RPKI / route-origin validation is out of
//! scope by design — it belongs in `vgi-netflow`.

mod arrow_io;
mod cloud;
mod meta;
mod options;
mod reader;
mod scalar;
mod table;

use vgi::catalog::{CatSchema, CatalogModel};
use vgi::Worker;

/// Catalog + schema metadata (description, provenance, discovery tags) surfaced
/// to DuckDB and the `vgi-lint` metadata linter.
fn catalog_metadata(name: &str) -> CatalogModel {
    CatalogModel {
        name: name.to_string(),
        comment: Some(
            "Decode MRT routing dumps (BGP4MP updates + TABLE_DUMP_V2 RIB snapshots) into SQL \
             rows, reusing the core INET type for prefixes and peer IPs."
                .to_string(),
        ),
        tags: vec![
            (
                "vgi.title".to_string(),
                "BGP / MRT Routing-Dump Decoder".to_string(),
            ),
            (
                "vgi.keywords".to_string(),
                crate::meta::keywords_json(
                    "BGP, MRT, BGP4MP, TABLE_DUMP_V2, RIB, routing table, RouteViews, RIPE RIS, \
                     route collector, AS path, origin ASN, prefix, CIDR, INET, next hop, \
                     community, large community, announcement, withdrawal, route leak, route \
                     hijack, prefix hijack, peer, BGP update, network analysis",
                ),
            ),
            (
                "vgi.doc_llm".to_string(),
                "Decode MRT routing dumps directly in SQL. Scan a TABLE_DUMP_V2 RIB snapshot into \
                 one row per (prefix, peer) entry with `read_rib`, a BGP4MP update stream into one \
                 row per announce/withdraw/state-change with `read_updates`, and list the distinct \
                 peers/collectors with `peers`. Each source argument is a path (local, a glob, an \
                 `s3://` URL, or an `http(s)://` URL) or an inline BLOB of MRT bytes; gzip and \
                 bzip2 archives are decompressed transparently. Prefixes, peer IPs, and next hops \
                 are emitted in DuckDB's core INET physical layout (cast with `::INET`) so prefix \
                 containment and joins against flow/geoip data work without parsing strings. AS \
                 paths are LIST(UINTEGER) and communities are LIST(VARCHAR). AS-path helpers \
                 (`path_length`, `origin_asn`, `as_path_prepends`, `path_contains`) and community \
                 decoders (`community_parse`, `is_large_community`) operate on those columns. A \
                 malformed MRT record yields a row with NULL fields and an `error` column rather \
                 than aborting the scan (toggle `strict => true`) — MRT archives routinely end in \
                 a truncated tail record. RPKI / route-origin validation is intentionally NOT \
                 here: emit `origin_asn` and JOIN it against an RPKI/VRP table (ROV lives in \
                 vgi-netflow)."
                    .to_string(),
            ),
            (
                "vgi.doc_md".to_string(),
                "# bgp\n\nDecode **MRT** routing dumps (RouteViews / RIPE RIS archives — BGP4MP \
                 updates and TABLE_DUMP_V2 RIB snapshots) into SQL rows, so route-leak / hijack / \
                 RIB-diff analysis is a JOIN in the engine instead of an ETL-to-Parquet \
                 step.\n\n**Table functions:** `read_rib(src)` (RIB entries), `read_updates(src)` \
                 (announce / withdraw / state-change), and `peers(src)` (distinct \
                 peers/collectors). `src` is a path (local / glob / `s3://` / `http(s)://`) or an \
                 inline BLOB; `.gz`/`.bz2` auto-decompress.\n\n**Scalars:** `path_length`, \
                 `origin_asn`, `as_path_prepends`, `path_contains` (over the `as_path` \
                 LIST(UINTEGER) column); `community_parse`, `is_large_community` (over community \
                 strings); and `bgp_version`.\n\nPrefixes / peer IPs / next hops are DuckDB **INET** \
                 values (cast with `::INET`) so `prefix::INET <<= '203.0.113.0/24'` containment \
                 and prefix joins work directly. RPKI / route-origin validation is out of scope — \
                 JOIN `origin_asn` against your VRP table (ROV lives in vgi-netflow)."
                    .to_string(),
            ),
            (
                "vgi.agent_test_tasks".to_string(),
                crate::meta::agent_test_tasks_json(&[
                    (
                        "version",
                        "Before relying on the bgp worker in a pipeline, an analyst wants to record \
                         which build is attached. Return the worker's version string as a single \
                         row with one column named version.",
                        "SELECT bgp.main.bgp_version() AS version",
                    ),
                    (
                        "path_hops",
                        "Given the AS path [7018, 174, 174, 13335], return the number of AS hops as \
                         a single column named hops.",
                        "SELECT bgp.main.path_length([7018, 174, 174, 13335]) AS hops",
                    ),
                    (
                        "origin",
                        "Given the AS path [7018, 174, 13335], return the origin AS (the AS that \
                         announced the prefix) as a single column named origin.",
                        "SELECT bgp.main.origin_asn([7018, 174, 13335]) AS origin",
                    ),
                    (
                        "large_community",
                        "Is the community string '65001:1:2' a large community? Return a single \
                         BOOLEAN column named is_large.",
                        "SELECT bgp.main.is_large_community('65001:1:2') AS is_large",
                    ),
                    (
                        "rib_count",
                        "The file data/rib.mrt is an MRT TABLE_DUMP_V2 RIB snapshot. Count how many \
                         RIB entries it contains and return the count as a single column named \
                         entries.",
                        "SELECT count(*) AS entries FROM bgp.main.read_rib('data/rib.mrt')",
                    ),
                    (
                        "rib_prefix_contains",
                        "From the RIB snapshot data/rib.mrt, count how many routes cover the \
                         address 203.0.113.5 (the prefix contains it). Return the count as a single \
                         column named routes.",
                        "SELECT count(*) AS routes FROM bgp.main.read_rib('data/rib.mrt') \
                         WHERE prefix::INET >>= '203.0.113.5'::INET",
                    ),
                ]),
            ),
            (
                "vgi.example_queries".to_string(),
                // Self-contained: the read_* / peers examples scan an inline MRT BLOB via
                // `from_hex(...)` so they execute without a `data/*.mrt` file or `LOAD inet`.
                // A real deployment passes a path or URL, e.g.
                // `read_rib('https://routeviews.org/.../rib.20260629.0000.bz2')`.
                format!(
                    "SELECT bgp.main.bgp_version();\n\
                     SELECT bgp.main.path_length([7018, 174, 13335]);\n\
                     SELECT bgp.main.origin_asn([7018, 174, 13335]);\n\
                     SELECT bgp.main.as_path_prepends([7018, 174, 174, 13335]);\n\
                     SELECT bgp.main.path_contains([7018, 174, 13335], 174);\n\
                     SELECT bgp.main.community_parse('65001:100');\n\
                     SELECT bgp.main.is_large_community('65001:1:2');\n\
                     SELECT count(*) FROM bgp.main.read_rib(from_hex('{rib}'));\n\
                     SELECT message_type, count(*) FROM \
                     bgp.main.read_updates(from_hex('{upd}')) GROUP BY 1;\n\
                     SELECT * FROM bgp.main.peers(from_hex('{rib}'));",
                    rib = crate::meta::RIB_MRT_HEX,
                    upd = crate::meta::UPD_MRT_HEX,
                ),
            ),
            ("vgi.author".to_string(), "Query.Farm".to_string()),
            (
                "vgi.copyright".to_string(),
                "Copyright 2026 Query Farm LLC - https://query.farm".to_string(),
            ),
            ("vgi.license".to_string(), "MIT".to_string()),
            (
                "vgi.support_contact".to_string(),
                "https://github.com/Query-farm/vgi-bgp/issues".to_string(),
            ),
            (
                "vgi.support_policy_url".to_string(),
                "https://github.com/Query-farm/vgi-bgp/blob/main/README.md".to_string(),
            ),
        ],
        source_url: Some("https://github.com/Query-farm/vgi-bgp".to_string()),
        schemas: vec![CatSchema {
            name: "main".to_string(),
            comment: Some(
                "MRT decode (read_rib / read_updates / peers) plus AS-path and community helper \
                 functions."
                    .to_string(),
            ),
            tags: vec![
                ("vgi.title".to_string(), "BGP — main".to_string()),
                (
                    "vgi.keywords".to_string(),
                    crate::meta::keywords_json(
                        "read_rib, read_updates, peers, path_length, origin_asn, as_path_prepends, \
                         path_contains, community_parse, is_large_community, MRT, BGP, INET, \
                         prefix, AS path",
                    ),
                ),
                ("domain".to_string(), "network-security".to_string()),
                ("category".to_string(), "routing-and-bgp".to_string()),
                ("topic".to_string(), "mrt-decoding".to_string()),
                (
                    "vgi.doc_llm".to_string(),
                    "Functions for MRT routing dumps: scan a TABLE_DUMP_V2 RIB into rows \
                     (`read_rib`), a BGP4MP update stream into rows (`read_updates`), list distinct \
                     peers (`peers`), and the AS-path (`path_length`, `origin_asn`, \
                     `as_path_prepends`, `path_contains`) and community (`community_parse`, \
                     `is_large_community`) helpers, plus `bgp_version`. read_rib/read_updates emit \
                     prefix / peer_ip / next_hop as DuckDB INET (cast `::INET`), as_path as \
                     LIST(UINTEGER), communities as LIST(VARCHAR)."
                        .to_string(),
                ),
                (
                    "vgi.doc_md".to_string(),
                    "The single schema for the `bgp` worker — the catalog name matches the ATTACH \
                     name, so qualify calls as `bgp.main.<fn>(...)`. It holds the MRT table \
                     functions `read_rib`, `read_updates`, and `peers`, the AS-path scalars \
                     `path_length` / `origin_asn` / `as_path_prepends` / `path_contains`, the \
                     community scalars `community_parse` / `is_large_community`, and \
                     `bgp_version`."
                        .to_string(),
                ),
                (
                    "vgi.example_queries".to_string(),
                    // Self-contained inline-BLOB examples (see the catalog note). For prefix
                    // containment in a real query add `LOAD inet;` and filter
                    // `WHERE prefix::INET >>= '203.0.113.5'::INET`.
                    format!(
                        "SELECT bgp.main.bgp_version();\n\
                         SELECT bgp.main.path_length([7018, 174, 13335]);\n\
                         SELECT bgp.main.origin_asn([7018, 174, 13335]);\n\
                         SELECT bgp.main.as_path_prepends([7018, 174, 174, 13335]);\n\
                         SELECT bgp.main.path_contains([7018, 174, 13335], 174);\n\
                         SELECT bgp.main.community_parse('65001:100');\n\
                         SELECT bgp.main.is_large_community('65001:1:2');\n\
                         SELECT count(*) FROM bgp.main.read_rib(from_hex('{rib}'));\n\
                         SELECT origin_asn, as_path, bgp.main.path_length(as_path) AS hops \
                         FROM bgp.main.read_rib(from_hex('{rib}')) ORDER BY hops;\n\
                         SELECT message_type, count(*) FROM \
                         bgp.main.read_updates(from_hex('{upd}')) GROUP BY 1;",
                        rib = crate::meta::RIB_MRT_HEX,
                        upd = crate::meta::UPD_MRT_HEX,
                    ),
                ),
            ],
            views: Vec::new(),
            macros: Vec::new(),
            tables: Vec::new(),
        }],
        ..Default::default()
    }
}

fn main() {
    // Logs MUST go to stderr — stdout is the Arrow-IPC channel.
    let _ = env_logger::Builder::from_env(env_logger::Env::default().filter_or("VGI_LOG", "info"))
        .format_timestamp_millis()
        .try_init();

    // The catalog name DuckDB sees in `ATTACH 'bgp' (TYPE vgi, …)`. Default to
    // `bgp`, but honor an override so a test harness can rename it.
    if std::env::var_os("VGI_WORKER_CATALOG_NAME").is_none() {
        std::env::set_var("VGI_WORKER_CATALOG_NAME", "bgp");
    }
    let catalog_name =
        std::env::var("VGI_WORKER_CATALOG_NAME").unwrap_or_else(|_| "bgp".to_string());

    let mut worker = Worker::new();
    scalar::register(&mut worker);
    table::register(&mut worker);
    worker.set_catalog(catalog_metadata(&catalog_name));
    worker.run();
}
