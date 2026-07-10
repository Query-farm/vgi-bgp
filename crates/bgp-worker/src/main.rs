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

use vgi::catalog::{CatSchema, CatView, CatalogModel};
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
                "Decode MRT routing dumps directly in SQL, skipping the usual ETL-to-Parquet step. \
                 MRT is the archive format RouteViews and RIPE RIS publish: BGP4MP update streams \
                 (announcements, withdrawals, and session state changes) and TABLE_DUMP_V2 RIB \
                 snapshots (a full routing table captured at one instant). This worker streams \
                 those archives into relational rows — one row per update message or per RIB \
                 entry — and provides scalar helpers over the AS-path and BGP-community fields \
                 those rows carry. A source argument accepts a local path, a glob, an `s3://` or \
                 `http(s)://` URL, or an inline BLOB of MRT bytes; gzip and bzip2 archives are \
                 decompressed transparently. Prefixes, peer IPs, and next hops are emitted in \
                 DuckDB's core INET physical layout (cast with `::INET`) so prefix-containment \
                 filters and joins against flow or geoip data work without parsing strings. AS \
                 paths surface as LIST(UINTEGER) and communities as LIST(VARCHAR). A malformed MRT \
                 record yields a row with NULL fields and an `error` column rather than aborting \
                 the scan (toggle `strict => true`) — archives routinely end in a truncated tail \
                 record. Reach for this worker for route-leak and prefix-hijack investigation, \
                 RIB diffing between snapshots, and origin-AS analysis. List the schema to \
                 discover the available functions and their signatures. RPKI / route-origin \
                 validation is intentionally out of scope: emit the origin AS and JOIN it against \
                 an RPKI/VRP table (ROV lives in vgi-netflow)."
                    .to_string(),
            ),
            (
                "vgi.doc_md".to_string(),
                "# bgp\n\nDecode **MRT** routing dumps — the archive format RouteViews and RIPE \
                 RIS publish — directly in SQL. MRT comes in two flavors this worker reads: \
                 **BGP4MP** update streams (announcements, withdrawals, and session state changes) \
                 and **TABLE_DUMP_V2** RIB snapshots (a full routing table at one instant). \
                 Streaming them into rows turns route-leak / hijack / RIB-diff analysis into a \
                 JOIN in the engine instead of an ETL-to-Parquet step.\n\nA source argument is a \
                 path (local / glob / `s3://` / `http(s)://`) or an inline BLOB; `.gz` / `.bz2` \
                 inputs auto-decompress. Prefixes, peer IPs, and next hops are DuckDB **INET** \
                 values (cast with `::INET`), so containment such as `prefix::INET <<= \
                 '203.0.113.0/24'` and prefix joins work directly. AS paths are LIST(UINTEGER) and \
                 BGP communities are LIST(VARCHAR); scalar helpers operate on those columns. List \
                 the schema to see the individual functions. RPKI / route-origin validation is out \
                 of scope — JOIN the origin AS against your VRP table (ROV lives in vgi-netflow)."
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
                    (
                        "prepends",
                        "Given the AS path [7018, 174, 174, 13335], how many AS-path prepends \
                         (padded repeated ASNs) does it contain? Return a single column named \
                         prepends.",
                        "SELECT bgp.main.as_path_prepends([7018, 174, 174, 13335]) AS prepends",
                    ),
                    (
                        "traverses",
                        "Does the AS path [7018, 174, 13335] pass through AS 174 anywhere along \
                         it? Return a single BOOLEAN column named traverses.",
                        "SELECT bgp.main.path_contains([7018, 174, 13335], 174) AS traverses",
                    ),
                    (
                        "community_parts",
                        "Split the standard BGP community '65001:100' into its ASN and value \
                         parts. Return two columns named asn and value.",
                        "SELECT bgp.main.community_parse('65001:100').asn AS asn, \
                         bgp.main.community_parse('65001:100').value AS value",
                    ),
                    (
                        "update_withdrawals",
                        "The file data/updates.mrt is an MRT BGP4MP update stream. Count how many \
                         withdrawal messages it contains and return the count as a single column \
                         named withdrawals.",
                        "SELECT count(*) AS withdrawals FROM bgp.main.read_updates('data/updates.mrt') \
                         WHERE message_type = 'withdraw'",
                    ),
                    (
                        "peer_count",
                        "The file data/rib.mrt is an MRT TABLE_DUMP_V2 RIB snapshot. How many \
                         distinct peers does it contain? Return the count as a single column named \
                         peers.",
                        "SELECT count(*) AS peers FROM bgp.main.peers('data/rib.mrt')",
                    ),
                    (
                        "sample_rows",
                        "The bgp worker exposes a small built-in sample of decoded RIB rows you \
                         can browse without providing a file. How many rows does that sample \
                         contain? Return the count as a single column named rows.",
                        "SELECT count(*) AS rows FROM bgp.main.example_rib",
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
                    // VGI413: the ordered category registry. Each object's
                    // `vgi.category` tag names one of these.
                    "vgi.categories".to_string(),
                    r#"[
  {"name":"MRT readers","description":"Table functions that stream MRT routing-dump archives — BGP4MP update streams and TABLE_DUMP_V2 RIB snapshots — into relational rows, with prefixes and peer IPs as DuckDB INET."},
  {"name":"AS-path analysis","description":"Scalar helpers over the LIST(UINTEGER) AS-path column: path length, origin AS, prepend counting, and ASN membership tests."},
  {"name":"BGP communities","description":"Scalar helpers that parse and classify standard and RFC 8092 large BGP community strings."},
  {"name":"Worker info","description":"Diagnostic helpers, such as the worker build/version string."}
]"#
                    .to_string(),
                ),
                (
                    "vgi.doc_llm".to_string(),
                    "The single schema for the `bgp` worker — the catalog name matches the ATTACH \
                     name, so calls qualify as `bgp.main.<fn>(...)`. It groups two kinds of \
                     objects: table functions that stream MRT archives (BGP4MP update streams and \
                     TABLE_DUMP_V2 RIB snapshots) into rows, and scalar helpers that operate on \
                     the AS-path and BGP-community columns those rows expose. Table-function \
                     output carries prefix / peer_ip / next_hop as DuckDB INET (cast `::INET`), \
                     the AS path as LIST(UINTEGER), and communities as LIST(VARCHAR). List the \
                     schema to discover the individual functions and their signatures."
                        .to_string(),
                ),
                (
                    "vgi.doc_md".to_string(),
                    "## What this schema covers\n\n\
                     MRT is the on-the-wire archive format route collectors such as RouteViews \
                     and RIPE RIS publish. It comes in two shapes: **BGP4MP** update streams — \
                     the announcements, withdrawals, and session-state changes a collector sees \
                     over time — and **TABLE_DUMP_V2** RIB snapshots, a full routing table frozen \
                     at one instant.\n\n\
                     This schema streams those archives into relational rows, so route-leak, \
                     prefix-hijack, and RIB-diff analysis becomes a JOIN in the engine instead of \
                     an ETL-to-Parquet step. One kind of object streams an archive into rows; \
                     another operates on the AS-path and BGP-community values each row carries.\n\n\
                     ## Data model\n\n\
                     Prefixes, peer IPs, and next hops are emitted in DuckDB's core **INET** \
                     physical layout, so cast them with `::INET` for containment such as \
                     `prefix::INET <<= '203.0.113.0/24'` and for joins against flow or \
                     geolocation data. AS paths surface as `UINTEGER[]` and communities as \
                     `VARCHAR[]`.\n\n\
                     ## When to reach for it\n\n\
                     Reach for it for route-leak and prefix-hijack investigation, for diffing two \
                     RIB snapshots over time, and for origin-AS analysis. Since the catalog name \
                     matches the ATTACH name, calls qualify as `bgp.main.<name>(...)`; list the \
                     schema to discover the exact functions and their signatures. RPKI / \
                     route-origin validation is out of scope here — JOIN the origin AS against \
                     your own VRP table."
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
            views: vec![example_rib_view()],
            macros: Vec::new(),
            tables: Vec::new(),
        }],
        ..Default::default()
    }
}

/// A browsable, zero-setup sample relation: it decodes the tiny built-in
/// `TABLE_DUMP_V2` RIB fixture (three routes) so an agent can `SELECT * FROM
/// bgp.main.example_rib` to see the shape `read_rib` produces without supplying
/// an MRT file (VGI146 — a table-function-only worker otherwise gives an agent
/// nothing to browse). Real work points `read_rib` / `read_updates` at a path,
/// glob, `s3://` / `http(s)://` URL, or an inline MRT BLOB.
fn example_rib_view() -> CatView {
    let mut tags = crate::meta::object_tags(
        "Sample RIB Rows (built-in fixture)",
        "A zero-setup preview of the row shape read_rib produces: three routes decoded from a \
         tiny TABLE_DUMP_V2 RIB fixture bundled into the worker. Browse it directly — a plain \
         no-argument scan — to see real decoded columns like timestamp, RIB view name, prefix \
         (INET), reporting peer ASN, origin ASN, AS path, next hop (INET), and communities before \
         you have a file in hand. It takes no arguments and always returns the same three rows. \
         For real data call read_rib / read_updates with a path or URL; this view is only a \
         self-describing example.",
        "A built-in, no-arguments sample of three decoded TABLE_DUMP_V2 RIB routes, so you can \
         browse `bgp.main.example_rib` to learn the reader's output columns without an MRT file. \
         Cast the INET columns (`prefix`, `next_hop`) with `::INET`. Point read_rib at your own \
         archive for real data.",
        "sample, example, preview, demo, RIB, TABLE_DUMP_V2, browsable, getting started, prefix, \
         INET, AS path, origin ASN",
        "MRT readers",
    );
    // Classifying tags (VGI123) — reuse the schema's domain / topic vocabulary
    // (VGI132) so the view facets alongside the rest of the worker.
    tags.push(("domain".to_string(), "network-security".to_string()));
    tags.push(("topic".to_string(), "mrt-decoding".to_string()));
    tags.push((
        "vgi.example_queries".to_string(),
        crate::meta::example_queries_json(&[(
            "Group the built-in sample routes by origin AS to see how many prefixes each \
             announced.",
            "SELECT origin_asn, count(*) AS routes FROM bgp.main.example_rib \
             GROUP BY origin_asn ORDER BY routes DESC, origin_asn;",
        )]),
    ));
    CatView {
        name: "example_rib".to_string(),
        // Projects the most useful columns of the built-in fixture (a real,
        // parameterized read_rib call — not pure indirection over a
        // parameterless function, so VGI145 does not apply).
        definition: format!(
            "SELECT timestamp, view_name, prefix, peer_asn, origin_asn, as_path, next_hop, \
             communities FROM bgp.main.read_rib(from_hex('{}'))",
            crate::meta::RIB_MRT_HEX
        ),
        comment: Some(
            "A built-in sample of three decoded TABLE_DUMP_V2 RIB routes — browse it to learn the \
             reader's output columns without supplying an MRT file."
                .to_string(),
        ),
        tags,
        column_comments: vec![
            (
                "timestamp".to_string(),
                "Route timestamp (UTC) from the sample RIB record's MRT header.".to_string(),
            ),
            (
                "view_name".to_string(),
                "RIB view / collector name from the fixture's PEER_INDEX_TABLE.".to_string(),
            ),
            (
                "prefix".to_string(),
                "The announced prefix in DuckDB's INET physical layout; cast `::INET`.".to_string(),
            ),
            (
                "peer_asn".to_string(),
                "The reporting peer's autonomous-system number.".to_string(),
            ),
            (
                "origin_asn".to_string(),
                "The origin AS (last ASN in as_path) that announced the prefix.".to_string(),
            ),
            (
                "as_path".to_string(),
                "The AS path in path order — the origin AS is last.".to_string(),
            ),
            (
                "next_hop".to_string(),
                "The BGP next-hop address in DuckDB's INET physical layout; cast `::INET`."
                    .to_string(),
            ),
            (
                "communities".to_string(),
                "BGP communities as strings (standard `asn:value` and RFC 8092 large).".to_string(),
            ),
        ],
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
