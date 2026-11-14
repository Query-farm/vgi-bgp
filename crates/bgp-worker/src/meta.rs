//! Shared helpers for the per-object discovery/description metadata that the
//! `vgi-lint` strict profile expects on **every** function and table.
//!
//! Each function/table surfaces these in its `FunctionMetadata.tags`:
//! - `vgi.title` (VGI124)            — human-friendly display name
//! - `vgi.doc_llm` (VGI112)          — concise prose aimed at LLMs
//! - `vgi.doc_md` (VGI113)           — short Markdown description
//! - `vgi.keywords` (VGI126/VGI138)  — a JSON array of search terms/synonyms
//!
//! Per-object `vgi.source_url` is intentionally NOT emitted here: it belongs on
//! the catalog object only (VGI139), whose `source_url` field points at the repo.

/// A tiny self-contained MRT `TABLE_DUMP_V2` RIB snapshot (3 RIB entries:
/// `2001:db8:abcd::/48` via peer 2001:db8::1, and `203.0.113.0/24` via peers
/// 198.51.100.7 and 192.0.2.1 — the last with a prepended path), as a hex
/// string. Embedding it lets the catalog and `read_rib` / `peers` example
/// queries run as `from_hex(RIB_MRT_HEX)` — fully self-contained, so the
/// vgi-lint sandbox executes them without a `data/*.mrt` file on disk or
/// `LOAD inet`. Mirrors `data/rib.mrt`.
pub const RIB_MRT_HEX: &str = "68608200000d00010000003b000000000000000302c0000201c00002010000fde902c6336407c63364070000fdea030000000020010db80000000000000000000000010000fde968608200000d000400000079000000003020010db8abcd00010002686082000064800e1c0002011020010db8000000000000000000000001003020010db8abcd40031020010db8000000000000000000000001c0110e02030000fde90000fbf40000fc58400101004005040000006480040400000000c0200c0000fde9000000070000000968608200000d0002000000af0000000118cb007100020001686082000041800e0d00010104c63364070018cb0071400304c6336407c0110e02030000fdea0000fc010000fc00400101004005040000006480040400000000c00804fdea00c80000686082000054800e0d00010104c00002010018cb0071400304c0000201c0111202040000fde90000fbf40000fbf40000fc00400101004005040000006480040400000000c00804fde90064c0200c0000fde90000000100000002";

/// A tiny self-contained MRT `BGP4MP` update stream (3 messages: an IPv4
/// announcement, an IPv6 announcement, and an IPv4 withdrawal), as a hex string.
/// Lets the `read_updates` example run as `from_hex(UPD_MRT_HEX)` without a file.
/// Mirrors `data/updates.mrt`.
pub const UPD_MRT_HEX: &str = "68608200001100040000007f000000000000fde90000000000000001c000020100000000ffffffffffffffffffffffffffffffff00670200000050800e0d00010104c00002010018cb0071400304c0000201c0110e02030000fde90000fbf40000fc00400101004005040000006480040400000000c00804fde90064c0200c0000fde90000000100000002686082010011000400000098000000000000fde9000000000000000220010db800000000000000000000000100000000000000000000000000000000ffffffffffffffffffffffffffffffff00680200000051800e1c0002011020010db8000000000000000000000001003020010db8abcd40031020010db8000000000000000000000001c0110a02020000fde90000fc58400101004005040000006480040400000000686082020011000400000039000000000000fde90000000000000001c000020100000000ffffffffffffffffffffffffffffffff0021020000000a800f0700010118cb0071";

/// Composed examples: each combines two or more of the worker's own objects in
/// one query over the built-in fixtures (offline, deterministic, no `LOAD inet` —
/// the INET structs compare by value). The RIB side reads the `example_rib` view
/// (the same RIB fixture) rather than inlining `RIB_MRT_HEX` again, which keeps
/// the schema-level example list under VGI417's size bound. Defined once here
/// and referenced from the schema-level `vgi.example_queries` and from the
/// driving object's example list.
///
/// RIB routes that the later update stream withdraws (same peer + prefix):
/// `example_rib` (the RIB fixture) JOIN `read_updates`. Driven by `read_updates`.
pub fn composed_withdrawn_routes() -> (&'static str, String) {
    (
        "Join the built-in sample RIB routes (example_rib) to the inline update stream on peer \
         and prefix to find which RIB routes are later withdrawn, and when (one route: peer AS \
         65001, origin AS 64512, withdrawn at 00:00:02).",
        format!(
            "SELECT r.peer_asn, r.origin_asn, r.as_path, u.timestamp AS withdrawn_at \
             FROM bgp.main.example_rib AS r \
             JOIN bgp.main.read_updates(from_hex('{upd}')) AS u \
             ON u.peer_ip = r.peer_ip AND u.prefix = r.prefix \
             WHERE u.message_type = 'withdraw' ORDER BY withdrawn_at, r.peer_asn;",
            upd = UPD_MRT_HEX,
        ),
    )
}

/// RIB-vs-update path diff with hop / prepend counts: `example_rib` JOIN
/// `read_updates`, scored by `path_length` + `as_path_prepends`. Driven by
/// `path_length` (listed there; `read_rib`'s own examples must call it, VGI504).
pub fn composed_path_changes() -> (&'static str, String) {
    (
        "Diff the built-in sample RIB routes (example_rib) against announcements in the inline \
         update stream: for each peer + prefix announced with a different AS path than the RIB \
         held, compare hop count (path_length) and prepends (as_path_prepends) before and after \
         (both paths got one hop shorter; one lost its prepend).",
        format!(
            "SELECT r.peer_asn, r.origin_asn, r.as_path AS rib_path, u.as_path AS update_path, \
             bgp.main.path_length(r.as_path) AS rib_hops, \
             bgp.main.path_length(u.as_path) AS update_hops, \
             bgp.main.as_path_prepends(r.as_path) AS rib_prepends, \
             bgp.main.as_path_prepends(u.as_path) AS update_prepends \
             FROM bgp.main.example_rib AS r \
             JOIN bgp.main.read_updates(from_hex('{upd}')) AS u \
             ON u.peer_ip = r.peer_ip AND u.prefix = r.prefix \
             WHERE u.message_type = 'announce' AND u.as_path <> r.as_path \
             ORDER BY r.origin_asn, r.peer_asn;",
            upd = UPD_MRT_HEX,
        ),
    )
}

/// Decode the standard communities on every RIB route: unnest `example_rib`'s
/// communities, drop large ones with `is_large_community`, split the rest with
/// `community_parse`. Driven by `community_parse`.
pub fn composed_route_communities() -> (&'static str, String) {
    (
        "Unnest the communities on every built-in sample RIB route (example_rib), skip RFC 8092 \
         large communities with is_large_community, and split each standard one into its tagging \
         ASN and value with community_parse.",
        "SELECT r.peer_asn, r.origin_asn, c.community, \
             bgp.main.community_parse(c.community).asn AS tagger_asn, \
             bgp.main.community_parse(c.community).value AS tag_value \
             FROM bgp.main.example_rib AS r \
             CROSS JOIN unnest(r.communities) AS c(community) \
             WHERE NOT bgp.main.is_large_community(c.community) \
             ORDER BY r.peer_asn, c.community;"
            .to_string(),
    )
}

/// A described example as the SDK's native `FunctionExample`.
pub fn function_example((description, sql): (&str, String)) -> vgi::FunctionExample {
    vgi::FunctionExample {
        sql,
        description: description.to_string(),
        expected_output: None,
    }
}

/// Encode comma-separated keywords as the JSON array of strings that
/// `vgi.keywords` requires (VGI138). Each term is trimmed, empties dropped.
pub fn keywords_json(keywords: &str) -> String {
    let items: Vec<String> = keywords
        .split(',')
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(|k| {
            let escaped = k.replace('\\', "\\\\").replace('"', "\\\"");
            format!("\"{escaped}\"")
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// Build the `vgi.agent_test_tasks` JSON value: a fixed suite of analyst tasks
/// that `vgi-lint simulate` (the `--ai` agent-check) runs. Each `(name, prompt)`
/// pair becomes a task object; only the `prompt` is published to the simulated
/// analyst. The private graders (`reference_sql`, keyed by task name) live in
/// `vgi-agent-tests.yaml` at the repo root so the agent never sees them (VGI416).
pub fn agent_test_tasks_json(tasks: &[(&str, &str)]) -> String {
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    }
    let items: Vec<String> = tasks
        .iter()
        .map(|(name, prompt)| {
            format!(
                "{{\"name\":\"{}\",\"prompt\":\"{}\"}}",
                esc(name),
                esc(prompt)
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// The DuckDB type string of a prefix / peer_ip / next_hop column. A worker
/// emits DuckDB's core `INET` over Arrow as this struct (DuckDB does not
/// round-trip the logical `INET` through Arrow), so `DESCRIBE` reports exactly
/// this — and `vgi.result_columns_schema` must declare it verbatim (VGI910).
/// Cast the column with `::INET` to recover a native `INET`.
pub const INET_STRUCT_TYPE: &str = "STRUCT(ip_type UTINYINT, address HUGEINT, mask USMALLINT)";

/// Build a `vgi.result_columns_schema` JSON value (VGI307/VGI321): a JSON array
/// of `{name, type, description}` objects, one per result column, in output
/// order. Each `type` must be a real DuckDB type so it matches the function's
/// live `DESCRIBE` output (VGI322 / VGI910), and each description must be
/// non-blank (VGI323).
pub fn result_columns_schema_json(cols: &[(&str, &str, &str)]) -> String {
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\").replace('"', "\\\"")
    }
    let items: Vec<String> = cols
        .iter()
        .map(|(name, ty, desc)| {
            format!(
                "{{\"name\":\"{}\",\"type\":\"{}\",\"description\":\"{}\"}}",
                esc(name),
                esc(ty),
                esc(desc)
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// Build a `vgi.example_queries` JSON value: a JSON array of `{description, sql}`
/// objects (VGI502/VGI503). Object-level example_queries (on a table/view/
/// function) MUST be this JSON shape — a bare SQL string is rejected.
pub fn example_queries_json(examples: &[(&str, &str)]) -> String {
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\").replace('"', "\\\"")
    }
    let items: Vec<String> = examples
        .iter()
        .map(|(desc, sql)| {
            format!(
                "{{\"description\":\"{}\",\"sql\":\"{}\"}}",
                esc(desc),
                esc(sql)
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// Build the standard per-object discovery/description tags
/// (`vgi.title`, `vgi.doc_llm`, `vgi.doc_md`, `vgi.keywords`, `vgi.category`).
///
/// `category` must name one of the entries in the schema's `vgi.categories`
/// registry (VGI413) — it drives the worker's navigation and listing sections.
pub fn object_tags(
    title: &str,
    description_llm: &str,
    description_md: &str,
    keywords: &str,
    category: &str,
) -> Vec<(String, String)> {
    vec![
        ("vgi.title".to_string(), title.to_string()),
        ("vgi.doc_llm".to_string(), description_llm.to_string()),
        ("vgi.doc_md".to_string(), description_md.to_string()),
        ("vgi.keywords".to_string(), keywords_json(keywords)),
        ("vgi.category".to_string(), category.to_string()),
    ]
}
