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
/// `192.0.2.0/24`, `2001:db8:abcd:1::/64`, `2001:db8:abcd:4003::/64`), as a hex
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
/// that `vgi-lint simulate` runs. Each `(name, prompt, reference_sql)` triple
/// becomes a task object; the `prompt` is shown to the simulated analyst while
/// `reference_sql` (the canonical solution) is hidden and re-run live to grade.
pub fn agent_test_tasks_json(tasks: &[(&str, &str, &str)]) -> String {
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    }
    let items: Vec<String> = tasks
        .iter()
        .map(|(name, prompt, reference_sql)| {
            format!(
                "{{\"name\":\"{}\",\"prompt\":\"{}\",\"reference_sql\":\"{}\"}}",
                esc(name),
                esc(prompt),
                esc(reference_sql)
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// Build the four standard per-object discovery/description tags
/// (`vgi.title`, `vgi.doc_llm`, `vgi.doc_md`, `vgi.keywords`).
pub fn object_tags(
    title: &str,
    description_llm: &str,
    description_md: &str,
    keywords: &str,
) -> Vec<(String, String)> {
    vec![
        ("vgi.title".to_string(), title.to_string()),
        ("vgi.doc_llm".to_string(), description_llm.to_string()),
        ("vgi.doc_md".to_string(), description_md.to_string()),
        ("vgi.keywords".to_string(), keywords_json(keywords)),
    ]
}
