//! Shared option parsing for the table functions: the overloaded `src` argument
//! (a VARCHAR path / list of paths / `s3://` / `http(s)://` URL, or an inline
//! BLOB of MRT bytes), the `strict` toggle, and the `s3://` object-store
//! overrides — mirroring `vgi-fixedformat`'s conventions.

use arrow_array::cast::AsArray;
use arrow_array::Array;
use vgi::arguments::Arguments;
use vgi::ArgSpec;
use vgi_rpc::{Result, RpcError};

fn ve(msg: impl Into<String>) -> RpcError {
    RpcError::value_error(msg.into())
}

/// The decoded `src` argument: one or more paths/URLs, or inline MRT bytes.
pub enum Src {
    /// One or more local paths / globs / `s3://` / `http(s)://` URLs.
    Paths(Vec<String>),
    /// Inline MRT bytes passed as a BLOB.
    Bytes(Vec<u8>),
}

/// Read the `src` argument at `pos`: a single VARCHAR path, a `LIST(VARCHAR)` of
/// paths, or a BLOB of MRT bytes (the `path` vs `bytes` overload, same as
/// `vgi-fixedformat`/`vgi-evtx`).
pub fn source(args: &Arguments, pos: usize) -> Result<Src> {
    // VARCHAR path (the common case).
    if let Some(s) = args.const_str(pos) {
        return Ok(Src::Paths(vec![s]));
    }
    let Some(arr) = args.arg(pos) else {
        return Err(ve(
            "a source path, list of paths, or BLOB of MRT bytes is required",
        ));
    };
    // BLOB of MRT bytes.
    if let Some(b) = arr.as_binary_opt::<i32>() {
        if b.is_valid(0) {
            return Ok(Src::Bytes(b.value(0).to_vec()));
        }
    }
    if let Some(b) = arr.as_binary_opt::<i64>() {
        if b.is_valid(0) {
            return Ok(Src::Bytes(b.value(0).to_vec()));
        }
    }
    // LIST(VARCHAR) of paths.
    let elems = if let Some(l) = arr.as_list_opt::<i32>() {
        l.value(0)
    } else if let Some(l) = arr.as_list_opt::<i64>() {
        l.value(0)
    } else {
        return Err(ve(
            "src must be a VARCHAR path, a LIST(VARCHAR), or a BLOB of MRT bytes",
        ));
    };
    let mut out = Vec::with_capacity(elems.len());
    if let Some(s) = elems.as_string_opt::<i32>() {
        for i in 0..s.len() {
            if s.is_valid(i) {
                out.push(s.value(i).to_string());
            }
        }
    } else if let Some(s) = elems.as_string_opt::<i64>() {
        for i in 0..s.len() {
            if s.is_valid(i) {
                out.push(s.value(i).to_string());
            }
        }
    } else {
        return Err(ve("path list elements must be VARCHAR"));
    }
    if out.is_empty() {
        return Err(ve("src path list is empty"));
    }
    Ok(Src::Paths(out))
}

/// Just the paths form of `src` (for `secret_lookups`, which only matters for
/// remote paths). Returns an empty vec for a BLOB source.
pub fn source_paths(args: &Arguments, pos: usize) -> Vec<String> {
    match source(args, pos) {
        Ok(Src::Paths(p)) => p,
        _ => Vec::new(),
    }
}

/// The `strict` toggle: when true, a malformed MRT record aborts the scan with
/// an error instead of yielding an error row. Default false (per-record capture).
pub fn strict(args: &Arguments) -> bool {
    args.named_bool("strict").unwrap_or(false)
}

/// Named-argument object-store overrides (`endpoint =>`, `region =>`,
/// `url_style =>`, `use_ssl =>`) for `s3://` paths.
pub fn cloud_overrides(args: &Arguments) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let use_ssl = args.named_bool("use_ssl").or_else(|| {
        args.named_str("use_ssl")
            .and_then(|v| crate::cloud::parse_bool(&v))
    });
    if let Some(ep) = args.named_str("endpoint") {
        out.push((
            "aws_endpoint".into(),
            crate::cloud::normalize_endpoint(&ep, use_ssl),
        ));
    }
    if let Some(r) = args.named_str("region") {
        out.push(("aws_region".into(), r));
    }
    if let Some(s) = args.named_str("url_style") {
        if s.eq_ignore_ascii_case("path") {
            out.push(("aws_virtual_hosted_style_request".into(), "false".into()));
        }
    }
    if use_ssl == Some(false) {
        out.push(("aws_allow_http".into(), "true".into()));
    }
    out
}

/// The shared named-argument specs: `strict` plus the `s3://` overrides. Used by
/// read_rib / read_updates, which capture per-record errors and honor `strict`.
pub fn common_arg_specs() -> Vec<ArgSpec> {
    let mut specs = vec![ArgSpec::const_arg(
        "strict",
        -1,
        "boolean",
        "When true, a malformed MRT record aborts the scan with an error. When false (the \
         default), each bad record yields a row with NULL fields and a populated `error` \
         column, so a truncated tail record never crashes the query.",
    )];
    specs.extend(cloud_arg_specs());
    specs
}

/// The `s3://` object-store override specs (`endpoint`, `region`, `url_style`,
/// `use_ssl`) shared by every source function — including `peers`, which has no
/// `strict` option.
pub fn cloud_arg_specs() -> Vec<ArgSpec> {
    vec![
        ArgSpec::const_arg(
            "endpoint",
            -1,
            "varchar",
            "Custom S3 endpoint for an `s3://` path (e.g. MinIO/R2 'host:9000'). Overrides any \
             endpoint from a CREATE SECRET.",
        ),
        ArgSpec::const_arg(
            "region",
            -1,
            "varchar",
            "AWS region for an `s3://` path. Overrides the region from a CREATE SECRET.",
        ),
        ArgSpec::const_arg(
            "url_style",
            -1,
            "varchar",
            "S3 addressing for an `s3://` path: 'path' (path-style, e.g. MinIO) or 'vhost' (the \
             default).",
        ),
        ArgSpec::const_arg(
            "use_ssl",
            -1,
            "boolean",
            "Whether to use TLS for an `s3://` path's custom endpoint (default true). Set false \
             for a plain-HTTP endpoint such as a local MinIO.",
        ),
    ]
}
