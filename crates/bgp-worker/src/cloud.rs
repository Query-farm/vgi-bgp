//! Cloud object-store access for `s3://` and `http(s)://` MRT sources.
//!
//! The worker runs as a subprocess outside DuckDB, so it has no `httpfs`. This
//! module classifies a path as local vs remote, maps a DuckDB `s3` secret
//! (resolved via the VGI two-phase secret bind) onto [`object_store`] S3
//! credentials, and reads/lists objects. MRT decoding is read-only, so there is
//! no write path here (unlike `vgi-fixedformat`, which this is modeled on).
//!
//! Scope: `s3://` (AWS S3, plus R2 / MinIO / GCS-HMAC via a `TYPE s3` secret with
//! `ENDPOINT`/`URL_STYLE`) and `http(s)://` reads. Native `gs://` / `az://` are
//! deliberately unsupported (a clear error, not a silent local-file fallback).

use std::future::Future;
use std::sync::OnceLock;

use object_store::path::Path as ObjPath;
use object_store::ObjectStore;
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};
use url::Url;
use vgi::secrets::{SecretLookup, Secrets};
use vgi_rpc::{Result, RpcError};

fn ve(e: impl std::fmt::Display) -> RpcError {
    RpcError::value_error(e.to_string())
}

/// Characters in an `s3://` key that must be percent-encoded before `Url::parse`
/// so they survive as part of the key: `?`/`#` are URL delimiters that would
/// otherwise truncate the key (and a `?` glob wildcard), and `%` so any existing
/// `%xx` round-trips. `*`, `[`, `]` pass through `Url` unharmed.
const S3_KEY_ESCAPE: &AsciiSet = &CONTROLS.add(b'%').add(b'?').add(b'#');

/// A resolved path: either a local filesystem path or a remote object URL.
pub enum Location {
    Local(String),
    Remote(Url),
}

/// URL schemes routed to the object store. Anything else with a `scheme://`
/// shape is rejected (rather than silently treated as a local file).
const REMOTE_SCHEMES: &[&str] = &["s3", "s3a", "http", "https"];

/// Classify a `path` argument as a local file path or a remote object URL.
pub fn classify(path: &str) -> Result<Location> {
    if let Some((scheme, rest)) = path.split_once("://") {
        let lower = scheme.to_ascii_lowercase();
        match lower.as_str() {
            "s3" | "s3a" => {
                let url = Url::parse(&encode_s3_url(&lower, rest))
                    .map_err(|e| ve(format!("bad URL '{path}': {e}")))?;
                return Ok(Location::Remote(url));
            }
            "http" | "https" => {
                let url = Url::parse(path).map_err(|e| ve(format!("bad URL '{path}': {e}")))?;
                return Ok(Location::Remote(url));
            }
            _ if !lower.is_empty()
                && lower
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) =>
            {
                return Err(ve(format!(
                    "unsupported URL scheme '{lower}://' for '{path}' (supported: s3://, \
                     http://, https://; local paths have no scheme)"
                )));
            }
            _ => {}
        }
    }
    Ok(Location::Local(path.to_string()))
}

/// Build an `s3://bucket/key` URL string with the key's URL-delimiter chars
/// percent-encoded so `Url::parse` preserves the whole key (incl. a `?` glob).
fn encode_s3_url(scheme: &str, rest: &str) -> String {
    let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
    let key_enc = utf8_percent_encode(key, S3_KEY_ESCAPE);
    format!("{scheme}://{bucket}/{key_enc}")
}

/// The decoded object key of a remote URL — the literal key with glob
/// metacharacters intact.
pub fn remote_key(url: &Url) -> String {
    let p = url.path().strip_prefix('/').unwrap_or(url.path());
    percent_decode_str(p).decode_utf8_lossy().into_owned()
}

/// True if the path is (or parses to) a remote URL — a quick check that does not
/// allocate a `Url` for the common local case.
pub fn is_remote(path: &str) -> bool {
    path.split_once("://")
        .map(|(s, _)| REMOTE_SCHEMES.contains(&s.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// The DuckDB secret type to request for a remote URL, or `None` when the scheme
/// needs no credentials (`http(s)://`).
pub fn secret_type_for(url: &Url) -> Option<&'static str> {
    match url.scheme() {
        "s3" | "s3a" => Some("s3"),
        _ => None,
    }
}

/// The DuckDB secret to request for a `path`: an `s3`-type secret scoped to the
/// URL for `s3://` paths, or `None` for local / `http(s)://` paths.
pub fn secret_lookup(path: &str) -> Option<SecretLookup> {
    match classify(path) {
        Ok(Location::Remote(url)) => secret_type_for(&url).map(|t| SecretLookup {
            secret_type: t.to_string(),
            scope: Some(url.to_string()),
            name: None,
        }),
        _ => None,
    }
}

/// The secret lookups to request for a set of `paths` — one per distinct
/// (type, scope).
pub fn secret_lookups(paths: &[String]) -> Vec<SecretLookup> {
    let mut out: Vec<SecretLookup> = Vec::new();
    for p in paths {
        if let Some(l) = secret_lookup(p) {
            if !out
                .iter()
                .any(|e| e.secret_type == l.secret_type && e.scope == l.scope)
            {
                out.push(l);
            }
        }
    }
    out
}

/// A shared multi-thread runtime owned by this process for cloud I/O.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime for cloud I/O")
    })
}

/// Drive a future to completion from synchronous code, whatever ambient runtime
/// (if any) the host transport set up.
fn block_on<F>(fut: F) -> F::Output
where
    F: Future + Send,
    F::Output: Send,
{
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(move || handle.block_on(fut))
        }
        Ok(_) => std::thread::scope(|s| s.spawn(|| runtime().block_on(fut)).join().unwrap()),
        Err(_) => runtime().block_on(fut),
    }
}

/// Whether `ip` is on a network the worker should not be tricked into reaching
/// server-side (the SSRF backstop): loopback, link-local (incl. the
/// `169.254.169.254` cloud-metadata address), private/ULA, or unspecified.
fn is_internal_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.octets()[0] == 0
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6
                    .to_ipv4_mapped()
                    .map(IpAddr::V4)
                    .is_some_and(is_internal_ip)
        }
    }
}

/// Reject a remote `host` that resolves to an internal address. Prevents an
/// `http(s)://` read from being aimed at cloud metadata, loopback, or RFC-1918
/// services. Set `BGP_ALLOW_INTERNAL_HOSTS=1` to override.
fn guard_host(host: &str) -> Result<()> {
    if std::env::var_os("BGP_ALLOW_INTERNAL_HOSTS").is_some() {
        return Ok(());
    }
    use std::net::ToSocketAddrs;
    let internal = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        is_internal_ip(ip)
    } else {
        match (host, 0u16).to_socket_addrs() {
            Ok(addrs) => addrs.map(|s| s.ip()).any(is_internal_ip),
            Err(_) => false,
        }
    };
    if internal {
        return Err(ve(format!(
            "refusing to read from internal host '{host}' (loopback / link-local / private / \
             cloud-metadata); set BGP_ALLOW_INTERNAL_HOSTS=1 to override"
        )));
    }
    Ok(())
}

pub(crate) fn parse_bool(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// DuckDB stores an `s3` endpoint as a bare `host[:port]`; object_store wants a
/// URL. Prepend a scheme (honoring `use_ssl`) when one is absent.
pub(crate) fn normalize_endpoint(ep: &str, use_ssl: Option<bool>) -> String {
    if ep.contains("://") {
        ep.to_string()
    } else {
        let scheme = if use_ssl == Some(false) {
            "http"
        } else {
            "https"
        };
        format!("{scheme}://{ep}")
    }
}

/// Build an object store for `url`, mapping the resolved DuckDB `s3` secret onto
/// object_store S3 config keys. `overrides` (named args) win over the secret.
pub fn build_store(
    url: &Url,
    secrets: &Secrets,
    overrides: &[(String, String)],
) -> Result<(Box<dyn ObjectStore>, ObjPath)> {
    if matches!(url.scheme(), "http" | "https") {
        if let Some(host) = url.host_str() {
            guard_host(host)?;
        }
    }

    let mut opts: Vec<(String, String)> = if secret_type_for(url) == Some("s3") {
        s3_options(secrets, url)
    } else {
        Vec::new()
    };
    opts.extend(overrides.iter().cloned());

    let (store, path) = object_store::parse_url_opts(url, opts)
        .map_err(|e| ve(format!("init store for '{url}': {e}")))?;
    Ok((store, path))
}

/// Map the DuckDB `s3` secret matching `url`'s scope onto object_store S3 config
/// keys. Selecting by scope+type means a call spanning several buckets uses the
/// right secret per URL.
fn s3_options(secrets: &Secrets, url: &Url) -> Vec<(String, String)> {
    let mut opts: Vec<(String, String)> = Vec::new();
    let Some(fields) = secrets.for_scope_of_type(url.as_str(), "s3") else {
        return opts;
    };
    let nonempty = |f: &str| fields.get(f).filter(|v| !v.is_empty()).cloned();
    let use_ssl = fields.get("use_ssl").and_then(|v| parse_bool(v));

    if let Some(v) = nonempty("key_id") {
        opts.push(("aws_access_key_id".into(), v));
    }
    if let Some(v) = nonempty("secret") {
        opts.push(("aws_secret_access_key".into(), v));
    }
    if let Some(v) = nonempty("session_token") {
        opts.push(("aws_session_token".into(), v));
    }
    if let Some(v) = nonempty("region") {
        opts.push(("aws_region".into(), v));
    }
    if let Some(v) = nonempty("endpoint") {
        opts.push(("aws_endpoint".into(), normalize_endpoint(&v, use_ssl)));
    }
    if let Some(v) = nonempty("url_style") {
        if v.eq_ignore_ascii_case("path") {
            opts.push(("aws_virtual_hosted_style_request".into(), "false".into()));
        }
    }
    if use_ssl == Some(false) {
        opts.push(("aws_allow_http".into(), "true".into()));
    }
    opts
}

/// Fetch a single object's bytes from an already-built `store`.
pub fn fetch_object(store: &dyn ObjectStore, path: &ObjPath, url: &Url) -> Result<Vec<u8>> {
    let bytes = block_on(async move {
        let r = store.get(path).await?;
        r.bytes().await
    })
    .map_err(|e| ve(format!("read {url}: {e}")))?;
    Ok(bytes.to_vec())
}

/// Does `key` match the glob `pattern` under DuckDB's S3 semantics? `*`, `?`,
/// `[...]` stay within one key segment; only `**` crosses `/`.
fn glob_matches(pattern: &glob::Pattern, key: &str) -> bool {
    pattern.matches_with(
        key,
        glob::MatchOptions {
            require_literal_separator: true,
            ..Default::default()
        },
    )
}

/// The list prefix for a glob key: everything up to and including the last `/`
/// before the first wildcard.
fn glob_prefix(key: &str) -> &str {
    match key.find(['*', '?', '[']) {
        Some(i) => match key[..i].rfind('/') {
            Some(slash) => &key[..=slash],
            None => "",
        },
        None => key,
    }
}

/// Expand a remote glob URL into the matching object URLs (sorted). For
/// `http(s)://` there is no listing, so the URL is returned as-is.
pub fn list_glob(url: &Url, secrets: &Secrets, overrides: &[(String, String)]) -> Result<Vec<Url>> {
    if matches!(url.scheme(), "http" | "https") {
        return Ok(vec![url.clone()]);
    }
    let key = remote_key(url);
    let pattern = glob::Pattern::new(&key).map_err(|e| ve(format!("bad glob '{url}': {e}")))?;
    let prefix = glob_prefix(&key).to_string();
    let (store, _) = build_store(url, secrets, overrides)?;
    let scheme = url.scheme().to_string();
    let bucket = url.host_str().unwrap_or_default().to_string();

    use futures::StreamExt;
    let prefix_path = (!prefix.is_empty()).then(|| ObjPath::from(prefix));
    let metas = block_on(async move {
        let mut stream = store.list(prefix_path.as_ref());
        let mut out = Vec::new();
        while let Some(meta) = stream.next().await {
            out.push(meta?);
        }
        Ok::<_, object_store::Error>(out)
    })
    .map_err(|e| ve(format!("list {url}: {e}")))?;

    let mut urls: Vec<Url> = metas
        .into_iter()
        .filter_map(|m| {
            let literal = percent_decode_str(m.location.as_ref())
                .decode_utf8_lossy()
                .into_owned();
            glob_matches(&pattern, &literal)
                .then(|| Url::parse(&encode_s3_url(&scheme, &format!("{bucket}/{literal}"))))
        })
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| ve(format!("rebuild s3 url under '{url}': {e}")))?;
    urls.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    Ok(urls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_locals_and_remotes() {
        assert!(matches!(
            classify("data/x.mrt").unwrap(),
            Location::Local(_)
        ));
        assert!(matches!(
            classify("/abs/x.mrt").unwrap(),
            Location::Local(_)
        ));
        assert!(matches!(
            classify("s3://bucket/x.mrt").unwrap(),
            Location::Remote(_)
        ));
        assert!(matches!(
            classify("HTTPS://host/x.mrt").unwrap(),
            Location::Remote(_)
        ));
        assert!(classify("gs://bucket/x.mrt").is_err());
        assert!(classify("az://c/x.mrt").is_err());
    }

    #[test]
    fn internal_ip_classification() {
        for ip in [
            "127.0.0.1",
            "169.254.169.254",
            "10.1.2.3",
            "192.168.0.1",
            "172.16.5.5",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                is_internal_ip(ip.parse().unwrap()),
                "{ip} should be internal"
            );
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2606:2800:220:1::1"] {
            assert!(
                !is_internal_ip(ip.parse().unwrap()),
                "{ip} should be public"
            );
        }
    }

    #[test]
    fn build_store_blocks_internal_http() {
        let sec = Secrets::default();
        let err = build_store(
            &Url::parse("http://169.254.169.254/latest/meta-data/").unwrap(),
            &sec,
            &[],
        )
        .unwrap_err();
        assert!(format!("{err}").contains("internal host"), "got: {err}");
    }

    #[test]
    fn is_remote_quick_check() {
        assert!(is_remote("s3://b/k"));
        assert!(is_remote("http://h/k"));
        assert!(!is_remote("data/x.mrt"));
        assert!(!is_remote("gs://b/k"));
    }

    #[test]
    fn secret_lookup_requests_s3_for_s3_paths() {
        let l = secret_lookup("s3://bucket/dumps/rib.mrt").expect("s3 path requests a secret");
        assert_eq!(l.secret_type, "s3");
        assert_eq!(l.scope.as_deref(), Some("s3://bucket/dumps/rib.mrt"));
        assert!(secret_lookup("https://host/f.mrt").is_none());
        assert!(secret_lookup("data/f.mrt").is_none());
    }

    #[test]
    fn s3_key_preserves_glob_metachars_through_url() {
        let Location::Remote(u) = classify("s3://bucket/dumps/rib?.mrt").unwrap() else {
            panic!("expected remote");
        };
        assert!(u.query().is_none());
        assert_eq!(remote_key(&u), "dumps/rib?.mrt");
    }

    #[test]
    fn glob_prefix_splits_at_last_slash_before_wildcard() {
        assert_eq!(glob_prefix("dumps/rib*.mrt"), "dumps/");
        assert_eq!(glob_prefix("*.mrt"), "");
        assert_eq!(glob_prefix("plain/key.mrt"), "plain/key.mrt");
    }

    #[test]
    fn glob_matches_duckdb_s3_semantics() {
        let p = |s: &str| glob::Pattern::new(s).unwrap();
        assert!(glob_matches(&p("dumps/*.mrt"), "dumps/a.mrt"));
        assert!(!glob_matches(&p("dumps/*.mrt"), "dumps/sub/a.mrt"));
        assert!(glob_matches(&p("dumps/**/*.mrt"), "dumps/sub/deep/a.mrt"));
    }

    #[test]
    fn parse_bool_forms() {
        assert_eq!(parse_bool("true"), Some(true));
        assert_eq!(parse_bool("FALSE"), Some(false));
        assert_eq!(parse_bool("maybe"), None);
    }

    #[test]
    fn endpoint_scheme_is_inferred_from_use_ssl() {
        assert_eq!(
            normalize_endpoint("minio:9000", Some(false)),
            "http://minio:9000"
        );
        assert_eq!(
            normalize_endpoint("minio:9000", Some(true)),
            "https://minio:9000"
        );
        assert_eq!(normalize_endpoint("minio:9000", None), "https://minio:9000");
    }
}
