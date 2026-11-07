# vgi-bgp

A [VGI](https://query.farm) worker that decodes **MRT** routing dumps
(RouteViews / RIPE RIS archives — `BGP4MP` update streams and `TABLE_DUMP_V2`
RIB snapshots) into DuckDB rows: BGP updates and RIB entries with prefixes,
AS-paths, communities, and next-hops. Route-leak / hijack / RIB-diff analysis
becomes a SQL JOIN against `vgi-threatintel`, `vgi-netflow`, and RPKI data
instead of an ETL-to-Parquet step.

> **Marketplace gap it fills:** nothing in the DuckDB ecosystem reads MRT. Today
> researchers run `bgpdump` / `bgpkit monocle` to CSV, then load it. This makes a
> RouteViews dump a table you can join live to attribution and flow data.
> Prefixes and peer IPs reuse the core `inet` CIDR type so they join natively.

```sql
INSTALL vgi FROM community; LOAD vgi; LOAD inet;
ATTACH 'bgp' (TYPE vgi, LOCATION 'github-auto://Query-farm/vgi-bgp@v0.2.1');

-- every route covering a prefix, ordered by AS-path length (leak/hijack triage)
SELECT peer_asn, origin_asn, as_path,
       bgp.main.path_length(as_path) AS hops, next_hop
FROM bgp.main.read_rib('https://routeviews.org/.../rib.20260629.0000.bz2')
WHERE prefix::INET >>= '203.0.113.5'::INET           -- core inet containment
ORDER BY hops;

-- announcements vs withdrawals in an update stream
SELECT message_type, count(*)
FROM bgp.main.read_updates('/dumps/updates.20260629.gz')
GROUP BY 1;
```

> **`INET` is a struct you cast.** A VGI worker emits Apache Arrow, and DuckDB
> always imports an `INET` as its underlying `STRUCT(ip_type, address, mask)`.
> The `prefix` / `peer_ip` / `next_hop` columns are that exact physical layout,
> so a **zero-cost `::INET` cast** turns them into native `INET` for the
> containment operators `<<=` (contained in) / `>>=` (contains) and prefix joins.
> (DuckDB's `inet` extension has no `&&` operator — use `<<=` / `>>=`.)

## Quick start

Every [GitHub release](https://github.com/Query-farm/vgi-bgp/releases) ships a prebuilt worker binary. The `vgi` extension downloads the one for your platform, checks its SHA-256 and caches it, so there is nothing to install besides DuckDB:

```sql
INSTALL vgi FROM community;
LOAD vgi;

ATTACH 'bgp' AS bgp (TYPE vgi, LOCATION 'github-auto://Query-farm/vgi-bgp@v0.2.1');

-- AS-path and community helpers over inline literals: hop count, origin AS, prepend
-- count, path membership, large-community classification, and standard-community parse.
SELECT bgp.main.path_length([7018, 174, 174, 13335]) AS hops;
SELECT bgp.main.origin_asn([7018, 174, 13335]) AS origin;
SELECT bgp.main.as_path_prepends([7018, 174, 174, 13335]) AS prepends;
SELECT bgp.main.path_contains([7018, 174, 13335], 174) AS via_174;
SELECT bgp.main.is_large_community('65001:1:2') AS is_large;
SELECT bgp.main.community_parse('65001:100').asn AS asn;

-- Decode the built-in inline TABLE_DUMP_V2 RIB fixture and count routes per origin AS.
SELECT origin_asn, count(*) AS routes FROM bgp.main.read_rib(from_hex('68608200000d00010000003b000000000000000302c0000201c00002010000fde902c6336407c63364070000fdea030000000020010db80000000000000000000000010000fde968608200000d000400000079000000003020010db8abcd00010002686082000064800e1c0002011020010db8000000000000000000000001003020010db8abcd40031020010db8000000000000000000000001c0110e02030000fde90000fbf40000fc58400101004005040000006480040400000000c0200c0000fde9000000070000000968608200000d0002000000af0000000118cb007100020001686082000041800e0d00010104c63364070018cb0071400304c6336407c0110e02030000fdea0000fc010000fc00400101004005040000006480040400000000c00804fdea00c80000686082000054800e0d00010104c00002010018cb0071400304c0000201c0111202040000fde90000fbf40000fbf40000fc00400101004005040000006480040400000000c00804fde90064c0200c0000fde90000000100000002')) GROUP BY origin_asn ORDER BY routes DESC, origin_asn;
```

Prebuilt binaries cover macOS (Apple silicon), Linux (x86-64 and arm64) and Windows (x86-64). `github-auto://` needs an explicit release tag; change `@v0.2.1` to move to a newer release.

### Other ways to run it

- **Docker** (the image bundles the worker; needs a container runtime):

  ```sql
  ATTACH 'bgp' AS bgp (TYPE vgi, LOCATION 'docker://ghcr.io/query-farm/vgi-bgp:0.2.1');
  ```

- **Manual download.** Download the archive for your platform from the [releases page](https://github.com/Query-farm/vgi-bgp/releases), verify it against its `.sha256` file (a cosign `.cosign.bundle` is published alongside), unpack it, and set `LOCATION` to the path of the extracted worker executable.

### Build from source

To build the worker yourself, see [Building & testing](#building--testing).

## Function catalog (`bgp.main`)

| SQL surface | Result |
| --- | --- |
| `read_rib(src)` | RIB entries: `timestamp`, `view_name`, `peer_ip` (INET), `peer_asn`, `prefix` (INET), `as_path` (`UINTEGER[]`), `origin_asn`, `next_hop` (INET), `communities` (`VARCHAR[]`), `med`, `local_pref`, `atomic_aggregate`, `aggregator_asn`, `error` |
| `read_updates(src)` | Messages: `timestamp`, `peer_ip`, `peer_asn`, `message_type` (`announce`\|`withdraw`\|`state_change`), `prefix`, `as_path`, `origin_asn`, `next_hop`, `communities`, `old_state`, `new_state`, `error` |
| `peers(src)` | `peer_ip` (INET), `peer_asn`, `collector` |
| `path_length(as_path)` | hop count (`BIGINT`) |
| `origin_asn(as_path)` | origin AS (`UINTEGER`) |
| `as_path_prepends(as_path)` | prepend count (`BIGINT`) |
| `path_contains(as_path, asn)` | `BOOLEAN` |
| `community_parse(raw)` | `STRUCT(asn UINTEGER, value UINTEGER)` |
| `is_large_community(raw)` | `BOOLEAN` |
| `bgp_version()` | worker version `VARCHAR` |

### The `src` argument

`src` is overloaded (the same convention as `vgi-fixedformat` / `vgi-evtx`):

- a **path** — a local file, a glob (`'/dumps/*.bz2'`), an `s3://bucket/key` URL,
  or an `https://host/file` URL;
- a **list of paths** (`['a.mrt', 'b.mrt']`), read in order;
- an inline **`BLOB`** of MRT bytes.

`.gz` (gzip) and `.bz2` (bzip2) archives are decompressed transparently. Cloud
credentials come from DuckDB's secret manager (`CREATE SECRET (TYPE s3, …)`),
resolved per path scope; `endpoint =>` / `region =>` / `url_style =>` /
`use_ssl =>` named overrides hit MinIO / R2 without a secret.

### Error handling (untrusted input)

MRT archives routinely end in a truncated tail record, and a corrupt body can
appear anywhere. By default a malformed record yields a **row with NULL fields
and a populated `error` column** rather than aborting the scan — pass
`strict => true` to make it a hard error instead. The parser is fuzz-tested to
never panic on arbitrary or truncated bytes (per-record error capture, never
crash the whole query).

## Examples

```sql
-- AS-path helpers (no file needed)
SELECT bgp.main.path_length([7018, 174, 13335]);            -- 3
SELECT bgp.main.origin_asn([7018, 174, 13335]);             -- 13335
SELECT bgp.main.as_path_prepends([7018, 174, 174, 13335]);  -- 1
SELECT bgp.main.path_contains([7018, 174, 13335], 174);     -- true

-- community decode
SELECT bgp.main.community_parse('65001:100');               -- {asn: 65001, value: 100}
SELECT bgp.main.is_large_community('65001:1:2');            -- true

-- join origin ASNs against your own RPKI/VRP table (ROV lives in vgi-netflow)
SELECT r.prefix, r.origin_asn, v.max_length
FROM bgp.main.read_rib('s3://my-dumps/rib.bz2') r
LEFT JOIN vrp v ON r.origin_asn = v.asn
                AND r.prefix::INET <<= v.prefix::INET;

-- enumerate the collector's vantage points
SELECT peer_ip::INET AS peer, peer_asn FROM bgp.main.peers('/dumps/rib.bz2');
```

## Scope / non-goals

**v1:** MRT decode (RIB + updates) plus AS-path / community helpers.
**Non-goals:** live BGP/BMP session peering (a stateful collector, not a
parser); **RPKI / route-origin validation** (that belongs in `vgi-netflow` —
`vgi-bgp` is the MRT *decoder* and emits `origin_asn` for you to JOIN against a
VRP table); and bundled ASN→org data (leave ASN enrichment to user JOINs against
free iptoasn / RIR delegated-stats tables).

## Building & testing

```sh
cargo build --release                       # build the worker binary
cargo test --workspace                      # unit + golden + proptest fuzzing
cargo clippy --all-targets -- -D warnings   # lint
./run_tests.sh                              # haybarn SQLLogic e2e (see below)
```

The end-to-end suite needs the haybarn tooling (one-time):

```sh
uv tool install --prerelease allow 'haybarn-unittest>=2.0.0rc11,<2.1'
echo "FORCE INSTALL vgi FROM community;" | uvx --prerelease allow --from 'haybarn-cli>=2.0.0rc11,<2.1' haybarn-cli
echo "INSTALL inet;"               | uvx --prerelease allow --from 'haybarn-cli>=2.0.0rc11,<2.1' haybarn-cli
```

`run_tests.sh` builds the worker and runs `haybarn-unittest` against
`test/sql/*` with `VGI_BGP_WORKER` pointed at the binary (and
`VGI_BGP_BATCH_ROWS=1`, which forces one row per Arrow batch to exercise the
byte-offset scan state crossing batch boundaries).

Golden MRT fixtures under `data/` are generated deterministically by
`data/generate_fixtures.rs` (a TABLE_DUMP_V2 RIB, a BGP4MP update batch, IPv4 +
IPv6, large communities, and a deliberately truncated tail record).

## Dependencies & licensing

- **[`bgpkit-parser`](https://github.com/bgpkit/bgpkit-parser)** (MIT) does the
  MRT / BGP4MP / TABLE_DUMP_V2 decode.
- The worker reuses DuckDB's core **`inet`** type for prefixes / peer IPs.
- **No bundled MaxMind GeoLite2-ASN** (CC-BY-SA-4.0) — ASN→org enrichment is
  left to user JOINs. RouteViews / RIPE-RIS MRT archives are public.

Worker code: MIT. Copyright 2026 Query Farm LLC — https://query.farm
