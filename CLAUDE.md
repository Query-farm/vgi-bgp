# CLAUDE.md

Guidance for working in this repository.

## What this is

`vgi-bgp` is a **VGI worker** (a standalone binary DuckDB launches and talks to
over Apache Arrow IPC, `ATTACH 'bgp' (TYPE vgi, LOCATION '…')`) that decodes
**MRT** routing dumps — `BGP4MP` update streams and `TABLE_DUMP_V2` RIB
snapshots — into rows under catalog `bgp`, schema `main`. Built on the published
VGI Rust SDK (`vgi = "0.9.5"` from crates.io), arrow 59. Modeled on
`../vgi-fixedformat`; the repo builds standalone — no local SDK checkout.

## Layout

Two crates, like `vgi-fixedformat`'s `*-core` + `*-worker`:

- `crates/bgp-core` — **pure compute, no Arrow/VGI deps** (`unsafe` forbidden).
  - `decode.rs` — MRT stream → `MrtRow` / `PeerRow` via `bgpkit-parser`'s
    `Elementor`; `CountingReader` (byte-offset tracking), `decompress_reader`
    (gzip/bzip2 sniffing), `next_record`, and the recoverable-vs-truncation error
    classification (`is_recoverable` / `is_clean_eof`).
  - `inet.rs` — IP / prefix → DuckDB `INET` field triple (the encoding below).
  - `aspath.rs` — `path_length` / `origin_asn` / `as_path_prepends` /
    `path_contains` over `&[u32]`.
  - `community.rs` — `community_parse` / `is_large_community` over `&str`.
  - `tests/golden.rs` (fixture rows) + `tests/fuzz.rs` (proptest: never panics).
- `crates/bgp-worker` — thin Arrow/VGI adapter.
  - `arrow_io.rs` — the `INET` Arrow struct, output schemas' column builders,
    and the scalar cell readers.
  - `reader.rs` — `MrtProducer` (the streaming `TableProducer` with the
    byte-offset externalized scan state) + `Source` resolution.
  - `cloud.rs` — `s3://` / `http(s)://` object-store access (read-only).
  - `options.rs` — the overloaded `src` arg + `strict` + cloud overrides.
  - `scalar/` + `table/` — the registered functions; `main.rs` wires the catalog
    metadata and calls `Worker::run()`.
- `data/*.mrt` — golden fixtures (regenerate with `data/generate_fixtures.rs`).
- `test/sql/*.test` — haybarn SQLLogic e2e.

## The `INET` columns (the load-bearing detail)

DuckDB's core `INET` is, on the Arrow boundary, a
`STRUCT(ip_type UTINYINT, address HUGEINT, mask USMALLINT)`. A VGI worker emits
Arrow, and **DuckDB always imports an `INET` back as that struct** (it does not
round-trip the logical `INET` type through Arrow). So `prefix` / `peer_ip` /
`next_hop` are emitted as exactly that struct and are a **zero-cost `::INET`
cast** from native `INET`. The `address` child is a `FixedSizeBinary(16)` field
carrying the `arrow.opaque` / `hugeint` extension metadata so DuckDB reads it as
`HUGEINT` (`arrow_io::hugeint_metadata`). Encoding (validated against DuckDB
1.5's `inet` extension, see `bgp_core::inet`):

- `ip_type` = 1 (IPv4) / 2 (IPv6).
- `address` (little-endian `i128`): IPv4 → the 32 address bits in the low bits;
  IPv6 → the 128 network-order bits with the **sign bit flipped** (`XOR 2^127`).
- `mask` = prefix length.

Containment uses `<<=` / `>>=` — DuckDB's `inet` has **no `&&` operator** (the
build spec's `&&` example is wrong; tests use `<<=` / `>>=`).

## Byte-offset externalized scan state

`MrtProducer` implements the SDK's `encode_resume` / `restore_resume` /
`resume_supported` hooks. The state is `[source_idx u64][byte_offset u64]` — the
decompressed-stream offset at a record boundary. On resume the producer
re-opens the source and **fast-forwards** by re-parsing leading records (feeding
the decoder so a TABLE_DUMP_V2 `PEER_INDEX_TABLE` is rebuilt — peer resolution
stays correct across a batch boundary), then resumes emitting. Under the stdio
transport (haybarn) the producer just drains in-process; resume is the HTTP
transport path. `VGI_BGP_BATCH_ROWS` (default 2048) forces small batches so the
e2e exercises multi-batch streaming.

## Conventions / gotchas

- All algorithms live in `bgp-core` with unit tests; the worker is a thin
  adapter. Logs go to **stderr** — stdout is the Arrow-IPC channel.
- The catalog name must match the ATTACH name; `main.rs` defaults
  `VGI_WORKER_CATALOG_NAME` to `bgp`.
- Per-record error capture: a malformed record yields a row with NULL data + an
  `error` column (unless `strict => true`). A **body parse error is recoverable**
  (bgpkit consumes the whole body before parsing, so the stream stays aligned —
  continue); an **I/O / EOF short read is a truncation** (stop the source). The
  proptest in `bgp-core/tests/fuzz.rs` asserts the parser never panics.
- Scalar AS-path args are declared **`BIGINT[]`** (not `UINTEGER[]`) so both an
  integer-list literal and the `UINTEGER[]` `as_path` column bind via a safe
  widening cast — `UINTEGER[]` would reject `[7018, 174, 13335]`.
- `peers` runs an eager single-batch scan (peers are few); `read_rib` /
  `read_updates` stream batch-by-batch.
- RPKI / route-origin validation is **deliberately out of scope** (it lives in
  `vgi-netflow`); emit `origin_asn` for the user to JOIN. Do not bundle
  MaxMind GeoLite2-ASN (CC-BY-SA-4.0).

## Build & test

```sh
cargo test --workspace                      # core unit + golden + proptest, worker tests
cargo clippy --all-targets -- -D warnings   # keep clean
cargo fmt --all -- --check
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo build --release                       # the worker binary
./run_tests.sh                              # haybarn SQLLogic e2e
./run_tests.sh test/sql/read_rib.test       # single file (trailing-* Catch2 filter)
```

vgi-lint (metadata quality), gated at `fail-on=info`:

```sh
uvx --from vgi-lint-check vgi-lint lint "$PWD/target/release/bgp-worker" --fail-on info
```
