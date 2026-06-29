//! `read_rib(src [, strict =>, endpoint =>, …])` — scan a TABLE_DUMP_V2 RIB
//! snapshot into one row per (prefix, peer) RIB entry.

use std::sync::Arc;

use arrow_schema::SchemaRef;
use vgi::secrets::SecretLookup;
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionMetadata, ProcessParams};
use vgi_rpc::Result;

use crate::cloud;
use crate::options;
use crate::reader::{resolve_sources, Kind, MrtProducer};

pub struct ReadRib;

impl TableFunction for ReadRib {
    fn name(&self) -> &str {
        "read_rib"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "Read MRT RIB Snapshot",
            "Scan an MRT TABLE_DUMP_V2 RIB snapshot (a RouteViews / RIPE RIS `rib.*` archive) into \
             one row per (prefix, peer) RIB entry. `src` is a path — local, a glob, an `s3://` \
             URL, or an `http(s)://` URL — or an inline BLOB of MRT bytes; gzip (`.gz`) and bzip2 \
             (`.bz2`) inputs are decompressed transparently. Each row carries the route timestamp, \
             RIB view name, the reporting peer (peer_ip INET, peer_asn), the prefix (INET), the \
             AS path (LIST(UINTEGER)), origin ASN, next hop (INET), communities (LIST(VARCHAR) — \
             standard and large), MED, local pref, atomic-aggregate flag, and aggregator ASN. \
             prefix / peer_ip / next_hop are DuckDB INET values (cast with `::INET`), so prefix \
             containment (`prefix::INET <<= '203.0.113.0/24'`) and joins against vgi-netflow / \
             geoip work without parsing strings. A malformed record yields a row with NULL fields \
             and a populated `error` column unless `strict => true`. This is the RIB counterpart \
             of read_updates.",
            "Scan an MRT TABLE_DUMP_V2 RIB dump into rows: timestamp, view_name, peer_ip (INET), \
             peer_asn, prefix (INET), as_path (LIST(UINTEGER)), origin_asn, next_hop (INET), \
             communities (LIST(VARCHAR)), med, local_pref, atomic_aggregate, aggregator_asn, and \
             an `error` capture column. `src` is a path / glob / `s3://` / `http(s)://` URL or a \
             BLOB; `.gz`/`.bz2` auto-decompress. Cast INET columns with `::INET` for containment.",
            "read rib, MRT, TABLE_DUMP_V2, RouteViews, RIPE RIS, routing table, BGP RIB, prefix, \
             AS path, origin ASN, next hop, communities, INET, route leak, hijack, table function",
        );
        tags.push((
            "vgi.result_columns_md".into(),
            "One row per (prefix, peer) RIB entry:\n\n\
             | column | type |\n|---|---|\n\
             | timestamp | TIMESTAMP |\n| view_name | VARCHAR |\n\
             | peer_ip | INET-struct (cast `::INET`) |\n| peer_asn | UINTEGER |\n\
             | prefix | INET-struct (cast `::INET`) |\n| as_path | UINTEGER[] |\n\
             | origin_asn | UINTEGER |\n| next_hop | INET-struct (cast `::INET`) |\n\
             | communities | VARCHAR[] |\n| med | UINTEGER |\n| local_pref | UINTEGER |\n\
             | atomic_aggregate | BOOLEAN |\n| aggregator_asn | UINTEGER |\n| error | VARCHAR |"
                .into(),
        ));
        FunctionMetadata {
            description: "Read an MRT TABLE_DUMP_V2 RIB snapshot into rows".into(),
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        let mut specs = vec![ArgSpec::const_arg(
            "src",
            0,
            "any",
            "The RIB dump to read: a path (local, a glob, `s3://bucket/key`, or \
             `https://host/file`), several such paths in a list, or inline MRT bytes. \
             gzip/bzip2 archives are decompressed automatically.",
        )];
        specs.extend(options::common_arg_specs());
        specs
    }

    fn secret_lookups(&self, params: &BindParams) -> Vec<SecretLookup> {
        cloud::secret_lookups(&options::source_paths(&params.arguments, 0))
    }

    fn on_bind(&self, params: &BindParams) -> Result<BindResponse> {
        // Validate local paths early (mirrors the native "File not found");
        // remote paths and BLOB sources are checked lazily at producer time.
        for p in options::source_paths(&params.arguments, 0) {
            if !cloud::is_remote(&p) {
                crate::reader::resolve_local(&p)?;
            }
        }
        Ok(BindResponse {
            output_schema: Arc::new(crate::table::rib_schema()),
            opaque_data: Vec::new(),
        })
    }

    fn producer(&self, params: &ProcessParams) -> Result<Box<dyn TableProducer>> {
        let src = options::source(&params.arguments, 0)?;
        let strict = options::strict(&params.arguments);
        let overrides = options::cloud_overrides(&params.arguments);
        let sources = resolve_sources(src, &params.secrets, &overrides)?;
        let schema: SchemaRef = params.output_schema.clone();
        Ok(Box::new(MrtProducer::new(
            schema,
            Kind::Rib,
            strict,
            sources,
        )))
    }
}
