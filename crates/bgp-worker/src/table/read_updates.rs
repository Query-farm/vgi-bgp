//! `read_updates(src [, strict =>, endpoint =>, …])` — scan a BGP4MP update
//! stream into one row per announcement / withdrawal / state change.

use std::sync::Arc;

use arrow_schema::SchemaRef;
use vgi::secrets::SecretLookup;
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams};
use vgi_rpc::Result;

use crate::cloud;
use crate::options;
use crate::reader::{resolve_sources, Kind, MrtProducer};

pub struct ReadUpdates;

impl TableFunction for ReadUpdates {
    fn name(&self) -> &str {
        "read_updates"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "Read MRT BGP4MP Update Stream",
            "Scan an MRT BGP4MP update stream (a RouteViews / RIPE RIS `updates.*` archive) into \
             one row per BGP message: a prefix announcement, a withdrawal, or an FSM state change. \
             `src` is a path — local, a glob, an `s3://` URL, or an `http(s)://` URL — or an \
             inline BLOB of MRT bytes; gzip (`.gz`) and bzip2 (`.bz2`) inputs are decompressed \
             transparently. Each row carries the timestamp, the reporting peer (peer_ip INET, \
             peer_asn), the message_type ('announce' / 'withdraw' / 'state_change'), the prefix \
             (INET), AS path (LIST(UINTEGER)), origin ASN, next hop (INET), communities \
             (LIST(VARCHAR)), and — for state changes — old_state and new_state. prefix / peer_ip \
             / next_hop are DuckDB INET values (cast with `::INET`) so containment and prefix \
             joins work without parsing strings. Announcements and withdrawals stay in one stream \
             so RIB churn can be reconstructed over time. A malformed record yields a row with \
             NULL fields and a populated `error` column unless `strict => true`. This is the \
             update-stream counterpart of read_rib.",
            "Scan an MRT BGP4MP update stream into rows: timestamp, peer_ip (INET), peer_asn, \
             message_type (announce/withdraw/state_change), prefix (INET), as_path \
             (LIST(UINTEGER)), origin_asn, next_hop (INET), communities (LIST(VARCHAR)), \
             old_state, new_state, and an `error` capture column. `src` is a path / glob / \
             `s3://` / `http(s)://` URL or a BLOB; `.gz`/`.bz2` auto-decompress. Cast INET \
             columns with `::INET` for containment.",
            "read updates, MRT, BGP4MP, RouteViews, RIPE RIS, announcement, withdrawal, state \
             change, prefix, AS path, communities, INET, RIB churn, route leak, table function",
        );
        tags.push((
            "vgi.result_columns_md".into(),
            "One row per BGP message:\n\n\
             | column | type |\n|---|---|\n\
             | timestamp | TIMESTAMP |\n| peer_ip | INET-struct (cast `::INET`) |\n\
             | peer_asn | UINTEGER |\n| message_type | VARCHAR |\n\
             | prefix | INET-struct (cast `::INET`) |\n| as_path | UINTEGER[] |\n\
             | origin_asn | UINTEGER |\n| next_hop | INET-struct (cast `::INET`) |\n\
             | communities | VARCHAR[] |\n| old_state | USMALLINT |\n| new_state | USMALLINT |\n\
             | error | VARCHAR |"
                .into(),
        ));
        FunctionMetadata {
            description: "Read an MRT BGP4MP update stream into rows".into(),
            examples: vec![FunctionExample {
                sql: format!(
                    "SELECT message_type, count(*) FROM bgp.main.read_updates(from_hex('{}')) \
                     GROUP BY 1;",
                    crate::meta::UPD_MRT_HEX
                ),
                description: "Count announce / withdraw / state-change messages in an inline \
                              BGP4MP update stream."
                    .into(),
                expected_output: None,
            }],
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        let mut specs = vec![ArgSpec::const_arg(
            "src",
            0,
            "any",
            "The update stream to read: a path (local, a glob, `s3://bucket/key`, or \
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
        // Validate local paths early; remote / BLOB sources are checked lazily.
        for p in options::source_paths(&params.arguments, 0) {
            if !cloud::is_remote(&p) {
                crate::reader::resolve_local(&p)?;
            }
        }
        Ok(BindResponse {
            output_schema: Arc::new(crate::table::updates_schema()),
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
            Kind::Updates,
            strict,
            sources,
        )))
    }
}
