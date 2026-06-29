//! `peers(src)` — list the distinct (peer_ip, peer_asn, collector) triples seen
//! in an MRT file: every peer in a TABLE_DUMP_V2 `PEER_INDEX_TABLE`, or each
//! distinct peer that produced a BGP4MP message.

use std::collections::HashSet;
use std::io::BufReader;
use std::net::IpAddr;
use std::sync::Arc;

use arrow_array::RecordBatch;
use arrow_schema::SchemaRef;
use bgp_core::decode::{decompress_reader, next_record, Decoder};
use bgp_core::PeerRow;
use vgi::secrets::SecretLookup;
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionMetadata, ProcessParams};
use vgi_rpc::{OutputCollector, Result, RpcError};

use crate::cloud;
use crate::options;
use crate::reader::{resolve_sources, Source};

pub struct Peers;

impl TableFunction for Peers {
    fn name(&self) -> &str {
        "peers"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "List MRT Peers / Collectors",
            "List the distinct BGP peers in an MRT file: one row per (peer_ip, peer_asn, \
             collector) triple. For a TABLE_DUMP_V2 RIB it returns every peer in the \
             PEER_INDEX_TABLE (with the RIB view name as the collector); for a BGP4MP update \
             stream it returns each distinct peer that produced a message. `src` is a path \
             (local, glob, `s3://`, or `http(s)://`) or an inline BLOB of MRT bytes; `.gz`/`.bz2` \
             auto-decompress. peer_ip is a DuckDB INET value (cast with `::INET`). Use it to \
             enumerate vantage points before scanning a dump, or to join peer ASNs against \
             attribution data.",
            "List the distinct peers in an MRT file: peer_ip (INET), peer_asn, and collector \
             (the RIB view name when present). `src` is a path / glob / `s3://` / `http(s)://` \
             URL or a BLOB; `.gz`/`.bz2` auto-decompress.",
            "peers, collectors, vantage points, MRT, PEER_INDEX_TABLE, peer ASN, peer IP, \
             RouteViews, RIPE RIS, table function",
        );
        tags.push((
            "vgi.result_columns_md".into(),
            "One row per distinct peer:\n\n\
             | column | type |\n|---|---|\n\
             | peer_ip | INET-struct (cast `::INET`) |\n| peer_asn | UINTEGER |\n\
             | collector | VARCHAR |"
                .into(),
        ));
        FunctionMetadata {
            description: "List the distinct peers / collectors in an MRT file".into(),
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        let mut specs = vec![ArgSpec::const_arg(
            "src",
            0,
            "any",
            "The MRT file to inspect: a path (local, a glob, `s3://bucket/key`, or \
             `https://host/file`), several such paths in a list, or inline MRT bytes. \
             gzip/bzip2 archives are decompressed automatically.",
        )];
        specs.extend(options::common_arg_specs());
        specs
    }

    fn secret_lookups(&self, params: &BindParams) -> Vec<SecretLookup> {
        cloud::secret_lookups(&options::source_paths(&params.arguments, 0))
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse {
            output_schema: Arc::new(crate::table::peers_schema()),
            opaque_data: Vec::new(),
        })
    }

    fn producer(&self, params: &ProcessParams) -> Result<Box<dyn TableProducer>> {
        let src = options::source(&params.arguments, 0)?;
        let overrides = options::cloud_overrides(&params.arguments);
        let sources = resolve_sources(src, &params.secrets, &overrides)?;
        Ok(Box::new(PeersProducer {
            schema: params.output_schema.clone(),
            sources: Some(sources),
        }))
    }
}

/// Collects distinct peers eagerly on the first `next_batch` (peers are few, so
/// a single batch is the natural shape).
struct PeersProducer {
    schema: SchemaRef,
    sources: Option<Vec<Source>>,
}

impl TableProducer for PeersProducer {
    fn next_batch(&mut self, _out: &mut OutputCollector) -> Result<Option<RecordBatch>> {
        let Some(sources) = self.sources.take() else {
            return Ok(None);
        };
        let mut seen: HashSet<(IpAddr, u32)> = HashSet::new();
        let mut rows: Vec<PeerRow> = Vec::new();
        for source in &sources {
            let raw = source.open()?;
            let plain = decompress_reader(raw).map_err(|e| RpcError::value_error(e.to_string()))?;
            let mut reader = BufReader::new(plain);
            let mut decoder = Decoder::new();
            // A clean EOF or a torn tail both just end the enumeration here.
            while let Ok(Some(record)) = next_record(&mut reader) {
                for p in decoder.peer_rows(record) {
                    if seen.insert((p.peer_ip, p.peer_asn)) {
                        rows.push(p);
                    }
                }
            }
        }
        let columns = crate::arrow_io::peers_columns(&rows);
        let batch = RecordBatch::try_new(self.schema.clone(), columns)
            .map_err(|e| RpcError::runtime_error(e.to_string()))?;
        Ok(Some(batch))
    }
}
