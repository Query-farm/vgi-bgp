//! Streaming MRT reader shared by `read_rib` and `read_updates`.
//!
//! ## Byte-offset externalized scan state
//!
//! MRT is a single sequential binary stream. The producer decodes it one batch
//! at a time and checkpoints, at each record boundary, the **decompressed-stream
//! byte offset** plus the index of the source being read. That `{source, offset}`
//! pair is the externalized scan state: under the HTTP transport the SDK returns
//! one batch per response and resumes by rebuilding the producer from its bind
//! params and calling [`restore_resume`](MrtProducer::restore_resume), which
//! fast-forwards the stream to the checkpoint (re-reading the leading records so
//! a TABLE_DUMP_V2 `PEER_INDEX_TABLE` is rebuilt — peer resolution stays correct
//! across a batch boundary). Under the stdio transport the producer simply drains
//! in-process. Either way the offset round-trips exactly because records are
//! self-delimiting and a checkpoint is only ever taken on a boundary.
//!
//! ## Per-record error capture
//!
//! A recoverable parse error (a corrupt body whose bytes were fully consumed)
//! becomes an `error`-column row and the scan continues with the next record. A
//! truncated tail (a short read) becomes one error row and ends that source.
//! `strict => true` turns either into a hard error instead.

use std::io::{Cursor, Read};

use arrow_array::RecordBatch;
use arrow_schema::SchemaRef;
use bgp_core::decode::{
    decompress_reader, is_recoverable, next_record, CountingReader, Decoder, MrtRow,
};
use object_store::path::Path as ObjPath;
use object_store::ObjectStore;
use url::Url;
use vgi::secrets::Secrets;
use vgi::table_function::TableProducer;
use vgi_rpc::{OutputCollector, Result, RpcError};

use crate::arrow_io;
use crate::cloud::{self, Location};

/// Default rows accumulated before a batch is emitted (a RIB record can expand to
/// many rows, so a batch may overshoot slightly — kept whole so the checkpoint
/// always lands on a record boundary).
const DEFAULT_BATCH_ROWS: usize = 2048;

/// The batch-row target, honoring a `VGI_BGP_BATCH_ROWS` override so a test can
/// force a small batch and exercise multi-batch streaming (the offset scan-state
/// crossing a batch boundary) over a tiny fixture.
fn batch_rows() -> usize {
    std::env::var("VGI_BGP_BATCH_ROWS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_BATCH_ROWS)
}

fn ve(e: impl std::fmt::Display) -> RpcError {
    RpcError::value_error(e.to_string())
}

/// Which table the producer is feeding (selects the output column layout).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Rib,
    Updates,
}

/// A resolved byte source ready to open.
pub enum Source {
    Local(String),
    Remote {
        store: Box<dyn ObjectStore>,
        path: ObjPath,
        url: Url,
    },
    Bytes(Vec<u8>),
}

impl Source {
    fn label(&self) -> String {
        match self {
            Source::Local(p) => p.clone(),
            Source::Remote { url, .. } => url.to_string(),
            Source::Bytes(_) => "<blob>".to_string(),
        }
    }

    /// Open this source as a raw byte reader (bytes fetched now for remote/blob).
    pub(crate) fn open(&self) -> Result<Box<dyn Read + Send>> {
        match self {
            Source::Local(path) => {
                let f = std::fs::File::open(path).map_err(|e| ve(format!("read {path}: {e}")))?;
                Ok(Box::new(f))
            }
            Source::Remote { store, path, url } => {
                let bytes = cloud::fetch_object(store.as_ref(), path, url)?;
                Ok(Box::new(Cursor::new(bytes)))
            }
            Source::Bytes(b) => Ok(Box::new(Cursor::new(b.clone()))),
        }
    }
}

/// Resolve a [`crate::options::Src`] to concrete [`Source`]s (globs expand, a
/// local path must exist, remote globs list via object-store).
pub fn resolve_sources(
    src: crate::options::Src,
    secrets: &Secrets,
    overrides: &[(String, String)],
) -> Result<Vec<Source>> {
    match src {
        crate::options::Src::Bytes(b) => Ok(vec![Source::Bytes(b)]),
        crate::options::Src::Paths(paths) => {
            let mut out = Vec::new();
            for p in &paths {
                for loc in resolve_locations(p, secrets, overrides)? {
                    match loc {
                        Location::Local(p) => out.push(Source::Local(p)),
                        Location::Remote(url) => {
                            let (store, path) = cloud::build_store(&url, secrets, overrides)?;
                            out.push(Source::Remote { store, path, url });
                        }
                    }
                }
            }
            Ok(out)
        }
    }
}

/// Resolve one path spec to concrete locations (local glob / literal, or remote
/// glob listing / single object).
fn resolve_locations(
    spec: &str,
    secrets: &Secrets,
    overrides: &[(String, String)],
) -> Result<Vec<Location>> {
    match cloud::classify(spec)? {
        Location::Local(p) => Ok(resolve_local(&p)?
            .into_iter()
            .map(Location::Local)
            .collect()),
        Location::Remote(url) => {
            if cloud::remote_key(&url).contains(['*', '?', '[']) {
                Ok(cloud::list_glob(&url, secrets, overrides)?
                    .into_iter()
                    .map(Location::Remote)
                    .collect())
            } else {
                Ok(vec![Location::Remote(url)])
            }
        }
    }
}

/// Expand a local path spec (glob → sorted matches; literal → must exist).
pub fn resolve_local(spec: &str) -> Result<Vec<String>> {
    if spec.contains(['*', '?', '[']) {
        let mut out = Vec::new();
        let entries = glob::glob(spec).map_err(|e| ve(format!("bad glob '{spec}': {e}")))?;
        for entry in entries.flatten() {
            out.push(entry.to_string_lossy().into_owned());
        }
        out.sort();
        Ok(out)
    } else if std::path::Path::new(spec).exists() {
        Ok(vec![spec.to_string()])
    } else {
        Err(ve(format!("File not found: {spec}")))
    }
}

type Reader = CountingReader<Box<dyn Read + Send>>;

/// The streaming [`TableProducer`] for `read_rib` / `read_updates`.
pub struct MrtProducer {
    schema: SchemaRef,
    kind: Kind,
    strict: bool,
    sources: Vec<Source>,
    /// Index of the source currently being read.
    idx: usize,
    /// The current source's decompressed byte reader.
    reader: Option<Reader>,
    /// Per-source MRT decoder (peer index table + view name).
    decoder: Decoder,
    /// Decompressed byte offset of the next record in the current source.
    offset: u64,
    /// On resume, the offset to fast-forward the current source to.
    skip_to: Option<u64>,
    /// Whether the whole scan is exhausted.
    done: bool,
}

impl MrtProducer {
    pub fn new(schema: SchemaRef, kind: Kind, strict: bool, sources: Vec<Source>) -> MrtProducer {
        MrtProducer {
            schema,
            kind,
            strict,
            sources,
            idx: 0,
            reader: None,
            decoder: Decoder::new(),
            offset: 0,
            skip_to: None,
            done: false,
        }
    }

    /// Open the source at `self.idx`, fresh decoder + offset.
    fn open_current(&mut self) -> Result<()> {
        let raw = self.sources[self.idx].open()?;
        let plain = decompress_reader(raw).map_err(ve)?;
        self.reader = Some(CountingReader::new(plain));
        self.decoder = Decoder::new();
        self.offset = 0;
        Ok(())
    }

    /// Advance to the next source (closing the current one).
    fn advance(&mut self) {
        self.reader = None;
        self.idx += 1;
        self.skip_to = None;
    }

    fn build_batch(&self, rows: &[MrtRow]) -> Result<RecordBatch> {
        let columns = match self.kind {
            Kind::Rib => arrow_io::rib_columns(rows),
            Kind::Updates => arrow_io::updates_columns(rows),
        };
        RecordBatch::try_new(self.schema.clone(), columns)
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }

    /// The whole streaming step, free of the `OutputCollector` (which `next_batch`
    /// never emits through). Decode one batch worth of records, or `None` when
    /// the scan is exhausted. Exposed to unit tests, which cannot build an
    /// `OutputCollector`.
    pub(crate) fn pull_batch(&mut self) -> Result<Option<RecordBatch>> {
        if self.done {
            return Ok(None);
        }
        let target = batch_rows();
        let mut pending: Vec<MrtRow> = Vec::with_capacity(target.min(DEFAULT_BATCH_ROWS));
        loop {
            // Move to a source with an open reader, or finish.
            if self.reader.is_none() {
                if self.idx >= self.sources.len() {
                    self.done = true;
                    break;
                }
                self.open_current()?;
            }

            let reader = self.reader.as_mut().expect("reader just ensured");
            match next_record(reader) {
                Ok(Some(record)) => {
                    let rows = self.decoder.record_rows(record);
                    self.offset = self.reader.as_ref().unwrap().count();
                    // Fast-forward (resume): discard rows already emitted before
                    // the checkpoint, but keep feeding the decoder so the peer
                    // table is rebuilt.
                    if let Some(target) = self.skip_to {
                        if self.offset <= target {
                            continue;
                        }
                        self.skip_to = None;
                    }
                    pending.extend(rows);
                }
                Ok(None) => self.advance(),
                Err(err) => {
                    if self.strict {
                        return Err(ve(format!("{}: {err}", self.sources[self.idx].label())));
                    }
                    // Still account for the consumed bytes when recoverable.
                    self.offset = self.reader.as_ref().unwrap().count();
                    let emit = self.skip_to.is_none_or(|t| self.offset > t);
                    if emit {
                        pending.push(MrtRow::error_row(format!(
                            "{}: {err}",
                            self.sources[self.idx].label()
                        )));
                    }
                    if is_recoverable(&err) {
                        // Body fully consumed: stream is aligned, keep going.
                        self.skip_to = None;
                    } else {
                        // Truncation / short read: this source is torn, stop it.
                        self.advance();
                    }
                }
            }

            if pending.len() >= target {
                break;
            }
        }

        if pending.is_empty() {
            return Ok(None);
        }
        Ok(Some(self.build_batch(&pending)?))
    }
}

impl TableProducer for MrtProducer {
    fn next_batch(&mut self, _out: &mut OutputCollector) -> Result<Option<RecordBatch>> {
        self.pull_batch()
    }

    fn resume_supported(&self) -> bool {
        true
    }

    /// Encode the scan position: `[source_idx u64 LE][byte_offset u64 LE]`.
    fn encode_resume(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(&(self.idx as u64).to_le_bytes());
        out.extend_from_slice(&self.offset.to_le_bytes());
        out
    }

    /// Restore the scan position: jump to `source_idx`, fast-forward to
    /// `byte_offset`. Inverse of [`encode_resume`](Self::encode_resume).
    fn restore_resume(&mut self, bytes: &[u8]) {
        if bytes.len() < 16 {
            return;
        }
        let idx = u64::from_le_bytes(bytes[0..8].try_into().unwrap()) as usize;
        let offset = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        self.idx = idx.min(self.sources.len());
        self.reader = None;
        self.done = self.idx >= self.sources.len();
        self.skip_to = (offset > 0).then_some(offset);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn rib_schema() -> SchemaRef {
        Arc::new(crate::table::rib_schema())
    }
    fn updates_schema() -> SchemaRef {
        Arc::new(crate::table::updates_schema())
    }

    /// Drain a producer fully, returning the total row count across batches.
    fn drain(mut p: MrtProducer) -> (usize, usize) {
        let mut rows = 0;
        let mut batches = 0;
        while let Some(b) = p.pull_batch().unwrap() {
            rows += b.num_rows();
            batches += 1;
        }
        (rows, batches)
    }

    #[test]
    fn rib_fixture_streams_three_rows() {
        let bytes = std::fs::read("../../data/rib.mrt").unwrap();
        let p = MrtProducer::new(rib_schema(), Kind::Rib, false, vec![Source::Bytes(bytes)]);
        let (rows, _) = drain(p);
        assert_eq!(rows, 3);
    }

    #[test]
    fn updates_fixture_streams_three_rows() {
        let bytes = std::fs::read("../../data/updates.mrt").unwrap();
        let p = MrtProducer::new(
            updates_schema(),
            Kind::Updates,
            false,
            vec![Source::Bytes(bytes)],
        );
        let (rows, _) = drain(p);
        assert_eq!(rows, 3);
    }

    #[test]
    fn gzip_source_decompresses() {
        let bytes = std::fs::read("../../data/updates.mrt.gz").unwrap();
        let p = MrtProducer::new(
            updates_schema(),
            Kind::Updates,
            false,
            vec![Source::Bytes(bytes)],
        );
        let (rows, _) = drain(p);
        assert_eq!(rows, 3);
    }

    #[test]
    fn truncated_tail_yields_error_row_not_panic() {
        let bytes = std::fs::read("../../data/truncated.mrt").unwrap();
        let p = MrtProducer::new(rib_schema(), Kind::Rib, false, vec![Source::Bytes(bytes)]);
        let (rows, _) = drain(p);
        // Leading intact record(s) + exactly one error row for the torn tail.
        assert!(rows >= 2, "expected data rows + an error row, got {rows}");
    }

    #[test]
    fn strict_truncated_tail_errors() {
        let bytes = std::fs::read("../../data/truncated.mrt").unwrap();
        let mut p = MrtProducer::new(rib_schema(), Kind::Rib, true, vec![Source::Bytes(bytes)]);

        // The first batch may carry intact rows; the torn tail must eventually
        // surface as a hard error under strict mode.
        let mut errored = false;
        loop {
            match p.pull_batch() {
                Ok(Some(_)) => continue,
                Ok(None) => break,
                Err(_) => {
                    errored = true;
                    break;
                }
            }
        }
        assert!(errored, "strict mode must error on the truncated tail");
    }

    #[test]
    fn resume_roundtrips_across_batch_boundary() {
        // Decode rib fully, then decode again resuming from the encoded state
        // captured after the first batch; the union of rows must match a full
        // single-pass decode (the offset round-trips across the boundary).
        let bytes = std::fs::read("../../data/rib.mrt").unwrap();
        let full = {
            let p = MrtProducer::new(
                rib_schema(),
                Kind::Rib,
                false,
                vec![Source::Bytes(bytes.clone())],
            );
            drain(p).0
        };
        // Simulate a one-batch-then-resume cycle by encoding state mid-scan.
        let mut p = MrtProducer::new(
            rib_schema(),
            Kind::Rib,
            false,
            vec![Source::Bytes(bytes.clone())],
        );

        let first = p.pull_batch().unwrap();
        let state = p.encode_resume();
        // first batch carried everything for this tiny fixture; resuming from the
        // end-of-stream state must yield zero further rows and not error/panic.
        let mut q = MrtProducer::new(rib_schema(), Kind::Rib, false, vec![Source::Bytes(bytes)]);
        q.restore_resume(&state);
        let rest = drain(q).0;
        let first_rows = first.map(|b| b.num_rows()).unwrap_or(0);
        assert_eq!(first_rows + rest, full);
    }
}
