//! MRT stream decode: turn the sequential `TABLE_DUMP_V2` / `BGP4MP` record
//! stream into flat [`MrtRow`] / [`PeerRow`] rows.
//!
//! Decoding is **resumable by byte offset**: the worker wraps its byte source in
//! a [`CountingReader`] and, between records, records the decompressed-stream
//! offset as the externalized scan state. On resume it re-opens the source and
//! skips that many bytes to land exactly on the next record boundary (records are
//! self-delimiting, so a checkpoint is always taken at a boundary).
//!
//! ## Untrusted-input hardening
//!
//! MRT archives routinely end in a truncated tail record, and a corrupt body can
//! appear anywhere. The batch driver in the worker captures a per-record error as
//! a row with NULL fields and a populated `error` column (unless `strict`), and
//! the parser is never allowed to panic the query — the `proptest` in
//! `tests/fuzz.rs` asserts that on arbitrary/truncated bytes.

use std::io::{self, BufRead, BufReader, Read};
use std::net::IpAddr;

use bgpkit_parser::models::{Bgp4MpEnum, ElemType, MrtMessage, MrtRecord, TableDumpV2Message};
use bgpkit_parser::parser::mrt::parse_mrt_record;
use bgpkit_parser::{Elementor, ParserError};

/// The kind of a decoded route/state row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    /// A prefix announcement (and every `read_rib` entry).
    Announce,
    /// A prefix withdrawal.
    Withdraw,
    /// A BGP FSM state change (`BGP4MP_STATE_CHANGE`).
    StateChange,
}

impl MsgType {
    /// The canonical lowercase label used in the `message_type` column.
    pub fn as_str(self) -> &'static str {
        match self {
            MsgType::Announce => "announce",
            MsgType::Withdraw => "withdraw",
            MsgType::StateChange => "state_change",
        }
    }
}

/// One decoded route or state-change row. A field is `None` when the underlying
/// MRT record does not carry it (e.g. a withdrawal has no `as_path`/`next_hop`;
/// a state change has no prefix). An [`error`](MrtRow::error) row carries the
/// failure message with every other field left at its empty default.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MrtRow {
    /// Record timestamp in microseconds since the Unix epoch.
    pub timestamp_us: i64,
    /// `announce` / `withdraw` / `state_change` (`None` only on an error row).
    pub msg_type: Option<MsgType>,
    /// RIB view name (TABLE_DUMP_V2 `PEER_INDEX_TABLE`), else `None`.
    pub view_name: Option<String>,
    /// The peer that reported the route.
    pub peer_ip: Option<IpAddr>,
    /// The peer's ASN.
    pub peer_asn: Option<u32>,
    /// The route prefix as `(address, prefix_len)`.
    pub prefix: Option<(IpAddr, u16)>,
    /// The AS path in path order (origin last).
    pub as_path: Option<Vec<u32>>,
    /// The origin AS (last AS in the path).
    pub origin_asn: Option<u32>,
    /// The route's next hop.
    pub next_hop: Option<IpAddr>,
    /// Communities, each as a canonical string (standard `a:b`, large `a:b:c`,
    /// or a well-known mnemonic).
    pub communities: Option<Vec<String>>,
    /// MULTI_EXIT_DISC.
    pub med: Option<u32>,
    /// LOCAL_PREF.
    pub local_pref: Option<u32>,
    /// ATOMIC_AGGREGATE attribute present.
    pub atomic_aggregate: bool,
    /// AGGREGATOR ASN.
    pub aggregator_asn: Option<u32>,
    /// Previous FSM state (state-change rows only).
    pub old_state: Option<u16>,
    /// New FSM state (state-change rows only).
    pub new_state: Option<u16>,
    /// Per-record decode error, else `None`.
    pub error: Option<String>,
}

impl MrtRow {
    /// An error row: every field empty except `error`.
    pub fn error_row(msg: impl Into<String>) -> MrtRow {
        MrtRow {
            error: Some(msg.into()),
            ..Default::default()
        }
    }
}

/// One peer row for `bgp.peers`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRow {
    /// The peer's IP address.
    pub peer_ip: IpAddr,
    /// The peer's ASN.
    pub peer_asn: u32,
    /// The collector / RIB view name, when known.
    pub collector: Option<String>,
}

/// Convert a bgpkit floating-point timestamp (seconds.fraction) to microseconds.
fn ts_to_micros(ts: f64) -> i64 {
    (ts * 1_000_000.0).round() as i64
}

/// Whether a parse error is *recoverable* — i.e. the record body was fully
/// consumed before the failure, so the stream is still aligned on the next
/// record and decoding can continue (a single bad record, not a torn stream).
/// I/O / EOF errors mean the read was short (truncation): the stream is no
/// longer aligned, so the caller must stop.
pub fn is_recoverable(err: &ParserError) -> bool {
    !matches!(
        err,
        ParserError::IoError(_) | ParserError::EofError(_) | ParserError::EofExpected
    )
}

/// Whether a parse error signals a *clean* end of stream (no more records).
pub fn is_clean_eof(err: &ParserError) -> bool {
    matches!(err, ParserError::EofExpected)
}

/// Stateful decoder over one MRT stream. Holds the `Elementor` (which carries the
/// TABLE_DUMP_V2 peer-index table needed to resolve RIB peer references) plus the
/// current RIB view name, so records must be fed **in order**.
#[derive(Default)]
pub struct Decoder {
    elementor: Elementor,
    view_name: Option<String>,
}

impl Decoder {
    /// A fresh decoder for one stream.
    pub fn new() -> Decoder {
        Decoder {
            elementor: Elementor::new(),
            view_name: None,
        }
    }

    /// The current RIB view name (set once a `PEER_INDEX_TABLE` is seen).
    pub fn view_name(&self) -> Option<&str> {
        self.view_name.as_deref()
    }

    /// Decode one parsed record into route / state-change rows. A
    /// `PEER_INDEX_TABLE` produces no rows (it primes the peer table for later
    /// RIB entries and captures the view name).
    pub fn record_rows(&mut self, record: MrtRecord) -> Vec<MrtRow> {
        let header = record.common_header;
        match record.message {
            MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(pit)) => {
                self.view_name = Some(pit.view_name.clone()).filter(|s| !s.is_empty());
                let rec = MrtRecord {
                    common_header: header,
                    message: MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(
                        pit,
                    )),
                };
                // Prime the peer-index table; ignore a malformed table (RIB
                // entries that then fail to resolve simply yield no rows).
                let _ = self.elementor.set_peer_table(rec);
                Vec::new()
            }
            MrtMessage::Bgp4Mp(Bgp4MpEnum::StateChange(sc)) => {
                let ts = header.timestamp as i64 * 1_000_000
                    + header.microsecond_timestamp.unwrap_or(0) as i64;
                vec![MrtRow {
                    timestamp_us: ts,
                    msg_type: Some(MsgType::StateChange),
                    view_name: self.view_name.clone(),
                    peer_ip: Some(sc.peer_ip),
                    peer_asn: Some(u32::from(sc.peer_asn)),
                    old_state: Some(u16::from(sc.old_state)),
                    new_state: Some(u16::from(sc.new_state)),
                    ..Default::default()
                }]
            }
            other => {
                let rec = MrtRecord {
                    common_header: header,
                    message: other,
                };
                let view = self.view_name.clone();
                self.elementor
                    .record_to_elems(rec)
                    .into_iter()
                    .map(|elem| row_from_elem(elem, view.clone()))
                    .collect()
            }
        }
    }

    /// Decode one parsed record into peer rows. A `PEER_INDEX_TABLE` yields one
    /// row per indexed peer; a `BGP4MP` message/state-change yields the single
    /// peer that produced it (the caller dedups). Other records yield none.
    pub fn peer_rows(&mut self, record: MrtRecord) -> Vec<PeerRow> {
        match &record.message {
            MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(pit)) => {
                self.view_name = Some(pit.view_name.clone()).filter(|s| !s.is_empty());
                let collector = self.view_name.clone();
                pit.id_peer_map
                    .values()
                    .map(|p| PeerRow {
                        peer_ip: p.peer_ip,
                        peer_asn: u32::from(p.peer_asn),
                        collector: collector.clone(),
                    })
                    .collect()
            }
            MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(m)) => vec![PeerRow {
                peer_ip: m.peer_ip,
                peer_asn: u32::from(m.peer_asn),
                collector: self.view_name.clone(),
            }],
            MrtMessage::Bgp4Mp(Bgp4MpEnum::StateChange(sc)) => vec![PeerRow {
                peer_ip: sc.peer_ip,
                peer_asn: u32::from(sc.peer_asn),
                collector: self.view_name.clone(),
            }],
            _ => Vec::new(),
        }
    }
}

/// Map one flattened `BgpElem` to an [`MrtRow`].
fn row_from_elem(elem: bgpkit_parser::BgpElem, view_name: Option<String>) -> MrtRow {
    let msg_type = match elem.elem_type {
        ElemType::ANNOUNCE => MsgType::Announce,
        ElemType::WITHDRAW => MsgType::Withdraw,
    };
    let as_path = elem.as_path.as_ref().and_then(|p| p.to_u32_vec_opt(false));
    let communities = elem
        .communities
        .as_ref()
        .map(|cs| cs.iter().map(|c| c.to_string()).collect::<Vec<_>>());
    MrtRow {
        timestamp_us: ts_to_micros(elem.timestamp),
        msg_type: Some(msg_type),
        view_name,
        peer_ip: Some(elem.peer_ip),
        peer_asn: Some(u32::from(elem.peer_asn)),
        prefix: Some((
            elem.prefix.prefix.addr(),
            elem.prefix.prefix.prefix_len() as u16,
        )),
        as_path,
        origin_asn: elem.get_origin_asn_opt(),
        next_hop: elem.next_hop,
        communities,
        med: elem.med,
        local_pref: elem.local_pref,
        atomic_aggregate: elem.atomic,
        aggregator_asn: elem.aggr_asn.map(u32::from),
        old_state: None,
        new_state: None,
        error: None,
    }
}

/// A [`Read`] wrapper that counts bytes consumed, so the worker can checkpoint
/// the decompressed-stream byte offset at each record boundary for resume.
pub struct CountingReader<R> {
    inner: R,
    count: u64,
}

impl<R: Read> CountingReader<R> {
    /// Wrap `inner`, counting from zero.
    pub fn new(inner: R) -> CountingReader<R> {
        CountingReader { inner, count: 0 }
    }

    /// Total bytes read so far.
    pub fn count(&self) -> u64 {
        self.count
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count += n as u64;
        Ok(n)
    }
}

/// Sniff the leading magic bytes and, if the stream is gzip (`1f 8b`) or bzip2
/// (`BZh`), wrap it in the matching streaming decompressor; otherwise return the
/// raw stream. The offset the worker checkpoints is therefore in the
/// **decompressed** MRT domain, which is what record framing walks.
pub fn decompress_reader(reader: Box<dyn Read + Send>) -> io::Result<Box<dyn Read + Send>> {
    let mut buf = BufReader::new(reader);
    let magic = buf.fill_buf()?;
    if magic.starts_with(&[0x1f, 0x8b]) {
        Ok(Box::new(flate2::read::MultiGzDecoder::new(buf)))
    } else if magic.starts_with(b"BZh") {
        Ok(Box::new(bzip2_rs::DecoderReader::new(buf)))
    } else {
        Ok(Box::new(buf))
    }
}

/// Read and discard exactly `n` bytes from `reader` (used to resume a scan at a
/// checkpointed decompressed byte offset).
pub fn skip_bytes<R: Read>(reader: &mut R, n: u64) -> io::Result<()> {
    let mut remaining = n;
    let mut scratch = [0u8; 8192];
    while remaining > 0 {
        let want = remaining.min(scratch.len() as u64) as usize;
        let got = reader.read(&mut scratch[..want])?;
        if got == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "stream ended before the resume offset",
            ));
        }
        remaining -= got as u64;
    }
    Ok(())
}

/// Parse the next MRT record from `reader`, returning:
/// - `Ok(Some(record))` — a record,
/// - `Ok(None)` — a clean end of stream,
/// - `Err(parser_error)` — a failure (use [`is_recoverable`] to decide whether to
///   skip the bad record and continue, or stop).
pub fn next_record<R: Read>(reader: &mut R) -> Result<Option<MrtRecord>, ParserError> {
    match parse_mrt_record(reader) {
        Ok(rec) => Ok(Some(rec)),
        Err(e) => {
            if is_clean_eof(&e.error) {
                Ok(None)
            } else {
                Err(e.error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn counting_reader_tracks_offset() {
        let data = b"hello world";
        let mut cr = CountingReader::new(Cursor::new(&data[..]));
        let mut out = [0u8; 5];
        cr.read_exact(&mut out).unwrap();
        assert_eq!(cr.count(), 5);
        let mut rest = Vec::new();
        cr.read_to_end(&mut rest).unwrap();
        assert_eq!(cr.count(), 11);
    }

    #[test]
    fn skip_bytes_advances() {
        let data = b"0123456789";
        let mut cur = Cursor::new(&data[..]);
        skip_bytes(&mut cur, 4).unwrap();
        let mut rest = Vec::new();
        cur.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"456789");
    }

    #[test]
    fn skip_past_end_errors() {
        let data = b"abc";
        let mut cur = Cursor::new(&data[..]);
        assert!(skip_bytes(&mut cur, 10).is_err());
    }

    #[test]
    fn decompress_passthrough_plain() {
        // Plain bytes are returned unchanged (no magic match).
        let raw: Box<dyn Read + Send> = Box::new(Cursor::new(b"not compressed".to_vec()));
        let mut r = decompress_reader(raw).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "not compressed");
    }

    #[test]
    fn gzip_roundtrips() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(b"mrt bytes here").unwrap();
        let gz = enc.finish().unwrap();
        let raw: Box<dyn Read + Send> = Box::new(Cursor::new(gz));
        let mut r = decompress_reader(raw).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "mrt bytes here");
    }
}
