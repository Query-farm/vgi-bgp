//! Arrow marshalling: the DuckDB `INET` physical struct, the table output
//! schemas, row→batch builders, and the cell readers the scalar functions use.
//!
//! ## The `INET` columns
//!
//! `prefix`, `peer_ip`, and `next_hop` are emitted as DuckDB's internal `INET`
//! layout — an Arrow `STRUCT(ip_type: UInt8, address: FixedSizeBinary(16),
//! mask: UInt16)` whose `address` child carries the `arrow.opaque`/`hugeint`
//! extension metadata so DuckDB reads it as a `HUGEINT`. The resulting column is
//! a zero-cost `::INET` cast away from the native type, so the `INET` containment
//! operators `<<=` (contained-in) / `>>=` (contains) and prefix joins work
//! directly (validated against DuckDB 1.5's `inet` extension). See
//! `bgp_core::inet` for the field encoding.

use std::collections::HashMap;
use std::sync::Arc;

use arrow_array::builder::{
    FixedSizeBinaryBuilder, ListBuilder, StringBuilder, UInt16Builder, UInt32Builder, UInt8Builder,
};
use arrow_array::cast::AsArray;
use arrow_array::{Array, ArrayRef, BooleanArray, StructArray, TimestampMicrosecondArray};
use arrow_buffer::{BooleanBufferBuilder, NullBuffer};
use arrow_schema::{DataType, Field, Fields, TimeUnit};
use bgp_core::inet::{encode, encode_ip, InetVal};
use bgp_core::MrtRow;

/// The two field-metadata entries DuckDB needs to read a `FixedSizeBinary(16)`
/// as a `HUGEINT` (the `INET` `address` child).
fn hugeint_metadata() -> HashMap<String, String> {
    HashMap::from([
        (
            "ARROW:extension:name".to_string(),
            "arrow.opaque".to_string(),
        ),
        (
            "ARROW:extension:metadata".to_string(),
            "{\"type_name\":\"hugeint\",\"vendor_name\":\"DuckDB\"}".to_string(),
        ),
    ])
}

/// The three child fields of the `INET` struct.
pub fn inet_child_fields() -> Fields {
    Fields::from(vec![
        Field::new("ip_type", DataType::UInt8, false),
        Field::new("address", DataType::FixedSizeBinary(16), false)
            .with_metadata(hugeint_metadata()),
        Field::new("mask", DataType::UInt16, false),
    ])
}

/// The Arrow `DataType` of an `INET` column.
pub fn inet_type() -> DataType {
    DataType::Struct(inet_child_fields())
}

/// A nullable `INET` field named `name`.
pub fn inet_field(name: &str) -> Field {
    Field::new(name, inet_type(), true)
}

/// `LIST(UINTEGER)` — the `as_path` column type (and the inner field name
/// `ListBuilder` produces, so a built array's type matches the schema).
pub fn list_u32_type() -> DataType {
    DataType::List(Arc::new(Field::new_list_field(DataType::UInt32, true)))
}

/// `LIST(VARCHAR)` — the `communities` column type.
pub fn list_str_type() -> DataType {
    DataType::List(Arc::new(Field::new_list_field(DataType::Utf8, true)))
}

/// `TIMESTAMP` (microsecond, no timezone).
pub fn timestamp_type() -> DataType {
    DataType::Timestamp(TimeUnit::Microsecond, None)
}

/// Build the `INET` struct column from per-row optional values.
fn build_inet(vals: &[Option<InetVal>]) -> ArrayRef {
    let n = vals.len();
    let mut ip_type = UInt8Builder::with_capacity(n);
    let mut address = FixedSizeBinaryBuilder::with_capacity(n, 16);
    let mut mask = UInt16Builder::with_capacity(n);
    let mut validity = BooleanBufferBuilder::new(n);
    for v in vals {
        match v {
            Some(iv) => {
                ip_type.append_value(iv.ip_type);
                address
                    .append_value(iv.address_le)
                    .expect("16-byte address");
                mask.append_value(iv.mask);
                validity.append(true);
            }
            None => {
                ip_type.append_value(0);
                address.append_value([0u8; 16]).expect("16-byte address");
                mask.append_value(0);
                validity.append(false);
            }
        }
    }
    let children: Vec<ArrayRef> = vec![
        Arc::new(ip_type.finish()),
        Arc::new(address.finish()),
        Arc::new(mask.finish()),
    ];
    let nulls = NullBuffer::new(validity.finish());
    Arc::new(StructArray::new(inet_child_fields(), children, Some(nulls)))
}

/// Build a `LIST(UINTEGER)` column from per-row optional ASN slices.
fn build_list_u32(rows: &[Option<&[u32]>]) -> ArrayRef {
    let mut b = ListBuilder::new(UInt32Builder::new());
    for r in rows {
        match r {
            Some(xs) => {
                for &x in *xs {
                    b.values().append_value(x);
                }
                b.append(true);
            }
            None => b.append(false),
        }
    }
    Arc::new(b.finish())
}

/// Build a `LIST(VARCHAR)` column from per-row optional string slices.
fn build_list_str(rows: &[Option<&[String]>]) -> ArrayRef {
    let mut b = ListBuilder::new(StringBuilder::new());
    for r in rows {
        match r {
            Some(xs) => {
                for x in *xs {
                    b.values().append_value(x);
                }
                b.append(true);
            }
            None => b.append(false),
        }
    }
    Arc::new(b.finish())
}

fn build_u32(rows: &[Option<u32>]) -> ArrayRef {
    let mut b = UInt32Builder::with_capacity(rows.len());
    for r in rows {
        match r {
            Some(v) => b.append_value(*v),
            None => b.append_null(),
        }
    }
    Arc::new(b.finish())
}

fn build_u16(rows: &[Option<u16>]) -> ArrayRef {
    let mut b = UInt16Builder::with_capacity(rows.len());
    for r in rows {
        match r {
            Some(v) => b.append_value(*v),
            None => b.append_null(),
        }
    }
    Arc::new(b.finish())
}

fn build_ts(rows: &[Option<i64>]) -> ArrayRef {
    Arc::new(TimestampMicrosecondArray::from(rows.to_vec()))
}

fn build_str(rows: &[Option<&str>]) -> ArrayRef {
    let mut b = StringBuilder::new();
    for r in rows {
        match r {
            Some(v) => b.append_value(v),
            None => b.append_null(),
        }
    }
    Arc::new(b.finish())
}

fn build_bool(rows: &[bool]) -> ArrayRef {
    Arc::new(BooleanArray::from(rows.to_vec()))
}

// The helpers below assemble the per-schema column vectors; `prefix` /
// `next_hop` / `peer_ip` INET values are derived per row.

/// Build the `read_rib` columns for `rows`, in schema order.
pub fn rib_columns(rows: &[MrtRow]) -> Vec<ArrayRef> {
    let ts: Vec<Option<i64>> = rows.iter().map(row_ts).collect();
    let view: Vec<Option<&str>> = rows.iter().map(|r| r.view_name.as_deref()).collect();
    let peer_ip: Vec<Option<InetVal>> = rows.iter().map(|r| r.peer_ip.map(encode_ip)).collect();
    let peer_asn: Vec<Option<u32>> = rows.iter().map(|r| r.peer_asn).collect();
    let prefix: Vec<Option<InetVal>> = rows.iter().map(row_prefix).collect();
    let as_path: Vec<Option<&[u32]>> = rows.iter().map(|r| r.as_path.as_deref()).collect();
    let origin: Vec<Option<u32>> = rows.iter().map(|r| r.origin_asn).collect();
    let next_hop: Vec<Option<InetVal>> = rows.iter().map(|r| r.next_hop.map(encode_ip)).collect();
    let comms: Vec<Option<&[String]>> = rows.iter().map(|r| r.communities.as_deref()).collect();
    let med: Vec<Option<u32>> = rows.iter().map(|r| r.med).collect();
    let lpref: Vec<Option<u32>> = rows.iter().map(|r| r.local_pref).collect();
    let atomic: Vec<bool> = rows.iter().map(|r| r.atomic_aggregate).collect();
    let aggr: Vec<Option<u32>> = rows.iter().map(|r| r.aggregator_asn).collect();
    let err: Vec<Option<&str>> = rows.iter().map(|r| r.error.as_deref()).collect();
    vec![
        build_ts(&ts),
        build_str(&view),
        build_inet(&peer_ip),
        build_u32(&peer_asn),
        build_inet(&prefix),
        build_list_u32(&as_path),
        build_u32(&origin),
        build_inet(&next_hop),
        build_list_str(&comms),
        build_u32(&med),
        build_u32(&lpref),
        build_bool(&atomic),
        build_u32(&aggr),
        build_str(&err),
    ]
}

/// Build the `read_updates` columns for `rows`, in schema order.
pub fn updates_columns(rows: &[MrtRow]) -> Vec<ArrayRef> {
    let ts: Vec<Option<i64>> = rows.iter().map(row_ts).collect();
    let peer_ip: Vec<Option<InetVal>> = rows.iter().map(|r| r.peer_ip.map(encode_ip)).collect();
    let peer_asn: Vec<Option<u32>> = rows.iter().map(|r| r.peer_asn).collect();
    let mtype: Vec<Option<&str>> = rows
        .iter()
        .map(|r| r.msg_type.map(|m| m.as_str()))
        .collect();
    let prefix: Vec<Option<InetVal>> = rows.iter().map(row_prefix).collect();
    let as_path: Vec<Option<&[u32]>> = rows.iter().map(|r| r.as_path.as_deref()).collect();
    let origin: Vec<Option<u32>> = rows.iter().map(|r| r.origin_asn).collect();
    let next_hop: Vec<Option<InetVal>> = rows.iter().map(|r| r.next_hop.map(encode_ip)).collect();
    let comms: Vec<Option<&[String]>> = rows.iter().map(|r| r.communities.as_deref()).collect();
    let old_state: Vec<Option<u16>> = rows.iter().map(|r| r.old_state).collect();
    let new_state: Vec<Option<u16>> = rows.iter().map(|r| r.new_state).collect();
    let err: Vec<Option<&str>> = rows.iter().map(|r| r.error.as_deref()).collect();
    vec![
        build_ts(&ts),
        build_inet(&peer_ip),
        build_u32(&peer_asn),
        build_str(&mtype),
        build_inet(&prefix),
        build_list_u32(&as_path),
        build_u32(&origin),
        build_inet(&next_hop),
        build_list_str(&comms),
        build_u16(&old_state),
        build_u16(&new_state),
        build_str(&err),
    ]
}

/// An all-NULL timestamp is invalid for an error row; carry the record
/// timestamp when present (it is 0 for an error row, which renders as the epoch).
fn row_ts(r: &MrtRow) -> Option<i64> {
    if r.error.is_some() && r.timestamp_us == 0 {
        None
    } else {
        Some(r.timestamp_us)
    }
}

fn row_prefix(r: &MrtRow) -> Option<InetVal> {
    r.prefix.map(|(ip, mask)| encode(ip, mask))
}

/// Build the `peers` columns (peer_ip INET, peer_asn, collector) for `rows`.
pub fn peers_columns(rows: &[bgp_core::PeerRow]) -> Vec<ArrayRef> {
    let peer_ip: Vec<Option<InetVal>> = rows.iter().map(|r| Some(encode_ip(r.peer_ip))).collect();
    let peer_asn: Vec<Option<u32>> = rows.iter().map(|r| Some(r.peer_asn)).collect();
    let collector: Vec<Option<&str>> = rows.iter().map(|r| r.collector.as_deref()).collect();
    vec![
        build_inet(&peer_ip),
        build_u32(&peer_asn),
        build_str(&collector),
    ]
}

// ---------------------------------------------------------------------------
// Scalar input cell readers
// ---------------------------------------------------------------------------

/// Read row `i` of a `LIST(UINTEGER)` column as a `Vec<u32>`. Accepts the common
/// integer element widths DuckDB may hand over. `None` for a NULL list.
pub fn list_u32_at(array: &ArrayRef, i: usize) -> Option<Vec<u32>> {
    let list = array.as_list_opt::<i32>()?;
    if !list.is_valid(i) {
        return None;
    }
    let values = list.value(i);
    Some(int_array_to_u32(&values))
}

/// Convert an integer array (any common width) to a `Vec<u32>`, NULLs → 0.
fn int_array_to_u32(values: &ArrayRef) -> Vec<u32> {
    use arrow_array::types::{Int32Type, Int64Type, UInt32Type, UInt64Type};
    let n = values.len();
    if let Some(a) = values.as_primitive_opt::<UInt32Type>() {
        (0..n)
            .map(|j| if a.is_valid(j) { a.value(j) } else { 0 })
            .collect()
    } else if let Some(a) = values.as_primitive_opt::<Int64Type>() {
        (0..n)
            .map(|j| if a.is_valid(j) { a.value(j) as u32 } else { 0 })
            .collect()
    } else if let Some(a) = values.as_primitive_opt::<Int32Type>() {
        (0..n)
            .map(|j| if a.is_valid(j) { a.value(j) as u32 } else { 0 })
            .collect()
    } else if let Some(a) = values.as_primitive_opt::<UInt64Type>() {
        (0..n)
            .map(|j| if a.is_valid(j) { a.value(j) as u32 } else { 0 })
            .collect()
    } else {
        Vec::new()
    }
}

/// Read row `i` of an integer column as a `u32`, accepting any common width.
pub fn u32_at(array: &ArrayRef, i: usize) -> Option<u32> {
    use arrow_array::types::{
        Int16Type, Int32Type, Int64Type, Int8Type, UInt16Type, UInt32Type, UInt64Type, UInt8Type,
    };
    if !array.is_valid(i) {
        return None;
    }
    macro_rules! try_t {
        ($t:ty) => {
            if let Some(a) = array.as_primitive_opt::<$t>() {
                return Some(a.value(i) as u32);
            }
        };
    }
    try_t!(UInt32Type);
    try_t!(Int64Type);
    try_t!(Int32Type);
    try_t!(UInt64Type);
    try_t!(UInt16Type);
    try_t!(UInt8Type);
    try_t!(Int16Type);
    try_t!(Int8Type);
    None
}

/// Read row `i` of a VARCHAR column as a `&str`. `None` for a NULL cell.
pub fn str_at(array: &ArrayRef, i: usize) -> Option<&str> {
    if let Some(a) = array.as_string_opt::<i32>() {
        return a.is_valid(i).then(|| a.value(i));
    }
    if let Some(a) = array.as_string_opt::<i64>() {
        return a.is_valid(i).then(|| a.value(i));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_array::{Int64Array, ListArray, StringArray, UInt32Array};
    use arrow_buffer::OffsetBuffer;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn inet_struct_layout() {
        let DataType::Struct(fields) = inet_type() else {
            panic!("inet must be a struct");
        };
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].name(), "ip_type");
        assert_eq!(fields[1].name(), "address");
        assert_eq!(fields[1].data_type(), &DataType::FixedSizeBinary(16));
        assert!(fields[1]
            .metadata()
            .get("ARROW:extension:name")
            .is_some_and(|v| v == "arrow.opaque"));
    }

    #[test]
    fn build_inet_has_nulls() {
        let v = vec![
            Some(encode(IpAddr::from_str("203.0.113.5").unwrap(), 24)),
            None,
        ];
        let arr = build_inet(&v);
        assert_eq!(arr.len(), 2);
        assert!(arr.is_valid(0));
        assert!(!arr.is_valid(1));
    }

    #[test]
    fn read_u32_list() {
        let values = Arc::new(UInt32Array::from(vec![7018u32, 174, 13335])) as ArrayRef;
        let offsets = OffsetBuffer::new(vec![0, 3].into());
        let field = Arc::new(Field::new_list_field(DataType::UInt32, true));
        let list = Arc::new(ListArray::new(field, offsets, values, None)) as ArrayRef;
        assert_eq!(list_u32_at(&list, 0), Some(vec![7018, 174, 13335]));
    }

    #[test]
    fn read_u32_scalar_widths() {
        let a = Arc::new(Int64Array::from(vec![Some(65001i64), None])) as ArrayRef;
        assert_eq!(u32_at(&a, 0), Some(65001));
        assert_eq!(u32_at(&a, 1), None);
    }

    #[test]
    fn read_str_cell() {
        let a = Arc::new(StringArray::from(vec![Some("65001:100"), None])) as ArrayRef;
        assert_eq!(str_at(&a, 0), Some("65001:100"));
        assert_eq!(str_at(&a, 1), None);
    }
}
