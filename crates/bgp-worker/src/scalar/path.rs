//! AS-path helper scalars: `path_length`, `origin_asn`, `as_path_prepends`,
//! `path_contains`. Each takes the `as_path` column (a `LIST(UINTEGER)`); the
//! logic lives in `bgp_core::aspath`.

use std::sync::Arc;

use arrow_array::builder::{BooleanBuilder, Int64Builder, UInt32Builder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field};
use bgp_core::aspath;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::{list_u32_at, u32_at};

/// The `as_path` argument is declared `BIGINT[]` (not `UINTEGER[]`) so both an
/// integer-list literal (`[7018, 174, 13335]`, which DuckDB types `INTEGER[]`)
/// and the `UINTEGER[]` `as_path` column from read_rib / read_updates bind by a
/// safe widening cast — declaring `UINTEGER[]` would reject the literal form.
fn as_path_type() -> DataType {
    DataType::List(Arc::new(Field::new_list_field(DataType::Int64, true)))
}

fn as_path_spec() -> ArgSpec {
    ArgSpec::column_typed(
        "as_path",
        0,
        as_path_type(),
        "The AS path, in path order — the origin AS that announced the prefix is last. This is the \
         `as_path` column emitted by read_rib / read_updates.",
    )
}

fn finish(params: &ProcessParams, arr: ArrayRef) -> Result<RecordBatch> {
    RecordBatch::try_new(params.output_schema.clone(), vec![arr])
        .map_err(|e| RpcError::runtime_error(e.to_string()))
}

/// `path_length(as_path) -> BIGINT` — the number of AS hops.
pub struct PathLength;

impl ScalarFunction for PathLength {
    fn name(&self) -> &str {
        "path_length"
    }
    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Number of AS hops in an AS path".into(),
            return_type: Some(DataType::Int64),
            examples: vec![FunctionExample {
                sql: "SELECT bgp.main.path_length([7018, 174, 13335]);".into(),
                description: "Count the AS hops in a path (here 3).".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "AS Path Length",
                "Return the number of AS hops in an AS path (its length) — the LIST(UINTEGER) \
                 `as_path` column from read_rib / read_updates. An empty path is 0; NULL input is \
                 NULL. Use it to rank routes for leak/hijack triage (a suspiciously long or short \
                 path).",
                "Number of AS hops in an AS path, e.g. `path_length([7018,174,13335])` = 3.",
                "path length, as path length, hops, route length, as_path, leak, hijack",
            ),
            ..Default::default()
        }
    }
    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![as_path_spec()]
    }
    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Int64))
    }
    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let mut b = Int64Builder::with_capacity(batch.num_rows());
        for i in 0..batch.num_rows() {
            match list_u32_at(col, i) {
                Some(path) => b.append_value(aspath::path_length(&path)),
                None => b.append_null(),
            }
        }
        finish(params, Arc::new(b.finish()))
    }
}

/// `origin_asn(as_path) -> UINTEGER` — the last (origin) AS in the path.
pub struct OriginAsn;

impl ScalarFunction for OriginAsn {
    fn name(&self) -> &str {
        "origin_asn"
    }
    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "The origin AS (last AS) of an AS path".into(),
            return_type: Some(DataType::UInt32),
            examples: vec![FunctionExample {
                sql: "SELECT bgp.main.origin_asn([7018, 174, 13335]);".into(),
                description: "Get the origin AS that announced the prefix (here 13335).".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "AS Path Origin",
                "Return the origin AS of an AS path — the last (right-most) ASN, which announced \
                 the prefix. NULL for an empty or NULL path. Join the result against an RPKI/VRP \
                 table to validate route origins (route-origin validation lives in vgi-netflow, \
                 not here).",
                "Origin AS of an AS path, e.g. `origin_asn([7018,174,13335])` = 13335.",
                "origin asn, origin as, route origin, last as, as_path, RPKI, hijack",
            ),
            ..Default::default()
        }
    }
    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![as_path_spec()]
    }
    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::UInt32))
    }
    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let mut b = UInt32Builder::with_capacity(batch.num_rows());
        for i in 0..batch.num_rows() {
            match list_u32_at(col, i).and_then(|p| aspath::origin_asn(&p)) {
                Some(asn) => b.append_value(asn),
                None => b.append_null(),
            }
        }
        finish(params, Arc::new(b.finish()))
    }
}

/// `as_path_prepends(as_path) -> BIGINT` — count of AS-path prepends.
pub struct AsPathPrepends;

impl ScalarFunction for AsPathPrepends {
    fn name(&self) -> &str {
        "as_path_prepends"
    }
    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Number of AS-path prepends (padded repeated ASNs)".into(),
            return_type: Some(DataType::Int64),
            examples: vec![FunctionExample {
                sql: "SELECT bgp.main.as_path_prepends([7018, 174, 174, 13335]);".into(),
                description: "Count the prepended (padded) ASNs in a path (here 1).".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "AS-Path Prepend Count",
                "Return the number of AS-path prepends: extra occurrences of an ASN that \
                 immediately repeats its predecessor, i.e. an AS padding its own number to \
                 deprioritize a route. `[1,1,1,2]` has two prepends, `[1,2,3]` has none. NULL \
                 input is NULL.",
                "Count of AS-path prepends, e.g. `as_path_prepends([1,1,1,2])` = 2.",
                "as path prepends, prepending, padding, traffic engineering, as_path",
            ),
            ..Default::default()
        }
    }
    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![as_path_spec()]
    }
    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Int64))
    }
    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let mut b = Int64Builder::with_capacity(batch.num_rows());
        for i in 0..batch.num_rows() {
            match list_u32_at(col, i) {
                Some(path) => b.append_value(aspath::as_path_prepends(&path)),
                None => b.append_null(),
            }
        }
        finish(params, Arc::new(b.finish()))
    }
}

/// `path_contains(as_path, asn) -> BOOLEAN` — whether `asn` is in the path.
pub struct PathContains;

impl ScalarFunction for PathContains {
    fn name(&self) -> &str {
        "path_contains"
    }
    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Whether an AS path traverses a given ASN".into(),
            return_type: Some(DataType::Boolean),
            examples: vec![FunctionExample {
                sql: "SELECT bgp.main.path_contains([7018, 174, 13335], 174);".into(),
                description: "Test whether a path traverses AS 174 (here true).".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "AS Path Contains ASN",
                "Return whether an AS path traverses a given ASN anywhere along it. NULL if the \
                 path is NULL. Use it to find every route that passes through a suspect transit \
                 AS (leak detection).",
                "Whether an AS path contains an ASN, e.g. \
                 `path_contains([7018,174,13335], 174)` = true.",
                "path contains, traverses, transit as, through asn, as_path, leak detection",
            ),
            ..Default::default()
        }
    }
    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![
            as_path_spec(),
            ArgSpec::column_typed(
                "asn",
                1,
                DataType::Int64,
                "The autonomous-system number to look for anywhere along the path.",
            ),
        ]
    }
    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Boolean))
    }
    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let path_col = batch.column(0);
        let asn_col = batch.column(1);
        let mut b = BooleanBuilder::with_capacity(batch.num_rows());
        for i in 0..batch.num_rows() {
            match (list_u32_at(path_col, i), u32_at(asn_col, i)) {
                (Some(path), Some(asn)) => b.append_value(aspath::path_contains(&path, asn)),
                _ => b.append_null(),
            }
        }
        finish(params, Arc::new(b.finish()))
    }
}
