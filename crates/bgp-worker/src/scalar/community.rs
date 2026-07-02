//! Community decode scalars: `community_parse` (→ STRUCT(asn, value)) and
//! `is_large_community` (→ BOOLEAN). Logic lives in `bgp_core::community`.

use std::sync::Arc;

use arrow_array::builder::{BooleanBuilder, UInt32Builder};
use arrow_array::{ArrayRef, RecordBatch, StructArray};
use arrow_buffer::{BooleanBufferBuilder, NullBuffer};
use arrow_schema::{DataType, Field, Fields};
use bgp_core::community;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::str_at;

/// The `STRUCT(asn UINTEGER, value UINTEGER)` return type of `community_parse`.
fn community_struct_fields() -> Fields {
    Fields::from(vec![
        Field::new("asn", DataType::UInt32, false),
        Field::new("value", DataType::UInt32, false),
    ])
}

fn raw_spec() -> ArgSpec {
    ArgSpec::column_typed(
        "raw",
        0,
        DataType::Utf8,
        "A community string, e.g. '65001:100' (standard) or '65001:1:2' (large).",
    )
}

/// `community_parse(raw) -> STRUCT(asn UINTEGER, value UINTEGER)`.
pub struct CommunityParse;

impl ScalarFunction for CommunityParse {
    fn name(&self) -> &str {
        "community_parse"
    }
    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Parse a standard community 'asn:value' into a STRUCT(asn, value)".into(),
            return_type: Some(DataType::Struct(community_struct_fields())),
            examples: vec![FunctionExample {
                sql: "SELECT bgp.main.community_parse('65001:100');".into(),
                description: "Split a standard community into {asn: 65001, value: 100}.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "Parse BGP Community",
                "Parse a standard BGP community string ('<asn>:<value>') into a STRUCT(asn \
                 UINTEGER, value UINTEGER). Returns a NULL struct for anything that is not a plain \
                 two-part community — a large community ('a:b:c'), a well-known mnemonic \
                 ('NO_EXPORT'), or NULL input. Use it to filter or group routes by community \
                 without a regex.",
                "Parse a standard community into (asn, value), e.g. \
                 `community_parse('65001:100')` = {asn: 65001, value: 100}.",
                "community parse, bgp community, asn value, standard community, tag, decode",
                "BGP communities",
            ),
            ..Default::default()
        }
    }
    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![raw_spec()]
    }
    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Struct(
            community_struct_fields(),
        )))
    }
    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let n = batch.num_rows();
        let mut asn = UInt32Builder::with_capacity(n);
        let mut value = UInt32Builder::with_capacity(n);
        let mut validity = BooleanBufferBuilder::new(n);
        for i in 0..n {
            match str_at(col, i).and_then(community::community_parse) {
                Some((a, v)) => {
                    asn.append_value(a);
                    value.append_value(v);
                    validity.append(true);
                }
                None => {
                    asn.append_value(0);
                    value.append_value(0);
                    validity.append(false);
                }
            }
        }
        let children: Vec<ArrayRef> = vec![Arc::new(asn.finish()), Arc::new(value.finish())];
        let nulls = NullBuffer::new(validity.finish());
        let arr: ArrayRef = Arc::new(StructArray::new(
            community_struct_fields(),
            children,
            Some(nulls),
        ));
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

/// `is_large_community(raw) -> BOOLEAN`.
pub struct IsLargeCommunity;

impl ScalarFunction for IsLargeCommunity {
    fn name(&self) -> &str {
        "is_large_community"
    }
    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Whether a community string is an RFC 8092 large community".into(),
            return_type: Some(DataType::Boolean),
            examples: vec![FunctionExample {
                sql: "SELECT bgp.main.is_large_community('65001:1:2');".into(),
                description: "Detect a large community (three numeric parts → true).".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "Large-Community Classifier",
                "Return whether a community string is a large community (RFC 8092): exactly three \
                 colon-separated unsigned-integer parts, '<global>:<data1>:<data2>'. False for a \
                 standard 'a:b' community or a well-known mnemonic; NULL input is NULL.",
                "Whether a community is a large community, e.g. \
                 `is_large_community('65001:1:2')` = true.",
                "large community, RFC 8092, community type, three part community, classify",
                "BGP communities",
            ),
            ..Default::default()
        }
    }
    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![raw_spec()]
    }
    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Boolean))
    }
    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let mut b = BooleanBuilder::with_capacity(batch.num_rows());
        for i in 0..batch.num_rows() {
            match str_at(col, i) {
                Some(s) => b.append_value(community::is_large_community(s)),
                None => b.append_null(),
            }
        }
        let arr: ArrayRef = Arc::new(b.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
