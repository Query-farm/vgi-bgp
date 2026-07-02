//! `bgp_version()` — return the worker's version string.

use std::sync::Arc;

use arrow_array::{ArrayRef, RecordBatch, StringArray};
use arrow_schema::DataType;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

pub struct BgpVersion;

impl ScalarFunction for BgpVersion {
    fn name(&self) -> &str {
        "bgp_version"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Returns the bgp worker version string".into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT bgp.main.bgp_version();".into(),
                description: "Return the bgp worker version string.".into(),
                expected_output: None,
            }],
            tags: {
                let mut tags = crate::meta::object_tags(
                    "BGP Worker Version",
                    "Return the version string of the running bgp worker binary (its own build \
                     version, the crate's Cargo version, not the SDK/protocol version). The string \
                     is semver MAJOR.MINOR.PATCH. The function takes no arguments and is \
                     deterministic — always the same single VARCHAR for a given build. Useful for \
                     diagnostics and confirming which build is attached.",
                    "Return the bgp worker version string, e.g. `bgp_version()` → '0.1.0'. \
                     Argument-free and deterministic.",
                    "version, build version, bgp_version, diagnostics, worker version, semver",
                    "Worker info",
                );
                tags.push((
                    "vgi.executable_examples".into(),
                    r#"[
  {
    "description": "Return the worker version string.",
    "sql": "SELECT bgp.main.bgp_version() AS version"
  },
  {
    "description": "AS-path helpers over an inline path: hops, origin, and prepend count.",
    "sql": [
      "SELECT bgp.main.path_length([7018, 174, 174, 13335]) AS hops",
      "SELECT bgp.main.origin_asn([7018, 174, 13335]) AS origin",
      "SELECT bgp.main.as_path_prepends([7018, 174, 174, 13335]) AS prepends",
      "SELECT bgp.main.path_contains([7018, 174, 13335], 174) AS via_174",
      "SELECT bgp.main.is_large_community('65001:1:2') AS is_large",
      "SELECT bgp.main.community_parse('65001:100').asn AS asn"
    ]
  }
]"#
                    .into(),
                ));
                tags
            },
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        Vec::new()
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let rows = batch.num_rows();
        let out: ArrayRef = Arc::new(StringArray::from(vec![bgp_core::version(); rows]));
        RecordBatch::try_new(params.output_schema.clone(), vec![out])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
