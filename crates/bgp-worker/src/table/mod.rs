//! Table functions exposed by the bgp worker: `read_rib`, `read_updates`, and
//! `peers`.

mod peers;
mod read_rib;
mod read_updates;

use arrow_schema::{DataType, Field, Schema};
use vgi::Worker;

use crate::arrow_io::{inet_field, list_str_type, list_u32_type, timestamp_type};

/// Register every table function on the worker.
pub fn register(worker: &mut Worker) {
    worker.register_table(read_rib::ReadRib);
    worker.register_table(read_updates::ReadUpdates);
    worker.register_table(peers::Peers);
}

/// The `read_rib` output schema (RIB entries + an `error` capture column).
pub fn rib_schema() -> Schema {
    Schema::new(vec![
        Field::new("timestamp", timestamp_type(), true),
        Field::new("view_name", DataType::Utf8, true),
        inet_field("peer_ip"),
        Field::new("peer_asn", DataType::UInt32, true),
        inet_field("prefix"),
        Field::new("as_path", list_u32_type(), true),
        Field::new("origin_asn", DataType::UInt32, true),
        inet_field("next_hop"),
        Field::new("communities", list_str_type(), true),
        Field::new("med", DataType::UInt32, true),
        Field::new("local_pref", DataType::UInt32, true),
        Field::new("atomic_aggregate", DataType::Boolean, true),
        Field::new("aggregator_asn", DataType::UInt32, true),
        Field::new("error", DataType::Utf8, true),
    ])
}

/// The `read_updates` output schema (announce / withdraw / state_change + an
/// `error` capture column).
pub fn updates_schema() -> Schema {
    Schema::new(vec![
        Field::new("timestamp", timestamp_type(), true),
        inet_field("peer_ip"),
        Field::new("peer_asn", DataType::UInt32, true),
        Field::new("message_type", DataType::Utf8, true),
        inet_field("prefix"),
        Field::new("as_path", list_u32_type(), true),
        Field::new("origin_asn", DataType::UInt32, true),
        inet_field("next_hop"),
        Field::new("communities", list_str_type(), true),
        Field::new("old_state", DataType::UInt16, true),
        Field::new("new_state", DataType::UInt16, true),
        Field::new("error", DataType::Utf8, true),
    ])
}

/// The `peers` output schema.
pub fn peers_schema() -> Schema {
    Schema::new(vec![
        inet_field("peer_ip"),
        Field::new("peer_asn", DataType::UInt32, true),
        Field::new("collector", DataType::Utf8, true),
    ])
}
