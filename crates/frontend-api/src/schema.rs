//! JSON Schema generation entry points (consumed by `cargo xtask schema-gen`).

use schemars::schema_for;

use crate::{
    ClientMessage, ConnectTarget, DaemonState, Event, EventEnvelope, Request, RequestResult,
    Response, RpcError, RpcErrorCode, ServerMessage,
};

/// Named root schemas emitted by the generator, in stable order.
pub fn root_schemas() -> Vec<(&'static str, schemars::Schema)> {
    vec![
        ("client-message", schema_for!(ClientMessage)),
        ("server-message", schema_for!(ServerMessage)),
        ("request", schema_for!(Request)),
        ("request-result", schema_for!(RequestResult)),
        ("response", schema_for!(Response)),
        ("connect-target", schema_for!(ConnectTarget)),
        ("rpc-error", schema_for!(RpcError)),
        ("rpc-error-code", schema_for!(RpcErrorCode)),
        ("daemon-state", schema_for!(DaemonState)),
        ("event", schema_for!(Event)),
        ("event-envelope", schema_for!(EventEnvelope)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_root_schema_generates() {
        assert_eq!(root_schemas().len(), 11);
        for (name, schema) in root_schemas() {
            assert!(
                serde_json::to_value(&schema).is_ok(),
                "schema {name} failed to serialize"
            );
        }
    }
}
