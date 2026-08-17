//! Core error taxonomy mapped onto the frontend API's RPC codes.

use protonwire_frontend_api::{RpcError, RpcErrorCode};

/// Errors produced by core request handling.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// The capability is planned but not implemented in this milestone.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),

    /// The request parameters failed validation.
    #[error("invalid parameters: {0}")]
    InvalidParams(String),

    /// The authenticated peer may not perform the request.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// An internal invariant broke.
    #[error("internal error: {0}")]
    Internal(String),
}

impl CoreError {
    /// Converts the error into its wire representation.
    pub fn into_rpc(self) -> RpcError {
        let (code, message) = match &self {
            CoreError::NotImplemented(what) => (RpcErrorCode::NotImplemented, what.to_string()),
            CoreError::InvalidParams(m) => (RpcErrorCode::InvalidParams, m.clone()),
            CoreError::PermissionDenied(m) => (RpcErrorCode::PermissionDenied, m.clone()),
            CoreError::Internal(m) => (RpcErrorCode::Internal, m.clone()),
        };
        RpcError::new(code, message)
    }
}

impl From<CoreError> for RpcError {
    fn from(e: CoreError) -> RpcError {
        e.into_rpc()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_implemented_maps_to_rpc() {
        let rpc = CoreError::NotImplemented("tunnel connect lands in milestone 4").into_rpc();
        assert_eq!(rpc.code, RpcErrorCode::NotImplemented);
        assert!(rpc.message.contains("milestone 4"));
    }
}
