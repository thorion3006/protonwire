//! Per-method IPC authorization (PRD 6.3).
//!
//! Socket access is not authority. Every request carries a required role,
//! checked against the authenticated peer credentials. Fine-grained ownership
//! (the active connection owner) is enforced by core on top of these roles.

use protonwire_frontend_api::{Request, RpcError, RpcErrorCode};

use crate::peer::PeerCredentials;

/// Roles a request can require.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcRole {
    /// Any local user that reached the socket.
    AnyUser,
    /// UID 0.
    Admin,
}

/// The role a request requires before the daemon executes it.
pub fn required_role(request: &Request) -> IpcRole {
    match request {
        Request::Ping { .. }
        | Request::GetState
        | Request::Connect { .. }
        | Request::Disconnect => IpcRole::AnyUser,
        Request::Shutdown => IpcRole::Admin,
    }
}

/// Checks a peer against a role requirement.
pub fn authorize(role: IpcRole, peer: &PeerCredentials) -> Result<(), RpcError> {
    match role {
        IpcRole::AnyUser => Ok(()),
        IpcRole::Admin if peer.is_root() => Ok(()),
        IpcRole::Admin => Err(RpcError::new(
            RpcErrorCode::PermissionDenied,
            format!(
                "this request requires administrator (UID 0) credentials; peer UID is {}",
                peer.uid
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(uid: u32) -> PeerCredentials {
        PeerCredentials {
            uid,
            gid: 100,
            pid: Some(4242),
        }
    }

    #[test]
    fn shutdown_requires_admin() {
        assert_eq!(required_role(&Request::Shutdown), IpcRole::Admin);
        assert!(authorize(IpcRole::Admin, &peer(0)).is_ok());
        let err = authorize(IpcRole::Admin, &peer(1000)).unwrap_err();
        assert_eq!(err.code, RpcErrorCode::PermissionDenied);
    }

    #[test]
    fn read_only_requests_allow_any_user() {
        for req in [
            Request::Ping { nonce: "n".into() },
            Request::GetState,
            Request::Connect {
                target: protonwire_frontend_api::ConnectTarget::Fastest,
            },
            Request::Disconnect,
        ] {
            assert_eq!(required_role(&req), IpcRole::AnyUser);
        }
        assert!(authorize(IpcRole::AnyUser, &peer(1000)).is_ok());
    }
}
