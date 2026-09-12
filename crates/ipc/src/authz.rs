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
        | Request::Disconnect
        // M2 S9: the servers/account/credential surface is user-level —
        // the scheduler's pacing and the confirmation ceremony protect
        // the upstream, the peer-secret boundary protects the values,
        // and the daemon is the single-account privileged host
        // (per-UID account namespacing rides the per-UID overlay
        // milestone).
        | Request::ServersList
        | Request::ServersRefresh { .. }
        | Request::BeginLogin { .. }
        | Request::SubmitTwoFactor { .. }
        | Request::SubmitFidoPayload { .. }
        | Request::RefreshSession
        | Request::Logout
        | Request::SubmitCredential { .. }
        | Request::GetAccount
        // M3 U6: the selection/groups surface is a read-only query
        // family — it reads the daemon's cached catalog and registry,
        // never mutates state, and performs no upstream request on the
        // listing paths (FR-23R). The bounded on-demand prober a
        // latency-ranked Select may run is the U5-bounded seam (rate
        // limits, shortlist cap), not a privileged action.
        | Request::Select { .. }
        | Request::GroupsList
        | Request::GroupShow { .. } => IpcRole::AnyUser,
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

    /// M2 S9: the servers/account/credential surface is user-level —
    /// every new method requires only [`IpcRole::AnyUser`]; the
    /// upstream-protection and secret-handling guarantees live in the
    /// daemon handler, not the socket role.
    #[test]
    fn s9_surface_requests_allow_any_user() {
        for req in [
            Request::ServersList,
            Request::ServersRefresh {
                confirmation_token: None,
            },
            Request::BeginLogin {
                username: protonwire_frontend_api::SecretParam::new("u"),
                password: protonwire_frontend_api::SecretParam::new("p"),
            },
            Request::SubmitTwoFactor {
                code: protonwire_frontend_api::SecretParam::new("123456"),
            },
            Request::SubmitFidoPayload {
                client_data: protonwire_frontend_api::SecretParam::new("cd"),
                authenticator_data: protonwire_frontend_api::SecretParam::new("ad"),
                signature: protonwire_frontend_api::SecretParam::new("sig"),
                credential_id: vec![1, 2, 3],
            },
            Request::RefreshSession,
            Request::Logout,
            Request::SubmitCredential {
                name: "session".into(),
                value: protonwire_frontend_api::SecretParam::new("v"),
            },
            Request::GetAccount,
            // M3 U6: the selection/groups surface joins the user-level
            // read-only family (FR-23R — the listing paths perform no
            // upstream request; the query reads daemon-cached state).
            Request::Select {
                target: protonwire_frontend_api::ConnectTarget::Fastest,
                modifiers: Default::default(),
            },
            Request::GroupsList,
            Request::GroupShow {
                id: "proton:fastest-country".into(),
            },
        ] {
            assert_eq!(required_role(&req), IpcRole::AnyUser, "{req:?}");
        }
        assert!(authorize(IpcRole::AnyUser, &peer(1000)).is_ok());
    }
}
