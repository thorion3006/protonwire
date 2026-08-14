//! `protonwire-gui` — the Tauri shell (PRD 9.10, FR-127G).
//!
//! The shell owns the shared client SDK connection and maps an explicit,
//! minimal allowlist of typed GUI commands onto SDK calls. Milestone 1
//! exposes exactly one command (`daemon_state`); connection lifecycle,
//! selection, profiles, and settings commands join with their SDK
//! counterparts in later milestones. The webview loads bundled local assets
//! only, under a restrictive CSP (inline styles permitted for the bundled
//! shell's own markup), with no generic shell, filesystem, process, or
//! network bridge.

use protonwire_client::{ClientError, ProtonwireClient};
use protonwire_frontend_api::ClientSurface;

/// The one Milestone 1 command: a full daemon state snapshot.
#[tauri::command]
fn daemon_state() -> Result<serde_json::Value, String> {
    let mut client =
        ProtonwireClient::connect_default(ClientSurface::Gui).map_err(|e| e.to_string())?;
    let state = client.state().map_err(|e| e.to_string())?;
    serde_json::to_value(state).map_err(|e| e.to_string())
}

/// Exit-code mapping kept for the future tray/notification surface.
#[allow(dead_code)]
fn daemon_exit_code(e: &ClientError) -> u8 {
    e.exit_code()
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![daemon_state])
        .run(tauri::generate_context!())
        .expect("protonwire-gui shell failed to start");
}
