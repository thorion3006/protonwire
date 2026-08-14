//! In-process IPC server fixture for this crate's tests and downstream
//! test suites (`test-util` feature; never enabled in release builds).
//!
//! Owns the bind/serve/stop plumbing shared by every test that needs a
//! daemon: bind a socket, serve a handler on a background thread, stop on
//! drop. Handlers stay in each test module — they encode test intent.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use protonwire_frontend_api::{ClientInfo, ClientSurface};

use crate::server::{IpcServer, RequestHandler};

/// A daemon-side server serving `handler` until dropped.
pub struct TestServer {
    path: PathBuf,
    stop: Arc<AtomicBool>,
}

impl TestServer {
    /// Binds `dir/socket_name` and serves until dropped.
    pub fn start<H: RequestHandler + 'static>(
        dir: &Path,
        socket_name: &str,
        handler: Arc<H>,
    ) -> std::io::Result<Self> {
        let server = IpcServer::bind(dir, socket_name)?;
        let path = server.socket_path().to_owned();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        std::thread::spawn(move || server.serve(handler, stop_flag));
        Ok(Self { path, stop })
    }

    /// Socket path clients should connect to.
    pub fn socket_path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Minimal handshake identity for tests.
pub fn client_info(name: &str) -> ClientInfo {
    ClientInfo {
        name: name.into(),
        version: "0".into(),
        surface: ClientSurface::Other,
    }
}
