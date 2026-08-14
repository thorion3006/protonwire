//! `SO_PEERCRED` peer credential lookup.

use std::io;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

/// Credentials of the process on the other end of a Unix socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    /// Effective UID of the peer process.
    pub uid: u32,
    /// Effective GID of the peer process.
    pub gid: u32,
    /// PID of the peer process, when available.
    pub pid: Option<i32>,
}

impl PeerCredentials {
    /// Reads the peer credentials of a connected Unix stream socket.
    pub fn of(stream: &UnixStream) -> io::Result<Self> {
        let creds = getsockopt(stream.as_fd(), PeerCredentials)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(Self {
            uid: creds.uid(),
            gid: creds.gid(),
            pid: creds.pid(),
        })
    }

    /// Whether the peer is the root user.
    pub fn is_root(&self) -> bool {
        self.uid == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_credentials_of_socketpair() {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let creds = PeerCredentials::of(&a).unwrap();
        assert_eq!(creds.uid, nix::unistd::getuid().as_raw());
        let _ = b;
    }
}
