//! TUN device creation and owned-FD lifecycle (PRD FR-24, FR-25, FR-26,
//! FR-31; integration test IT-1).
//!
//! The daemon creates the Linux TUN interface (default `protonwire0`),
//! owns its file descriptor, and hands that descriptor to ProTUN's
//! [`Connection::unix_connect`](protun::api::connection::Connection).
//! ProTUN v2.2.1 wraps the descriptor in its own owning stream
//! (`File::from_raw_fd` — it *closes* the fd on disconnect), so the
//! hand-off is an ownership *transfer*: after
//! [`TunHandle::into_raw_fd`] this side never closes the descriptor
//! again (the classic double-close hazard IT-1 pins).
//!
//! # The address contract
//!
//! ProTUN does not negotiate TUN addresses through its public API.
//! [`TunAddressPlan::contract`] exposes the pinned
//! [`crate::tun_contract`] values the adapter must configure (FR-27);
//! the M5 netlink router applies them and detects conflicts before
//! commit. This module owns the *plan*; M5 owns the application.
//!
//! # Decision record: hand-rolled `TUNSETIFF` (no `tun` crate)
//!
//! The workspace denies `unsafe` everywhere else; attaching a device
//! is the one kernel interface with no safe std/nix path. Options
//! weighed for M4 PR-3:
//!
//! * a `tun`/`tun2`/`tappers` crate — adds a dependency for one
//!   ioctl, each with its own threading/ownership model and audit
//!   surface (the stdlib-first policy's "no tiny-fraction imports"
//!   arm);
//! * `rtnetlink` link creation — the M5 dependency, heavyweight for
//!   the M4 adapter's create-and-hand-off need;
//! * **hand-rolled (chosen)** — ~30 lines: open `/dev/net/tun`, one
//!   `ioctl(TUNSETIFF)` with `IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL`, read
//!   back the assigned name. Scoped `#[allow(unsafe_code)]`, single buffer,
//!   no pointer arithmetic beyond the ioctl's own argument.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, RawFd};

use protun::api::connection::TunStreamInfo;
use thiserror::Error;

/// Default TUN interface name (FR-25).
pub const DEFAULT_IF_NAME: &str = "protonwire0";

/// Errors from TUN device creation and lifecycle.
#[derive(Debug, Error)]
pub enum TunError {
    /// The requested interface name cannot be passed to the kernel
    /// (FR-26 configurability stays within `ifreq` limits: 1–15 chars
    /// of `[A-Za-z0-9._-]`, leading alphanumeric).
    #[error(
        "invalid TUN interface name `{0}`: 1-15 chars of [A-Za-z0-9._-], first char alphanumeric"
    )]
    InvalidName(String),
    /// `/dev/net/tun` could not be opened.
    #[error("opening /dev/net/tun failed: {0}")]
    DeviceOpen(io::Error),
    /// The `TUNSETIFF` attach failed (missing `CAP_NET_ADMIN`, name
    /// already attached with different flags, …).
    #[error("attaching TUN device `{name}` failed: {error}")]
    Attach {
        /// The requested interface name.
        name: String,
        /// The kernel's refusal.
        error: io::Error,
    },
}

/// One interface address of the FR-27 integration contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunIfAddress {
    /// The address assigned to the interface.
    pub address: IpAddr,
    /// Prefix length. The contract's `/32` and `/128` are host routes:
    /// the gateway is reached through the tunnel peer, never through an
    /// on-link subnet (the pvpnclient integration model).
    pub prefix_len: u8,
    /// The internal peer/gateway address (`.1` counterpart).
    pub gateway: IpAddr,
}

impl TunIfAddress {
    fn parse(addr_with_prefix: &str, gateway: &str) -> Option<Self> {
        let (address, prefix) = addr_with_prefix.split_once('/')?;
        Some(Self {
            address: address.parse().ok()?,
            prefix_len: prefix.parse().ok()?,
            gateway: gateway.parse().ok()?,
        })
    }
}

/// The pinned TUN address plan (FR-27, OQ-15): exactly the
/// [`crate::tun_contract`] constants, parsed once for the M5 router to
/// apply and conflict-check before commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunAddressPlan {
    /// The IPv4 interface address and gateway.
    pub ipv4: TunIfAddress,
    /// The IPv6 interface address and gateway (applied when IPv6 is
    /// enabled).
    pub ipv6: TunIfAddress,
}

impl TunAddressPlan {
    /// The contract plan. Infallible: the constants are pinned
    /// well-formed by unit tests (a bad constant fails the test suite,
    /// not production parsing).
    pub fn contract() -> Self {
        Self {
            ipv4: TunIfAddress::parse(
                crate::tun_contract::IPV4_ADDRESS,
                crate::tun_contract::IPV4_GATEWAY,
            )
            .expect("FR-27 IPv4 contract constant is well formed (pinned by tests)"),
            ipv6: TunIfAddress::parse(
                crate::tun_contract::IPV6_ADDRESS,
                crate::tun_contract::IPV6_GATEWAY,
            )
            .expect("FR-27 IPv6 contract constant is well formed (pinned by tests)"),
        }
    }
}

/// An owned TUN device descriptor (FR-24).
///
/// Creating the handle attaches a fresh `IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL` device
/// inside the caller's network namespace; the descriptor closes on
/// drop or explicit [`close`](TunHandle::close) — idempotently (FR-31
/// cleanup discipline). Transferring the descriptor to ProTUN
/// relinquishes this side's ownership entirely.
///
/// The attach is EXCLUSIVE by kernel contract: `IFF_TUN_EXCL` makes a
/// second `TUNSETIFF` on an existing name fail `EBUSY` on every kernel
/// (IT-1 pins the refusal), so the device has exactly one owner at any
/// moment — its creating descriptor until the transfer, ProTUN's
/// stream after. The device is destroyed when that descriptor closes.
#[derive(Debug)]
pub struct TunHandle {
    file: Option<File>,
    name: String,
}

/// `TUNSETIFF` — `_IOW('T', 202, int)` from `linux/if_tun.h` (not
/// exposed by glibc or the `libc` crate; the value is
/// `(1 << 30) | (4 << 16) | (0x54 << 8) | 202`).
/// TUNSETIFF is only correct on asm-generic-ioctl architectures
/// (the bot round's P2): mips/powerpc/sparc encode _IOW differently,
/// and the hardcoded request would fail ENOTTY there. Fail the BUILD
/// on those targets rather than shipping a silently-broken create —
/// derive the per-arch value if such a port ever becomes real.
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "riscv64",
    target_arch = "riscv32",
    target_arch = "loongarch64",
    target_arch = "csky",
)))]
compile_error!(
    "TUNSETIFF's asm-generic encoding is not valid on this architecture — \
     derive the request per-arch before building here (see tun.rs)"
);
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
/// `IFF_TUN` from `linux/if_tun.h` (same glibc/libc gap).
const IFF_TUN: i16 = 0x0001;
/// `IFF_NO_PI` from `linux/if_tun.h`: no packet-information prefix —
/// ProTUN's `TunStreamUnix` expects raw IP frames.
const IFF_NO_PI: i16 = 0x1000;
/// `IFF_TUN_EXCL` from `linux/if_tun.h`: the attach is refused
/// (`EBUSY`) if the device already exists — exclusivity by kernel
/// CONTRACT, not by incidental same-flags behavior (the rust gate's
/// P2: the refusal must hold on every kernel, CI's 6.x included).
const IFF_TUN_EXCL: i16 = 0x8000u16 as i16; // bit 15: negative as i16, the intended bit pattern
/// `IFNAMSIZ` from `linux/if.h`; `libc` re-exports it.
const IFNAMSIZ: usize = libc::IFNAMSIZ;
/// `sizeof(struct ifreq)` on Linux: `IFNAMSIZ` + the 24-byte
/// `ifr_ifru` union. `TUNSETIFF` copies the full struct even though
/// its ioctl number declares `sizeof(int)`.
const IFREQ_LEN: usize = IFNAMSIZ + 24;

/// Attaches `name` to a fresh `IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL`
/// device on an open `/dev/net/tun` descriptor and returns the
/// kernel-assigned name.
///
/// # Safety
///
/// The workspace denies `unsafe`; this is the codebase's sanctioned
/// kernel interface (decision record in the module docs — hand-rolled
/// ~30 lines over a vetted crate, per the stdlib-first policy).
/// `fd` must be an open file descriptor. The ioctl writes only within
/// the `ifreq` buffer passed to it.
#[allow(unsafe_code)]
fn tunsetiff(fd: RawFd, name: &CStr) -> io::Result<String> {
    let mut ifreq = [0u8; IFREQ_LEN];
    let name_bytes = name.to_bytes_with_nul();
    // The caller validated the name; the copy stays in bounds.
    ifreq[..name_bytes.len()].copy_from_slice(name_bytes);
    let flags: i16 = IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL;
    ifreq[IFNAMSIZ..IFNAMSIZ + 2].copy_from_slice(&flags.to_ne_bytes());
    // SAFETY: fd is an open descriptor; the ioctl writes only within
    // ifreq (kernel `copy_from_user`/`copy_to_user` of sizeof(ifreq)).
    let rc = unsafe { libc::ioctl(fd, TUNSETIFF, ifreq.as_mut_ptr().cast::<libc::c_void>()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // The kernel returns the assigned name in ifr_name (it fills a %d
    // wildcard; a fixed name comes back unchanged). The lossy decode
    // cannot mangle in practice: validate_name admits only ASCII and
    // no '%', so the echoed name is byte-identical to the request —
    // the lossy arm exists only to keep the decode total.
    let raw = &ifreq[..IFNAMSIZ];
    let end = raw.iter().position(|b| *b == 0).unwrap_or(IFNAMSIZ);
    Ok(String::from_utf8_lossy(&raw[..end]).into_owned())
}

impl TunHandle {
    /// Validates `name` without touching the system.
    pub fn validate_name(name: &str) -> Result<(), TunError> {
        let valid = (1..=IFNAMSIZ - 1).contains(&name.len())
            && name
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
        if valid {
            Ok(())
        } else {
            Err(TunError::InvalidName(name.to_owned()))
        }
    }

    /// Creates and attaches the TUN device `name` in the caller's
    /// network namespace (requires `CAP_NET_ADMIN` over that namespace
    /// — the netns harness grants it without real root).
    pub fn create(name: &str) -> Result<Self, TunError> {
        Self::validate_name(name)?;
        let file = File::options()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(TunError::DeviceOpen)?;
        // validate_name guarantees no interior NUL and IFNAMSIZ-1
        // length, so the CString round-trip cannot fail.
        let c_name = CString::new(name).expect("validated name has no NUL");
        let assigned = tunsetiff(file.as_raw_fd(), &c_name).map_err(|error| TunError::Attach {
            name: name.to_owned(),
            error,
        })?;
        Ok(Self {
            file: Some(file),
            name: assigned,
        })
    }

    /// The kernel-assigned interface name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The `update_unix_tun` update shape: what a LIVE connection
    /// takes when the TUN descriptor must change without a session
    /// teardown (FR-32C). CONSUMES the handle (the bot round's P1):
    /// ProTUN wraps the carried fd in its own owning `File`, so a
    /// borrowing shape left a SECOND owner of the same descriptor —
    /// dropping either could close it under the other or target a
    /// reused fd later. The initial hand-off is different —
    /// `Connection::unix_connect` takes the raw fd
    /// (`Some(handle.into_raw_fd())`), not this type.
    pub fn into_stream_info(mut self) -> TunStreamInfo {
        let file = self
            .file
            .take()
            .expect("handle owns its fd until close or transfer");
        let fd = file.as_raw_fd();
        // ProTUN's stream owns the descriptor now (same transfer
        // semantics as into_raw_fd).
        std::mem::forget(file);
        TunStreamInfo::TunFd(fd)
    }

    /// The owned descriptor (valid until `close`/transfer).
    pub fn raw_fd(&self) -> RawFd {
        self.file
            .as_ref()
            .expect("handle owns its fd until close or transfer")
            .as_raw_fd()
    }

    /// Ownership transfer to ProTUN (FR-24): ProTUN's stream takes the
    /// descriptor and closes it on disconnect. After this call the
    /// handle is spent and this side must not close the descriptor.
    ///
    /// # Panics
    ///
    /// If the handle was already [`close`](TunHandle::close)d — the
    /// engine sequences create → transfer immediately.
    pub fn into_raw_fd(mut self) -> RawFd {
        let file = self
            .file
            .take()
            .expect("handle owns its fd until close or transfer");
        let fd = file.as_raw_fd();
        // The descriptor now belongs to ProTUN's stream; dropping our
        // File would close it under the new owner.
        std::mem::forget(file);
        fd
    }

    /// Closes the owned descriptor, idempotently (FR-31): a second
    /// close — or a drop after a close — is a no-op, never a
    /// double-close.
    pub fn close(&mut self) {
        self.file.take();
    }
}

impl Drop for TunHandle {
    fn drop(&mut self) {
        // take() makes the close idempotent and cannot double-close
        // after a transfer (into_raw_fd already took the File).
        self.file.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-27's contract, restated independently: the plan the adapter
    /// will configure is exactly the hardcoded integration addresses
    /// (10.2.0.2/32 → 10.2.0.1, 2a07:b944::2:2/128 → 2a07:b944::2:1),
    /// in the host-route shape (no on-link subnet).
    #[test]
    fn address_plan_is_exactly_the_fr27_contract() {
        let plan = TunAddressPlan::contract();
        assert_eq!(
            plan.ipv4,
            TunIfAddress {
                address: "10.2.0.2".parse::<IpAddr>().unwrap(),
                prefix_len: 32,
                gateway: "10.2.0.1".parse::<IpAddr>().unwrap(),
            }
        );
        assert_eq!(
            plan.ipv6,
            TunIfAddress {
                address: "2a07:b944::2:2".parse::<IpAddr>().unwrap(),
                prefix_len: 128,
                gateway: "2a07:b944::2:1".parse::<IpAddr>().unwrap(),
            }
        );
        // The host-route model: the gateway is a peer address, never a
        // member of the interface's own network.
        assert_ne!(plan.ipv4.address, plan.ipv4.gateway);
        assert_ne!(plan.ipv6.address, plan.ipv6.gateway);
        assert_eq!(plan.ipv4.prefix_len, 32);
        assert_eq!(plan.ipv6.prefix_len, 128);
    }

    #[test]
    fn default_name_is_fr25_protonwire0() {
        assert_eq!(DEFAULT_IF_NAME, "protonwire0");
    }

    /// The documented discipline, pinned: transferring a handle that
    /// was closed first is an invalid state and panics (rather than
    /// handing ProTUN a closed descriptor). The engine sequences
    /// create → transfer immediately; PR-4's error paths must not
    /// close-then-transfer.
    #[test]
    #[should_panic(expected = "handle owns its fd until close or transfer")]
    fn into_raw_fd_after_close_panics_rather_than_handing_a_dead_fd() {
        let mut handle = TunHandle {
            file: None,
            name: "unspent".to_owned(),
        };
        handle.close();
        let _ = handle.into_raw_fd();
    }

    #[test]
    fn names_validate_within_ifreq_limits() {
        assert!(TunHandle::validate_name(DEFAULT_IF_NAME).is_ok());
        assert!(TunHandle::validate_name("pw-1.x_9").is_ok());
        // Overlong (IFNAMSIZ-1 = 15 is the kernel limit).
        assert!(TunHandle::validate_name(&"a".repeat(15)).is_ok());
        assert!(matches!(
            TunHandle::validate_name(&"a".repeat(16)),
            Err(TunError::InvalidName(_))
        ));
        // Empty, separator-leading, and non-interface characters.
        assert!(matches!(
            TunHandle::validate_name(""),
            Err(TunError::InvalidName(_))
        ));
        assert!(matches!(
            TunHandle::validate_name("-pw"),
            Err(TunError::InvalidName(_))
        ));
        assert!(matches!(
            TunHandle::validate_name("pw/0"),
            Err(TunError::InvalidName(_))
        ));
        assert!(matches!(
            TunHandle::validate_name("pw 0"),
            Err(TunError::InvalidName(_))
        ));
    }
}
