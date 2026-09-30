//! IT-1 (PRD 17.2): create a TUN interface, transfer its file
//! descriptor to the ProTUN hand-off shape, and clean it up
//! idempotently — inside the netns harness (NFR-31).
//!
//! Every test here mutates kernel networking state and is therefore
//! gated on the managed network namespace: run with
//! `cargo xtask netns-it`. Outside the runner each test skips with a
//! disclosure line and touches nothing. Observations go through
//! netlink (`if_nametoindex`) or `/proc/net` — never `/sys/class/net`,
//! which reflects the host's mount of sysfs, not the namespace.

use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::Arc;

use nix::net::if_::if_nametoindex;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, getsockopt, socket, sockopt};
use protonwire_net::netns;
use protonwire_protocol::DEFAULT_IF_NAME;
use protonwire_protocol::marks::{MarkHealth, MarkingFdCallback, SoMarkApplier};
use protonwire_protocol::tun::TunHandle;
use protun::api::connection_unix::OnSocketFdAvailableCallback;

fn interface_exists(name: &str) -> bool {
    if_nametoindex(name).is_ok()
}

#[test]
fn it1_create_transfer_cleanup() {
    if !netns::gate("IT-1 create → transfer → cleanup") {
        return;
    }
    // FR-24/FR-25: create the default-named device in this namespace.
    let handle = TunHandle::create(DEFAULT_IF_NAME).expect("create protonwire0");
    assert_eq!(handle.name(), DEFAULT_IF_NAME);
    let ifindex = if_nametoindex(DEFAULT_IF_NAME).expect("the device exists");
    assert!(ifindex > 0);

    // The hand-off shape `Connection::unix_connect` accepts, and the
    // ownership transfer: ProTUN's TunStreamUnix wraps the fd in
    // File::from_raw_fd and CLOSES it on disconnect. Emulating exactly
    // that move proves the fd survives our handle's drop (no
    // double-close on the transfer path).
    let stream_info = handle.stream_info();
    let fd = handle.into_raw_fd(); // consumes the handle — nothing left to double-close
    match stream_info {
        protun::api::connection::TunStreamInfo::TunFd(reported) => assert_eq!(reported, fd),
        protun::api::connection::TunStreamInfo::NoTun => panic!("stream_info must carry the fd"),
    }
    #[allow(unsafe_code)] // test: the exact ownership move ProTUN performs
    let protun_owner = unsafe { File::from_raw_fd(fd) };
    drop(protun_owner); // ProTUN's disconnect close
    assert!(
        !interface_exists(DEFAULT_IF_NAME),
        "the device dies with its last fd — the transfer was single-ownership"
    );
}

#[test]
fn it1_close_is_idempotent_and_drop_stays_clean() {
    if !netns::gate("IT-1 idempotent cleanup (FR-31)") {
        return;
    }
    let mut handle = TunHandle::create("pwclean0").expect("create pwclean0");
    assert!(interface_exists("pwclean0"));
    handle.close();
    handle.close(); // idempotent — no EBADF double-close
    drop(handle); // drop after close — still clean
    assert!(!interface_exists("pwclean0"));
}

#[test]
fn it1_second_attach_is_refused_not_shared() {
    if !netns::gate("IT-1 TUNSETIFF attach semantics on an existing name") {
        return;
    }
    // Pin the kernel contract: IFF_TUN_EXCL in the attach flags makes
    // a second TUNSETIFF on an existing TUN name fail EBUSY on every
    // kernel — the device is exclusive to its creating descriptor. The
    // failed attach leaves the first owner untouched, and its cleanup
    // still removes the device. FR-31's cleanup never races a shadow
    // owner.
    let first = TunHandle::create("pwshare0").expect("first create");
    assert!(interface_exists("pwshare0"));

    match TunHandle::create("pwshare0") {
        Err(protonwire_protocol::tun::TunError::Attach { error, .. }) => {
            assert_eq!(
                error.raw_os_error(),
                Some(libc::EBUSY),
                "kernel refuses a second attach with EBUSY (got {error})"
            );
        }
        other => panic!("second attach must be refused with EBUSY, got {other:?}"),
    }
    assert!(
        interface_exists("pwshare0"),
        "the refused attach left the first owner untouched"
    );

    drop(first);
    assert!(!interface_exists("pwshare0"));
}

#[test]
fn it1_outer_socket_mark_seam_roundtrip() {
    if !netns::gate("FR-32B mark seam round-trip (SO_MARK needs CAP_NET_ADMIN)") {
        return;
    }
    // The seam's live proof at unit scope: a socket protun would report
    // gets the stable bypass mark through the callback, readable back
    // via SO_MARK. (The before-route-commit ordering is IT-13, M5.)
    let socket_fd = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )
    .expect("create a UDP socket in the namespace");
    let health = Arc::new(MarkHealth::new());
    let callback = MarkingFdCallback::new(Arc::new(SoMarkApplier::new(0x51820)), health.clone());
    callback.on_socket_fd_available(socket_fd.as_raw_fd());

    let mark = getsockopt(&socket_fd, sockopt::Mark).expect("SO_MARK is readable back");
    assert_eq!(mark, 0x51820, "the callback applied the stable mark");
    assert!(health.all_marked(), "no failure was recorded");
}
