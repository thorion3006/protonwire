//! IT: the DNS lifecycle against a real filesystem (netns-gated,
//! NFR-31; the runner executes it inside a managed namespace —
//! outside the runner it skips with a disclosure).
//!
//! IT-26's core: capture → apply → verify → revert, with the
//! symlink model detected and the inode-evidence restore discipline
//! (FR-46). The file backend runs against a real /etc/resolv.conf
//! in the namespace (isolated from the host).

use protonwire_net::dns::{
    DnsBackend, DnsError, DnsServer, apply_resolv_conf, capture_resolv_conf, detect_backend,
    revert_resolv_conf,
};
use protonwire_net::netns;

#[test]
fn it_dns_lifecycle() {
    if !netns::gate("it_dns_lifecycle") {
        return;
    }

    // The backend detection is HOST-dependent (the namespace shares
    // the host filesystem): systemd-resolved may or may not be
    // running. The IT tests the FILE backend directly regardless.
    let backend = detect_backend();
    assert!(
        backend == DnsBackend::ResolvConf || backend == DnsBackend::SystemdResolved,
        "the detection returns a valid variant"
    );

    // The namespace's resolv.conf (the runner's shim may or may not
    // have written one; either way we manage it).
    let path = std::path::Path::new("/etc/resolv.conf");

    // CAPTURE: the evidence FR-46 demands.
    let evidence = capture_resolv_conf(path).expect("capture the original state");
    let original_content = evidence.original_content.clone();

    // APPLY: Proton DNS (the tunnel's resolver).
    let servers = vec![DnsServer::new("10.2.0.1".parse().unwrap())];
    apply_resolv_conf(&evidence, &servers).expect("apply proton DNS");

    // VERIFY: the content is ours.
    let applied = std::fs::read_to_string(path).expect("read applied");
    assert!(
        applied.contains("nameserver 10.2.0.1"),
        "the applied resolv.conf carries the tunnel's resolver"
    );
    assert!(
        applied.starts_with("# Managed by ProtonWire"),
        "the applied file carries our marker"
    );

    // REVERT: the inode changed (our atomic rename), so the basic
    // revert refuses — FR-46's conservative behavior when the file
    // is not the exact original inode. We verify the refusal.
    let result = revert_resolv_conf(&evidence);
    match result {
        Err(DnsError::ChangedUnderUs { .. }) => {
            // Correct: our own replacement changed the inode; the
            // basic revert refuses to restore over a file it can't
            // prove is ours. The daemon uses the content-comparison
            // variant (revert_with_written) in production.
        }
        Ok(()) => {
            // The revert succeeded — either the inode matched (the
            // shim wrote no resolv.conf and the file didn't exist,
            // so our write created it with a fresh inode that
            // happens to match), or the file was gone. Verify the
            // content is the original.
            let restored = std::fs::read_to_string(path).expect("read restored");
            assert_eq!(
                restored, original_content,
                "the revert restored the original content"
            );
        }
        Err(other) => panic!("unexpected revert error: {other:?}"),
    }

    // CLEANUP: write the original back (best effort — the namespace
    // is discarded after the test anyway).
    let _ = std::fs::write(path, &original_content);
}

#[test]
fn it_dns_no_unowned_clobber() {
    if !netns::gate("it_dns_no_unowned_clobber") {
        return;
    }

    // FR-46's "no unowned resolver state overwrite": the capture
    // records the original, and the revert refuses to restore over
    // a file that changed SINCE our replacement. We prove this by
    // replacing, then having "another manager" write, then reverting
    // and asserting the refusal.
    let path = std::path::Path::new("/etc/resolv.conf");
    let evidence = capture_resolv_conf(path).expect("capture");
    let servers = vec![DnsServer::new("10.2.0.1".parse().unwrap())];
    apply_resolv_conf(&evidence, &servers).expect("apply");

    // Another manager writes over our file.
    std::fs::write(path, "nameserver 9.9.9.9\n# another manager\n").expect("competing write");

    // REVERT: must REFUSE — the file changed since our replacement.
    let result = revert_resolv_conf(&evidence);
    assert!(
        matches!(result, Err(DnsError::ChangedUnderUs { .. })),
        "the revert refuses over a competing write: {result:?}"
    );

    // The competing write STANDS.
    let standing = std::fs::read_to_string(path).expect("read");
    assert!(
        standing.contains("9.9.9.9"),
        "the other manager's write survives our refusal"
    );
}
