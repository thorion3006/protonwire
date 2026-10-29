//! The daemon's net context (M6 slice 1b): everything the connection
//! lane needs from the HOST side to compose the engine with the M5
//! session orchestrator — the STARTUP-ALLOCATED bypass mark (the
//! 2026-10-08 owner decision: random, collision-checked against the
//! live world before anything arms), the routing-tables text, the
//! default-route uplink, the DNS/IPv6 posture from the daemon's
//! config surface, and the kill-switch generation counter.
//!
//! The startup allocation runs BEFORE the IPC socket binds: a
//! saturated or un-surveyable host fails the daemon at boot, not at
//! the first connect.

use std::sync::atomic::{AtomicU32, Ordering};

use protonwire_net::dns::DnsConfig;
use protonwire_net::kill_switch::GenerationId;
use protonwire_net::mark::MarkError;
use protonwire_net::route_drift::Ipv6Desired;
use protonwire_net::route_txn::RtnetlinkExecutor;

/// Why startup refused: no safe mark exists on this host, or the
/// surveys needed to prove it cannot run.
#[derive(Debug, thiserror::Error)]
pub enum NetStartupError {
    #[error("bypass-mark allocation: {0}")]
    Mark(#[from] MarkError),
    #[error("netlink: {0}")]
    Netlink(String),
}

/// The per-daemon net context (one, built at startup).
pub struct NetContext {
    /// The allocated bypass mark — the engine's outer sockets carry
    /// it (SO_MARK), the kill switch permits it, the policy rules
    /// route it. The SAME value reaches every layer through this
    /// context and the lane's [`protonwire_protocol::engine`]
    /// configuration built from it.
    pub mark: u32,
    /// The shared netlink handle (the rtnetlink connection is
    /// spawned on the daemon's runtime at startup).
    pub handle: rtnetlink::Handle,
    /// `/etc/iproute2/rt_tables` as read at startup (empty when the
    /// file is absent — the planner treats named tables as absent).
    pub rt_tables: String,
    /// The DNS posture (the daemon config's mode + servers).
    pub dns: DnsConfig,
    /// The IPv6 posture (the daemon config's).
    pub ipv6: Ipv6Desired,
    /// The default route's interface — the kill switch's uplink.
    /// `None` (no default route at boot) REFUSES connects typed
    /// until a default route exists; the lane re-detects per connect.
    pub uplink_ifname: Option<String>,
    generation: AtomicU32,
}

impl NetContext {
    /// STARTUP: spawn the netlink connection on `runtime`, allocate
    /// the mark against the live world, survey the uplink.
    pub fn startup(
        runtime: tokio::runtime::Handle,
        dns: DnsConfig,
        ipv6: Ipv6Desired,
    ) -> Result<Self, NetStartupError> {
        let (connection, handle, _) =
            rtnetlink::new_connection().map_err(|e| NetStartupError::Netlink(e.to_string()))?;
        runtime.spawn(connection);
        let mut executor = RtnetlinkExecutor::new(handle.clone());
        // One block_on for BOTH surveys: the mark allocation and the
        // uplink dump share the executor (the async runtime drives
        // the rtnetlink connection; a plain futures block_on cannot).
        let (mark, uplink_ifname) = runtime.block_on(async {
            let mark = protonwire_net::mark::allocate(&mut executor).await?;
            let uplink = detect_uplink(&handle).await;
            Ok::<_, NetStartupError>((mark, uplink))
        })?;
        let rt_tables = std::fs::read_to_string("/etc/iproute2/rt_tables").unwrap_or_default();
        Ok(Self {
            mark,
            handle,
            rt_tables,
            dns,
            ipv6,
            uplink_ifname,
            generation: AtomicU32::new(1),
        })
    }

    /// The next kill-switch generation: 1, 2, 3, … per daemon
    /// process (the persisted-record integration is the state-file
    /// lane's; the switch's own live-marker discipline governs
    /// replacement either way).
    pub fn next_generation(&self) -> GenerationId {
        GenerationId(self.generation.fetch_add(1, Ordering::SeqCst).into())
    }
}

/// The v4 default route's interface name (the uplink the kill switch
/// probes): lowest-metric default wins, the kernel's own ordering
/// among equals. `None` when no default route exists.
pub async fn detect_uplink(handle: &rtnetlink::Handle) -> Option<String> {
    use futures_util::StreamExt;
    use rtnetlink::packet_route::route::{RouteAttribute, RouteMessage};
    // (metric, ifindex) of the best default so far.
    let mut best: Option<(u32, u32)> = None;
    let mut routes = handle.route().get(RouteMessage::default()).execute();
    while let Some(message) = routes.next().await {
        let Ok(message) = message else { continue };
        if message.header.destination_prefix_length != 0 {
            continue; // not a default route
        }
        if message.header.address_family != rtnetlink::packet_route::AddressFamily::Inet {
            continue; // the v4 default is the kill switch's uplink
        }
        let mut oif = None;
        let mut priority = u32::MAX;
        for attribute in &message.attributes {
            match attribute {
                RouteAttribute::Oif(index) => oif = Some(*index),
                RouteAttribute::Priority(metric) => priority = *metric,
                _ => {}
            }
        }
        if let Some(index) = oif
            && best.is_none_or(|(metric, _)| priority < metric)
        {
            best = Some((priority, index));
        }
    }
    let (_, ifindex) = best?;
    // Resolve the index to a name via the link dump.
    let mut links = handle.link().get().execute();
    while let Some(message) = links.next().await {
        let Ok(message) = message else { continue };
        if message.header.index != ifindex {
            continue;
        }
        for attribute in &message.attributes {
            if let rtnetlink::packet_route::link::LinkAttribute::IfName(name) = attribute {
                return Some(name.clone());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generations_advance_from_one() {
        // The rtnetlink handle needs a reactor even to CONSTRUCT —
        // a throwaway current-thread runtime supplies one for the
        // duration of the call; the handle is never used here.
        let handle = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
            .block_on(async { rtnetlink::new_connection().expect("netlink").1 });
        let context = NetContext {
            mark: 0x0010_0001,
            handle,
            rt_tables: String::new(),
            dns: DnsConfig {
                mode: protonwire_net::dns::DnsMode::None,
                servers: vec![],
                routing: protonwire_net::dns::DnsRouting::ThroughVpn,
            },
            ipv6: Ipv6Desired::Blocked,
            uplink_ifname: None,
            generation: AtomicU32::new(1),
        };
        assert_eq!(context.next_generation(), GenerationId(1));
        assert_eq!(context.next_generation(), GenerationId(2));
        assert_eq!(context.next_generation(), GenerationId(3));
    }

    /// `NetOpError` is the executor's string error — the context
    /// surfaces it verbatim, never guessing a layer.
    #[test]
    fn netstartuperror_renders_its_sources() {
        let error = NetStartupError::Netlink("boom".into());
        assert!(error.to_string().contains("netlink"));
        let error = NetStartupError::Mark(MarkError::Saturated);
        assert!(error.to_string().contains("saturated"));
    }

    // detect_uplink is netlink-live: proven by IT-32 in the netns
    // harness (a dummy uplink + default route → its name).
}
