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
    /// The daemon's async runtime (the lane composes the async net
    /// session from sync IPC-handler threads via `block_on`).
    pub runtime: tokio::runtime::Handle,
    /// The TUN interface's name (the engine's `if_name`; carried for
    /// the session's DNS revert and teardown).
    pub tun_ifname: String,
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
        tun_ifname: String,
        dns: DnsConfig,
        ipv6: Ipv6Desired,
    ) -> Result<Self, NetStartupError> {
        // Everything netlink runs INSIDE one block_on: the
        // connection constructor itself needs an active reactor at
        // call time (calling it on a plain thread panics in
        // netlink-sys), and the surveys share the executor.
        let (mark, uplink_ifname, handle) = runtime.block_on(async {
            let (connection, handle, _) =
                rtnetlink::new_connection().map_err(|e| NetStartupError::Netlink(e.to_string()))?;
            tokio::spawn(connection);
            let mut executor = RtnetlinkExecutor::new(handle.clone());
            let mark = protonwire_net::mark::allocate(&mut executor).await?;
            let uplink = detect_uplink(&handle).await;
            Ok::<_, NetStartupError>((mark, uplink, handle))
        })?;
        let rt_tables = std::fs::read_to_string("/etc/iproute2/rt_tables").unwrap_or_default();
        Ok(Self {
            mark,
            handle,
            runtime,
            tun_ifname,
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

/// The interface index for `name`, via the link dump — the same
/// netlink view the route transaction commits against (no C-ABI
/// call: the workspace denies unsafe).
pub async fn ifindex_by_name(handle: &rtnetlink::Handle, name: &str) -> Option<u32> {
    use futures_util::StreamExt;
    let mut links = handle.link().get().execute();
    while let Some(message) = links.next().await {
        let Ok(message) = message else { continue };
        for attribute in &message.attributes {
            if let rtnetlink::packet_route::link::LinkAttribute::IfName(if_name) = attribute
                && if_name == name
            {
                return Some(message.header.index);
            }
        }
    }
    None
}

/// Assigns the TUN's contract addresses (the bot round's P1): the
/// engine creates the device but tun.rs leaves address application
/// to the MANAGER — without `10.2.0.2/32` (and the v6 address when
/// tunnelled), traffic routed into the TUN sources from the uplink
/// address and the peer cannot return it. Idempotent (a duplicate
/// add is ENEXIST, swallowed — reconnect reuses the same TUN name).
pub async fn assign_tun_addresses(
    handle: &rtnetlink::Handle,
    ifindex: u32,
    ipv6_tunneled: bool,
) -> Result<(), String> {
    let plan = protonwire_protocol::tun::TunAddressPlan::contract();
    let mut failures = Vec::new();
    for address in [Some(plan.ipv4), ipv6_tunneled.then_some(plan.ipv6)]
        .into_iter()
        .flatten()
    {
        if let Err(error) = handle
            .address()
            .add(ifindex, address.address, address.prefix_len)
            .execute()
            .await
        {
            // EEXIST on reconnect: the address is already ours.
            let text = error.to_string();
            if !text.contains("File exists") {
                failures.push(format!(
                    "assign {} on {}: {}",
                    address.address, ifindex, text
                ));
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

/// Brings the interface UP (RTM_NEWLINK flags+mask): protun's
/// `InterfaceState::Up` only means the TUN STREAM registered — the
/// kernel link itself stays administratively DOWN until the manager
/// raises it (the wg-quick role; the route commit's ENETDOWN without
/// it).
pub async fn set_link_up(handle: &rtnetlink::Handle, ifindex: u32) -> Result<(), String> {
    use rtnetlink::packet_route::link::{LinkFlags, LinkMessage};
    let mut message = LinkMessage::default();
    message.header.index = ifindex;
    message.header.flags |= LinkFlags::Up;
    message.header.change_mask |= LinkFlags::Up;
    handle
        .link()
        .set(message)
        .execute()
        .await
        .map_err(|e| format!("set link up: {e}"))
}

/// Waits (bounded) for the interface to report IFF_UP: the engine
/// creates the TUN asynchronously and sets it up moments after its
/// sockets open — a route commit against a DOWN device fails with
/// ENETDOWN (the IT-32 race). `false` on the deadline: the caller
/// refuses typed, never guessing.
pub async fn wait_link_up(
    handle: &rtnetlink::Handle,
    ifindex: u32,
    deadline: std::time::Instant,
) -> bool {
    use futures_util::StreamExt;
    loop {
        let mut links = handle.link().get().execute();
        let mut up = false;
        while let Some(message) = links.next().await {
            let Ok(message) = message else { continue };
            if message.header.index == ifindex {
                up = message
                    .header
                    .flags
                    .contains(rtnetlink::packet_route::link::LinkFlags::Up);
            }
        }
        if up {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
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
        // The metric defaults to ZERO, not u32::MAX (the rust gate's
        // P2): the kernel emits RTA_PRIORITY only when non-zero, so a
        // plain zero-metric default carries NO attribute — a u32::MAX
        // default would rank it BELOW a metric-100 DHCP default and
        // the switch would probe the wrong uplink.
        let mut priority = 0u32;
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
        // a throwaway current-thread runtime supplies one and stays
        // alive for the context's lifetime (its handle is a field).
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let handle = runtime.block_on(async { rtnetlink::new_connection().expect("netlink").1 });
        let context = NetContext {
            mark: 0x0010_0001,
            handle,
            runtime: runtime.handle().clone(),
            tun_ifname: "pw-test0".to_owned(),
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
