//! Server-catalog model and local cache (FR-8/FR-9/FR-10/FR-13B/FR-13E).
//!
//! ## The fixture is the contract
//!
//! `catalog_fixture.json` records the `/vpn/logicals` wire shape. It could
//! not be recorded live: the endpoint now rejects unversioned clients
//! (HTTP 422 `Code 5003`) and requires a fingerprinted anonymous API
//! session (see the S6 addendum in `docs/spike-2026-08.md`), and forging
//! anti-abuse fingerprints against production is out of bounds. The
//! fixture is therefore grounded field-for-field in the deserialization
//! models of Proton's own maintained clients — win-app master
//! (`LogicalServerResponse`/`PhysicalServerResponse`/`ServersResponse`),
//! android-app master (`LogicalServer`/`ConnectingDomain`/
//! `LogicalsResponse`), and python-proton-vpn-api-core stable
//! (`LogicalServer`/`PhysicalServer`) — which collectively define every
//! field the API has ever shipped for this endpoint. Values are
//! synthetic; names, types, nullability, and presence are the recorded
//! contract.
//!
//! ## Drift fails loudly, never approximates
//!
//! Every wire type uses `deny_unknown_fields` and no `default` on wire
//! fields: an upstream field this module does not map, a renamed field,
//! or a changed type is a hard [`CatalogError`] naming the field — never
//! a silently dropped key. The same doctrine governs VALUES: the
//! recorded domains (`Status` 0/1, `Tier` 0–3, `Load` 0–100) are
//! enforced at parse, so a number the model has no representation for
//! fails loudly instead of silently reclassifying a server (a
//! `Status: 2` is drift, not "offline"). Fields the official clients
//! disagree about
//! (one still maps it, another dropped it) are `Option`: absence stays
//! absence. Nothing is ever fabricated: an absent status, load, score,
//! gateway, or revision field is `None`, and [`LogicalServer::is_online`]
//! reports `None` — *unknown* — rather than guessing (FR-13B).
//!
//! ## What is deliberately NOT here
//!
//! Port-forwarding *support* (FR-9) is not a catalog field upstream: it
//! derives from account entitlement (S8's model) composed with the
//! catalog at the decision layer, so the catalog model carries no such
//! field to fabricate. Gateway/dedicated *authorization* likewise rides
//! S8; this model carries the identity (`GatewayName`, tier).
//!
//! ## Cache
//!
//! [`CatalogCache`] persists the raw upstream body plus its revision
//! (`ETag`) under `/var/cache/protonwire` (via
//! [`crate::paths::ConfigPaths::cache_dir`]). Loads are strict: the
//! fs_trust walk rejects symlinked or group/world-writable components
//! (a poisoned cache would steer routing), the cached body is re-parsed
//! against the live model so a drifted cache fails loudly instead of
//! feeding garbage, and writes are atomic per the [`crate::state`]
//! precedent (sibling temp file, fsync, rename) with size/count caps
//! enforced both at parse time and at store time.

use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::fs_trust::{self, MissingLeaf};

/// Upper bound for the raw catalog document (16 MiB — the live catalog is
/// a few MiB and grows slowly; anything larger is garbage or an attack).
pub const MAX_CATALOG_BYTES: usize = 16 << 20;

/// Maximum logical servers in one document (the live catalog carries a
/// few thousand logicals; five digits with headroom).
pub const MAX_LOGICAL_SERVERS: usize = 16_384;

/// Maximum total physical servers across the document (logical→physical
/// fan-out is single digits; the cap bounds aggregate work per parse).
pub const MAX_PHYSICAL_SERVERS_TOTAL: usize = 262_144;

// Depth note: JSON nesting in a catalog stops at five levels (envelope →
// servers → physical → per-protocol → ports); serde_json's built-in
// 128-deep recursion limit is the backstop beneath the field-strict
// model, which cannot nest deeper than its declared shape.

/// Schema version of the cache document.
pub const CATALOG_CACHE_SCHEMA_VERSION: u32 = 1;

/// Failures of catalog parsing and of the cache.
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    /// The document exceeds [`MAX_CATALOG_BYTES`].
    #[error("catalog document of {0} bytes exceeds the {MAX_CATALOG_BYTES}-byte limit")]
    TooLarge(usize),
    /// The document exceeds a server-count cap (logical or aggregate
    /// physical).
    #[error(
        "catalog document exceeds server-count caps: {logical} logical servers (cap {MAX_LOGICAL_SERVERS}), {physical} physical servers (cap {MAX_PHYSICAL_SERVERS_TOTAL})"
    )]
    TooManyServers {
        /// Logical servers counted.
        logical: usize,
        /// Physical servers counted.
        physical: usize,
    },
    /// The upstream API refused the request (`Code != 1000`); the code
    /// and error string are surfaced, never approximated.
    #[error("catalog request refused upstream: Code {code} ({error})")]
    Api {
        /// The upstream `Code` value.
        code: i64,
        /// The upstream `Error` string, if any.
        error: String,
    },
    /// The document is structurally invalid against the recorded
    /// contract: malformed JSON, a missing required field, a wrong type,
    /// or an upstream field drift. Names the field where serde can.
    #[error("invalid catalog document (upstream contract drift must be mapped deliberately): {0}")]
    Malformed(String),
}

/// The `/vpn/logicals` envelope — the recorded contract (see the module
/// documentation). Wire field names are explicit `rename`s (never
/// `rename_all`: serde's PascalCase would fold `ID` to `Id` and `EntryIP`
/// to `EntryIp`, silently diverging from the wire).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogDocument {
    /// The API result code; anything but 1000 is [`CatalogError::Api`].
    #[serde(rename = "Code")]
    pub code: i64,
    /// The API error string (present even on success, empty).
    #[serde(rename = "Error")]
    pub error: Option<String>,
    /// The API error-detail bag; empty on success, never feeds the model.
    #[serde(rename = "Details")]
    pub details: Option<ApiErrorDetails>,
    /// Conditional-refresh status token (android `StatusID`).
    #[serde(rename = "StatusID")]
    pub status_id: String,
    /// Response metadata; `None` when the API omits it.
    #[serde(rename = "ResponseMetadata")]
    pub response_metadata: Option<ResponseMetadata>,
    /// The logical servers.
    #[serde(rename = "LogicalServers")]
    pub logical_servers: Vec<LogicalServer>,
}

impl CatalogDocument {
    /// Parses and validates the raw upstream body. Size and server-count
    /// caps are enforced before and after deserialization.
    pub fn from_bytes(body: &[u8]) -> Result<Self, CatalogError> {
        if body.len() > MAX_CATALOG_BYTES {
            return Err(CatalogError::TooLarge(body.len()));
        }
        let doc: Self =
            serde_json::from_slice(body).map_err(|e| CatalogError::Malformed(e.to_string()))?;
        if doc.code != 1000 {
            return Err(CatalogError::Api {
                code: doc.code,
                error: doc.error.clone().unwrap_or_default(),
            });
        }
        let physical: usize = doc.logical_servers.iter().map(|s| s.servers.len()).sum();
        if doc.logical_servers.len() > MAX_LOGICAL_SERVERS || physical > MAX_PHYSICAL_SERVERS_TOTAL
        {
            return Err(CatalogError::TooManyServers {
                logical: doc.logical_servers.len(),
                physical,
            });
        }
        validate_value_domains(&doc)?;
        Ok(doc)
    }
}

/// Enforces the recorded VALUE domains — the drift doctrine applied to
/// values, not just field names: a structurally valid field carrying a
/// number the model has no representation for (`Status: 2` mapped to
/// "offline" by `is_online`'s `== 1`, a negative or >100 `Load` feeding
/// ranking, a `Tier` outside the 0–3 plan vocabulary) is contract
/// drift and fails loudly here, before anything may be cached or
/// served (the Codex PR#4 finding; the module's own "drift fails
/// loudly, never approximates" rule).
fn validate_value_domains(doc: &CatalogDocument) -> Result<(), CatalogError> {
    for (index, server) in doc.logical_servers.iter().enumerate() {
        if let Some(status) = server.status
            && status != 0
            && status != 1
        {
            return Err(CatalogError::Malformed(format!(
                "LogicalServers[{index}].Status = {status} is outside the recorded domain \
                 (0 offline, 1 online; absent is unknown — never approximated)"
            )));
        }
        if !(0..=3).contains(&server.tier) {
            return Err(CatalogError::Malformed(format!(
                "LogicalServers[{index}].Tier = {} is outside the recorded plan vocabulary \
                 (0 free, 1 basic, 2 plus, 3 PM)",
                server.tier
            )));
        }
        if let Some(load) = server.load
            && !(0..=100).contains(&load)
        {
            return Err(CatalogError::Malformed(format!(
                "LogicalServers[{index}].Load = {load} is outside the recorded 0–100 \
                 percentage domain"
            )));
        }
        for (physical_index, physical) in server.servers.iter().enumerate() {
            if physical.status != 0 && physical.status != 1 {
                return Err(CatalogError::Malformed(format!(
                    "LogicalServers[{index}].Servers[{physical_index}].Status = {} is outside \
                     the recorded domain (0 offline/maintenance, 1 online)",
                    physical.status
                )));
            }
        }
    }
    Ok(())
}

/// `ResponseMetadata` on the logicals envelope.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseMetadata {
    /// Whether the server list was truncated for this client.
    #[serde(rename = "ListIsTruncated")]
    pub list_is_truncated: bool,
}

/// The API error-detail bag (`Details`), mapped strictly so even the
/// error path cannot smuggle unknown fields past the drift guard. On a
/// successful fetch this is empty and unused.
#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiErrorDetails {
    /// Machine-suggested actions.
    #[serde(rename = "Actions")]
    pub actions: Option<Vec<ApiErrorAction>>,
    /// Human-readable error description.
    #[serde(rename = "Description")]
    pub description: Option<String>,
    /// Error title.
    #[serde(rename = "Title")]
    pub title: Option<String>,
    /// Error body text.
    #[serde(rename = "Body")]
    pub body: Option<String>,
    /// Error hint (markdown).
    #[serde(rename = "HintWithMarkdown")]
    pub hint_with_markdown: Option<String>,
    /// Human-verification method names (blocked-upstream territory).
    #[serde(rename = "HumanVerificationMethods")]
    pub human_verification_methods: Option<Vec<String>>,
    /// Human-verification token (blocked-upstream territory; never
    /// persisted or logged).
    #[serde(rename = "HumanVerificationToken")]
    pub human_verification_token: Option<String>,
}

/// One entry of [`ApiErrorDetails::actions`].
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiErrorAction {
    /// Action code.
    #[serde(rename = "Code")]
    pub code: Option<String>,
    /// Action name.
    #[serde(rename = "Name")]
    pub name: Option<String>,
    /// Action category.
    #[serde(rename = "Category")]
    pub category: Option<String>,
    /// Action URL.
    #[serde(rename = "URL")]
    pub url: Option<String>,
}

/// One logical server: the unit users pick (FR-9). Abstracts one or more
/// [`PhysicalServer`]s.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalServer {
    /// The logical server ID.
    #[serde(rename = "ID")]
    pub id: String,
    /// Display name (`CH#10`, `CH-SE#1`, `acme-corp#1`).
    #[serde(rename = "Name")]
    pub name: String,
    /// City where the exit is exposed; null on gateway/free entries.
    #[serde(rename = "City")]
    pub city: Option<String>,
    /// State or region where exposed; null outside a few countries.
    #[serde(rename = "State")]
    pub state: Option<String>,
    /// Entry country code (Secure Core entry, else equals exit).
    #[serde(rename = "EntryCountry")]
    pub entry_country: String,
    /// Exit country code.
    #[serde(rename = "ExitCountry")]
    pub exit_country: String,
    /// The logical's domain (dropped by the android model, still mapped
    /// by win-app and python; absence stays absence).
    #[serde(rename = "Domain")]
    pub domain: Option<String>,
    /// Minimum tier that may connect (0 free, 1 basic, 2 plus, 3 PM).
    #[serde(rename = "Tier")]
    pub tier: i8,
    /// Feature bitmask; see [`ServerFeatures`].
    #[serde(rename = "Features")]
    pub features: ServerFeatures,
    /// Online status (1 online, 0 offline). Absent means unknown —
    /// never fabricated to online (FR-13B).
    #[serde(rename = "Status")]
    pub status: Option<i8>,
    /// Load percentage 0–100 (fresher values arrive via `/vpn/loads`).
    #[serde(rename = "Load")]
    pub load: Option<i8>,
    /// Proton-computed selection score (lower is better).
    #[serde(rename = "Score")]
    pub score: Option<f32>,
    /// Country the physical hardware actually sits in when it differs
    /// from [`Self::exit_country`] (smart routing); `None` otherwise.
    #[serde(rename = "HostCountry")]
    pub host_country: Option<String>,
    /// Gateway (dedicated-server) identity this logical belongs to;
    /// `None` for the public fleet. Authorization is S8 entitlement
    /// data, never fabricated here.
    #[serde(rename = "GatewayName")]
    pub gateway_name: Option<String>,
    /// Localized city/state names keyed by language code; values may be
    /// null (no translation).
    #[serde(rename = "Translations")]
    pub translations: Option<std::collections::BTreeMap<String, Option<String>>>,
    /// Proton's status/scoring reference.
    #[serde(rename = "StatusReference")]
    pub status_reference: Option<StatusReference>,
    /// Physical entry coordinates.
    #[serde(rename = "EntryLocation")]
    pub entry_location: Option<ServerLocation>,
    /// Physical exit coordinates.
    #[serde(rename = "ExitLocation")]
    pub exit_location: Option<ServerLocation>,
    /// Legacy combined coordinates (python-stable shape; `Long` not
    /// `Longitude`).
    #[serde(rename = "Location")]
    pub location: Option<LegacyLocation>,
    /// The physical servers implementing this logical.
    #[serde(rename = "Servers")]
    pub servers: Vec<PhysicalServer>,
}

impl LogicalServer {
    /// Online status as a tri-state: `None` is *unknown* (field absent),
    /// never a fabricated verdict (FR-13B).
    pub fn is_online(&self) -> Option<bool> {
        self.status.map(|s| s == 1)
    }

    /// Secure Core route: the entry and exit countries differ (the
    /// hop-through that defines Secure Core).
    pub fn is_secure_core_route(&self) -> bool {
        self.entry_country != self.exit_country
    }

    /// This logical belongs to a named gateway (dedicated-server fleet).
    pub fn is_gateway(&self) -> bool {
        self.gateway_name.is_some()
    }
}

/// Feature bitmask on a logical server. Bits per the official clients
/// (android-app `LogicalServer.kt`): 1 Secure Core, 2 Tor, 4 P2P,
/// 8 Streaming, 16 IPv6, 32 Restricted (64 was the deprecated partner
/// bit). Unknown bits are preserved, not dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(transparent)]
pub struct ServerFeatures(pub u64);

impl ServerFeatures {
    /// Secure Core support.
    pub const SECURE_CORE: u64 = 1 << 0;
    /// Tor support.
    pub const TOR: u64 = 1 << 1;
    /// P2P support.
    pub const P2P: u64 = 1 << 2;
    /// Streaming support (where exposed).
    pub const STREAMING: u64 = 1 << 3;
    /// IPv6 support.
    pub const IPV6: u64 = 1 << 4;
    /// Restricted server.
    pub const RESTRICTED: u64 = 1 << 5;

    /// Whether the given bit is set.
    fn has(self, bit: u64) -> bool {
        self.0 & bit != 0
    }

    /// Secure Core support.
    pub fn secure_core(self) -> bool {
        self.has(Self::SECURE_CORE)
    }
    /// Tor support.
    pub fn tor(self) -> bool {
        self.has(Self::TOR)
    }
    /// P2P support.
    pub fn p2p(self) -> bool {
        self.has(Self::P2P)
    }
    /// Streaming support (where exposed).
    pub fn streaming(self) -> bool {
        self.has(Self::STREAMING)
    }
    /// IPv6 support.
    pub fn ipv6(self) -> bool {
        self.has(Self::IPV6)
    }
    /// Restricted server.
    pub fn restricted(self) -> bool {
        self.has(Self::RESTRICTED)
    }
}

/// Proton's status reference on a logical server.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusReference {
    /// Status index.
    #[serde(rename = "Index")]
    pub index: u64,
    /// Cost weight.
    #[serde(rename = "Cost")]
    pub cost: u64,
    /// Penalty weight.
    #[serde(rename = "Penalty")]
    pub penalty: f64,
}

/// Entry/exit coordinates (current clients' shape).
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerLocation {
    /// Latitude.
    #[serde(rename = "Latitude")]
    pub latitude: f32,
    /// Longitude.
    #[serde(rename = "Longitude")]
    pub longitude: f32,
}

/// Legacy combined coordinates (python-stable shape).
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyLocation {
    /// Latitude.
    #[serde(rename = "Lat")]
    pub lat: f32,
    /// Longitude (`Long`, not `Longitude`).
    #[serde(rename = "Long")]
    pub long: f32,
}

/// One physical server: the network identity a connection lands on.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalServer {
    /// The physical server ID; null only in android's migration window.
    #[serde(rename = "ID")]
    pub id: Option<String>,
    /// Legacy single entry IP; null when only per-protocol entries exist.
    #[serde(rename = "EntryIP")]
    pub entry_ip: Option<String>,
    /// Exit IP where it differs from the entry IP; null when equal or
    /// unknown. Absence is never approximated to the entry IP.
    #[serde(rename = "ExitIP")]
    pub exit_ip: Option<String>,
    /// The physical server's domain (TLS identity).
    #[serde(rename = "Domain")]
    pub domain: String,
    /// Online status (1 online, 0 offline/maintenance).
    #[serde(rename = "Status")]
    pub status: i8,
    /// Server label (`""` for the base host, `"1"`, `"2"`, ... for
    /// additional IPs).
    #[serde(rename = "Label")]
    pub label: Option<String>,
    /// WireGuard X25519 public key (base64); null on non-WireGuard
    /// physicals.
    #[serde(rename = "X25519PublicKey")]
    pub x25519_public_key: Option<String>,
    /// Proton's server signature (proves the catalog entry's
    /// authenticity to the connection layer).
    #[serde(rename = "Signature")]
    pub signature: Option<String>,
    /// Server hardware generation.
    #[serde(rename = "Generation")]
    pub generation: Option<String>,
    /// Why services are down, when they are.
    #[serde(rename = "ServicesDownReason")]
    pub services_down_reason: Option<String>,
    /// Per-protocol entry addresses; `None` on legacy entries that only
    /// carry [`Self::entry_ip`].
    #[serde(rename = "EntryPerProtocol")]
    pub entry_per_protocol: Option<EntryPerProtocol>,
}

impl PhysicalServer {
    /// Whether this physical is online. The status field is required on
    /// the wire, so this is a plain bool (a missing field already failed
    /// loudly at parse time).
    pub fn is_online(&self) -> bool {
        self.status == 1
    }
}

/// Per-protocol entry addresses (android `EntryPerProtocol`). Absent
/// protocols are `None`; the presence map IS the server's supported
/// protocol set (FR-9 "Supported protocols").
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryPerProtocol {
    /// WireGuard over UDP.
    #[serde(rename = "WireGuardUDP")]
    pub wireguard_udp: Option<ProtocolEndpoint>,
    /// WireGuard over TCP.
    #[serde(rename = "WireGuardTCP")]
    pub wireguard_tcp: Option<ProtocolEndpoint>,
    /// WireGuard over TLS.
    #[serde(rename = "WireGuardTLS")]
    pub wireguard_tls: Option<ProtocolEndpoint>,
    /// OpenVPN over UDP.
    #[serde(rename = "OpenVPNUDP")]
    pub openvpn_udp: Option<ProtocolEndpoint>,
    /// OpenVPN over TCP.
    #[serde(rename = "OpenVPNTCP")]
    pub openvpn_tcp: Option<ProtocolEndpoint>,
}

/// One protocol endpoint: an IPv4 address plus the ports it serves.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolEndpoint {
    /// The entry IPv4 address.
    #[serde(rename = "IPv4")]
    pub ipv4: String,
    /// Ports served; `None` when the API omits them.
    #[serde(rename = "Ports")]
    pub ports: Option<Vec<u16>>,
}

/// The persisted cache document: the raw upstream body plus its
/// revision. The body is stored verbatim so a not-modified refresh never
/// rewrites catalog data (FR-13E) and a model bump re-validates old
/// caches loudly on load.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CachedCatalog {
    /// Cache schema version.
    pub schema_version: u32,
    /// The response `ETag`, preserved for the next conditional request
    /// (FR-13B). `None` when the API sent none.
    pub etag: Option<String>,
    /// When this revision was fetched (Unix seconds). Freshness-only;
    /// scheduling floors are S7's, persisted separately.
    pub fetched_unix: u64,
    /// The raw upstream catalog body, byte-for-byte.
    pub body: String,
}

/// Failures of the catalog cache.
#[derive(Debug, thiserror::Error)]
pub enum CatalogCacheError {
    /// Reading or writing failed.
    #[error("catalog cache I/O failure: {0}")]
    Io(#[from] std::io::Error),
    /// The fs_trust walk rejected a path component.
    #[error("catalog cache path is not trusted: {0}")]
    FsTrust(#[from] fs_trust::FsTrustError),
    /// The cached document exceeds a cap.
    #[error("catalog cache of {0} bytes exceeds the {MAX_CATALOG_BYTES}-byte limit")]
    TooLarge(usize),
    /// The cached document is structurally invalid, has the wrong
    /// schema version, or its body no longer parses against the live
    /// catalog model (upstream drift fails loudly, not approximately).
    #[error("invalid catalog cache: {0}")]
    Malformed(String),
}

/// Distinct temp-file counter (the [`crate::state`] atomic-write
/// precedent: concurrent writers get distinct siblings).
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Atomic store for the server catalog under `/var/cache/protonwire`
/// (typically `servers.json` inside
/// [`crate::paths::ConfigPaths::cache_dir`]).
#[derive(Debug, Clone)]
pub struct CatalogCache {
    path: PathBuf,
}

impl CatalogCache {
    /// Opens the cache at `path` (created on first [`Self::store`]).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The cache file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Strictly loads the cache: the fs_trust walk (leaf to `trust_root`,
    /// missing leaf allowed) runs before any read, then the document and
    /// its body are validated against the live model. A missing cache is
    /// `Ok(None)`. This is the production loader — the daemon runs as
    /// root over a root-owned `/var/cache/protonwire` tree.
    pub fn load_strict(
        &self,
        trust_root: &Path,
    ) -> Result<Option<CachedCatalog>, CatalogCacheError> {
        fs_trust::verify_trusted_path(&self.path, trust_root, MissingLeaf::Allow)?;
        self.load_validated()
    }

    /// The read+validate body of the load, after a caller has established
    /// path trust. Private: outside callers get [`Self::load_strict`].
    fn load_validated(&self) -> Result<Option<CachedCatalog>, CatalogCacheError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if bytes.len() > MAX_CATALOG_BYTES {
            return Err(CatalogCacheError::TooLarge(bytes.len()));
        }
        let cached: CachedCatalog = serde_json::from_slice(&bytes)
            .map_err(|e| CatalogCacheError::Malformed(e.to_string()))?;
        if cached.schema_version != CATALOG_CACHE_SCHEMA_VERSION {
            return Err(CatalogCacheError::Malformed(format!(
                "cache schema version {} != {CATALOG_CACHE_SCHEMA_VERSION}",
                cached.schema_version
            )));
        }
        // The cached body must still parse against the live model: a
        // drifted upstream (or a hand-edited cache) fails loudly here.
        CatalogDocument::from_bytes(cached.body.as_bytes())
            .map_err(|e| CatalogCacheError::Malformed(e.to_string()))?;
        Ok(Some(cached))
    }

    /// Atomically stores `doc`: sibling temp file (mode 0644), fsync,
    /// rename — the [`crate::state`] precedent. The size cap is enforced
    /// on the body before any I/O AND on the serialized envelope after
    /// serialization (the [`crate::state`] post-serialization precedent):
    /// pretty-printing adds escaping and layout, so a quote-dense body
    /// just under the cap can serialize past it — and a file the loader
    /// would reject must never be written.
    pub fn store(&self, doc: &CachedCatalog) -> Result<(), CatalogCacheError> {
        if doc.body.len() > MAX_CATALOG_BYTES {
            return Err(CatalogCacheError::TooLarge(doc.body.len()));
        }
        let bytes = serde_json::to_vec_pretty(doc)
            .map_err(|e| CatalogCacheError::Malformed(e.to_string()))?;
        if bytes.len() > MAX_CATALOG_BYTES {
            return Err(CatalogCacheError::TooLarge(bytes.len()));
        }
        let parent = self.path.parent().unwrap_or(Path::new(".")).to_path_buf();
        create_cache_dir(&parent)?;
        let tmp = parent.join(format!(
            ".{}.tmp-{}-{}",
            self.path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("catalog"),
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o644)
                .open(&tmp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// FR-13E: a not-modified response updates freshness without
    /// rewriting catalog data. The caller supplies the currently cached
    /// document (as strictly loaded); the stored body bytes are carried
    /// through verbatim and only `fetched_unix` changes. Returns the
    /// updated document.
    pub fn refresh_freshness(
        &self,
        current: &CachedCatalog,
        fetched_unix: u64,
    ) -> Result<CachedCatalog, CatalogCacheError> {
        let mut updated = current.clone();
        updated.fetched_unix = fetched_unix;
        self.store(&updated)?;
        Ok(updated)
    }
}

/// Creates the cache directory and any missing parents with mode 0755 —
/// no group/world write bits regardless of umask. Directories that
/// already exist are NEVER touched (the daemon must not chmod its way
/// across `/var` or `/var/cache`): a bad pre-existing mode is the strict
/// loader's walk to reject, not this function's to fix.
fn create_cache_dir(path: &Path) -> Result<(), CatalogCacheError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o755);
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    /// The recorded `/vpn/logicals` fixture: the upstream contract this
    /// module deserializes. See the module documentation for provenance.
    const FIXTURE: &str = include_str!("catalog_fixture.json");

    fn find<'a>(catalog: &'a CatalogDocument, name: &str) -> &'a LogicalServer {
        catalog
            .logical_servers
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("fixture must contain {name}"))
    }

    // --- FR-9 coverage against the recorded fixture -------------------------

    #[test]
    fn recorded_fixture_parses_and_covers_fr9() {
        let catalog = CatalogDocument::from_bytes(FIXTURE.as_bytes()).unwrap();
        assert_eq!(catalog.code, 1000);
        assert_eq!(
            catalog.status_id, "logicals-status-token-1a2b3c",
            "the status token (conditional-refresh revision) must be preserved"
        );
        assert_eq!(catalog.logical_servers.len(), 8);

        // Logical/physical mapping, identity, and geography.
        let ch10 = find(&catalog, "CH#10");
        assert_eq!(
            ch10.id,
            "kR0gYQ1tZcSwV2iNq3LpXfUeD8oHb6AyJm5Cn7TvWhEfRdGsHuIkLjMzNqPxCvB1"
        );
        assert_eq!(ch10.entry_country, "CH");
        assert_eq!(ch10.exit_country, "CH");
        assert_eq!(ch10.city.as_deref(), Some("Zurich"));
        assert_eq!(ch10.state, None);
        assert_eq!(ch10.tier, 2);
        assert_eq!(ch10.load, Some(42));
        assert_eq!(ch10.score, Some(1.4211));
        assert_eq!(ch10.servers.len(), 2);

        // Exit IPs, entry IPs, WireGuard key, protocols, physical status.
        let physical = &ch10.servers[0];
        assert_eq!(physical.entry_ip.as_deref(), Some("185.242.4.10"));
        assert_eq!(physical.exit_ip.as_deref(), Some("185.242.4.10"));
        assert_eq!(physical.domain, "ch-10a.protonvpn.com");
        assert_eq!(physical.label.as_deref(), Some(""));
        assert_eq!(
            physical.x25519_public_key.as_deref(),
            Some("nKx0PQp6lRj8tGeW3FzsXvCuMoAyHbJdSfEgTkLqZi0=")
        );
        assert!(physical.is_online());
        let per_protocol = physical.entry_per_protocol.as_ref().unwrap();
        let wg = per_protocol.wireguard_udp.as_ref().unwrap();
        assert_eq!(wg.ipv4, "185.242.4.10");
        assert_eq!(wg.ports.as_deref(), Some(&[443u16, 1194][..]));
        assert!(per_protocol.wireguard_tls.is_none());
        assert_eq!(
            per_protocol.openvpn_udp.as_ref().unwrap().ipv4,
            "185.242.4.10"
        );

        // A protocol-only physical: no legacy EntryIP, full per-protocol map.
        assert_eq!(ch10.servers[1].entry_ip, None);
        assert!(
            ch10.servers[1]
                .entry_per_protocol
                .as_ref()
                .unwrap()
                .wireguard_tls
                .is_some()
        );

        // State/region where exposed.
        let usca = find(&catalog, "US-CA#1");
        assert_eq!(usca.state.as_deref(), Some("California"));

        // Secure Core route metadata.
        let sc = find(&catalog, "CH-SE#1");
        assert!(sc.features.secure_core());
        assert_eq!(sc.entry_country, "CH");
        assert_eq!(sc.exit_country, "SE");
        assert!(sc.is_secure_core_route());
        assert!(!ch10.is_secure_core_route());

        // Feature bits: Tor, streaming, IPv6, P2P.
        assert!(find(&catalog, "CH#10-T").features.tor());
        let us20 = find(&catalog, "US#20");
        assert!(us20.features.streaming());
        assert!(us20.features.ipv6());
        assert!(ch10.features.p2p());
        assert!(!ch10.features.tor());
        // Smart routing: emulated exit exposed via HostCountry.
        assert_eq!(us20.host_country.as_deref(), Some("IS"));

        // Gateway/dedicated identity (authorization itself is S8
        // entitlement data and must never be fabricated here).
        let gw = find(&catalog, "acme-corp#1");
        assert_eq!(gw.gateway_name.as_deref(), Some("acme-corp"));
        assert!(gw.is_gateway());
        assert!(!ch10.is_gateway());
        assert_eq!(ch10.gateway_name, None);

        // Free tier and a nullable City.
        let free = find(&catalog, "NL-FREE#1");
        assert_eq!(free.tier, 0);
        assert!(free.features.0 == 0);

        // Online/offline status: the offline server stays offline and the
        // reason is preserved (FR-13B never makes an offline server usable).
        let offline = find(&catalog, "SE#9");
        assert_eq!(offline.status, Some(0));
        assert_eq!(offline.is_online(), Some(false));
        assert!(!offline.servers[0].is_online());
        assert_eq!(
            offline.servers[0].services_down_reason.as_deref(),
            Some("Scheduled maintenance window")
        );
        assert_eq!(ch10.is_online(), Some(true));
    }

    /// A one-logical catalog for the value-domain fixtures. `logical`
    /// splices the logical's domain-carrying fields (the default carries
    /// only the in-domain `,"Tier":0`), `physical` is the complete
    /// physical object contents (default in-domain). Every override
    /// REPLACES a field — no duplicate keys, so a failure can only come
    /// from the arm under test.
    fn domain_catalog(logical: &str, physical: &str) -> String {
        let mut doc = String::from(
            r#"{"Code":1000,"StatusID":"t","LogicalServers":[{"ID":"x","Name":"X#1","EntryCountry":"XX","ExitCountry":"XX","Features":0"#,
        );
        doc.push_str(logical);
        doc.push_str(r#","Servers":[{"#);
        doc.push_str(physical);
        doc.push_str(r#"}]}]}"#);
        doc
    }

    const IN_DOMAIN_LOGICAL: &str = r#","Tier":0"#;
    const IN_DOMAIN_PHYSICAL: &str = r#""Domain":"x.example","Status":1"#;

    // --- Value domains: drift fails loudly, never silently
    // misclassifies (the Codex PR#4 finding; the module's own doctrine
    // applied to VALUES, not just field names) ------------------------

    #[test]
    fn an_out_of_domain_logical_status_fails_loudly_not_offline() {
        // Status 2 (or any value beyond the recorded 0/1) is contract
        // drift: mapping it to `is_online() == Some(false)` would
        // silently reclassify a server the model cannot represent.
        let err = CatalogDocument::from_bytes(
            domain_catalog(r#","Tier":0,"Status":2"#, IN_DOMAIN_PHYSICAL).as_bytes(),
        )
        .unwrap_err();
        let CatalogError::Malformed(detail) = &err else {
            panic!("an out-of-domain logical Status must be Malformed drift, got: {err}");
        };
        assert!(
            detail.contains("Status"),
            "the failure must name the field: {detail}"
        );
        // The control arms: both in-domain statuses parse.
        for status in [0, 1] {
            let body = domain_catalog(
                &format!(r#","Tier":0,"Status":{status}"#),
                IN_DOMAIN_PHYSICAL,
            );
            CatalogDocument::from_bytes(body.as_bytes())
                .unwrap_or_else(|e| panic!("in-domain Status {status} must parse: {e}"));
        }
    }

    #[test]
    fn an_out_of_domain_physical_status_fails_loudly() {
        let err = CatalogDocument::from_bytes(
            domain_catalog(IN_DOMAIN_LOGICAL, r#""Domain":"x.example","Status":2"#).as_bytes(),
        )
        .unwrap_err();
        let CatalogError::Malformed(detail) = &err else {
            panic!("an out-of-domain physical Status must be Malformed drift, got: {err}");
        };
        assert!(
            detail.contains("Status"),
            "the failure must name the field: {detail}"
        );
    }

    #[test]
    fn an_out_of_domain_load_fails_loudly() {
        // Load is a percentage; -1 and 101 are equally outside it.
        for load in [-1, 101] {
            let err = CatalogDocument::from_bytes(
                domain_catalog(&format!(r#","Tier":0,"Load":{load}"#), IN_DOMAIN_PHYSICAL)
                    .as_bytes(),
            )
            .unwrap_err();
            let CatalogError::Malformed(detail) = &err else {
                panic!("Load {load} must be Malformed drift, got: {err}");
            };
            assert!(
                detail.contains("Load"),
                "the failure must name the field: {detail}"
            );
        }
        // Boundary controls: 0 and 100 are in-domain.
        for load in [0, 100] {
            let body = domain_catalog(&format!(r#","Tier":0,"Load":{load}"#), IN_DOMAIN_PHYSICAL);
            CatalogDocument::from_bytes(body.as_bytes())
                .unwrap_or_else(|e| panic!("boundary Load {load} must parse: {e}"));
        }
    }

    #[test]
    fn an_out_of_domain_tier_fails_loudly() {
        // The recorded vocabulary is 0 free, 1 basic, 2 plus, 3 PM.
        for tier in [-1, 4] {
            let err = CatalogDocument::from_bytes(
                domain_catalog(&format!(r#","Tier":{tier}"#), IN_DOMAIN_PHYSICAL).as_bytes(),
            )
            .unwrap_err();
            let CatalogError::Malformed(detail) = &err else {
                panic!("Tier {tier} must be Malformed drift, got: {err}");
            };
            assert!(
                detail.contains("Tier"),
                "the failure must name the field: {detail}"
            );
        }
    }

    #[test]
    fn absent_fields_are_absent_never_fabricated() {
        // A minimal document: only fields every official client requires.
        // Every optional field must stay `None` — no defaults, no
        // fabrication (FR-13B).
        let minimal = concat!(
            r#"{"Code":1000,"StatusID":"t","LogicalServers":[{"ID":"x","#,
            r#""Name":"X#1","EntryCountry":"XX","ExitCountry":"XX","#,
            r#""Tier":0,"Features":0,"Servers":[{"Domain":"x.example","Status":1}]}]}"#
        );
        let catalog = CatalogDocument::from_bytes(minimal.as_bytes()).unwrap();
        let server = &catalog.logical_servers[0];
        assert_eq!(server.city, None);
        assert_eq!(server.state, None);
        assert_eq!(server.domain, None);
        assert_eq!(server.status, None);
        assert_eq!(server.is_online(), None, "unknown status is unknown");
        assert_eq!(server.load, None);
        assert_eq!(server.score, None);
        assert_eq!(server.host_country, None);
        assert_eq!(server.gateway_name, None);
        assert_eq!(server.status_reference, None);
        assert_eq!(server.entry_location, None);
        assert_eq!(server.exit_location, None);
        assert_eq!(server.location, None);
        let physical = &server.servers[0];
        assert_eq!(physical.id, None);
        assert_eq!(physical.entry_ip, None);
        assert_eq!(physical.exit_ip, None);
        assert_eq!(physical.label, None);
        assert_eq!(physical.x25519_public_key, None);
        assert_eq!(physical.entry_per_protocol, None);
    }

    #[test]
    fn upstream_field_drift_fails_loudly() {
        // An upstream field this model does not map is a hard error naming
        // the field — never silently dropped.
        let drifted = FIXTURE.replace("\"Code\": 1000", "\"Code\": 1000, \"FutureField\": 1");
        let err = CatalogDocument::from_bytes(drifted.as_bytes()).unwrap_err();
        assert!(
            err.to_string().contains("FutureField"),
            "drift error must name the field: {err}"
        );

        // Same discipline inside a server entry.
        let drifted = FIXTURE.replace(
            "\"Name\": \"CH#10\"",
            "\"Name\": \"CH#10\", \"NewServerField\": true",
        );
        let err = CatalogDocument::from_bytes(drifted.as_bytes()).unwrap_err();
        assert!(
            err.to_string().contains("NewServerField"),
            "drift error must name the field: {err}"
        );
    }

    #[test]
    fn drift_guard_reaches_the_deepest_wire_struct() {
        // `deny_unknown_fields` is per-struct, so it is pinned at the
        // deepest nesting level the contract has: envelope → logical →
        // physical → per-protocol map → ProtocolEndpoint. Removing the
        // guard from any struct on that path's leaf previously survived
        // the suite (qa P2-2: only envelope and logical were pinned);
        // this injection closes that class by proving the discipline
        // holds at full depth. Structural surgery via serde_json::Value,
        // immune to fixture formatting (the round-6 anchor-drift note).
        let mut value: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
        let endpoint =
            &mut value["LogicalServers"][0]["Servers"][0]["EntryPerProtocol"]["WireGuardUDP"];
        assert_eq!(
            endpoint.get("IPv4"),
            Some(&serde_json::json!("185.242.4.10")),
            "fixture anchor drifted: the CH#10 WireGuardUDP endpoint moved"
        );
        endpoint["QuantumPorts"] = serde_json::json!([1]);
        let err = CatalogDocument::from_bytes(value.to_string().as_bytes()).unwrap_err();
        assert!(
            err.to_string().contains("QuantumPorts"),
            "drift at the deepest wire struct must fail loudly: {err}"
        );
    }

    #[test]
    fn malformed_documents_fail_loudly() {
        // Truncated JSON.
        let truncated = &FIXTURE[..FIXTURE.len() / 2];
        assert!(CatalogDocument::from_bytes(truncated.as_bytes()).is_err());
        // Structural surgery via serde_json::Value, immune to fixture
        // formatting: wrong field type, missing required field, and an
        // API-level refusal. (serde names the field for unknown and
        // missing fields; for a wrong type it reports type and position
        // only, so that arm asserts the hard failure itself.)
        let mut value: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
        value["LogicalServers"][0]["Tier"] = serde_json::json!("plus");
        let err = CatalogDocument::from_bytes(value.to_string().as_bytes()).unwrap_err();
        assert!(
            matches!(err, CatalogError::Malformed(_)) && err.to_string().contains("i8"),
            "wrong type must fail loudly: {err}"
        );

        value["LogicalServers"][0]["Tier"] = serde_json::json!(2);
        value["LogicalServers"][0]
            .as_object_mut()
            .unwrap()
            .remove("ExitCountry");
        let err = CatalogDocument::from_bytes(value.to_string().as_bytes()).unwrap_err();
        assert!(err.to_string().contains("ExitCountry"), "{err}");

        value["LogicalServers"][0]["ExitCountry"] = serde_json::json!("CH");
        value["Code"] = serde_json::json!(5003);
        value["Error"] = serde_json::json!("This version of the app is no longer supported");
        let err = CatalogDocument::from_bytes(value.to_string().as_bytes()).unwrap_err();
        assert!(
            matches!(err, CatalogError::Api { code: 5003, .. })
                && err.to_string().contains("no longer supported"),
            "{err}"
        );
    }

    #[test]
    fn document_caps_are_enforced() {
        // Oversized document.
        let padded = format!(
            "{{\"Code\":1000,\"Pad\":\"{}\"}}",
            "x".repeat(MAX_CATALOG_BYTES)
        );
        let err = CatalogDocument::from_bytes(padded.as_bytes()).unwrap_err();
        assert!(matches!(err, CatalogError::TooLarge(_)), "{err}");

        // Logical-server count cap: every entry is individually valid, so
        // the count cap is what fires.
        let one = r#"{"ID":"x","Name":"X","EntryCountry":"XX","ExitCountry":"XX","Tier":0,"Features":0,"Servers":[]}"#;
        let mut huge = String::from(r#"{"Code":1000,"StatusID":"t","LogicalServers":["#);
        for i in 0..=MAX_LOGICAL_SERVERS {
            if i > 0 {
                huge.push(',');
            }
            huge.push_str(one);
        }
        huge.push_str("]}");
        let err = CatalogDocument::from_bytes(huge.as_bytes()).unwrap_err();
        assert!(matches!(err, CatalogError::TooManyServers { .. }), "{err}");
    }

    /// Builds a valid document of `logicals` logical servers, each with
    /// `physicals_each` minimal physical servers (`{"Domain","Status"}`
    /// only — every field every client requires, nothing more).
    fn catalog_with(logicals: usize, physicals_each: usize) -> String {
        let mut doc = String::with_capacity(logicals * (physicals_each * 26 + 128) + 64);
        doc.push_str(r#"{"Code":1000,"StatusID":"t","LogicalServers":["#);
        for l in 0..logicals {
            if l > 0 {
                doc.push(',');
            }
            doc.push_str(&format!(
                r#"{{"ID":"l{l}","Name":"L{l}","EntryCountry":"XX","ExitCountry":"XX","#,
            ));
            doc.push_str(r#""Tier":0,"Features":0,"Servers":["#);
            for p in 0..physicals_each {
                if p > 0 {
                    doc.push(',');
                }
                doc.push_str(r#"{"Domain":"p","Status":1}"#);
            }
            doc.push_str("]}");
        }
        doc.push_str("]}");
        doc
    }

    #[test]
    fn aggregate_physical_cap_spans_logicals() {
        // The TOTAL-physical cap aggregates across logical boundaries:
        // two logicals, each unremarkable on its own, whose combined
        // physicals exceed MAX_PHYSICAL_SERVERS_TOTAL are rejected. The
        // document (~6.3 MiB) is well under the byte cap and its logical
        // count (2) far under MAX_LOGICAL_SERVERS, so the aggregate
        // physical arm is the only check that can fire.
        let each = MAX_PHYSICAL_SERVERS_TOTAL / 2 + 1;
        let doc = catalog_with(2, each);
        assert!(
            doc.len() < MAX_CATALOG_BYTES,
            "fixture must stay under the byte cap: {}",
            doc.len()
        );
        let err = CatalogDocument::from_bytes(doc.as_bytes()).unwrap_err();
        let CatalogError::TooManyServers { logical, physical } = &err else {
            panic!("the aggregate physical cap must fire, got: {err}");
        };
        assert_eq!(*logical, 2);
        assert_eq!(
            *physical,
            2 * each,
            "the SUM across logicals is what counts"
        );
    }

    #[test]
    fn at_cap_document_bytes_parse() {
        // `>` semantics, not `>=`: a document of EXACTLY
        // MAX_CATALOG_BYTES bytes parses; one byte more is TooLarge.
        // The pad character adds exactly one byte per occurrence (ASCII,
        // never escaped), so the padding is exact by construction.
        let base = padded_catalog(0).len();
        let doc = padded_catalog(MAX_CATALOG_BYTES - base);
        assert_eq!(doc.len(), MAX_CATALOG_BYTES);
        let parsed = CatalogDocument::from_bytes(doc.as_bytes()).unwrap();
        assert_eq!(parsed.status_id.len(), MAX_CATALOG_BYTES - base);
        let err =
            CatalogDocument::from_bytes(padded_catalog(MAX_CATALOG_BYTES - base + 1).as_bytes())
                .unwrap_err();
        assert!(matches!(err, CatalogError::TooLarge(_)), "{err}");
    }

    #[test]
    fn at_cap_logical_count_parses() {
        // Exactly MAX_LOGICAL_SERVERS logical servers parse: `>`, not `>=`.
        let doc = catalog_with(MAX_LOGICAL_SERVERS, 0);
        let parsed = CatalogDocument::from_bytes(doc.as_bytes()).unwrap();
        assert_eq!(parsed.logical_servers.len(), MAX_LOGICAL_SERVERS);
    }

    #[test]
    fn at_cap_total_physicals_parse() {
        // Exactly MAX_PHYSICAL_SERVERS_TOTAL physicals across the
        // document parse: `>`, not `>=`.
        let doc = catalog_with(2, MAX_PHYSICAL_SERVERS_TOTAL / 2);
        let parsed = CatalogDocument::from_bytes(doc.as_bytes()).unwrap();
        let total: usize = parsed.logical_servers.iter().map(|s| s.servers.len()).sum();
        assert_eq!(total, MAX_PHYSICAL_SERVERS_TOTAL);
    }

    /// A minimal valid catalog whose `StatusID` carries `pad` padding
    /// characters — one byte each in the document AND in the serialized
    /// cache envelope (never escaped), making both sizes solvable.
    fn padded_catalog(pad: usize) -> String {
        format!(
            r#"{{"Code":1000,"StatusID":"{}","LogicalServers":[]}}"#,
            "x".repeat(pad)
        )
    }

    // --- The /var/cache/protonwire cache (FR-10, FR-13B, FR-13E) -----------

    fn cache_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn cached(etag: Option<&str>, body: &str) -> CachedCatalog {
        CachedCatalog {
            schema_version: CATALOG_CACHE_SCHEMA_VERSION,
            etag: etag.map(str::to_owned),
            fetched_unix: 1_771_000_000,
            body: body.to_owned(),
        }
    }

    #[test]
    fn cache_round_trips_the_recorded_catalog() {
        // Mechanics through the validated loader (the strict wrapper adds
        // the fs_trust walk, proven below; the full strict happy path is
        // root-runner territory, same compromise as the config module's
        // strict-load tests).
        let dir = cache_dir();
        let cache = CatalogCache::new(dir.path().join("servers.json"));
        cache.store(&cached(Some("\"rev-42\""), FIXTURE)).unwrap();

        let loaded = cache.load_validated().unwrap().expect("cached entry");
        assert_eq!(
            loaded.etag.as_deref(),
            Some("\"rev-42\""),
            "revision preserved (FR-13B)"
        );
        assert_eq!(loaded.fetched_unix, 1_771_000_000);
        assert_eq!(loaded.body, FIXTURE);
        // Validated load re-parses the cached body against the live model.
        CatalogDocument::from_bytes(loaded.body.as_bytes()).unwrap();

        // A missing cache is absent, not an error.
        let fresh = CatalogCache::new(dir.path().join("elsewhere.json"));
        assert!(fresh.load_validated().unwrap().is_none());
    }

    #[test]
    fn not_modified_updates_freshness_without_rewriting_catalog_data() {
        let dir = cache_dir();
        let cache = CatalogCache::new(dir.path().join("servers.json"));
        cache.store(&cached(Some("\"rev-42\""), FIXTURE)).unwrap();

        let current = cache.load_validated().unwrap().expect("cached entry");
        let updated = cache.refresh_freshness(&current, 1_771_018_000).unwrap();
        assert_eq!(updated.fetched_unix, 1_771_018_000);
        assert_eq!(updated.etag.as_deref(), Some("\"rev-42\""));
        assert_eq!(
            updated.body, FIXTURE,
            "FR-13E: a 304 refresh must not rewrite catalog data"
        );

        let reloaded = cache.load_validated().unwrap().unwrap();
        assert_eq!(reloaded.body, FIXTURE);
        assert_eq!(reloaded.fetched_unix, 1_771_018_000);
    }

    #[test]
    fn cache_store_is_atomic_and_leaves_no_residue() {
        let dir = cache_dir();
        let path = dir.path().join("nested/servers.json");
        let cache = CatalogCache::new(path.clone());
        cache.store(&cached(None, FIXTURE)).unwrap();
        cache.store(&cached(None, FIXTURE)).unwrap();
        let entries: Vec<std::ffi::OsString> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, [std::ffi::OsString::from("servers.json")]);
    }

    #[test]
    fn cache_rejects_oversized_and_malformed_bodies() {
        let dir = cache_dir();
        let cache = CatalogCache::new(dir.path().join("servers.json"));
        let oversized = cached(None, &"x".repeat(MAX_CATALOG_BYTES + 1));
        assert!(matches!(
            cache.store(&oversized).unwrap_err(),
            CatalogCacheError::TooLarge(_)
        ));
        // A syntactically valid cache document whose body is not a catalog
        // is a hard error on validated load.
        cache
            .store(&cached(None, "{\"Code\":1000,\"Not\":\"a catalog\"}"))
            .unwrap();
        assert!(matches!(
            cache.load_validated().unwrap_err(),
            CatalogCacheError::Malformed(_)
        ));
    }

    #[test]
    fn store_rejects_bodies_that_serialize_past_the_cap() {
        // Cap-semantics asymmetry: `store` capped only the raw body
        // pre-serialization while `load_validated` caps the serialized
        // envelope post-read — a quote-dense body just under the byte cap
        // pretty-prints past it (every `"` escapes to `\"`), so the store
        // succeeded and every later load failed TooLarge. The envelope
        // cap must hold at STORE time: a file the loader will reject must
        // never be written. (The body need not be valid JSON — `store`
        // never parses it; only size and serialization see it.)
        let quote_dense = "\"".repeat(MAX_CATALOG_BYTES - 1);
        assert!(quote_dense.len() < MAX_CATALOG_BYTES, "under the body cap");
        let dir = cache_dir();
        let cache = CatalogCache::new(dir.path().join("servers.json"));
        let err = cache.store(&cached(None, &quote_dense)).expect_err(
            "a body whose serialized envelope exceeds the cap must be refused at store time",
        );
        assert!(
            matches!(err, CatalogCacheError::TooLarge(n) if n > MAX_CATALOG_BYTES),
            "the serialized envelope size is what must be reported: {err}"
        );
        // Refused before any I/O: no file, no residue.
        assert!(cache.load_validated().unwrap().is_none());
    }

    #[test]
    fn at_cap_cache_envelope_stores_and_loads_back() {
        // `>` semantics end-to-end at the byte cap: a cache whose
        // SERIALIZED envelope is exactly MAX_CATALOG_BYTES bytes stores
        // and loads back (one byte more is the quote-dense/oversized
        // territory above). The pad character contributes exactly one
        // serialized byte per occurrence, so the envelope is solved to
        // the byte against the serializer itself.
        let base = cached(None, &padded_catalog(0));
        let base_len = serde_json::to_vec_pretty(&base).unwrap().len();
        let body = padded_catalog(MAX_CATALOG_BYTES - base_len);
        let doc = cached(None, &body);
        assert_eq!(
            serde_json::to_vec_pretty(&doc).unwrap().len(),
            MAX_CATALOG_BYTES
        );
        let dir = cache_dir();
        let cache = CatalogCache::new(dir.path().join("servers.json"));
        cache.store(&doc).unwrap();
        assert_eq!(
            std::fs::read(cache.path()).unwrap().len(),
            MAX_CATALOG_BYTES,
            "the written envelope must sit exactly at the cap"
        );
        let loaded = cache.load_validated().unwrap().expect("at-cap cache loads");
        assert_eq!(loaded.body, body);
    }

    /// The full strict loader (walk + validated load) happy path, run
    /// only where the runner can construct a root-owned tree — the same
    /// compromise as the config module's strict-load tests. Unprivileged
    /// runners still get the walk's pass-1 arms below.
    #[test]
    fn strict_load_walks_then_loads_for_root_runners() {
        use std::os::unix::fs::MetadataExt;

        let dir = cache_dir();
        let path = dir.path().join("servers.json");
        let cache = CatalogCache::new(path.clone());
        cache.store(&cached(Some("\"rev-42\""), FIXTURE)).unwrap();
        let root_owned = std::fs::metadata(&path)
            .map(|m| m.uid() == 0 && m.gid() == 0)
            .unwrap_or(false);
        if !root_owned {
            // NOTICE skip (CONTRIBUTING rule 5, the a368775 idiom): the
            // ownership pass of the fs_trust walk needs a root-owned
            // tree, which an unprivileged runner cannot construct. The
            // walk's mode arms are covered unprivileged below; visible
            // under `cargo test -- --nocapture`.
            eprintln!(
                "NOTICE: skipping strict_load_walks_then_loads_for_root_runners: the \
                 cache file is not root-owned on this runner — the ownership arm of \
                 the fs_trust walk is unprovable unprivileged"
            );
            return;
        }
        let loaded = cache
            .load_strict(dir.path())
            .unwrap()
            .expect("cached entry");
        assert_eq!(loaded.etag.as_deref(), Some("\"rev-42\""));
    }

    #[test]
    fn cache_strict_load_rejects_a_symlinked_leaf() {
        let dir = cache_dir();
        let real = dir.path().join("real.json");
        let link = dir.path().join("servers.json");
        CatalogCache::new(&real)
            .store(&cached(None, FIXTURE))
            .unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = CatalogCache::new(link.clone())
            .load_strict(dir.path())
            .unwrap_err();
        assert!(matches!(err, CatalogCacheError::FsTrust(_)), "{err}");
        // The walk never followed the link: the load failed without
        // reading through it.
    }

    #[test]
    fn cache_strict_load_rejects_a_writable_leaf() {
        // Mode arms of the walk are constructible unprivileged (pass 1
        // runs before the ownership pass — see fs_trust).
        let dir = cache_dir();
        let path = dir.path().join("servers.json");
        let cache = CatalogCache::new(path.clone());
        cache.store(&cached(None, FIXTURE)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let err = cache.load_strict(dir.path()).unwrap_err();
        assert!(matches!(err, CatalogCacheError::FsTrust(_)), "{err}");
    }

    #[test]
    fn cache_write_sets_no_group_or_world_bits() {
        let dir = cache_dir();
        let path = dir.path().join("servers.json");
        let cache = CatalogCache::new(path.clone());
        cache.store(&cached(None, FIXTURE)).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode & 0o022,
            0,
            "cache file must not be group/world writable, got {mode:o}"
        );
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            dir_mode & 0o022,
            0,
            "cache dir must not be group/world writable, got {dir_mode:o}"
        );
    }
}
