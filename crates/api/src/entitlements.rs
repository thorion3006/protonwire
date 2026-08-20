//! VPN entitlement model and free-plan change-server cooldown (FR-5,
//! FR-23G, M2 S8 / T-16 data layer).
//!
//! ## Endpoint ownership and transport
//!
//! Muon models no `/vpn` endpoints (spike memo Q8): the user model is
//! `core/v4/users` = `{id, name, email, keys}` with no plan or VPN
//! entitlement fields. The entitlements document is therefore a
//! ProtonWire-owned typed model sent through `Session::send_with_sdk` —
//! PRD 6.5's sanctioned path for endpoints Muon does not model (the
//! single required transport, no second Proton HTTP stack), exactly as
//! the S6 catalog lane does for `/vpn/logicals`.
//!
//! The endpoint is `GET /vpn/v2`. The adapter imposes no login-state
//! precondition of its own: it travels whatever session it was built
//! over, and the daemon composes authentication before entitlement
//! reads (S9's wiring).
//!
//! ## The wire contract and its provenance
//!
//! The contract below (names, types, nullability, presence) is recorded
//! field-for-field from the deserialization models of Proton's own
//! maintained clients at the revisions pinned in
//! `docs/official-parity.yaml` (`upstream.*`), the S6 provenance
//! convention (synthetic values, faithful shape):
//!
//! * android-app `cc1e29f8acd5f11f63701b48f97410e90fa6a71d`:
//!   `ProtonVPNRetrofit.kt` (`@GET("vpn/v2")`), `models/login/
//!   VpnInfoResponse.kt` (envelope: `Code`/`VPN`/`Subscribed`/
//!   `Services`/`Delinquent`/`Credit?`/`HasPaymentMethod?`) and
//!   `models/login/VPNInfo.kt` (VPN object: `Status`/
//!   `ExpirationTime`/`PlanName?`/`PlanTitle?`/`MaxTier?`/`MaxConnect`/
//!   `Name`/`GroupID?`/`IsBusiness`/`NetShield?` with `Malware`/
//!   `AdsAndTrackers`/`AdultContent`), plus `auth/data/VpnUser.kt`
//!   (tier constants: `FREE_TIER = 0`, `BASIC_TIER = 1`,
//!   `PLUS_TIER = 2`; `MaxTier` is nullable with an explicit
//!   `userTierUnknown` arm).
//! * win-app master `4d9ac60d1db5d3f2908498470a9d1646723afcfd`:
//!   `Api.Contracts/Auth/VpnInfoWrapperResponse.cs` (+ `BaseResponse`:
//!   `Code`/`Error`/`Details`), `VpnInfoResponse.cs` — whose pinned
//!   comment is the authority for status semantics ("0 = no vpn
//!   access, 1 = vpn access, 2 = vpn access requested (waitlist)") —
//!   and the recorded integration mock `Tests/TestData/
//!   VpnInfoWrapperResponseMock.json`, which fixes the live envelope
//!   shape (top-level `Code`/`Error`/`Details` present, PascalCase
//!   keys, `MaxTier: 0` for a free plan).
//! * ios-mac-app `6973fc1f7703314d80cada3eba377766c55710e5`:
//!   `libraries/Foundations/Domain/Sources/Domain/User/
//!   Int+UserTier.swift` — the free/paid classification rule this
//!   module pins (`free == 0`, `paid = !free`, `plus = 2`,
//!   `internal = 3`).
//!
//! The committed fixture `crates/api/testdata/entitlements_fixture.json`
//! is the same class of recorded fixture as the S6 catalog fixture: it
//! could not be recorded live (the API rejects unversioned/unfingerprinted
//! clients; forging anti-abuse fingerprints is out of bounds), so its
//! values are synthetic while its shape is the contract above. The wire
//! tests serve this exact file through the real Muon transport, so
//! transport and model provably speak about one document.
//!
//! ## Wire discipline (the S6 rules, adapted)
//!
//! Every wire field is an explicit name (never a rename-all convention:
//! serde PascalCase would fold `GroupID` to `GroupId` and silently
//! diverge), unknown keys at every object level are hard errors naming
//! the key, and there are no defaults anywhere: a missing required
//! field, a wrong type, an unrepresented value, or an upstream drift is
//! [`EntitlementsError::Malformed`] — never a silently dropped key.
//! Fields the official clients disagree about (one maps it, another
//! dropped it, e.g. `ExpirationTime`, `Name`, `Details`) are `Option`:
//! **absence stays absence**. Nothing is ever fabricated: an absent
//! `MaxTier` yields `plan_tier == None` and `None` feature allowances
//! rather than a guessed free tier (the android `userTierUnknown` arm;
//! FR-13B's never-fabricate rule applied to entitlements).
//!
//! The parse is hand-rolled over `muon::json` (Muon's serde_json
//! re-export) rather than serde derives: this crate deliberately does
//! not depend on serde directly, and no new dependency enters the graph
//! for this unit. The discipline is identical — explicit names,
//! unknown-key rejection, no defaults — with this module's own error
//! messages naming field paths.
//!
//! ## Derived allowances (PRESENT/ABSENT, never defaults)
//!
//! [`FeatureAllowances`] summarizes the plan-level parity surface
//! ([`crate`] module docs, FR-7 "detect paid-only feature support"):
//!
//! * `netshield` — the wire `NetShield` object verbatim (tri-state:
//!   absent object → `None`).
//! * `p2p`, `secure_core`, `tor` — `Some(plan is paid)`; the parity
//!   manifest's own entitlement vocabulary (`servers.p2p`,
//!   `servers.secure-core`, `servers.tor`: `entitlement: paid`) and the
//!   pinned apple classification rule. These are plan-level summaries
//!   for surfaces like FR-23G's "clear upgrade/entitlement errors"; the
//!   authoritative connection gate remains the per-server tier
//!   comparison `server.tier <= max_tier` (FR-23P), composed by the
//!   selection layer from the raw `max_tier` this model also carries.
//! * `gateway` — the wire `IsBusiness` flag verbatim (FR-7O: Gateway
//!   entitlement for an authenticated organization account; absent flag
//!   → `None`).
//!
//! ## Free-plan change-server cooldown (FR-23G, T-16)
//!
//! [`change_server_eligibility`] is a PURE policy function — no clock
//! reads, no side effects. It takes the entitlement tier, the timestamp
//! of the last change-server action, an observation time, and the
//! applicable window; it never mints deadlines (positive jitter,
//! single-flight, persisted suppression, and rollback monotonicity are
//! S7's scheduler; the daemon wiring is S9/S10). The window constants
//! are pinned from the official support contract recorded in
//! `docs/official-parity.yaml` (`sources.free_change_server`, retrieved
//! 2026-08-19): "This cooldown period starts at 45 seconds for the
//! first change, followed by 10-minute intervals for additional
//! changes."
//!
//! Boundary decisions, pinned by tests: eligibility resumes exactly AT
//! the deadline (the countdown "ends" there); a paid tier is always
//! eligible (the policy is a free-plan policy — a paid interlude never
//! restarts or shrinks the anchored window, and an unknown tier never
//! simulates one: FR-23G forbids simulating plan behavior locally); a
//! free tier with NO recorded change is eligible (absent evidence is
//! not a fabricated countdown — the backend remains the authority).
//!
//! ## Deliberate boundaries of this unit
//!
//! NO caching: [`EntitlementsApi::fetch`] is a fresh fetch every call.
//! Caching, conditional refresh, and freshness deadlines are the
//! scheduler/store composition (S7/S9), not this layer. NO daemon or
//! core wiring: the trait is the `&dyn` seam S9 injects.

use std::future::Future;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;

use muon::common::ServiceType;
use muon::common::sdk::Sdk;
use muon::http::{HttpReq, Method};

/// The VPN entitlements endpoint (android `getVPNInfo`, spike memo Q8:
/// a ProtonWire-owned typed request over the Muon transport).
pub const ENTITLEMENTS_PATH: &str = "/vpn/v2";

/// End-to-end time budget for one entitlements fetch. The document is a
/// few hundred bytes, but the single transport may race alternative
/// routes; 30 s stays consistent with the S6 catalog budget while
/// bounded.
pub const ENTITLEMENTS_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// The Proton API result code for success (spike memo; every official
/// client's `BaseResponse`).
pub const PROTON_RESULT_CODE_OK: i64 = 1000;

/// The free-plan change-server cooldown after the FIRST change: 45 s
/// (official support contract, `docs/official-parity.yaml`
/// `sources.free_change_server`, retrieved 2026-08-19).
pub const FREE_CHANGE_SERVER_FIRST_COOLDOWN: Duration = Duration::from_secs(45);

/// The free-plan change-server cooldown between SUBSEQUENT changes:
/// 10 min (same source).
pub const FREE_CHANGE_SERVER_COOLDOWN: Duration = Duration::from_secs(10 * 60);

/// Failures of the entitlements fetch and model. Mirrors the S6
/// `CatalogError` taxonomy (transport, upstream refusal, contract
/// drift) with the same never-approximate posture.
#[derive(Debug, thiserror::Error)]
pub enum EntitlementsError {
    /// The upstream API refused the request (`Code != 1000`); the code
    /// and error string are surfaced, never approximated.
    #[error("entitlements request refused upstream: Code {code} ({error})")]
    Api {
        /// The upstream `Code` value.
        code: i64,
        /// The upstream `Error` string, if any.
        error: String,
    },
    /// The document is structurally invalid against the recorded
    /// contract: malformed JSON, a missing required field, a wrong
    /// type, an unrepresented value, or an upstream field drift. Names
    /// the field where it can.
    #[error(
        "invalid entitlements document (upstream contract drift must be mapped deliberately): {0}"
    )]
    Malformed(String),
    /// The Proton API transport failed.
    #[error("transport failure: {0}")]
    Transport(String),
}

/// VPN entitlement state per the win-app contract comment: "0 = no vpn
/// access, 1 = vpn access, 2 = vpn access requested (waitlist)". Any
/// other upstream value is a hard [`EntitlementsError::Malformed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnAccess {
    /// Status 0: the account has no VPN access (e.g. expired).
    NoAccess,
    /// Status 1: the VPN entitlement is active.
    Active,
    /// Status 2: VPN access requested, on the waitlist.
    Waitlisted,
}

/// The plan-tier classification the parity surface needs (the
/// free/paid distinction): `0` is free, anything above is paid — the
/// pinned apple rule (`Int+UserTier.swift`: `isFreeTier == 0`,
/// `isPaidTier = !isFreeTier`). An absent `MaxTier` is NOT a tier:
/// it stays `None` (android's `userTierUnknown` arm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanTier {
    /// `MaxTier == 0`.
    Free,
    /// `MaxTier > 0` (basic 1 / plus 2 / internal 3 — all paid).
    Paid,
}

/// The wire `NetShield` allowance object, verbatim (android
/// `NetShieldConfig`): three per-level availability flags. Absent
/// object → `None`; never a default allowance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetShieldAllowance {
    /// Malware blocking is available to this account.
    pub malware: bool,
    /// Ads-and-trackers blocking is available.
    pub ads_and_trackers: bool,
    /// Adult-content blocking (NetShield level 3) is available.
    pub adult_content: bool,
}

/// Plan-level feature allowances for the parity surface, as
/// PRESENT/ABSENT booleans: `Some(flag)` is a derived-or-recorded
/// upstream fact; `None` means the wire gave no basis (absent
/// `MaxTier`/`IsBusiness`/`NetShield`) and absence stays absent. See
/// the module documentation for each derivation and its evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeatureAllowances {
    /// The wire `NetShield` object, verbatim (`None` when absent).
    pub netshield: Option<NetShieldAllowance>,
    /// P2P: `Some(plan is paid)` per the parity manifest vocabulary;
    /// `None` when the tier is unknown.
    pub p2p: Option<bool>,
    /// Secure Core: `Some(plan is paid)`; `None` when the tier is
    /// unknown.
    pub secure_core: Option<bool>,
    /// Tor over VPN: `Some(plan is paid)`; `None` when the tier is
    /// unknown.
    pub tor: Option<bool>,
    /// Organization Gateway/dedicated-server entitlement: the wire
    /// `IsBusiness` flag verbatim (`None` when absent), per FR-7O.
    pub gateway: Option<bool>,
}

/// The classified entitlements view the client surfaces consume (FR-5:
/// account plan and entitlement information). Raw wire fields that
/// later layers compose (e.g. `max_tier` for FR-23P's server-tier
/// filter) are carried alongside the classifications, never replaced
/// by them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnEntitlements {
    /// The VPN entitlement state (wire `Status`, classified).
    pub vpn_access: VpnAccess,
    /// The raw wire `MaxTier` (absent stays absent; the FR-23P
    /// per-server tier filter composes against this).
    pub max_tier: Option<i64>,
    /// The free/paid classification of `max_tier` (`None` when the
    /// wire sent no tier).
    pub plan_tier: Option<PlanTier>,
    /// The subscription service-end time, Unix seconds (wire
    /// `ExpirationTime`; android maps it, win-app does not — Option per
    /// the union rule).
    pub expiration_time: Option<i64>,
    /// The plan name (wire `PlanName`, e.g. "free", "visionary2028").
    pub plan_name: Option<String>,
    /// The plan display title (wire `PlanTitle`).
    pub plan_title: Option<String>,
    /// The device-connection limit (wire `MaxConnect`); session-limit
    /// errors ride FR-7M, this is the raw datum.
    pub max_connect: i64,
    /// The VPN credential name (wire `Name`).
    pub vpn_name: Option<String>,
    /// The organization group (wire `GroupID`).
    pub group_id: Option<String>,
    /// The business/organization flag (wire `IsBusiness`; absent stays
    /// absent).
    pub is_business: Option<bool>,
    /// Account-level: the subscription flag (wire `Subscribed`).
    pub subscribed: i64,
    /// Account-level: the Proton services bitmask (wire `Services`).
    pub services: i64,
    /// Account-level: the delinquency counter (wire `Delinquent`;
    /// android treats `>= 3` as delinquent).
    pub delinquent: i64,
    /// Account-level credit (wire `Credit`).
    pub credit: Option<i64>,
    /// Account-level payment-method flag, raw int on the wire (win-app
    /// models the int; android converts to bool — kept raw, `None`
    /// when absent).
    pub has_payment_method: Option<i64>,
    /// The plan-level feature allowances (derived, tri-state).
    pub features: FeatureAllowances,
}

// ---------------------------------------------------------------------------
// Wire parse
// ---------------------------------------------------------------------------

/// The known envelope keys — the union of the pinned official-client
/// models; anything else is drift.
const ENVELOPE_KEYS: &[&str] = &[
    "Code",
    "Error",
    "Details",
    "VPN",
    "Subscribed",
    "Services",
    "Delinquent",
    "Credit",
    "HasPaymentMethod",
];

/// The known VPN-object keys.
const VPN_KEYS: &[&str] = &[
    "Status",
    "ExpirationTime",
    "PlanName",
    "PlanTitle",
    "MaxTier",
    "MaxConnect",
    "Name",
    "GroupID",
    "IsBusiness",
    "NetShield",
];

/// The known NetShield-object keys (android `NetShieldConfig`).
const NETSHIELD_KEYS: &[&str] = &["Malware", "AdsAndTrackers", "AdultContent"];

impl VpnEntitlements {
    /// Parses and validates the raw upstream body against the recorded
    /// contract. Unknown keys, missing required fields, wrong types,
    /// and unrepresented values fail loudly naming the field; a
    /// refusal envelope (`Code != 1000`) surfaces as
    /// [`EntitlementsError::Api`].
    ///
    /// # Errors
    /// [`EntitlementsError::Malformed`] on any contract violation or
    /// drift; [`EntitlementsError::Api`] on an upstream refusal code.
    pub fn from_wire_bytes(body: &[u8]) -> Result<Self, EntitlementsError> {
        let value: muon::json::Value = muon::json::from_slice(body)
            .map_err(|e| EntitlementsError::Malformed(format!("body is not JSON: {e}")))?;
        let root = value
            .as_object()
            .ok_or_else(|| EntitlementsError::Malformed("document root is not an object".into()))?;
        reject_unknown_keys("envelope", root.keys(), ENVELOPE_KEYS)?;

        // The refusal envelope short-circuits before any field of the
        // success document is demanded: a Code != 1000 is the upstream's
        // own refusal statement and surfaces verbatim.
        let code = require_i64(root, "Code")?;
        if code != PROTON_RESULT_CODE_OK {
            let error = optional_string(root, "Error")?.unwrap_or_default();
            return Err(EntitlementsError::Api { code, error });
        }

        // Envelope metadata on a success document: typed (null-or-string
        // / null-or-object — both pinned clients model them so), never
        // surfaced. `Details` carries error metadata upstream; on Code
        // 1000 it is null in every recorded shape.
        optional_string(root, "Error")?;
        match root.get("Details").cloned() {
            None | Some(muon::json::Value::Null) | Some(muon::json::Value::Object(_)) => {}
            Some(_) => {
                return Err(EntitlementsError::Malformed(
                    "Details must be null or an object".into(),
                ));
            }
        }

        let subscribed = require_i64(root, "Subscribed")?;
        let services = require_i64(root, "Services")?;
        let delinquent = require_i64(root, "Delinquent")?;
        let credit = optional_i64(root, "Credit")?;
        let has_payment_method = optional_i64(root, "HasPaymentMethod")?;

        let vpn = root
            .get("VPN")
            .ok_or_else(|| EntitlementsError::Malformed("missing required field VPN".into()))?
            .as_object()
            .ok_or_else(|| EntitlementsError::Malformed("field VPN must be an object".into()))?;
        reject_unknown_keys("VPN", vpn.keys(), VPN_KEYS)?;

        let status = require_i64(vpn, "Status")?;
        let vpn_access = match status {
            0 => VpnAccess::NoAccess,
            1 => VpnAccess::Active,
            2 => VpnAccess::Waitlisted,
            other => {
                return Err(EntitlementsError::Malformed(format!(
                    "field Status has unrepresented value {other} (recorded contract: 0/1/2)"
                )));
            }
        };

        let max_tier = optional_i64(vpn, "MaxTier")?;
        let plan_tier = match max_tier {
            None => None,
            Some(tier @ 0..) => Some(if tier == 0 {
                PlanTier::Free
            } else {
                PlanTier::Paid
            }),
            Some(tier) => {
                return Err(EntitlementsError::Malformed(format!(
                    "field MaxTier has unrepresented value {tier} (no client assigns semantics to a negative tier)"
                )));
            }
        };

        let netshield = match vpn.get("NetShield").cloned() {
            None | Some(muon::json::Value::Null) => None,
            Some(muon::json::Value::Object(object)) => {
                reject_unknown_keys("NetShield", object.keys(), NETSHIELD_KEYS)?;
                Some(NetShieldAllowance {
                    malware: require_bool(&object, "Malware")?,
                    ads_and_trackers: require_bool(&object, "AdsAndTrackers")?,
                    adult_content: require_bool(&object, "AdultContent")?,
                })
            }
            Some(_) => {
                return Err(EntitlementsError::Malformed(
                    "field NetShield must be null or an object".into(),
                ));
            }
        };

        // The tier-derived allowances: PRESENT only when a tier is; a
        // paid plan carries the parity manifest's `entitlement: paid`
        // surface, a free one demonstrably lacks it.
        let paid = plan_tier.map(|tier| tier == PlanTier::Paid);
        let is_business = optional_bool(vpn, "IsBusiness")?;
        Ok(Self {
            vpn_access,
            max_tier,
            plan_tier,
            expiration_time: optional_i64(vpn, "ExpirationTime")?,
            plan_name: optional_string(vpn, "PlanName")?,
            plan_title: optional_string(vpn, "PlanTitle")?,
            max_connect: require_i64(vpn, "MaxConnect")?,
            vpn_name: optional_string(vpn, "Name")?,
            group_id: optional_string(vpn, "GroupID")?,
            is_business,
            subscribed,
            services,
            delinquent,
            credit,
            has_payment_method,
            features: FeatureAllowances {
                netshield,
                p2p: paid,
                secure_core: paid,
                tor: paid,
                // The Gateway allowance is the wire flag verbatim
                // (FR-7O), not a tier derivation.
                gateway: is_business,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Wire-field helpers: explicit presence, explicit types, no defaults. A
// null and an absent key are the SAME absence (the union rule); any
// other type mismatch names its field.
// ---------------------------------------------------------------------------

/// Fails naming `field` unless every key is in the recorded contract.
fn reject_unknown_keys<'a>(
    object: &str,
    keys: impl Iterator<Item = &'a String>,
    known: &[&str],
) -> Result<(), EntitlementsError> {
    for key in keys {
        if !known.contains(&key.as_str()) {
            return Err(EntitlementsError::Malformed(format!(
                "unknown {object} key {key:?} (upstream contract drift must be mapped deliberately)"
            )));
        }
    }
    Ok(())
}

fn field_type_error(field: &str, expected: &str) -> EntitlementsError {
    EntitlementsError::Malformed(format!("field {field} must be {expected}"))
}

fn require_i64(
    object: &muon::json::Map<String, muon::json::Value>,
    field: &str,
) -> Result<i64, EntitlementsError> {
    object
        .get(field)
        .ok_or_else(|| EntitlementsError::Malformed(format!("missing required field {field}")))?
        .as_i64()
        .ok_or_else(|| field_type_error(field, "an integer"))
}

fn optional_i64(
    object: &muon::json::Map<String, muon::json::Value>,
    field: &str,
) -> Result<Option<i64>, EntitlementsError> {
    match object.get(field) {
        None | Some(muon::json::Value::Null) => Ok(None),
        Some(value) => value
            .as_i64()
            .map(Some)
            .ok_or_else(|| field_type_error(field, "null or an integer")),
    }
}

fn optional_string(
    object: &muon::json::Map<String, muon::json::Value>,
    field: &str,
) -> Result<Option<String>, EntitlementsError> {
    match object.get(field) {
        None | Some(muon::json::Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(|s| Some(s.to_owned()))
            .ok_or_else(|| field_type_error(field, "null or a string")),
    }
}

fn optional_bool(
    object: &muon::json::Map<String, muon::json::Value>,
    field: &str,
) -> Result<Option<bool>, EntitlementsError> {
    match object.get(field) {
        None | Some(muon::json::Value::Null) => Ok(None),
        Some(value) => value
            .as_bool()
            .map(Some)
            .ok_or_else(|| field_type_error(field, "null or a boolean")),
    }
}

fn require_bool(
    object: &muon::json::Map<String, muon::json::Value>,
    field: &str,
) -> Result<bool, EntitlementsError> {
    object
        .get(field)
        .ok_or_else(|| EntitlementsError::Malformed(format!("missing required field {field}")))?
        .as_bool()
        .ok_or_else(|| field_type_error(field, "a boolean"))
}

// ---------------------------------------------------------------------------
// Free-plan change-server cooldown (pure policy)
// ---------------------------------------------------------------------------

/// The outcome of a change-server eligibility evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeServerEligibility {
    /// A change may be requested now (paid tier or unknown tier —
    /// never simulated — a free tier with no recorded change, or a
    /// free tier whose window has ended).
    Eligible,
    /// The free-plan cooldown is still running; the time left until
    /// the deadline (always > 0).
    Cooldown {
        /// Time remaining until eligibility resumes.
        remaining: Duration,
    },
}

/// The applicable free-plan cooldown window from the official support
/// contract: 45 s after the FIRST change (`changes_made == 1`), 10 min
/// after each additional one.
///
/// `changes_made` counts change-server actions already performed in the
/// current policy period (S9's persisted state); with zero changes no
/// window is running at all, which is why the argument is non-zero.
#[must_use]
pub fn free_change_cooldown_window(changes_made: NonZeroU32) -> Duration {
    if changes_made.get() == 1 {
        FREE_CHANGE_SERVER_FIRST_COOLDOWN
    } else {
        FREE_CHANGE_SERVER_COOLDOWN
    }
}

/// The pure free-plan change-server policy (FR-23G, T-16).
///
/// * `tier` — the entitlement classification at evaluation time
///   (`None` = the wire sent no tier: the policy does not apply, since
///   a cooldown is a FREE-plan rule and FR-23G forbids simulating one).
/// * `last_change` — when the last change-server action happened
///   (`None` = none recorded: no fabricated countdown; the backend
///   remains the authority).
/// * `now` — the observation time (injected; this function never reads
///   a clock).
/// * `window` — the applicable window (see
///   [`free_change_cooldown_window`]; the S7 scheduler adds its
///   positive jitter when it wires the deadline, never here).
///
/// Boundary semantics, pinned by tests: eligibility resumes exactly AT
/// `last_change + window`; a paid tier is eligible regardless of the
/// window (and a paid interlude never restarts or shrinks it — the
/// window stays anchored to `last_change`); a rolled-back clock
/// (`now < last_change`) is pure arithmetic here — the remaining grows
/// past the window and S7's rollback-monotonicity suppression is the
/// guard that prevents such inputs in production.
#[must_use]
pub fn change_server_eligibility(
    tier: Option<PlanTier>,
    last_change: Option<SystemTime>,
    now: SystemTime,
    window: Duration,
) -> ChangeServerEligibility {
    // The cooldown is a FREE-plan rule: a paid tier is eligible, and an
    // unknown tier never simulates one (FR-23G forbids the simulation).
    if tier != Some(PlanTier::Free) {
        return ChangeServerEligibility::Eligible;
    }
    // No recorded change: no fabricated countdown (never-fabricate; the
    // backend remains the authority on cooldowns).
    let Some(last) = last_change else {
        return ChangeServerEligibility::Eligible;
    };
    // The deadline is `last + window`; eligibility resumes exactly AT
    // it (duration_since is Ok(ZERO) there). A representable-overflow
    // deadline can never arrive, so it can only mean eligible.
    let Some(deadline) = last.checked_add(window) else {
        return ChangeServerEligibility::Eligible;
    };
    match now.duration_since(deadline) {
        Ok(_) => ChangeServerEligibility::Eligible,
        // `now` is before the deadline — including a rolled-back clock
        // before `last`, where the remaining legitimately grows past the
        // window (S7's rollback-monotonicity suppression prevents such
        // inputs in production; this stays pure arithmetic).
        Err(_) => ChangeServerEligibility::Cooldown {
            remaining: deadline
                .duration_since(now)
                .expect("now is before the deadline in this arm"),
        },
    }
}

// ---------------------------------------------------------------------------
// The adapter
// ---------------------------------------------------------------------------

/// One in-flight entitlements request, as presented to the blocking
/// bridge (the S4/S6 seam idiom).
pub type FetchFuture = Pin<Box<dyn Future<Output = muon::Result<muon::ProtonResponse>>>>;

/// The sync→async bridge: blocks on a Muon response future. Injected
/// at construction so this crate depends on no runtime; the daemon's
/// engine runtime ([`crate::runtime::TokioBridge`]) is wired by S4/S9.
pub type BlockOn = Arc<dyn Fn(FetchFuture) -> muon::Result<muon::ProtonResponse> + Send + Sync>;

type SendEntitlements = Arc<dyn Fn(HttpReq) -> muon::Result<muon::ProtonResponse> + Send + Sync>;

/// [`EntitlementsApi`] over a Muon session. The session is captured at
/// construction into a sending closure (it must be `Send + Sync`
/// there, provable where the context type is concrete), so the adapter
/// is a plain `Send + Sync` type that drops the context generic — the
/// `&dyn EntitlementsApi` seam S9 injects.
pub struct MuonEntitlements {
    send: SendEntitlements,
}

impl MuonEntitlements {
    /// Wraps `session`. `sdk` identifies ProtonWire in `x-pm-origin-sdk`
    /// (register the same [`Sdk`] on the client builder); `block_on`
    /// bridges to the engine runtime.
    pub fn new<C: muon::Context>(session: muon::Session<C>, sdk: Sdk, block_on: BlockOn) -> Self
    where
        muon::Session<C>: Send + Sync + 'static,
    {
        let session = Arc::new(session);
        let sdk = Arc::new(sdk);
        let send = Arc::new(move |req: HttpReq| {
            let session = Arc::clone(&session);
            let sdk = Arc::clone(&sdk);
            block_on(Box::pin(
                async move { session.send_with_sdk(req, &sdk).await },
            ))
        });
        Self { send }
    }

    /// The entitlements GET. `ServiceType::Interactive` per Muon's own
    /// taxonomy ("important for the client UI ... fetching data not in
    /// cache"): account state read on demand, idempotent.
    fn entitlements_request() -> HttpReq {
        HttpReq::new(Method::GET, ENTITLEMENTS_PATH)
            .allowed_time(ENTITLEMENTS_FETCH_TIMEOUT)
            .service_type(ServiceType::Interactive, true)
    }
}

/// Entitlement retrieval through Muon (FR-5/FR-7). Every read travels
/// the Muon transport including its alternative-routing path
/// (FR-13A); the fetch is always fresh — caching is the S7/S9
/// scheduler/store composition, never this layer.
pub trait EntitlementsApi: Send + Sync {
    /// Fetch and validate the account's VPN entitlements.
    ///
    /// # Errors
    /// [`EntitlementsError::Transport`] on transport failure,
    /// [`EntitlementsError::Api`] on an upstream refusal code,
    /// [`EntitlementsError::Malformed`] on contract drift.
    fn fetch(&self) -> Result<VpnEntitlements, EntitlementsError>;
}

impl EntitlementsApi for MuonEntitlements {
    fn fetch(&self) -> Result<VpnEntitlements, EntitlementsError> {
        let res = (self.send)(Self::entitlements_request()).map_err(|e| {
            EntitlementsError::Transport(format!("entitlements transport failure: {e}"))
        })?;
        // ok() accepts 3xx; an HTTP-level refusal is transport-class
        // here (the catalog idiom) — the upstream's own refusal
        // statement is the Code envelope, mapped inside the parse.
        let res = res.ok().map_err(|err| {
            EntitlementsError::Transport(format!(
                "entitlements endpoint refused: HTTP {} ({err})",
                err.0.as_u16()
            ))
        })?;
        VpnEntitlements::from_wire_bytes(&res.into_body())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod model_tests {
    use super::*;

    /// The recorded fixture — the same contract document the wire
    /// tests serve through the real transport, so the model and the
    /// transport provably speak about one document (the S6 idiom).
    const FIXTURE: &str = include_str!("../testdata/entitlements_fixture.json");

    /// Builds an entitlements body from the fixture with per-test
    /// surgery applied (dev-dependency serde_json; the production
    /// parse stays `muon::json`-only).
    fn fixture_with(surgery: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
        let mut value: serde_json::Value =
            serde_json::from_str(FIXTURE).expect("fixture parses as JSON");
        surgery(&mut value);
        serde_json::to_vec(&value).expect("serialize variant")
    }

    /// The full classified model from the recorded fixture: every
    /// mapped field pinned, envelope and VPN object both exercised.
    #[test]
    fn fixture_parses_into_the_full_classified_model() {
        let entitlements = VpnEntitlements::from_wire_bytes(FIXTURE.as_bytes())
            .expect("fixture is the recorded contract");

        assert_eq!(entitlements.vpn_access, VpnAccess::Active);
        assert_eq!(entitlements.max_tier, Some(3));
        assert_eq!(entitlements.plan_tier, Some(PlanTier::Paid));
        assert_eq!(entitlements.expiration_time, Some(1_820_000_000));
        assert_eq!(entitlements.plan_name.as_deref(), Some("visionary2028"));
        assert_eq!(
            entitlements.plan_title.as_deref(),
            Some("Visionary (synthetic)")
        );
        assert_eq!(entitlements.max_connect, 10);
        assert_eq!(entitlements.vpn_name.as_deref(), Some("synthetic-vpn-user"));
        assert_eq!(entitlements.group_id, None);
        assert_eq!(entitlements.is_business, Some(false));
        assert_eq!(entitlements.subscribed, 1);
        assert_eq!(entitlements.services, 4);
        assert_eq!(entitlements.delinquent, 0);
        assert_eq!(entitlements.credit, Some(0));
        assert_eq!(entitlements.has_payment_method, Some(1));
        assert_eq!(
            entitlements.features,
            FeatureAllowances {
                netshield: Some(NetShieldAllowance {
                    malware: true,
                    ads_and_trackers: true,
                    adult_content: false,
                }),
                p2p: Some(true),
                secure_core: Some(true),
                tor: Some(true),
                gateway: Some(false),
            }
        );
    }

    /// The free-plan generation (win-app's recorded mock shape): tier
    /// 0 classifies Free, paid-only allowances are PRESENT-and-false,
    /// and null-vs-absent Option arms both stay absent.
    #[test]
    fn free_tier_classifies_and_nulls_stay_absent() {
        let body = fixture_with(|value| {
            value["VPN"]["MaxTier"] = serde_json::json!(0);
            value["VPN"]["ExpirationTime"] = serde_json::Value::Null;
            value["VPN"]["NetShield"] = serde_json::Value::Null;
            value["VPN"].as_object_mut().unwrap().remove("GroupID");
            value["VPN"].as_object_mut().unwrap().remove("IsBusiness");
        });

        let entitlements = VpnEntitlements::from_wire_bytes(&body).expect("free generation parses");
        assert_eq!(entitlements.plan_tier, Some(PlanTier::Free));
        assert_eq!(entitlements.expiration_time, None);
        assert_eq!(entitlements.features.netshield, None);
        assert_eq!(entitlements.features.p2p, Some(false));
        assert_eq!(entitlements.features.secure_core, Some(false));
        assert_eq!(entitlements.features.tor, Some(false));
        assert_eq!(entitlements.features.gateway, None);
        assert_eq!(entitlements.group_id, None);
        assert_eq!(entitlements.is_business, None);
    }

    /// THE tri-state pin: an absent MaxTier is not a fabricated free
    /// tier — the classification and every tier-derived allowance stay
    /// absent (android's `userTierUnknown`; FR-13B never-fabricate).
    #[test]
    fn absent_max_tier_stays_absent_everywhere() {
        let body = fixture_with(|value| {
            value["VPN"]["MaxTier"] = serde_json::Value::Null;
        });

        let entitlements =
            VpnEntitlements::from_wire_bytes(&body).expect("null tier parses (android models it)");
        assert_eq!(entitlements.max_tier, None);
        assert_eq!(entitlements.plan_tier, None);
        assert_eq!(entitlements.features.p2p, None);
        assert_eq!(entitlements.features.secure_core, None);
        assert_eq!(entitlements.features.tor, None);
    }

    #[test]
    fn unknown_envelope_key_fails_loudly() {
        let body = fixture_with(|value| {
            value["Wappa"] = serde_json::json!(1);
        });
        let err = VpnEntitlements::from_wire_bytes(&body).expect_err("unknown key must fail");
        match err {
            EntitlementsError::Malformed(report) => {
                assert!(report.contains("Wappa"), "must name the key: {report}");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn unknown_vpn_key_fails_loudly() {
        let body = fixture_with(|value| {
            value["VPN"]["Wappa"] = serde_json::json!(1);
        });
        let err = VpnEntitlements::from_wire_bytes(&body).expect_err("unknown key must fail");
        match err {
            EntitlementsError::Malformed(report) => {
                assert!(report.contains("Wappa"), "must name the key: {report}");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn unknown_netshield_key_fails_loudly() {
        let body = fixture_with(|value| {
            value["VPN"]["NetShield"]["Wappa"] = serde_json::json!(true);
        });
        let err = VpnEntitlements::from_wire_bytes(&body).expect_err("unknown key must fail");
        match err {
            EntitlementsError::Malformed(report) => {
                assert!(report.contains("Wappa"), "must name the key: {report}");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn missing_required_field_fails_loudly() {
        let body = fixture_with(|value| {
            value["VPN"].as_object_mut().unwrap().remove("Status");
        });
        let err = VpnEntitlements::from_wire_bytes(&body).expect_err("missing field must fail");
        match err {
            EntitlementsError::Malformed(report) => {
                assert!(report.contains("Status"), "must name the field: {report}");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    /// Status values beyond the pinned official contract (0/1/2) are
    /// drift, not a guessed enum arm.
    #[test]
    fn unrepresented_status_fails_loudly() {
        let body = fixture_with(|value| {
            value["VPN"]["Status"] = serde_json::json!(7);
        });
        let err = VpnEntitlements::from_wire_bytes(&body).expect_err("status 7 is unrepresented");
        match err {
            EntitlementsError::Malformed(report) => {
                assert!(report.contains("Status"), "must name the field: {report}");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    /// win-app types MaxTier as a signed byte but no client assigns
    /// semantics to negatives: refuse rather than guess.
    #[test]
    fn negative_max_tier_fails_loudly() {
        let body = fixture_with(|value| {
            value["VPN"]["MaxTier"] = serde_json::json!(-1);
        });
        let err =
            VpnEntitlements::from_wire_bytes(&body).expect_err("negative tier is unrepresented");
        match err {
            EntitlementsError::Malformed(report) => {
                assert!(report.contains("MaxTier"), "must name the field: {report}");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn wrong_typed_field_fails_loudly() {
        let body = fixture_with(|value| {
            value["VPN"]["MaxConnect"] = serde_json::json!("ten");
        });
        let err = VpnEntitlements::from_wire_bytes(&body).expect_err("wrong type must fail");
        match err {
            EntitlementsError::Malformed(report) => {
                assert!(
                    report.contains("MaxConnect"),
                    "must name the field: {report}"
                );
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    /// A refusal envelope surfaces the upstream code and error string,
    /// never an approximated model (the catalog `Api` idiom).
    #[test]
    fn refusal_code_surfaces_code_and_error() {
        let body = fixture_with(|value| {
            value["Code"] = serde_json::json!(5003);
            value["Error"] = serde_json::json!("app no longer supported");
        });
        match VpnEntitlements::from_wire_bytes(&body) {
            Err(EntitlementsError::Api { code, error }) => {
                assert_eq!(code, 5003);
                assert_eq!(error, "app no longer supported");
            }
            other => panic!("expected Api refusal, got {other:?}"),
        }
    }

    #[test]
    fn non_json_body_fails_loudly() {
        let err = VpnEntitlements::from_wire_bytes(b"<html>login page</html>")
            .expect_err("non-JSON must fail");
        assert!(matches!(err, EntitlementsError::Malformed(_)));
    }

    /// The waitlist and no-access arms of the status classification.
    #[test]
    fn every_documented_status_classifies() {
        for (status, expected) in [
            (0, VpnAccess::NoAccess),
            (1, VpnAccess::Active),
            (2, VpnAccess::Waitlisted),
        ] {
            let body = fixture_with(|value| {
                value["VPN"]["Status"] = serde_json::json!(status);
            });
            let entitlements = VpnEntitlements::from_wire_bytes(&body)
                .unwrap_or_else(|e| panic!("status {status} is documented: {e}"));
            assert_eq!(entitlements.vpn_access, expected);
        }
    }
}

#[cfg(test)]
mod cooldown_tests {
    use super::*;

    /// A fixed anchor: pure arithmetic, no clocks anywhere.
    const BASE: SystemTime = SystemTime::UNIX_EPOCH;

    #[test]
    fn paid_tier_is_always_eligible() {
        let last = Some(BASE);
        let mid_window = BASE + Duration::from_secs(30);
        assert_eq!(
            change_server_eligibility(
                Some(PlanTier::Paid),
                last,
                mid_window,
                FREE_CHANGE_SERVER_COOLDOWN
            ),
            ChangeServerEligibility::Eligible
        );
    }

    /// PINNED DECISION — a free tier with no recorded change is
    /// ELIGIBLE: absent evidence is not a fabricated countdown
    /// (never-fabricate; FR-23G keeps the backend the authority on
    /// cooldowns, and ProtonWire must not simulate plan behavior
    /// locally).
    #[test]
    fn free_without_a_recorded_change_is_eligible() {
        assert_eq!(
            change_server_eligibility(
                Some(PlanTier::Free),
                None,
                BASE,
                FREE_CHANGE_SERVER_COOLDOWN
            ),
            ChangeServerEligibility::Eligible
        );
    }

    /// PINNED BOUNDARY — eligibility resumes exactly AT the deadline:
    /// the support contract's countdown "ends" there, so
    /// `last + window` is eligible, not one instant after it.
    #[test]
    fn free_exactly_at_the_window_boundary_is_eligible() {
        let last = Some(BASE);
        let now = BASE + FREE_CHANGE_SERVER_COOLDOWN;
        assert_eq!(
            change_server_eligibility(Some(PlanTier::Free), last, now, FREE_CHANGE_SERVER_COOLDOWN),
            ChangeServerEligibility::Eligible
        );
    }

    #[test]
    fn free_one_nanos_before_the_boundary_is_ineligible() {
        let last = Some(BASE);
        let now = BASE + FREE_CHANGE_SERVER_COOLDOWN - Duration::from_nanos(1);
        assert_eq!(
            change_server_eligibility(Some(PlanTier::Free), last, now, FREE_CHANGE_SERVER_COOLDOWN),
            ChangeServerEligibility::Cooldown {
                remaining: Duration::from_nanos(1)
            }
        );
    }

    #[test]
    fn remaining_is_exactly_the_leftover_window() {
        let window = FREE_CHANGE_SERVER_COOLDOWN;
        for fraction in [0_u32, 1, 2, 3] {
            let elapsed = window * fraction / 4;
            let now = BASE + elapsed;
            let expected = ChangeServerEligibility::Cooldown {
                remaining: window - elapsed,
            };
            assert_eq!(
                change_server_eligibility(Some(PlanTier::Free), Some(BASE), now, window),
                expected,
                "elapsed {elapsed:?}"
            );
        }
    }

    /// Property-style: the remaining time never increases as the
    /// observation time advances, and the evaluation flips to eligible
    /// exactly at the window end.
    #[test]
    fn remaining_never_increases_as_time_advances() {
        let window = FREE_CHANGE_SERVER_FIRST_COOLDOWN;
        let mut previous: Option<Duration> = None;
        for step in 0..=90 {
            let now = BASE + window * step / 90;
            match change_server_eligibility(Some(PlanTier::Free), Some(BASE), now, window) {
                ChangeServerEligibility::Cooldown { remaining } => {
                    if let Some(prev) = previous {
                        assert!(
                            remaining <= prev,
                            "remaining increased at step {step}: {remaining:?} > {prev:?}"
                        );
                    }
                    previous = Some(remaining);
                }
                ChangeServerEligibility::Eligible => {
                    assert!(now >= BASE + window, "eligible before the window ended");
                    previous = None;
                }
            }
        }
    }

    /// PINNED — the tier flip: a paid evaluation mid-window is
    /// eligible AND does not disturb the free window: the window stays
    /// anchored to the same last-change, so a flip back to free
    /// computes the SAME remaining as if the paid interlude never
    /// happened (purity: no state, no restart).
    #[test]
    fn paid_interlude_does_not_restart_or_shrink_the_free_window() {
        let last = Some(BASE);
        let now = BASE + Duration::from_secs(120);
        let window = FREE_CHANGE_SERVER_COOLDOWN;

        // A paid evaluation happens mid-window (an upgrade, say)...
        assert_eq!(
            change_server_eligibility(Some(PlanTier::Paid), last, now, window),
            ChangeServerEligibility::Eligible
        );
        // ...and the free evaluation at the same instant is unchanged
        // by it: still anchored to `last`, not to the paid moment.
        let free_view = change_server_eligibility(Some(PlanTier::Free), last, now, window);
        let expected = ChangeServerEligibility::Cooldown {
            remaining: window - Duration::from_secs(120),
        };
        assert_eq!(free_view, expected);
    }

    /// PINNED — an unknown tier never simulates a free-plan cooldown:
    /// the policy is a free-plan rule, and fabricating one from absent
    /// data is exactly what FR-23G forbids.
    #[test]
    fn unknown_tier_does_not_simulate_a_free_cooldown() {
        assert_eq!(
            change_server_eligibility(
                None,
                Some(BASE),
                BASE + Duration::from_secs(1),
                FREE_CHANGE_SERVER_COOLDOWN
            ),
            ChangeServerEligibility::Eligible
        );
    }

    /// A rolled-back clock input (now before the recorded change) is
    /// pure arithmetic here: the remaining grows past the window. S7's
    /// rollback-monotonicity suppression is the production guard; this
    /// function must still never return a negative or wrapped value.
    #[test]
    fn rolled_back_clock_input_yields_a_saturating_larger_remaining() {
        let rolled_back = BASE;
        let last = Some(BASE + Duration::from_secs(60));
        match change_server_eligibility(
            Some(PlanTier::Free),
            last,
            rolled_back,
            FREE_CHANGE_SERVER_COOLDOWN,
        ) {
            ChangeServerEligibility::Cooldown { remaining } => {
                assert!(remaining > FREE_CHANGE_SERVER_COOLDOWN);
            }
            other => panic!("expected Cooldown, got {other:?}"),
        }
    }

    /// A zero window is degenerate but well-defined: the deadline is
    /// the change itself, so any now at-or-after it is eligible and
    /// any earlier now is a zero-free cooldown away.
    #[test]
    fn zero_window_is_well_defined() {
        assert_eq!(
            change_server_eligibility(Some(PlanTier::Free), Some(BASE), BASE, Duration::ZERO),
            ChangeServerEligibility::Eligible
        );
    }

    /// The official window constants and the first-vs-subsequent
    /// picker, pinned from the support contract.
    #[test]
    fn the_official_window_constants_are_pinned() {
        assert_eq!(FREE_CHANGE_SERVER_FIRST_COOLDOWN, Duration::from_secs(45));
        assert_eq!(FREE_CHANGE_SERVER_COOLDOWN, Duration::from_secs(600));
        assert_eq!(
            free_change_cooldown_window(NonZeroU32::new(1).expect("1 is non-zero")),
            FREE_CHANGE_SERVER_FIRST_COOLDOWN
        );
        for changes in [2_u32, 3, 40] {
            assert_eq!(
                free_change_cooldown_window(NonZeroU32::new(changes).expect("non-zero")),
                FREE_CHANGE_SERVER_COOLDOWN,
                "changes {changes}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Wire seam — hermetic tests through the real Muon hyper transport
// against a keep-alive loopback responder (spike memo Q3; the S4
// pooled-sender finding).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod wire_tests {
    use std::io::{Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::*;

    /// The recorded entitlements fixture (provenance in the module
    /// documentation): synthetic values, the recorded contract shape.
    const FIXTURE: &str = include_str!("../testdata/entitlements_fixture.json");

    /// The anonymous-session mint muon performs before the first send
    /// on a credential-less session (spike memo; the S6/S4 body).
    const ANON_SESSION_BODY: &str = r#"{"UID":"anon-uid","UserID":null,"AccessToken":"anon-token","RefreshToken":"anon-refresh","Scopes":["unauth"]}"#;

    // ===== the std HTTP/1.1 KEEP-ALIVE responder ==========================
    //
    // Serves the script sequentially over keep-alive connections — the
    // client's whole exchange rides the one pooled HTTP/1.1 connection
    // Muon's pool maintains, exactly how the real API is spoken. NOT
    // `Connection: close` per exchange (the S6 catalog responder's
    // shape): closing under Muon's pooled sender triggers its
    // channel-closed retry path, whose redial stalls under the sync
    // adapter's foreign-thread `block_on` drive — observed by the S4
    // lane as a 30 s timeout (crates/api/tests/wire.rs, "Responder
    // discipline"). Keep-alive avoids that path and matches production.

    /// One recorded request: method, path, and headers (lower-cased
    /// names).
    #[derive(Debug, Clone)]
    struct Recorded {
        method: String,
        path: String,
        headers: Vec<(String, String)>,
    }

    impl Recorded {
        fn header(&self, name: &str) -> Option<&str> {
            let name = name.to_ascii_lowercase();
            self.headers
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.as_str())
        }
    }

    /// One scripted response, with the request the responder expects
    /// to be serving it.
    struct Step {
        method: &'static str,
        path: &'static str,
        status: &'static str,
        body: Vec<u8>,
    }

    impl Step {
        /// The anonymous-session mint (POST /auth/v4/sessions).
        fn anon_session() -> Self {
            Self {
                method: "POST",
                path: "/auth/v4/sessions",
                status: "200 OK",
                body: ANON_SESSION_BODY.as_bytes().to_vec(),
            }
        }

        /// The entitlements response.
        fn entitlements(status: &'static str, body: Vec<u8>) -> Self {
            Self {
                method: "GET",
                path: ENTITLEMENTS_PATH,
                status,
                body,
            }
        }
    }

    /// Hard ceilings so an unexpected protocol stall fails the test
    /// instead of hanging it.
    const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
    const IO_TIMEOUT: Duration = Duration::from_secs(10);

    /// Serves the script sequentially over keep-alive connections,
    /// recording every request; after the script the listener closes.
    fn spawn_responder(
        script: Vec<Step>,
    ) -> (std::thread::JoinHandle<()>, u16, Arc<Mutex<Vec<Recorded>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().unwrap().port();
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&recorded);
        let handle = std::thread::spawn(move || {
            listener
                .set_nonblocking(true)
                .expect("responder nonblocking");
            let mut script = script.into_iter().peekable();
            'script: loop {
                if script.peek().is_none() {
                    break 'script;
                }
                let waited = Instant::now();
                let mut stream = 'accept: loop {
                    match listener.accept() {
                        Ok((stream, _)) => break 'accept stream,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            if waited.elapsed() > ACCEPT_TIMEOUT {
                                break 'script;
                            }
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) => panic!("responder accept failed: {e}"),
                    }
                };
                stream.set_nonblocking(false).expect("blocking stream");
                stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
                stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
                // Serve as many steps as the client pipelines onto this
                // connection; stop when it closes or a read times out.
                while script.peek().is_some() {
                    let step = script.next().expect("peeked");
                    match read_request(&mut stream) {
                        Ok(recorded) => serve_exchange(&mut stream, step, recorded, &seen),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                        Err(e) => panic!("responder read failed: {e}"),
                    }
                }
            }
        });
        (handle, port, recorded)
    }

    /// Reads one request (headers + any Content-Length body) from the
    /// live connection.
    fn read_request(stream: &mut TcpStream) -> std::io::Result<Recorded> {
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        let mut chunk = [0u8; 4096];
        let header_end;
        loop {
            if let Some(pos) = find_terminator(&buf) {
                header_end = pos;
                break;
            }
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed between requests",
                ));
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap_or_default().to_owned();
        let (method, path) = match request_line.split_once(' ') {
            Some((m, rest)) => (
                m.to_owned(),
                rest.split(' ').next().unwrap_or_default().to_owned(),
            ),
            None => (String::new(), String::new()),
        };
        let headers: Vec<(String, String)> = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
            .collect();
        // Drain any body the client claims (muon sends none on these
        // requests, but robustness is free).
        if let Some((_, len)) = headers.iter().find(|(k, _)| k == "content-length")
            && let Ok(len) = len.parse::<usize>()
        {
            let mut taken = buf[header_end..].len();
            while taken < len {
                let n = stream.read(&mut chunk)?;
                if n == 0 {
                    break;
                }
                taken += n;
            }
        }
        Ok(Recorded {
            method,
            path,
            headers,
        })
    }

    /// Serves one scripted response on the live keep-alive connection.
    fn serve_exchange(
        stream: &mut TcpStream,
        step: Step,
        recorded: Recorded,
        seen: &Mutex<Vec<Recorded>>,
    ) {
        // The responder enforces its own script: an unexpected exchange
        // fails the test here rather than deep inside muon's error
        // mapping.
        assert_eq!(
            recorded.method, step.method,
            "responder script mismatch on method (path {})",
            recorded.path
        );
        let bare_path = recorded.path.split('?').next().unwrap_or(&recorded.path);
        assert_eq!(
            bare_path, step.path,
            "responder script mismatch on path (method {})",
            recorded.method
        );
        seen.lock().unwrap().push(recorded);
        let out = format!(
            "HTTP/1.1 {}\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n",
            step.status,
            step.body.len()
        );
        stream
            .write_all(out.as_bytes())
            .expect("responder write head");
        stream.write_all(&step.body).expect("responder write body");
        stream.flush().expect("responder flush");
    }

    fn find_terminator(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
    }

    // ===== the muon client against the loopback env ========================

    /// The custom environment: one direct loopback `http://` server —
    /// `Scheme::Http` skips TLS entirely (spike memo Q3), and being
    /// the only direct server it is always the one chosen.
    #[derive(Debug, Clone)]
    struct LoopbackEnv {
        server: muon::common::Server,
    }

    impl muon::env::Env for LoopbackEnv {
        fn servers(&self, _version: &muon::app::AppVersion) -> Vec<muon::common::Server> {
            vec![self.server.clone()]
        }
        fn ar_pins(&self) -> Option<&muon::tls::pins::TlsPinSet> {
            None
        }
        fn api_pins(&self) -> Option<&muon::tls::pins::TlsPinSet> {
            None
        }
    }

    /// The ProtonWire SDK identity for the tests.
    fn test_sdk() -> muon::common::sdk::Sdk {
        muon::common::sdk::Sdk::new("protonwire", env!("CARGO_PKG_VERSION"))
            .expect("valid sdk identity")
    }

    /// Builds the adapter against the loopback env on a dedicated
    /// MULTI-thread runtime (`worker_threads(2)`) — multi-thread is
    /// load-bearing (spike memo, "Adapter-facing facts for S4"):
    /// blocking a current-thread runtime from a foreign thread
    /// deadlocks the connector. The OS/runtime pieces are the crate's
    /// PRODUCTION implementations (`crate::runtime`), not test
    /// re-implementations.
    fn adapter_against(port: u16) -> (MuonEntitlements, tokio::runtime::Runtime) {
        // Opt-in transport tracing for seam debugging: silent unless
        // RUST_LOG is set (e.g. RUST_LOG=muon=trace).
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "off".into()),
            )
            .with_writer(std::io::stderr)
            .try_init();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("test runtime");
        let server: muon::common::Server = format!("http://127.0.0.1:{port}/")
            .parse()
            .expect("loopback server url");
        let app = muon::App::new("linux-vpn@0.1.0").expect("app version");
        let env = muon::Environment::new_custom(LoopbackEnv { server });
        let sdk = test_sdk();

        let session = rt.block_on(async {
            let client = muon::Client::builder(app, env)
                .with_operating_system(
                    crate::runtime::TokioOs::default(),
                    crate::runtime::os_prng().expect("entropy"),
                )
                .with_multi_thread_executor(crate::runtime::TokioSpawner)
                .without_persistence::<()>()
                .without_cookie_store()
                .register_sdk(sdk.clone())
                .build()
                .expect("muon client");
            client
                .new_session_without_credentials(())
                .await
                .expect("session")
        });

        let handle = rt.handle().clone();
        let block_on: BlockOn = Arc::new(move |fut| handle.block_on(fut));
        (MuonEntitlements::new(session, sdk, block_on), rt)
    }

    // ===== the tests ========================================================

    /// fetch(): the full muon machinery — anonymous-session mint, then
    /// the entitlements GET — returns the recorded fixture parsed into
    /// the same model a direct parse produces, proving transport and
    /// model share one contract. The trait-object coercion proves the
    /// `&dyn EntitlementsApi` seam idiom for S9.
    #[test]
    fn fetch_round_trips_the_recorded_fixture() {
        let (handle, port, seen) = spawn_responder(vec![
            Step::anon_session(),
            Step::entitlements("200 OK", FIXTURE.as_bytes().to_vec()),
        ]);
        let (adapter, _rt) = adapter_against(port);

        let api: &dyn EntitlementsApi = &adapter;
        let fetched = api.fetch().expect("entitlements fetch");
        handle.join().expect("responder thread");

        let direct =
            VpnEntitlements::from_wire_bytes(FIXTURE.as_bytes()).expect("fixture parses directly");
        assert_eq!(
            fetched, direct,
            "the wire path and the model must agree on the fixture"
        );
        assert_eq!(fetched.plan_tier, Some(PlanTier::Paid));
        assert_eq!(fetched.vpn_access, VpnAccess::Active);

        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 2, "mint + fetch: {requests:?}");
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].path, "/auth/v4/sessions");
        assert_eq!(requests[1].method, "GET");
        assert_eq!(requests[1].path, ENTITLEMENTS_PATH);
        // The real transport's headers traveled: the app version and
        // the anonymous bearer muon minted and attached.
        assert!(
            requests[1].header("x-pm-appversion").is_some(),
            "muon app-version header missing: {:?}",
            requests[1].headers
        );
        assert_eq!(
            requests[1].header("authorization"),
            Some("Bearer anon-token"),
            "the minted anonymous session must author the entitlements GET"
        );
        // Entitlements are a fresh fetch (no conditional machinery —
        // caching/conditional refresh is the S7/S9 composition).
        assert_eq!(requests[1].header("if-none-match"), None);
    }

    /// A refusal envelope (HTTP 200, Code 5003) surfaces as
    /// `EntitlementsError::Api` carrying the upstream code and error.
    #[test]
    fn fetch_maps_envelope_refusals() {
        let refused = r#"{"Code":5003,"Error":"app no longer supported"}"#.to_string();
        let (handle, port, _seen) = spawn_responder(vec![
            Step::anon_session(),
            Step::entitlements("200 OK", refused.into_bytes()),
        ]);
        let (adapter, _rt) = adapter_against(port);

        match adapter.fetch() {
            Err(EntitlementsError::Api { code, error }) => {
                assert_eq!(code, 5003);
                assert_eq!(error, "app no longer supported");
            }
            other => panic!("expected Api refusal, got {other:?}"),
        }
        handle.join().expect("responder thread");
    }

    /// A dead endpoint surfaces as `EntitlementsError::Transport`
    /// (stable-code territory; never a panic, never a fabricated
    /// model).
    #[test]
    fn fetch_maps_transport_failures() {
        // Bind, learn the port, drop the listener: nothing listens.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let (adapter, _rt) = adapter_against(port);

        match adapter.fetch() {
            Err(EntitlementsError::Transport(report)) => {
                assert!(!report.is_empty());
            }
            other => panic!("expected Transport failure, got {other:?}"),
        }
    }
}
