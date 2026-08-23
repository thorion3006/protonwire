//! User-location capture (FR-23L/FR-23P physical-country source, M2
//! S10 / T-31 data layer).
//!
//! ## Endpoint ownership and transport
//!
//! Muon models no `/vpn` endpoints (spike memo Q7/Q8): the user's
//! location is a ProtonWire-owned typed request sent through
//! `Session::send_with_sdk` — PRD 6.5's sanctioned path for endpoints
//! Muon does not model (the single required transport, its alternative
//! routing included, FR-13A), exactly as the S6 catalog and S8
//! entitlements lanes do.
//!
//! The endpoint is `GET /vpn/v1/location`. The adapter imposes no
//! login-state precondition of its own: it travels whatever session it
//! was built over (the location read is deliberately reachable for
//! unauthenticated checks in the official clients — android's guest
//! hole and the apple `UserLocation` fetch both run it — and the
//! daemon composes whatever precondition the product wants).
//!
//! ## The wire contract and its provenance
//!
//! The contract below (names, types, nullability, presence) is recorded
//! field-for-field from the deserialization models of Proton's own
//! maintained clients at the revisions pinned in
//! `docs/official-parity.yaml` (`upstream.*`), the S6/S8 provenance
//! convention (synthetic values, faithful shape):
//!
//! * android-app `cc1e29f8acd5f11f63701b48f97410e90fa6a71d`
//!   (`upstream.official_android_app`): `api/ProtonVPNRetrofit.kt`
//!   (`@GET("vpn/v1/location")` → `getLocation(): UserLocation`) and
//!   `models/vpn/UserLocation.kt` — `IP: String`, `Country: String`,
//!   `ISP: String`, `Lat: Float`, `Long: Float`.
//! * win-app master `4d9ac60d1db5d3f2908498470a9d1646723afcfd`
//!   (`upstream.official_windows_app`): `Api/ApiClient.cs`
//!   (`GetLocationDataAsync` → `GET "vpn/location"` over the v1 base)
//!   and `Api.Contracts/Geographical/DeviceLocationResponse.cs` —
//!   `LocationResponse`/`LocationResponseBase` carry `Lat`/`Long`
//!   (client-side CLAMPED to ±90/±180 — a presentation filter this
//!   module deliberately does NOT copy; see the domain note below) and
//!   extend `BaseResponse`, which fixes the envelope (`Code`, `Error`,
//!   `Details`) on this endpoint.
//! * ios-mac-app `6973fc1f7703314d80cada3eba377766c55710e5`
//!   (`upstream.official_apple_app`):
//!   `Foundations/Domain/Sources/Domain/User/UserLocation.swift` —
//!   `IP`, `Country`, `ISP` with `Lat`/`Long` DROPPED (the union rule
//!   makes the coordinates `Option`); its `#if DEBUG` samples are also
//!   the precedent for synthetic documentation IPs in the fixture.
//!
//! The committed fixture `crates/api/testdata/location_fixture.json`
//! is the same class of recorded fixture as S6/S8: it could not be
//! recorded live (the API rejects unversioned/unfingerprinted clients),
//! so its values are synthetic while its shape is the contract above.
//! The IP values are RFC 5737 documentation addresses
//! (`192.0.2.0/24` TEST-NET-1) — never a real address, in fixtures or
//! tests. The wire tests serve this exact file through the real Muon
//! transport, so transport and model provably speak about one document.
//!
//! ## Wire discipline (the S6/S8 rules, verbatim)
//!
//! Every wire field is an explicit name, unknown keys at the object
//! level are hard errors naming the key, and there are no defaults
//! anywhere: a missing required field, a wrong type, an unrepresented
//! value, or an upstream drift is [`LocationError::Malformed`] —
//! never a silently dropped key. Fields the official clients disagree
//! about (`Lat`/`Long`: android and win map them, apple dropped them)
//! are `Option`: **absence stays absence**. The coordinate domain note:
//! win-app clamps out-of-range `Lat`/`Long` silently; android carries
//! them verbatim; this module fails closed — a latitude outside
//! ±90 or a longitude outside ±180 is drift ([`LocationError::
//! Malformed`]), never a silently-filtered coordinate and never a
//! fabricated clamp (the never-approximate posture applied to a field
//! with a defined physical domain).
//!
//! ## IP discipline (SEC-16-class payload)
//!
//! The response carries the user's public IP — identifying data. Three
//! rules, pinned by tests:
//!
//! 1. [`UserLocation`]'s `Debug` is hand-written: `ip` and `isp` (the
//!    real-world organization — the same disclosure class as the IP
//!    for a targeted individual) render `[redacted]`; only the coarse
//!    facts (country, coordinates) render. A `tracing` field, a panic
//!    message, or an error formatter derived from `{:?}` can never
//!    carry the IP or the ISP.
//! 2. No error embeds the IP or the raw body: [`LocationError`]'s
//!    messages name FIELDS and code numbers, never values (the S5a
//!    parse-summary precedent — serde-style Displays embed the
//!    offending value verbatim, and this payload's offending value is
//!    the user's IP).
//! 3. At rest, the S10 store-side cache (`protonwire-store`'s
//!    `location` module) writes the payload 0600 — this module never
//!    persists anything itself.
//!
//! ## Deliberate boundaries of this unit
//!
//! NO caching, NO single-flight, NO scheduling: [`LocationApi::fetch`]
//! is a fresh fetch every call. The three-hour persisted floor, the
//! on-demand-only wiring, `Retry-After`/block honoring, and
//! physical-country-required composition are the S10 scheduler/store
//! composition and the daemon lane (m2-plan S10; the store module
//! carries the floor constant and the pure freshness predicate this
//! side composes with). NO daemon or core wiring: the trait is the
//! `&dyn` seam the future unit injects.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use muon::common::ServiceType;
use muon::common::sdk::Sdk;
use muon::http::{HttpReq, Method};

/// The user-location endpoint (android `getLocation`, spike memo Q7:
/// a ProtonWire-owned typed request over the Muon transport).
pub const LOCATION_PATH: &str = "/vpn/v1/location";

/// End-to-end time budget for one location fetch. The document is a
/// few hundred bytes, but the single transport may race alternative
/// routes; 30 s stays consistent with the S6/S8 budgets while bounded.
pub const LOCATION_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// The Proton API result code for success (every official client's
/// `BaseResponse`; the S8 constant, same envelope).
pub const PROTON_RESULT_CODE_OK: i64 = 1000;

/// The physical domain of a latitude (win-app's clamp bounds, taken
/// here as the recorded domain instead of the clamp).
pub const LATITUDE_RANGE: f32 = 90.0;

/// The physical domain of a longitude.
pub const LONGITUDE_RANGE: f32 = 180.0;

/// Failures of the location fetch and model. Mirrors the S6/S8 error
/// taxonomy (transport, upstream refusal, contract drift) with the
/// same never-approximate posture — and the IP-discipline rule: no
/// variant's message ever embeds the response body or the IP.
#[derive(Debug, thiserror::Error)]
pub enum LocationError {
    /// The upstream API refused the request (`Code != 1000`); the code
    /// and the upstream `Error` string are surfaced, never
    /// approximated.
    #[error("location request refused upstream: Code {code} ({error})")]
    Api {
        /// The upstream `Code` value.
        code: i64,
        /// The upstream `Error` string, if any.
        error: String,
    },
    /// The document is structurally invalid against the recorded
    /// contract: malformed JSON, a missing required field, a wrong
    /// type, an unrepresented value (including an out-of-domain
    /// coordinate), or an upstream field drift. Names the field where
    /// it can; never embeds the value.
    #[error("invalid location document (upstream contract drift must be mapped deliberately): {0}")]
    Malformed(String),
    /// The Proton API transport failed.
    #[error("transport failure: {0}")]
    Transport(String),
}

/// The user's location as reported by the upstream — the IP-bearing
/// model (SEC-16-class; see the module's IP-discipline rules). The
/// coordinates are `Option` per the union rule (apple's model drops
/// them; android and win map them).
#[derive(Clone, PartialEq)]
pub struct UserLocation {
    /// The user's public IP (wire `IP`, verbatim — the official
    /// clients model an opaque string, so no local re-formatting).
    pub ip: String,
    /// The user's ISO country code (wire `Country`).
    pub country: String,
    /// The user's ISP (wire `ISP`).
    pub isp: String,
    /// The latitude (wire `Lat`), within ±90; `None` when the upstream
    /// sent none (apple's shape).
    pub latitude: Option<f32>,
    /// The longitude (wire `Long`), within ±180; `None` when absent.
    pub longitude: Option<f32>,
}

/// IP discipline, rule 1: `ip` and `isp` never render — a `tracing`
/// field, panic message, or error formatter derived from `{:?}` cannot
/// carry them. Only the coarse facts render.
impl std::fmt::Debug for UserLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserLocation")
            .field("ip", &"[redacted]")
            .field("country", &self.country)
            .field("isp", &"[redacted]")
            .field("latitude", &self.latitude)
            .field("longitude", &self.longitude)
            .finish()
    }
}

impl UserLocation {
    /// Parses and validates the raw upstream body against the recorded
    /// contract. Unknown keys, missing required fields, wrong types,
    /// and unrepresented values (including out-of-domain coordinates)
    /// fail loudly naming the field; a refusal envelope
    /// (`Code != 1000`) surfaces as [`LocationError::Api`].
    ///
    /// # Errors
    /// [`LocationError::Malformed`] on any contract violation or
    /// drift; [`LocationError::Api`] on an upstream refusal code.
    pub fn from_wire_bytes(body: &[u8]) -> Result<Self, LocationError> {
        let value: muon::json::Value = muon::json::from_slice(body)
            .map_err(|e| LocationError::Malformed(format!("body is not JSON: {e}")))?;
        let root = value
            .as_object()
            .ok_or_else(|| LocationError::Malformed("document root is not an object".into()))?;
        reject_unknown_keys(root.keys())?;

        // The refusal envelope short-circuits before any field of the
        // success document is demanded (the S8 idiom).
        let code = require_i64(root, "Code")?;
        if code != PROTON_RESULT_CODE_OK {
            let error = optional_string(root, "Error")?.unwrap_or_default();
            return Err(LocationError::Api { code, error });
        }

        // Envelope metadata on a success document: typed, never
        // surfaced (the S8 arms — `Details` is null-or-object).
        optional_string(root, "Error")?;
        match root.get("Details").cloned() {
            None | Some(muon::json::Value::Null) | Some(muon::json::Value::Object(_)) => {}
            Some(_) => {
                return Err(LocationError::Malformed(
                    "Details must be null or an object".into(),
                ));
            }
        }

        let latitude = optional_f32(root, "Lat")?;
        if let Some(lat) = latitude
            && !(-LATITUDE_RANGE..=LATITUDE_RANGE).contains(&lat)
        {
            return Err(LocationError::Malformed(format!(
                "field Lat is outside its physical domain (recorded domain: \
                 -{LATITUDE_RANGE}..={LATITUDE_RANGE}; win-app clamps, this module fails closed)"
            )));
        }
        let longitude = optional_f32(root, "Long")?;
        if let Some(long) = longitude
            && !(-LONGITUDE_RANGE..=LONGITUDE_RANGE).contains(&long)
        {
            return Err(LocationError::Malformed(format!(
                "field Long is outside its physical domain (recorded domain: \
                 -{LONGITUDE_RANGE}..={LONGITUDE_RANGE}; win-app clamps, this module fails closed)"
            )));
        }
        Ok(Self {
            ip: require_string(root, "IP")?,
            country: require_string(root, "Country")?,
            isp: require_string(root, "ISP")?,
            latitude,
            longitude,
        })
    }
}

// ---------------------------------------------------------------------------
// Wire-field helpers: explicit presence, explicit types, no defaults. A
// null and an absent key are the SAME absence (the union rule); any
// other type mismatch names its field (never the value — the IP
// discipline).
// ---------------------------------------------------------------------------

/// The known object keys — the union of the pinned official-client
/// models (the win envelope + android/apple fields); anything else is
/// drift.
const KNOWN_KEYS: &[&str] = &[
    "Code", "Error", "Details", "IP", "Country", "ISP", "Lat", "Long",
];

fn reject_unknown_keys<'a>(keys: impl Iterator<Item = &'a String>) -> Result<(), LocationError> {
    for key in keys {
        if !KNOWN_KEYS.contains(&key.as_str()) {
            return Err(LocationError::Malformed(format!(
                "unknown key {key:?} (upstream contract drift must be mapped deliberately)"
            )));
        }
    }
    Ok(())
}

fn field_type_error(field: &str, expected: &str) -> LocationError {
    LocationError::Malformed(format!("field {field} must be {expected}"))
}

fn require_i64(
    object: &muon::json::Map<String, muon::json::Value>,
    field: &str,
) -> Result<i64, LocationError> {
    object
        .get(field)
        .ok_or_else(|| LocationError::Malformed(format!("missing required field {field}")))?
        .as_i64()
        .ok_or_else(|| field_type_error(field, "an integer"))
}

fn require_string(
    object: &muon::json::Map<String, muon::json::Value>,
    field: &str,
) -> Result<String, LocationError> {
    object
        .get(field)
        .ok_or_else(|| LocationError::Malformed(format!("missing required field {field}")))?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| field_type_error(field, "a string"))
}

fn optional_string(
    object: &muon::json::Map<String, muon::json::Value>,
    field: &str,
) -> Result<Option<String>, LocationError> {
    match object.get(field) {
        None | Some(muon::json::Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(|s| Some(s.to_owned()))
            .ok_or_else(|| field_type_error(field, "null or a string")),
    }
}

fn optional_f32(
    object: &muon::json::Map<String, muon::json::Value>,
    field: &str,
) -> Result<Option<f32>, LocationError> {
    match object.get(field) {
        None | Some(muon::json::Value::Null) => Ok(None),
        Some(value) => value
            .as_f64()
            .map(|n| Some(n as f32))
            .ok_or_else(|| field_type_error(field, "null or a number")),
    }
}

// ---------------------------------------------------------------------------
// The adapter
// ---------------------------------------------------------------------------

/// One in-flight location request, as presented to the blocking bridge
/// (the S4/S6/S8 seam idiom).
pub type FetchFuture = Pin<Box<dyn Future<Output = muon::Result<muon::ProtonResponse>>>>;

/// The sync→async bridge: blocks on a Muon response future. Injected
/// at construction so this crate depends on no runtime; the daemon's
/// engine runtime ([`crate::runtime::TokioBridge`]) is wired by its
/// lane.
pub type BlockOn = Arc<dyn Fn(FetchFuture) -> muon::Result<muon::ProtonResponse> + Send + Sync>;

type SendLocation = Arc<dyn Fn(HttpReq) -> muon::Result<muon::ProtonResponse> + Send + Sync>;

/// [`LocationApi`] over a Muon session. The session is captured at
/// construction into a sending closure (it must be `Send + Sync`
/// there, provable where the context type is concrete), so the adapter
/// is a plain `Send + Sync` type that drops the context generic — the
/// `&dyn LocationApi` seam the S10 composition injects.
pub struct MuonLocation {
    send: SendLocation,
}

impl MuonLocation {
    /// Wraps `session`. `sdk` identifies ProtonWire in
    /// `x-pm-origin-sdk` (register the same [`Sdk`] on the client
    /// builder); `block_on` bridges to the engine runtime.
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

    /// The location GET. `ServiceType::Interactive` per Muon's own
    /// taxonomy ("important for the client UI"): an on-demand read,
    /// idempotent — the S10 policy layer (NOT this adapter) is what
    /// makes it rare.
    fn location_request() -> HttpReq {
        HttpReq::new(Method::GET, LOCATION_PATH)
            .allowed_time(LOCATION_FETCH_TIMEOUT)
            .service_type(ServiceType::Interactive, true)
    }
}

/// User-location retrieval through Muon (FR-23L's physical-country
/// source). Every read travels the Muon transport including its
/// alternative-routing path (FR-13A); the fetch is always fresh — the
/// three-hour floor and its persistence are the S10 store/scheduler
/// composition, never this layer.
pub trait LocationApi: Send + Sync {
    /// Fetch and validate the user's location.
    ///
    /// # Errors
    /// [`LocationError::Transport`] on transport failure,
    /// [`LocationError::Api`] on an upstream refusal code,
    /// [`LocationError::Malformed`] on contract drift.
    fn fetch(&self) -> Result<UserLocation, LocationError>;
}

impl LocationApi for MuonLocation {
    fn fetch(&self) -> Result<UserLocation, LocationError> {
        let res = (self.send)(Self::location_request())
            .map_err(|e| LocationError::Transport(format!("location transport failure: {e}")))?;
        // ok() accepts 3xx; an HTTP-level refusal is transport-class
        // here (the S6/S8 idiom) — the upstream's own refusal
        // statement is the Code envelope, mapped inside the parse.
        let res = res.ok().map_err(|err| {
            LocationError::Transport(format!(
                "location endpoint refused: HTTP {} ({err})",
                err.0.as_u16()
            ))
        })?;
        UserLocation::from_wire_bytes(&res.into_body())
    }
}

// ---------------------------------------------------------------------------
// Model tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod model_tests {
    use super::*;

    /// The recorded fixture — the same contract document the wire
    /// tests serve through the real transport, so the model and the
    /// transport provably speak about one document (the S6/S8 idiom).
    /// The IP is an RFC 5737 documentation address, never a real one.
    const FIXTURE: &str = include_str!("../testdata/location_fixture.json");
    const FIXTURE_IP: &str = "192.0.2.1";
    const FIXTURE_ISP: &str = "Synthetic Test ISP";

    /// Builds a location body from the fixture with per-test surgery
    /// applied (dev-dependency serde_json; the production parse stays
    /// `muon::json`-only).
    fn fixture_with(surgery: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
        let mut value: serde_json::Value =
            serde_json::from_str(FIXTURE).expect("fixture parses as JSON");
        surgery(&mut value);
        serde_json::to_vec(&value).expect("serialize variant")
    }

    /// The full model from the recorded fixture: every mapped field
    /// pinned.
    #[test]
    fn fixture_parses_into_the_full_model() {
        let location = UserLocation::from_wire_bytes(FIXTURE.as_bytes())
            .expect("fixture is the recorded contract");
        assert_eq!(location.ip, FIXTURE_IP);
        assert_eq!(location.country, "IS");
        assert_eq!(location.isp, FIXTURE_ISP);
        assert_eq!(location.latitude, Some(64.1466));
        assert_eq!(location.longitude, Some(-21.9426));
    }

    /// IP discipline, rule 1 (the RED this unit was built around: with
    /// a derived `Debug` this test failed — the documentation IP and
    /// the ISP rendered verbatim): the model's `Debug` never carries
    /// the IP or the ISP, and still renders the coarse facts.
    #[test]
    fn debug_never_renders_the_ip_or_isp() {
        let location = UserLocation::from_wire_bytes(FIXTURE.as_bytes()).unwrap();
        let rendered = format!("{location:?}");
        assert!(!rendered.contains(FIXTURE_IP), "the IP leaked: {rendered}");
        assert!(
            !rendered.contains(FIXTURE_ISP),
            "the ISP leaked: {rendered}"
        );
        assert!(
            rendered.contains("[redacted]"),
            "the redaction marker: {rendered}"
        );
        assert!(
            rendered.contains("IS"),
            "the coarse country renders: {rendered}"
        );
        assert!(
            rendered.contains("64.1466"),
            "the coarse latitude renders: {rendered}"
        );
    }

    /// IP discipline, rule 2: no failure of the parse ever embeds the
    /// response body's values — every error class the parse can produce
    /// is exercised against fixture-derived bodies (which carry the
    /// documentation IP), and none of the messages contains it.
    #[test]
    fn no_error_message_ever_contains_the_ip() {
        let variants: Vec<Vec<u8>> = vec![
            b"<html>login page</html>".to_vec(),
            fixture_with(|v| {
                v["Wappa"] = serde_json::json!(1);
            }),
            fixture_with(|v| {
                v.as_object_mut().unwrap().remove("IP");
            }),
            fixture_with(|v| {
                v["IP"] = serde_json::json!(7);
            }),
            fixture_with(|v| {
                v["Country"] = serde_json::Value::Null;
            }),
            fixture_with(|v| {
                v["Lat"] = serde_json::json!(91.5);
            }),
            fixture_with(|v| {
                v["Long"] = serde_json::json!(-181.0);
            }),
            fixture_with(|v| {
                v["Lat"] = serde_json::json!("not a number");
            }),
            fixture_with(|v| {
                v["Code"] = serde_json::json!(5003);
            }),
        ];
        for body in variants {
            let rendered = match UserLocation::from_wire_bytes(&body) {
                Err(error) => error.to_string(),
                Ok(_) => continue, // the refusal variant may parse; only errors matter here
            };
            assert!(
                !rendered.contains(FIXTURE_IP),
                "an error message carried the IP: {rendered}"
            );
        }
    }

    /// The union rule: `Lat`/`Long` absent and null both stay absent
    /// (apple's model drops the coordinates entirely).
    #[test]
    fn coordinates_are_optional_and_absence_stays_absent() {
        for surgery in [
            |v: &mut serde_json::Value| {
                v.as_object_mut().unwrap().remove("Lat");
                v.as_object_mut().unwrap().remove("Long");
            },
            |v: &mut serde_json::Value| {
                v["Lat"] = serde_json::Value::Null;
                v["Long"] = serde_json::Value::Null;
            },
        ] {
            let location = UserLocation::from_wire_bytes(&fixture_with(surgery))
                .expect("the apple shape parses");
            assert_eq!(location.latitude, None);
            assert_eq!(location.longitude, None);
        }
    }

    /// The domain decision (win-app clamps; android carries verbatim;
    /// this module fails closed): an out-of-domain coordinate is drift,
    /// never a silently-filtered value.
    #[test]
    fn out_of_domain_coordinates_fail_closed() {
        for (field, value) in [
            ("Lat", 91.5_f64),
            ("Lat", -90.5),
            ("Long", 180.5),
            ("Long", -181.0),
        ] {
            let body = fixture_with(|v| {
                v[field] = serde_json::json!(value);
            });
            match UserLocation::from_wire_bytes(&body) {
                Err(LocationError::Malformed(report)) => assert!(
                    report.contains(field),
                    "the drift must name its field: {report}"
                ),
                other => panic!("out-of-domain {field}={value} must fail closed: {other:?}"),
            }
        }
        // The domain boundaries themselves are representable.
        for (field, value) in [
            ("Lat", 90.0_f64),
            ("Lat", -90.0),
            ("Long", 180.0),
            ("Long", -180.0),
        ] {
            let body = fixture_with(|v| {
                v[field] = serde_json::json!(value);
            });
            assert!(
                UserLocation::from_wire_bytes(&body).is_ok(),
                "the boundary {field}={value} is in-domain"
            );
        }
    }

    #[test]
    fn unknown_key_fails_loudly() {
        let body = fixture_with(|v| {
            v["Wappa"] = serde_json::json!(1);
        });
        match UserLocation::from_wire_bytes(&body) {
            Err(LocationError::Malformed(report)) => {
                assert!(report.contains("Wappa"), "must name the key: {report}");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn missing_required_field_fails_loudly() {
        for field in ["IP", "Country", "ISP", "Code"] {
            let body = fixture_with(|v| {
                v.as_object_mut().unwrap().remove(field);
            });
            match UserLocation::from_wire_bytes(&body) {
                Err(LocationError::Malformed(report)) => assert!(
                    report.contains(field),
                    "must name the field {field}: {report}"
                ),
                other => panic!("removing {field} must fail: {other:?}"),
            }
        }
    }

    /// A refusal envelope surfaces the upstream code and error string,
    /// never an approximated model (the S6/S8 `Api` idiom).
    #[test]
    fn refusal_code_surfaces_code_and_error() {
        let body = fixture_with(|v| {
            v["Code"] = serde_json::json!(5003);
            v["Error"] = serde_json::json!("app no longer supported");
        });
        match UserLocation::from_wire_bytes(&body) {
            Err(LocationError::Api { code, error }) => {
                assert_eq!(code, 5003);
                assert_eq!(error, "app no longer supported");
            }
            other => panic!("expected Api refusal, got {other:?}"),
        }
    }

    #[test]
    fn non_json_body_fails_loudly() {
        let err = UserLocation::from_wire_bytes(b"<html>login page</html>")
            .expect_err("non-JSON must fail");
        assert!(matches!(err, LocationError::Malformed(_)));
    }
}

// ---------------------------------------------------------------------------
// Wire seam — hermetic tests through the real Muon hyper transport
// against a keep-alive loopback responder (the S6/S8 seam; the S4
// pooled-sender finding).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod wire_tests {
    use std::io::{Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::*;

    /// The recorded location fixture (provenance in the module
    /// documentation): synthetic values, the recorded contract shape,
    /// an RFC 5737 documentation IP.
    const FIXTURE: &str = include_str!("../testdata/location_fixture.json");

    /// The anonymous-session mint muon performs before the first send
    /// on a credential-less session (spike memo; the S6/S8 body).
    const ANON_SESSION_BODY: &str = r#"{"UID":"anon-uid","UserID":null,"AccessToken":"anon-token","RefreshToken":"anon-refresh","Scopes":["unauth"]}"#;

    // ===== the std HTTP/1.1 KEEP-ALIVE responder ==========================
    //
    // Serves the script sequentially over keep-alive connections (the
    // S8 copy, verbatim discipline: NOT `Connection: close` — closing
    // under Muon's pooled sender triggers its channel-closed retry
    // path, whose redial stalls under the sync adapter's foreign-thread
    // `block_on` drive; keep-alive avoids that path and matches
    // production).

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

        /// The location response.
        fn location(status: &'static str, body: Vec<u8>) -> Self {
            Self {
                method: "GET",
                path: LOCATION_PATH,
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
    /// MULTI-thread runtime — multi-thread is load-bearing (the S4
    /// finding): blocking a current-thread runtime from a foreign
    /// thread deadlocks the connector. The OS/runtime pieces are the
    /// crate's PRODUCTION implementations (`crate::runtime`).
    fn adapter_against(port: u16) -> (MuonLocation, tokio::runtime::Runtime) {
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
        (MuonLocation::new(session, sdk, block_on), rt)
    }

    // ===== the tests ========================================================

    /// fetch(): the full muon machinery — anonymous-session mint, then
    /// the location GET — returns the recorded fixture parsed into the
    /// same model a direct parse produces, proving transport and model
    /// share one contract. The trait-object coercion proves the
    /// `&dyn LocationApi` seam idiom for the S10 composition.
    #[test]
    fn fetch_round_trips_the_recorded_fixture() {
        let (handle, port, seen) = spawn_responder(vec![
            Step::anon_session(),
            Step::location("200 OK", FIXTURE.as_bytes().to_vec()),
        ]);
        let (adapter, _rt) = adapter_against(port);

        let api: &dyn LocationApi = &adapter;
        let fetched = api.fetch().expect("location fetch");
        handle.join().expect("responder thread");

        let direct =
            UserLocation::from_wire_bytes(FIXTURE.as_bytes()).expect("fixture parses directly");
        assert_eq!(
            fetched, direct,
            "the wire path and the model must agree on the fixture"
        );
        assert_eq!(fetched.country, "IS");

        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 2, "mint + fetch: {requests:?}");
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].path, "/auth/v4/sessions");
        assert_eq!(requests[1].method, "GET");
        assert_eq!(requests[1].path, LOCATION_PATH);
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
            "the minted anonymous session must author the location GET"
        );
        // A location read is unconditional (no ETag machinery — the
        // three-hour floor is the policy layer's, never a conditional
        // request).
        assert_eq!(requests[1].header("if-none-match"), None);
    }

    /// A refusal envelope (HTTP 200, Code 5003) surfaces as
    /// `LocationError::Api` carrying the upstream code and error.
    #[test]
    fn fetch_maps_envelope_refusals() {
        let refused = r#"{"Code":5003,"Error":"app no longer supported"}"#.to_string();
        let (handle, port, _seen) = spawn_responder(vec![
            Step::anon_session(),
            Step::location("200 OK", refused.into_bytes()),
        ]);
        let (adapter, _rt) = adapter_against(port);

        match adapter.fetch() {
            Err(LocationError::Api { code, error }) => {
                assert_eq!(code, 5003);
                assert_eq!(error, "app no longer supported");
            }
            other => panic!("expected Api refusal, got {other:?}"),
        }
        handle.join().expect("responder thread");
    }

    /// A dead endpoint surfaces as `LocationError::Transport`
    /// (stable-code territory; never a panic, never a fabricated
    /// location).
    #[test]
    fn fetch_maps_transport_failures() {
        // Bind, learn the port, drop the listener: nothing listens.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let (adapter, _rt) = adapter_against(port);

        match adapter.fetch() {
            Err(LocationError::Transport(report)) => {
                assert!(!report.is_empty());
            }
            other => panic!("expected Transport failure, got {other:?}"),
        }
    }
}
