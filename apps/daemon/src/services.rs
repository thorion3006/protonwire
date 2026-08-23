//! The S9 daemon-side service surface: the single-flight scheduler
//! wiring, the catalog-fetch bridge, and the provider cells the session
//! lane installs its engine adapters into.
//!
//! Architecture: core owns the scheduler POLICY but must not depend on a
//! transport ([`protonwire_core::scheduler`]'s own architecture note), so
//! the daemon bridges the S6 adapter traits onto core's seams here:
//!
//! * [`CatalogService`] is the [`CatalogFetch`] closure the scheduler is
//!   constructed with — it resolves the CURRENT catalog adapter from a
//!   provider cell and maps the adapter result onto core's
//!   [`FetchOutcome`]/[`FetchFailure`], carrying [`ApiError::RateLimited`]
//!   onto [`FetchFailure::RateLimited`] so the scheduler's suppression
//!   path is live (S9 obligation b — until this bridge existed, no
//!   rate-limited fetch could ever mint a suppression deadline).
//! * [`DaemonServices::build`] constructs the production scheduler
//!   STRICTLY ([`Scheduler::production`], trust root `/`): a malformed,
//!   oversized, or fs-trust-refused persisted document ABORTS startup —
//!   never a default fallback, which would re-arm the FR-13H refetch
//!   storm the persisted high-water mark exists to prevent.

use std::path::Path;
use std::sync::Arc;
use std::sync::RwLock;

use protonwire_api::{ApiError, CatalogApi, CatalogFetch};
use protonwire_core::scheduler::CatalogFetch as SchedulerFetch;
use protonwire_core::scheduler::{
    FetchFailure, FetchOutcome, Scheduler, SchedulerConfig, SchedulerError, SystemClock,
};
use protonwire_frontend_api::ServersRefreshOutcome;
use protonwire_frontend_api::ServersRefreshReport;
use protonwire_store::catalog::CatalogCache;
use protonwire_store::catalog::CatalogCacheError;
use protonwire_store::config::SystemConfig;
use protonwire_store::paths::ConfigPaths;

/// The catalog-adapter provider cell: the session lane INSTALLS the
/// live `&dyn CatalogApi` (a `MuonCatalog` over the authenticated
/// session) once the engine wiring lands; until then every fetch
/// refuses with a typed transport failure — never a fabricated catalog
/// and never a silent success.
#[derive(Default)]
pub struct CatalogService {
    provider: RwLock<Option<Arc<dyn CatalogApi>>>,
}

impl CatalogService {
    /// Installs (or replaces) the catalog adapter.
    pub fn install(&self, api: Arc<dyn CatalogApi>) {
        *self.provider.write().expect("catalog provider lock") = Some(api);
    }

    /// One scheduler-seam fetch through the current adapter, bridged.
    pub fn fetch(&self, etag: Option<&str>) -> Result<FetchOutcome, FetchFailure> {
        let guard = self.provider.read().expect("catalog provider lock");
        match guard.as_ref() {
            Some(api) => bridge_fetch(api.fetch(etag)),
            None => Err(FetchFailure::Transport(
                "no catalog adapter installed (the session engine wiring owns this slot)"
                    .to_owned(),
            )),
        }
    }

    /// The [`SchedulerFetch`] closure over a shared service.
    pub fn closure(self: &Arc<Self>) -> SchedulerFetch {
        let service = Arc::clone(self);
        Arc::new(move |etag| service.fetch(etag))
    }
}

/// S9 obligation (b): maps one adapter fetch result onto the scheduler's
/// fetch seam. [`ApiError::RateLimited`] carries its (already-clamped at
/// the ef0074f parse seam — [`protonwire_api::catalog::
/// RETRY_AFTER_CEILING_SECONDS`], 30 days) `Retry-After` delay onto
/// [`FetchFailure::RateLimited`]; every other adapter failure is
/// transport-class; successes pass through byte-for-byte.
pub fn bridge_fetch(result: Result<CatalogFetch, ApiError>) -> Result<FetchOutcome, FetchFailure> {
    match result {
        Ok(CatalogFetch::Changed { etag, body }) => Ok(FetchOutcome::Changed { etag, body }),
        Ok(CatalogFetch::NotModified) => Ok(FetchOutcome::NotModified),
        Err(ApiError::RateLimited {
            retry_after_seconds,
        }) => Err(FetchFailure::RateLimited {
            retry_after_seconds,
        }),
        Err(other) => Err(FetchFailure::Transport(other.to_string())),
    }
}

/// Failures of the S9 service construction — every arm aborts startup
/// (exit 15, the PRD 9.8 config-class code: the persisted policy state
/// is daemon-managed configuration in the same sense as the system
/// document, and a misdeployment is a deployment error, not a runtime
/// degradation to serve through).
#[derive(Debug, thiserror::Error)]
pub enum ServiceStartupError {
    /// The scheduler could not be constructed: a sub-floor policy
    /// derivation (unreachable through a validated `SystemConfig` —
    /// defense in depth) or a STRICT load refusal of the persisted
    /// deadlines/cache documents (malformed, oversized, or
    /// fs-trust-refused).
    #[error("scheduler construction failed: {0}")]
    Scheduler(#[from] SchedulerError),
}

/// The live daemon services the request handler dispatches into.
pub struct DaemonServices {
    /// The single-flight catalog scheduler (FR-13C: one per process).
    pub scheduler: Arc<Scheduler>,
    /// The catalog adapter cell + the scheduler's fetch bridge.
    pub catalog: Arc<CatalogService>,
    /// The strict-loaded catalog cache document location (the
    /// `ServersList` read side; the scheduler is the only writer).
    pub cache_file: std::path::PathBuf,
    /// The fs_trust root every strict load here walks to — `/` in
    /// production, the hermetic root in tests (the same opt-in the
    /// construction takes).
    trust_root: std::path::PathBuf,
}

impl DaemonServices {
    /// The production construction: derives the scheduler policy from
    /// the validated system configuration and constructs the scheduler
    /// STRICTLY over the `ConfigPaths` cache directory with `/` as the
    /// fs_trust root.
    ///
    /// # Errors
    /// [`ServiceStartupError::Scheduler`] — see its doc for the
    /// fail-closed contract (abort startup; never default deadlines).
    pub fn build(config: &SystemConfig, paths: &ConfigPaths) -> Result<Self, ServiceStartupError> {
        Self::build_with_trust_root(config, paths, Path::new("/"))
    }

    /// The same construction over an explicit fs_trust root — the
    /// hermetic-test opt-in (see the core-side doc on
    /// [`Scheduler::production_with_trust_root`]): an unprivileged
    /// runner cannot make a tree root-owned, so the ownership pass
    /// would refuse every test-planted document before the arm under
    /// test. Production callers use [`Self::build`] (root `/`).
    ///
    /// # Errors
    /// As [`Self::build`].
    pub fn build_with_trust_root(
        config: &SystemConfig,
        paths: &ConfigPaths,
        trust_root: &Path,
    ) -> Result<Self, ServiceStartupError> {
        let policy = SchedulerConfig::from_metadata_cache(&config.server_selection.metadata_cache)?;
        let catalog = Arc::new(CatalogService::default());
        let scheduler = Arc::new(Scheduler::production_with_trust_root(
            policy,
            Arc::new(SystemClock),
            catalog.closure(),
            paths,
            trust_root,
        )?);
        Ok(Self {
            scheduler,
            catalog,
            cache_file: paths.cache_dir.join("servers.json"),
            trust_root: trust_root.to_path_buf(),
        })
    }

    /// Serves the cached catalog revision for `ServersList` (FR-10: the
    /// raw upstream body byte-for-byte, never rewritten) with the same
    /// STRICT posture the scheduler loaded it under — a cache document
    /// that changed into something untrusted since boot fails closed
    /// rather than serving possibly-planted bytes.
    ///
    /// # Errors
    /// [`CatalogCacheError`] when a PRESENT document fails the strict
    /// load (tampered, oversized, malformed). An ABSENT document is the
    /// legitimate nothing-cached-yet state and yields `Ok(None)`.
    pub fn cached_catalog(
        &self,
    ) -> Result<Option<protonwire_store::catalog::CachedCatalog>, CatalogCacheError> {
        CatalogCache::new(&self.cache_file).load_strict(&self.trust_root)
    }
}

/// Converts one scheduler refresh outcome onto the wire report
/// (`ServersRefresh`'s reply). The body bytes stay daemon-side (the wire
/// carries the etag only; clients read the catalog through
/// `ServersList`).
pub fn refresh_report_to_wire(
    report: protonwire_core::scheduler::RefreshReport,
) -> ServersRefreshReport {
    let outcome = match report.outcome {
        protonwire_core::scheduler::RefreshOutcome::Changed { etag, .. } => {
            ServersRefreshOutcome::Changed { etag }
        }
        protonwire_core::scheduler::RefreshOutcome::NotModified => {
            ServersRefreshOutcome::NotModified
        }
        protonwire_core::scheduler::RefreshOutcome::RateLimited {
            retry_after_seconds,
        } => ServersRefreshOutcome::RateLimited {
            retry_after_seconds,
        },
        protonwire_core::scheduler::RefreshOutcome::Failed { reason } => {
            ServersRefreshOutcome::Failed { reason }
        }
    };
    ServersRefreshReport {
        outcome,
        coalesced: report.coalesced,
        next_eligible_unix: report.next_eligible_unix,
        suppression_until_unix: report.suppression_until_unix,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake adapter scripting one result per call. `ApiError` is not
    /// `Clone` (it owns its detail strings), so the fake produces a
    /// fresh result per call.
    struct FakeCatalog {
        produce: Box<dyn Fn() -> Result<CatalogFetch, ApiError> + Send + Sync>,
    }

    impl FakeCatalog {
        fn always(
            produce: impl Fn() -> Result<CatalogFetch, ApiError> + Send + Sync + 'static,
        ) -> Self {
            Self {
                produce: Box::new(produce),
            }
        }
    }

    impl CatalogApi for FakeCatalog {
        fn fetch(&self, _etag: Option<&str>) -> Result<CatalogFetch, ApiError> {
            (self.produce)()
        }
    }

    fn changed() -> Result<CatalogFetch, ApiError> {
        Ok(CatalogFetch::Changed {
            etag: Some("\"v1\"".to_owned()),
            body: b"catalog-bytes".to_vec(),
        })
    }

    /// S9 (b): every arm of the RateLimited→FetchFailure bridge. The
    /// `RateLimited` mapping is the obligation — the scheduler's
    /// suppression path is production-dead without it (a rate-limited
    /// fetch would degrade to a plain transport failure, minting NO
    /// suppression deadline and hammering Proton on the next window).
    #[test]
    fn bridge_maps_every_adapter_arm_onto_the_scheduler_seam() {
        // Changed passes through byte-for-byte (the scheduler validates
        // and persists the body; nothing is rewritten here).
        assert_eq!(
            bridge_fetch(changed()),
            Ok(FetchOutcome::Changed {
                etag: Some("\"v1\"".to_owned()),
                body: b"catalog-bytes".to_vec(),
            })
        );
        assert_eq!(
            bridge_fetch(Ok(CatalogFetch::NotModified)),
            Ok(FetchOutcome::NotModified)
        );
        // THE obligation: the parsed (already-clamped) Retry-After delay
        // rides onto FetchFailure::RateLimited untouched.
        assert_eq!(
            bridge_fetch(Err(ApiError::RateLimited {
                retry_after_seconds: Some(60),
            })),
            Err(FetchFailure::RateLimited {
                retry_after_seconds: Some(60),
            })
        );
        assert_eq!(
            bridge_fetch(Err(ApiError::RateLimited {
                retry_after_seconds: None,
            })),
            Err(FetchFailure::RateLimited {
                retry_after_seconds: None
            })
        );
        // Every other adapter failure degrades to transport-class (the
        // scheduler still paces from the attempt, but no suppression).
        for error in [
            ApiError::Transport("timeout".to_owned()),
            ApiError::BlockedUpstream("human-verification"),
            ApiError::UnsupportedChallenge("recovery-code"),
            ApiError::InvalidState("no 2FA challenge in progress"),
        ] {
            let mapped = bridge_fetch(Err(error));
            assert!(
                matches!(mapped, Err(FetchFailure::Transport(_))),
                "non-rate-limit failures must stay transport-class: {mapped:?}"
            );
        }
    }

    /// The provider cell: an empty cell refuses with a typed transport
    /// failure (never a fabricated catalog, never a silent success), an
    /// installed adapter serves through the bridge.
    #[test]
    fn catalog_service_refuses_without_an_installed_adapter() {
        let service = CatalogService::default();
        match service.fetch(None) {
            Err(FetchFailure::Transport(reason)) => assert!(
                reason.contains("no catalog adapter installed"),
                "the refusal must name the empty cell: {reason}"
            ),
            other => panic!("empty cell must refuse, got {other:?}"),
        }
        service.install(Arc::new(FakeCatalog::always(|| {
            Err(ApiError::RateLimited {
                retry_after_seconds: Some(7),
            })
        })));
        assert_eq!(
            service.fetch(None),
            Err(FetchFailure::RateLimited {
                retry_after_seconds: Some(7),
            })
        );
    }

    /// (a): the strict construction refuses a corrupted
    /// persisted-deadlines document — never a default fallback. Arm
    /// disclosure (the honest red-evidence nuance): unprivileged
    /// runners cannot make the planted tree root-owned, so the walk's
    /// ownership pass refuses it before the parse arm — the class is
    /// FsTrust; a root-owned tree reaches the Malformed arm (pinned at
    /// the store seam by the deadlines suite). The pinned contract is
    /// the REFUSAL, with the scheduler-error surface intact.
    #[test]
    fn build_refuses_a_corrupted_deadlines_document() {
        let dir =
            std::env::temp_dir().join(format!("protonwire-daemon-s9-build-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = ConfigPaths::rooted(&dir);
        std::fs::create_dir_all(&paths.cache_dir).unwrap();
        std::fs::write(paths.cache_dir.join("deadlines.json"), b"{not json").unwrap();

        let err = DaemonServices::build_with_trust_root(&SystemConfig::default(), &paths, &dir)
            .err()
            .expect("a corrupted deadlines document must refuse construction");
        assert!(
            matches!(err, ServiceStartupError::Scheduler(_)),
            "the refusal must surface the scheduler's strict-load failure: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// (a) control: a cache directory whose documents are all ABSENT is
    /// the legitimate first boot — the walk skips absent components
    /// (MissingLeaf::Allow semantics), the scheduler constructs with
    /// bootstrap deadlines and no stored revision. Nothing is created
    /// under the root before construction, so this passes on every
    /// runner.
    #[test]
    fn build_on_an_absent_cache_tree_is_the_first_boot() {
        let dir =
            std::env::temp_dir().join(format!("protonwire-daemon-s9-boot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = ConfigPaths::rooted(&dir);

        let services =
            DaemonServices::build_with_trust_root(&SystemConfig::default(), &paths, &dir)
                .expect("first boot constructs the scheduler");
        // The FR-13F bootstrap: never fetched, so everything is due.
        assert_eq!(services.scheduler.next_due_unix(), None);
        assert_eq!(
            services.cached_catalog().expect("absent cache is clean"),
            None
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The suppression path, end to end through the REAL bridge: a
    /// rate-limited adapter behind the provider cell drives the
    /// scheduler's manual refresh into `Suppressed` — the path that was
    /// production-dead before obligation (b).
    #[test]
    fn a_rate_limited_adapter_behind_the_bridge_mints_a_suppression() {
        use protonwire_core::scheduler::ManualOutcome;

        let dir =
            std::env::temp_dir().join(format!("protonwire-daemon-s9-sup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = ConfigPaths::rooted(&dir);
        let services =
            DaemonServices::build_with_trust_root(&SystemConfig::default(), &paths, &dir)
                .expect("first boot");
        services.catalog.install(Arc::new(FakeCatalog::always(|| {
            Err(ApiError::RateLimited {
                retry_after_seconds: Some(60),
            })
        })));

        // First refresh: the rate limit REPORTS (the report carries the
        // suppression the deadline computation minted)...
        match services.scheduler.refresh_manual(None) {
            ManualOutcome::Refreshed(report) => {
                let wire = refresh_report_to_wire(report);
                assert_eq!(
                    wire.outcome,
                    ServersRefreshOutcome::RateLimited {
                        retry_after_seconds: Some(60),
                    }
                );
                assert!(wire.suppression_until_unix.is_some());
            }
            other => panic!("the first manual refresh must run, got {other:?}"),
        }
        // ...and the minted suppression refuses the NEXT attempt outrank
        // even a confirmed manual refresh (ER-16).
        match services.scheduler.refresh_manual(None) {
            ManualOutcome::Suppressed { .. } => {}
            other => panic!("the suppression must refuse the next manual refresh: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
