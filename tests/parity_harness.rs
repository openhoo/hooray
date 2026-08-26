//! End-to-end tests for the JFrog Xray parity record–replay harness.
//!
//! The sibling-owned corpus (`tests/fixtures/parity/corpus`) and recordings
//! (`tests/fixtures/parity/recordings`) may be absent or empty while that
//! work lands concurrently. Tier 1 skips with an explicit message when the
//! manifest is missing, and the whole tier-2 section skips when no
//! recordings exist, so this suite passes today and enforces everything
//! once both land.
//!
//! Gating structure: the tier tests consume harness types that only exist
//! behind the `parity` feature, so they are individually `#[cfg]`-gated.
//! The committed-fixtures canary and the CycloneDX conformance smoke depend
//! only on always-compiled paths (`serde_json`, `hooray::model`,
//! `hooray::report`) and therefore also run under default `cargo test`.

use std::collections::BTreeSet;
#[cfg(feature = "parity")]
use std::path::Path;
use std::path::PathBuf;

#[cfg(feature = "parity")]
use hooray::config::Config;
#[cfg(feature = "parity")]
use hooray::engine::{Engine, ScanRequest};
#[cfg(feature = "parity")]
use hooray::input::ScanInput;
use hooray::model::{
    Asset, AssetId, Component, Finding, FindingKind, License, RunId, RunMetadata, ScanReport,
    Scope, stable_component_id, stable_finding_id,
};
#[cfg(feature = "parity")]
use hooray::parity::compare;
#[cfg(feature = "parity")]
use hooray::parity::corpus;
#[cfg(feature = "parity")]
use hooray::parity::model::CanonicalReport;
#[cfg(feature = "parity")]
use hooray::parity::normalize;
#[cfg(feature = "parity")]
use hooray::parity::recording::Recording;
use hooray::report::ReportFormat;
#[cfg(feature = "parity")]
use hooray::store::Store;

const PINNED_RUN_ID: &str = "run:00000000-0000-4000-8000-000000000000";
const PINNED_AS_OF: &str = "2026-01-01T00:00:00Z";

/// Slack for scorecard gate comparisons. The gates absorb only float
/// round-trip noise from the ratio computations; any real regression
/// exceeds this margin by orders of magnitude.
#[cfg(feature = "parity")]
const GATE_TOLERANCE: f64 = 1e-9;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn corpus_dir() -> PathBuf {
    repo_root().join("tests/fixtures/parity/corpus")
}

#[cfg(feature = "parity")]
fn recordings_dir() -> PathBuf {
    repo_root().join("tests/fixtures/parity/recordings")
}

/// Resolves the tier policy: the sibling-owned minimal policy when present,
/// otherwise a deterministic allow-all fallback in the temp directory.
#[cfg(feature = "parity")]
fn policy_path() -> PathBuf {
    let fixture = repo_root().join("tests/fixtures/parity/policy/minimal-policy.yaml");
    if fixture.is_file() {
        return fixture;
    }
    let dir = std::env::temp_dir().join("hooray-parity");
    std::fs::create_dir_all(&dir).expect("temp policy dir");
    let path = dir.join("minimal-policy.yaml");
    std::fs::write(
        &path,
        "version: 1\ndefault_outcome: allow\nrules: []\nexceptions: []\n",
    )
    .expect("write fallback policy");
    path
}

/// Offline configuration shared by every corpus-driven scan.
#[cfg(feature = "parity")]
fn offline_config() -> Config {
    Config {
        offline: true,
        ..Config::default()
    }
}

#[cfg(feature = "parity")]
async fn run_pinned_offline(input: ScanInput) -> ScanReport {
    let mut store = Store::open_memory().expect("in-memory store");
    let config = offline_config();
    let mut engine = Engine::new(&config, &mut store, None);
    let mut request = ScanRequest::new(input, policy_path());
    request.run_id = Some(RunId::new(PINNED_RUN_ID).expect("pinned run id"));
    request.as_of = Some(
        chrono::DateTime::parse_from_rfc3339(PINNED_AS_OF)
            .expect("pinned as-of")
            .with_timezone(&chrono::Utc),
    );
    engine.scan(request).await.expect("pinned scan")
}

/// Shared pinned pipeline for one corpus case: resolve the scannable input
/// through the kind-aware corpus resolver, scan offline with pinned run
/// identity, and normalize to the canonical report.
#[cfg(feature = "parity")]
async fn normalized_case_scan(case_id: &str, kind: &str, case_path: &Path) -> CanonicalReport {
    let input = corpus::scan_input_for_kind(kind, case_path, &offline_config())
        .expect("corpus case input classifies");
    let report = run_pinned_offline(input).await;
    normalize::normalize_hooray(&report, case_id, "offline").expect("normalization succeeds")
}

/// Ungated canary: the corpus fixtures are committed, so the manifest must
/// always exist, parse, and declare at least one case. Kills the
/// vacuous-skip risk of the feature-gated tiers silently passing when the
/// fixtures go missing.
#[test]
fn parity_fixtures_are_committed() {
    let manifest_path = corpus_dir().join("manifest.json");
    let text = std::fs::read_to_string(&manifest_path).unwrap_or_else(|error| {
        panic!(
            "corpus manifest missing at {}: {error}",
            manifest_path.display()
        )
    });
    let manifest: serde_json::Value =
        serde_json::from_str(&text).expect("corpus manifest parses as JSON");
    let cases = manifest
        .get("cases")
        .and_then(|cases| cases.as_array())
        .expect("corpus manifest has a cases array");
    assert!(!cases.is_empty(), "corpus manifest declares no cases");
}

#[cfg(feature = "parity")]
#[tokio::test]
async fn tier1_corpus_and_normalization() {
    let manifest_path = corpus_dir().join("manifest.json");
    if !manifest_path.is_file() {
        eprintln!(
            "tier-1 skipped: corpus manifest not found at {}",
            manifest_path.display()
        );
        return;
    }
    let text = std::fs::read_to_string(&manifest_path).expect("read corpus manifest");
    let manifest: corpus::CorpusManifest =
        serde_json::from_str(&text).expect("parse corpus manifest");
    if manifest.cases.is_empty() {
        eprintln!("tier-1 skipped: corpus manifest contains no cases");
        return;
    }

    for case in &manifest.cases {
        let case_path = corpus_dir().join(&case.case_id);
        assert!(
            case_path.exists(),
            "tier-1: manifest case '{}' missing at {}",
            case.case_id,
            case_path.display()
        );
        let canonical = normalized_case_scan(&case.case_id, &case.kind, &case_path).await;

        let observed: BTreeSet<&str> = canonical
            .components
            .iter()
            .map(|component| component.ecosystem.as_str())
            .collect();
        for expected in &case.expected_ecosystems {
            assert!(
                observed.contains(expected.as_str()),
                "tier-1 {}: expected ecosystem '{expected}' not in {observed:?}",
                case.case_id
            );
        }
        assert!(
            canonical.components.len() >= case.min_components,
            "tier-1 {}: {} components below minimum {}",
            case.case_id,
            canonical.components.len(),
            case.min_components
        );
        if case.directness_comparable {
            assert!(
                canonical
                    .components
                    .iter()
                    .any(|component| component.directness != "disconnected"),
                "tier-1 {}: directness-comparable case has only disconnected components",
                case.case_id
            );
        }
    }
}

/// The license-files corpus case must keep exercising real signature
/// detection: detected files attribute only to the unlicensed asset-named
/// component (license.rs `asset_component` contract), so the fixture's
/// package name has to equal its directory name. If attribution breaks,
/// hooray degrades to per-component `license:unknown` findings and parity
/// loses its only license-detection dimension.
///
/// It also pins the portability invariant the drift guard relies on:
/// canonical paths are case-relative by construction, so recordings made in
/// one checkout replay byte-identically everywhere regardless of whether the
/// harness canonicalized the case path to an absolute location.
#[cfg(feature = "parity")]
#[tokio::test]
async fn license_case_detects_signatures_with_portable_paths() {
    let case_path = corpus_dir().join("license-files-project");
    if !case_path.is_dir() {
        eprintln!("skipped: license-files-project case not present");
        return;
    }
    let canonical =
        normalized_case_scan("license-files-project", "project-directory", &case_path).await;

    let detectors: Vec<&str> = canonical
        .license_findings
        .iter()
        .filter_map(|finding| finding.detector.as_deref())
        .collect();
    assert!(
        detectors.contains(&"MIT canonical clauses"),
        "expected MIT signature detection, got {detectors:?} — asset-name attribution may have broken"
    );
    assert!(
        detectors.contains(&"BSD redistribution clauses"),
        "expected BSD-2-Clause signature detection, got {detectors:?}"
    );
    for finding in &canonical.license_findings {
        assert!(
            !finding.path.starts_with('/') && !finding.path.contains(".."),
            "canonical license path {:?} is not case-relative; drift guard would false-fail across checkouts",
            finding.path
        );
    }
}

#[cfg(feature = "parity")]
#[tokio::test]
async fn tier2_scorecard_and_drift() {
    let recordings = recordings_dir();
    if !recordings.is_dir() {
        eprintln!(
            "tier-2 skipped: recordings directory not found at {}",
            recordings.display()
        );
        return;
    }
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&recordings)
        .expect("list recordings")
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".recording.json"))
        })
        .collect();
    paths.sort();
    if paths.is_empty() {
        eprintln!(
            "tier-2 skipped: no *.recording.json files under {}",
            recordings.display()
        );
        return;
    }

    // Case kinds come from the corpus manifest so the drift re-scan
    // classifies exactly like tier-1 and `record` do.
    let manifest_path = corpus_dir().join("manifest.json");
    let manifest_text = std::fs::read_to_string(&manifest_path).expect("read corpus manifest");
    let manifest: corpus::CorpusManifest =
        serde_json::from_str(&manifest_text).expect("parse corpus manifest");

    for path in paths {
        let recording = Recording::load(&path).expect("recording loads and validates");

        // Scorecard computation must always succeed on a valid recording.
        let card = compare::scorecard(&recording.hooray, &recording.xray);
        if let Some(enforcement) = &recording.enforcement {
            if let Some(minimum) = enforcement.min_purl_recall {
                assert!(
                    card.purl_recall >= minimum - GATE_TOLERANCE,
                    "{}: purl recall {:.3} below gate {minimum}",
                    recording.case_id,
                    card.purl_recall
                );
            }
            if let Some(minimum) = enforcement.min_purl_precision {
                assert!(
                    card.purl_precision >= minimum - GATE_TOLERANCE,
                    "{}: purl precision {:.3} below gate {minimum}",
                    recording.case_id,
                    card.purl_precision
                );
            }
            if let Some(minimum) = enforcement.min_cve_jaccard {
                assert!(
                    card.cve_jaccard >= minimum - GATE_TOLERANCE,
                    "{}: cve jaccard {:.3} below gate {minimum}",
                    recording.case_id,
                    card.cve_jaccard
                );
            }
        }

        // Drift guard: a fresh pinned offline scan must reproduce the
        // recorded hooray side exactly (vulnerabilities are exempt because
        // offline scans produce none).
        let case_path = corpus_dir().join(&recording.case_id);
        assert!(
            case_path.exists(),
            "tier-2 {}: case path {} missing",
            recording.case_id,
            case_path.display()
        );
        let kind = &manifest
            .cases
            .iter()
            .find(|case| case.case_id == recording.case_id)
            .unwrap_or_else(|| panic!("tier-2 {}: no manifest case", recording.case_id))
            .kind;
        let fresh = normalized_case_scan(&recording.case_id, kind, &case_path).await;
        assert_eq!(
            fresh.components,
            recording.hooray.components,
            "tier-2 {}: component drift against {}",
            recording.case_id,
            path.display()
        );
        assert_eq!(
            fresh.license_findings,
            recording.hooray.license_findings,
            "tier-2 {}: license finding drift against {}",
            recording.case_id,
            path.display()
        );
        assert_eq!(
            fresh.parse_errors,
            recording.hooray.parse_errors,
            "tier-2 {}: parse error drift against {}",
            recording.case_id,
            path.display()
        );
    }
}

/// Builds the minimal deterministic hooray report used for the CycloneDX
/// conformance smoke (feature-independent render path).
fn conformance_fixture() -> ScanReport {
    let asset_id = AssetId::new("asset:parity-conformance").expect("asset id");
    let identity = stable_component_id("pkg:npm/lodash@4.17.15").expect("component id");
    let component = Component {
        identity: identity.clone(),
        name: "lodash".to_owned(),
        version: "4.17.15".to_owned(),
        purl: "pkg:npm/lodash@4.17.15".to_owned(),
        scope: Scope::Runtime,
        provenance: Default::default(),
        licenses: BTreeSet::from([License {
            expression: Some("MIT".to_owned()),
            name: None,
            url: None,
        }]),
        locations: Default::default(),
    };
    let rule = hooray::model::RuleId::new("license:detected").expect("rule id");
    let license_finding = Finding {
        id: stable_finding_id(FindingKind::License, &rule, Some(&identity), None),
        kind: FindingKind::License,
        rule_id: rule,
        advisory_id: None,
        component_id: Some(identity),
        location_id: None,
        aliases: BTreeSet::from(["MIT".to_owned()]),
        summary: None,
        details: None,
        severity: Default::default(),
        confidence: Default::default(),
        evidence: Default::default(),
        applicability: None,
        remediation: None,
        risk: None,
        first_seen: None,
        last_seen: None,
        modified: None,
        status: Default::default(),
    };
    ScanReport {
        schema_version: "1".to_owned(),
        run: RunMetadata {
            id: RunId::new(PINNED_RUN_ID).expect("run id"),
            started_at: PINNED_AS_OF.to_owned(),
            completed_at: Some(PINNED_AS_OF.to_owned()),
            scanner_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            metadata: Default::default(),
        },
        inventory: hooray::model::Inventory {
            asset: Asset {
                id: asset_id,
                name: "parity-conformance".to_owned(),
                kind: Default::default(),
                version: None,
                metadata: Default::default(),
            },
            components: std::collections::BTreeMap::from([(
                stable_component_id("pkg:npm/lodash@4.17.15").expect("component id"),
                component,
            )]),
            locations: Default::default(),
            dependencies: Default::default(),
        },
        findings: std::collections::BTreeMap::from([(license_finding.id.clone(), license_finding)]),
        policy_decisions: Default::default(),
        policy_summary: Default::default(),
    }
}

struct OfflineSchemaRetriever;

impl jsonschema::Retrieve for OfflineSchemaRetriever {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let content = match uri.as_str() {
            "http://cyclonedx.org/schema/spdx.schema.json"
            | "https://cyclonedx.org/schema/spdx.schema.json" => {
                include_str!("fixtures/cyclonedx-1.6/spdx.schema.json")
            }
            "http://cyclonedx.org/schema/jsf-0.82.schema.json"
            | "https://cyclonedx.org/schema/jsf-0.82.schema.json" => {
                include_str!("fixtures/cyclonedx-1.6/jsf-0.82.schema.json")
            }
            _ => return Err(format!("offline schema not found: {uri}").into()),
        };
        Ok(serde_json::from_str(content)?)
    }
}

#[test]
fn cyclonedx_conformance_smoke() {
    let rendered =
        hooray::report::render_to_string(&conformance_fixture(), ReportFormat::CycloneDxVex)
            .expect("cyclonedx render");
    let document: serde_json::Value = serde_json::from_str(&rendered).expect("rendered json");

    let schema_text = std::fs::read_to_string(
        repo_root().join("tests/fixtures/cyclonedx-1.6/bom-1.6.schema.json"),
    )
    .expect("bom-1.6 schema fixture");
    let schema: serde_json::Value = serde_json::from_str(&schema_text).expect("schema json");
    let validator = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft7)
        .with_retriever(OfflineSchemaRetriever)
        .build(&schema)
        .expect("schema compiles");
    assert!(
        validator.is_valid(&document),
        "rendered CycloneDX VEX document does not conform to bom-1.6.schema.json:\n{rendered}"
    );
}
