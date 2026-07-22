use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
};

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    analysis::{ApplicabilityAnalyzer, ApplicabilityInput},
    config::Config,
    graph::DependencyGraph,
    input::ScanInput,
    license,
    model::{
        ApplicabilityStatus, ComponentId, DependencyKind, Evidence, Finding, FindingId,
        FindingKind, Inventory, RunId, RunMetadata, ScanReport,
    },
    osv::{OsvClient, OsvError},
    policy::{Policy, PolicyError},
    remediation,
    risk::{
        OperationalRiskAnalyzer, OperationalRiskConfig, OperationalRiskInput, RiskInput, RiskScorer,
    },
    scanners::{self, MalwareSignatures, ScannerConfig},
    store::{Store, StoreError},
};

pub const REPORT_SCHEMA_VERSION: &str = "1";
const MAX_POLICY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DEPENDENCY_PATHS: usize = 32;
const MAX_DEPENDENCY_DEPTH: usize = 128;

pub type ProviderFuture<'a> =
    Pin<Box<dyn Future<Output = Result<BTreeMap<FindingId, Finding>, OsvError>> + Send + 'a>>;

/// Provider seam used by production OSV access and deterministic offline tests.
pub trait VulnerabilityProvider: Send + Sync {
    fn scan<'a>(&'a self, inventory: &'a Inventory) -> ProviderFuture<'a>;
}

impl VulnerabilityProvider for OsvClient {
    fn scan<'a>(&'a self, inventory: &'a Inventory) -> ProviderFuture<'a> {
        Box::pin(async move { OsvClient::scan(self, inventory).await })
    }
}

#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub input: ScanInput,
    pub policy_path: PathBuf,
    pub baseline: Option<RunId>,
    pub new_findings_only: bool,
    pub run_id: Option<RunId>,
    pub as_of: Option<DateTime<Utc>>,
}

impl ScanRequest {
    pub fn new(input: ScanInput, policy_path: PathBuf) -> Self {
        Self {
            input,
            policy_path,
            baseline: None,
            new_findings_only: false,
            run_id: None,
            as_of: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("input failed: {0}")]
    Input(#[from] crate::input::InputError),
    #[error("vulnerability provider failed: {0}")]
    Osv(#[from] OsvError),
    #[error("license analysis failed: {0}")]
    License(#[from] license::LicenseError),
    #[error("filesystem analysis failed: {0}")]
    Scanner(#[from] scanners::ScanError),
    #[error("dependency analysis failed: {0}")]
    Graph(#[from] crate::graph::GraphError),
    #[error("policy evaluation failed: {0}")]
    Policy(#[from] PolicyError),
    #[error("store operation failed: {0}")]
    Store(#[from] StoreError),
    #[error("generated report is invalid: {0}")]
    Model(#[from] crate::model::ModelInvariantError),
    #[error("failed to read policy {path}: {source}")]
    PolicyRead {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("policy {path} is {actual} bytes, exceeding the {maximum} byte limit")]
    PolicyTooLarge {
        path: PathBuf,
        actual: u64,
        maximum: u64,
    },
    #[error("unsupported policy format: {0}")]
    UnsupportedPolicyFormat(PathBuf),
    #[error("baseline run '{0}' was not found")]
    BaselineNotFound(RunId),
    #[error(
        "baseline run '{run_id}' belongs to asset '{baseline_asset}', not current asset '{current_asset}'"
    )]
    BaselineAssetMismatch {
        run_id: RunId,
        baseline_asset: crate::model::AssetId,
        current_asset: crate::model::AssetId,
    },
    #[error("new-findings-only requires an explicit baseline or an existing run for this asset")]
    MissingBaseline,
}

pub struct Engine<'a> {
    config: &'a Config,
    store: &'a mut Store,
    provider: Option<&'a dyn VulnerabilityProvider>,
}

impl<'a> Engine<'a> {
    pub fn new(
        config: &'a Config,
        store: &'a mut Store,
        provider: Option<&'a dyn VulnerabilityProvider>,
    ) -> Self {
        Self {
            config,
            store,
            provider,
        }
    }

    pub async fn scan(&mut self, request: ScanRequest) -> Result<ScanReport, EngineError> {
        let as_of = request.as_of.unwrap_or_else(Utc::now);
        let started_at = timestamp(as_of);
        let mut inventory = request.input.inventory(self.config)?;
        let policy = load_policy(&request.policy_path)?;
        let baseline = self.resolve_baseline(
            request.baseline.as_ref(),
            request.new_findings_only,
            &inventory.asset.id,
        )?;

        let mut findings = if self.config.offline {
            BTreeMap::new()
        } else {
            match self.provider {
                Some(provider) => provider.scan(&inventory).await?,
                None => {
                    let provider =
                        OsvClient::new(&self.config.osv_url, self.config.max_concurrency)?;
                    provider.scan(&inventory).await?
                }
            }
        };

        contextualize_and_score(&inventory, &mut findings, as_of)?;
        merge_findings(
            &mut findings,
            license_findings(&request.input, &inventory, self.config)?,
        );
        merge_findings(
            &mut findings,
            filesystem_findings(&request.input, &mut inventory, self.config)?,
        );
        attach_dependency_remediation(&inventory, &mut findings)?;
        merge_operational_risk(&inventory, &mut findings, as_of);
        contextualize_and_score(&inventory, &mut findings, as_of)?;

        if let Some(baseline) = baseline.as_ref() {
            mark_history(&mut findings, baseline, &started_at);
            if request.new_findings_only {
                findings.retain(|id, _| !baseline.findings.contains_key(id));
            }
        } else {
            mark_first_seen(&mut findings, &started_at);
        }

        let evaluation = policy.evaluate(&findings, &inventory, as_of.fixed_offset())?;
        let completed_at = timestamp(as_of);
        let report = ScanReport {
            schema_version: REPORT_SCHEMA_VERSION.to_owned(),
            run: RunMetadata {
                id: request.run_id.unwrap_or_else(|| {
                    RunId::new(format!("run:{}", Uuid::new_v4()))
                        .expect("generated run identifier is non-empty")
                }),
                started_at,
                completed_at: Some(completed_at),
                scanner_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
                metadata: BTreeMap::from([
                    (
                        "input".to_owned(),
                        Value::String(input_label(&request.input)),
                    ),
                    (
                        "policy".to_owned(),
                        Value::String(request.policy_path.display().to_string()),
                    ),
                    ("offline".to_owned(), Value::Bool(self.config.offline)),
                    (
                        "new_findings_only".to_owned(),
                        Value::Bool(request.new_findings_only),
                    ),
                    (
                        "baseline".to_owned(),
                        baseline
                            .as_ref()
                            .map(|report| Value::String(report.run.id.to_string()))
                            .unwrap_or(Value::Null),
                    ),
                ]),
            },
            inventory,
            findings,
            policy_decisions: evaluation.decisions,
            policy_summary: evaluation.summary,
        };
        report.validate()?;
        self.store.save_report(&report)?;
        Ok(report)
    }

    fn resolve_baseline(
        &self,
        explicit: Option<&RunId>,
        required: bool,
        asset_id: &crate::model::AssetId,
    ) -> Result<Option<ScanReport>, EngineError> {
        match explicit {
            Some(id) => {
                let report = self
                    .store
                    .get_run(id)?
                    .ok_or_else(|| EngineError::BaselineNotFound(id.clone()))?;
                if report.inventory.asset.id != *asset_id {
                    return Err(EngineError::BaselineAssetMismatch {
                        run_id: id.clone(),
                        baseline_asset: report.inventory.asset.id,
                        current_asset: asset_id.clone(),
                    });
                }
                Ok(Some(report))
            }
            None if required => self
                .store
                .latest_run_for_asset(asset_id)?
                .ok_or(EngineError::MissingBaseline)
                .map(Some),
            None => Ok(None),
        }
    }
}

pub fn load_policy(path: &Path) -> Result<Policy, EngineError> {
    let metadata = fs::metadata(path).map_err(|source| EngineError::PolicyRead {
        path: path.to_owned(),
        source,
    })?;
    if metadata.len() > MAX_POLICY_BYTES {
        return Err(EngineError::PolicyTooLarge {
            path: path.to_owned(),
            actual: metadata.len(),
            maximum: MAX_POLICY_BYTES,
        });
    }
    let contents = fs::read_to_string(path).map_err(|source| EngineError::PolicyRead {
        path: path.to_owned(),
        source,
    })?;
    match path
        .extension()
        .and_then(OsStr::to_str)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("yaml" | "yml") => Ok(Policy::from_yaml(&contents)?),
        Some("toml") => Ok(Policy::from_toml(&contents)?),
        _ => Err(EngineError::UnsupportedPolicyFormat(path.to_owned())),
    }
}

fn contextualize_and_score(
    inventory: &Inventory,
    findings: &mut BTreeMap<FindingId, Finding>,
    as_of: DateTime<Utc>,
) -> Result<(), crate::graph::GraphError> {
    let graph = DependencyGraph::from_inventory(inventory)?;
    for finding in findings.values_mut() {
        let Some(component_id) = finding.component_id.as_ref() else {
            continue;
        };
        let Some(component) = inventory.components.get(component_id) else {
            continue;
        };
        let evidence = finding.evidence.clone();
        if finding.applicability.is_none() {
            finding.applicability = Some(ApplicabilityAnalyzer::analyze(ApplicabilityInput {
                component,
                inventory: Some(inventory),
                evidence: &evidence,
                affected_ranges: &[],
            }));
        }
        let applicability = finding
            .applicability
            .as_ref()
            .map(|value| value.status)
            .unwrap_or(ApplicabilityStatus::Unknown);
        let direct = match graph.classify(component_id)? {
            DependencyKind::Direct => Some(true),
            DependencyKind::Transitive => Some(false),
            DependencyKind::Disconnected => None,
        };
        finding.risk = Some(RiskScorer::score(RiskInput {
            severity: finding.severity,
            confidence: finding.confidence,
            applicability,
            component,
            direct,
            remediation: finding.remediation.as_ref(),
            evidence: &evidence,
            as_of: as_of.date_naive(),
        }));
    }
    Ok(())
}

fn license_findings(
    input: &ScanInput,
    inventory: &Inventory,
    config: &Config,
) -> Result<Vec<Finding>, license::LicenseError> {
    let root = match input {
        ScanInput::ProjectDirectory(path) | ScanInput::OciImageLayout(path) => Some(path.as_path()),
        _ => None,
    };
    Ok(license::analyze(inventory, root, config.max_input_bytes.min(8 * 1024 * 1024))?.findings)
}

fn filesystem_findings(
    input: &ScanInput,
    inventory: &mut Inventory,
    config: &Config,
) -> Result<Vec<Finding>, scanners::ScanError> {
    let path = input_path(input);
    let scanner_config = ScannerConfig {
        max_file_bytes: config.max_input_bytes.min(8 * 1024 * 1024),
        max_total_bytes: config.max_input_bytes,
        max_files: config.max_archive_entries,
        max_archive_entries: config.max_archive_entries,
        max_archive_uncompressed_bytes: config.max_archive_bytes,
        ..ScannerConfig::default()
    };
    let output = scanners::scan_path(
        path,
        &inventory.asset.id,
        &scanner_config,
        &MalwareSignatures::default(),
    )?;
    inventory.locations.extend(output.locations);
    let known_locations = inventory.location_ids();
    Ok(output
        .findings
        .into_iter()
        .map(|mut finding| {
            if finding
                .location_id
                .as_ref()
                .is_some_and(|id| !known_locations.contains(id))
            {
                finding.location_id = None;
            }
            finding.evidence = finding
                .evidence
                .into_iter()
                .map(|mut evidence| {
                    evidence.locations.retain(|id| known_locations.contains(id));
                    evidence
                })
                .collect();
            finding
        })
        .collect())
}

fn attach_dependency_remediation(
    inventory: &Inventory,
    findings: &mut BTreeMap<FindingId, Finding>,
) -> Result<(), crate::graph::GraphError> {
    let graph = DependencyGraph::from_inventory(inventory)?;
    for finding in findings
        .values_mut()
        .filter(|finding| finding.kind == FindingKind::Vulnerability)
    {
        let Some(component_id) = finding.component_id.as_ref() else {
            continue;
        };
        let Some(component) = inventory.components.get(component_id) else {
            continue;
        };
        let kind = graph.classify(component_id)?;
        let paths = graph.all_paths(component_id, MAX_DEPENDENCY_DEPTH, MAX_DEPENDENCY_PATHS)?;
        if let Ok(plan) = remediation::plan_upgrade(finding, component, kind, paths) {
            let plan_json = serde_json::to_string(&plan).expect("upgrade plan is serializable");
            finding.evidence.insert(Evidence {
                description: "Deterministic dependency path and upgrade plan".to_owned(),
                locations: BTreeSet::new(),
                references: BTreeSet::new(),
                properties: BTreeMap::from([("remediation.upgrade-plan".to_owned(), plan_json)]),
                redacted: false,
            });
        }
    }
    Ok(())
}

fn merge_operational_risk(
    inventory: &Inventory,
    findings: &mut BTreeMap<FindingId, Finding>,
    as_of: DateTime<Utc>,
) {
    let mut evidence_by_component: BTreeMap<ComponentId, BTreeSet<Evidence>> = BTreeMap::new();
    for finding in findings.values() {
        if let Some(component_id) = &finding.component_id {
            evidence_by_component
                .entry(component_id.clone())
                .or_default()
                .extend(finding.evidence.iter().cloned());
        }
    }
    for (_, finding) in OperationalRiskAnalyzer::analyze(OperationalRiskInput {
        inventory,
        evidence_by_component: &evidence_by_component,
        as_of,
        config: OperationalRiskConfig::default(),
    }) {
        merge_finding(findings, finding);
    }
}

fn merge_findings(target: &mut BTreeMap<FindingId, Finding>, incoming: Vec<Finding>) {
    for finding in incoming {
        merge_finding(target, finding);
    }
}

fn merge_finding(target: &mut BTreeMap<FindingId, Finding>, finding: Finding) {
    target
        .entry(finding.id.clone())
        .and_modify(|existing| {
            existing.evidence.extend(finding.evidence.iter().cloned());
            existing.aliases.extend(finding.aliases.iter().cloned());
            existing.first_seen = earliest(existing.first_seen.take(), finding.first_seen.clone());
            existing.last_seen = latest(existing.last_seen.take(), finding.last_seen.clone());
            existing.modified = latest(existing.modified.take(), finding.modified.clone());
        })
        .or_insert(finding);
}

fn earliest(left: Option<String>, right: Option<String>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (left, right) => left.or(right),
    }
}

fn latest(left: Option<String>, right: Option<String>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (left, right) => left.or(right),
    }
}

fn mark_history(findings: &mut BTreeMap<FindingId, Finding>, baseline: &ScanReport, now: &str) {
    for (id, finding) in findings {
        if let Some(previous) = baseline.findings.get(id) {
            finding.first_seen = previous
                .first_seen
                .clone()
                .or_else(|| Some(baseline.run.started_at.clone()));
        } else {
            finding.first_seen = Some(now.to_owned());
        }
        finding.last_seen = Some(now.to_owned());
    }
}

fn mark_first_seen(findings: &mut BTreeMap<FindingId, Finding>, now: &str) {
    for finding in findings.values_mut() {
        finding.first_seen = Some(now.to_owned());
        finding.last_seen = Some(now.to_owned());
    }
}

fn input_path(input: &ScanInput) -> &Path {
    match input {
        ScanInput::ProjectDirectory(path)
        | ScanInput::OciImageLayout(path)
        | ScanInput::OciImageTar(path)
        | ScanInput::CycloneDx(path) => path,
        ScanInput::Archive { path, .. } => path,
    }
}

fn input_label(input: &ScanInput) -> String {
    let kind = match input {
        ScanInput::ProjectDirectory(_) => "project",
        ScanInput::Archive { .. } => "artifact",
        ScanInput::OciImageLayout(_) | ScanInput::OciImageTar(_) => "container",
        ScanInput::CycloneDx(_) => "sbom",
    };
    format!("{kind}:{}", input_path(input).display())
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Asset, AssetId, AssetKind, FindingKind, PolicySummary};
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    struct FakeProvider {
        findings: BTreeMap<FindingId, Finding>,
    }

    impl VulnerabilityProvider for FakeProvider {
        fn scan<'a>(&'a self, _inventory: &'a Inventory) -> ProviderFuture<'a> {
            let findings = self.findings.clone();
            Box::pin(async move { Ok(findings) })
        }
    }

    struct InventoryProvider {
        calls: AtomicUsize,
    }

    impl VulnerabilityProvider for InventoryProvider {
        fn scan<'a>(&'a self, inventory: &'a Inventory) -> ProviderFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let component = inventory.components.keys().next().cloned();
            Box::pin(async move {
                let finding: Finding = serde_json::from_value(json!({
                    "id": "finding:online",
                    "kind": "vulnerability",
                    "rule_id": "osv:TEST-1",
                    "advisory_id": "TEST-1",
                    "component_id": component,
                    "severity": "high",
                    "confidence": "high",
                    "status": "open",
                    "remediation": {"description": "upgrade", "fixed_versions": ["2.0.0"]},
                    "evidence": [{"description":"provenance","properties":{"maintenance.status":"abandoned"}}]
                })).unwrap();
                Ok(BTreeMap::from([(finding.id.clone(), finding)]))
            })
        }
    }

    fn sbom_fixture(temp: &TempDir) -> PathBuf {
        let path = temp.path().join("bom.cdx.json");
        fs::write(&path, r#"{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"component":{"type":"application","name":"demo","version":"1"}},"components":[{"type":"library","bom-ref":"root","name":"root","version":"1.0.0","purl":"pkg:cargo/root@1.0.0","licenses":[{"license":{"id":"MIT"}}]},{"type":"library","bom-ref":"dep","name":"dep","version":"1.0.0","purl":"pkg:cargo/dep@1.0.0"}],"dependencies":[{"ref":"root","dependsOn":["dep"]}]}"#).unwrap();
        path
    }

    fn sbom_fixture_named(temp: &TempDir, file: &str, application: &str) -> PathBuf {
        let path = temp.path().join(file);
        fs::write(
            &path,
            format!(
                r#"{{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{{"component":{{"type":"application","name":"{application}","version":"1"}}}},"components":[{{"type":"library","bom-ref":"dep","name":"dep","version":"1.0.0","purl":"pkg:cargo/dep@1.0.0"}}]}}"#
            ),
        )
        .unwrap();
        path
    }

    fn policy_fixture(temp: &TempDir, outcome: &str) -> PathBuf {
        let path = temp.path().join("policy.yaml");
        fs::write(&path, format!("version: 1\ndefault_outcome: {outcome}\n")).unwrap();
        path
    }

    fn online_config(temp: &TempDir) -> Config {
        Config {
            offline: false,
            database_path: temp.path().join("scan.db"),
            ..Config::default()
        }
    }

    #[test]
    fn policy_loader_rejects_unknown_extensions() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("policy.json");
        fs::write(&path, "{}").unwrap();
        assert!(matches!(
            load_policy(&path),
            Err(EngineError::UnsupportedPolicyFormat(_))
        ));
    }

    #[test]
    fn baseline_filter_is_stable_and_preserves_first_seen() {
        let id = FindingId::new("finding:one").unwrap();
        let mut current = BTreeMap::from([(id.clone(), minimal_finding(id.clone()))]);
        let mut previous = minimal_report();
        previous
            .findings
            .insert(id, minimal_finding(FindingId::new("finding:one").unwrap()));
        mark_history(&mut current, &previous, "2026-02-01T00:00:00.000Z");
        let finding = current.values().next().unwrap();
        assert_eq!(
            finding.first_seen.as_deref(),
            Some("2026-01-01T00:00:00.000Z")
        );
        assert_eq!(
            finding.last_seen.as_deref(),
            Some("2026-02-01T00:00:00.000Z")
        );
    }

    #[test]
    fn operational_risk_collision_preserves_existing_information() {
        let id = FindingId::new("finding:collision").unwrap();
        let mut existing = minimal_finding(id.clone());
        existing.aliases.insert("CVE-existing".into());
        existing.evidence.insert(Evidence {
            description: "existing evidence".into(),
            locations: BTreeSet::new(),
            references: BTreeSet::new(),
            properties: BTreeMap::new(),
            redacted: false,
        });
        existing.first_seen = Some("2026-01-01T00:00:00.000Z".into());
        existing.last_seen = Some("2026-01-02T00:00:00.000Z".into());
        existing.modified = Some("2026-01-02T00:00:00.000Z".into());

        let mut operational = minimal_finding(id.clone());
        operational.kind = FindingKind::OperationalRisk;
        operational.aliases.insert("operational-alias".into());
        operational.evidence.insert(Evidence {
            description: "operational evidence".into(),
            locations: BTreeSet::new(),
            references: BTreeSet::new(),
            properties: BTreeMap::new(),
            redacted: false,
        });
        operational.first_seen = Some("2026-01-03T00:00:00.000Z".into());
        operational.last_seen = Some("2026-01-04T00:00:00.000Z".into());
        operational.modified = Some("2026-01-04T00:00:00.000Z".into());

        let mut findings = BTreeMap::from([(id.clone(), existing)]);
        merge_finding(&mut findings, operational);
        let merged = findings.get(&id).unwrap();
        assert_eq!(merged.kind, FindingKind::Sast);
        assert_eq!(
            merged.aliases,
            BTreeSet::from(["CVE-existing".into(), "operational-alias".into()])
        );
        assert_eq!(merged.evidence.len(), 2);
        assert_eq!(
            merged.first_seen.as_deref(),
            Some("2026-01-01T00:00:00.000Z")
        );
        assert_eq!(
            merged.last_seen.as_deref(),
            Some("2026-01-04T00:00:00.000Z")
        );
        assert_eq!(merged.modified.as_deref(), Some("2026-01-04T00:00:00.000Z"));
    }

    #[tokio::test]
    async fn filesystem_locations_survive_offline_pipeline_and_persistence() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("project");
        fs::create_dir(&project).unwrap();
        fs::write(
            project.join("Cargo.toml"),
            "[package]\nname='demo'\nversion='1.0.0'\nlicense='MIT'\n",
        )
        .unwrap();
        fs::write(
            project.join("Cargo.lock"),
            "version = 3\n[[package]]\nname='demo'\nversion='1.0.0'\n",
        )
        .unwrap();
        fs::write(
            project.join("sample.py"),
            "subprocess.run(user_input, shell=True)\n",
        )
        .unwrap();
        let policy = temp.path().join("policy.yaml");
        fs::write(&policy, "version: 1\ndefault_outcome: allow\n").unwrap();
        let config = Config {
            offline: true,
            database_path: temp.path().join("scan.db"),
            ..Config::default()
        };
        let input = ScanInput::detect(&project, &config).unwrap();
        let mut store = Store::open(&config.database_path).unwrap();
        let fake = FakeProvider {
            findings: BTreeMap::new(),
        };
        let scanner_report = {
            let mut engine = Engine::new(&config, &mut store, Some(&fake));
            let mut request = ScanRequest::new(input, policy);
            request.run_id = Some(RunId::new("run:offline").unwrap());
            request.as_of = Some("2026-01-01T00:00:00Z".parse().unwrap());
            let report = engine.scan(request).await.unwrap();
            assert_eq!(report.run.id.as_str(), "run:offline");
            assert_eq!(
                report.policy_summary,
                PolicySummary::from_decisions(&report.policy_decisions)
            );
            assert!(
                report
                    .findings
                    .values()
                    .any(|finding| finding.kind == FindingKind::License)
            );
            let sast = report
                .findings
                .values()
                .find(|finding| finding.rule_id.as_str() == "sast.python.shell-true")
                .unwrap();
            let location_id = sast.location_id.as_ref().unwrap();
            let location = report
                .inventory
                .locations
                .iter()
                .find(|location| &location.id == location_id)
                .unwrap();
            assert_eq!(location.path, "sample.py");
            assert!(report.validate().is_ok());
            assert_eq!(report.inventory.components.len(), 1);
            assert!(report.inventory.dependencies.is_empty());

            fs::write(
                project.join("credentials.txt"),
                format!("{}{}", "ghp_", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"),
            )
            .unwrap();
            let input = ScanInput::detect(&project, &config).unwrap();
            let mut request = ScanRequest::new(input, temp.path().join("policy.yaml"));
            request.run_id = Some(RunId::new("run:scanner").unwrap());
            request.as_of = Some("2026-01-02T00:00:00Z".parse().unwrap());
            engine.scan(request).await.unwrap()
        };
        assert!(
            scanner_report
                .findings
                .values()
                .any(|finding| finding.kind == FindingKind::Secret)
        );
        assert!(
            store
                .get_run(&RunId::new("run:offline").unwrap())
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .get_run(&RunId::new("run:scanner").unwrap())
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn policy_loader_reports_invalid_yaml_and_toml() {
        let temp = TempDir::new().unwrap();
        let yaml = temp.path().join("policy.yaml");
        let toml = temp.path().join("policy.toml");
        fs::write(&yaml, "version: [").unwrap();
        fs::write(&toml, "version = [").unwrap();
        assert!(matches!(load_policy(&yaml), Err(EngineError::Policy(_))));
        assert!(matches!(load_policy(&toml), Err(EngineError::Policy(_))));
    }

    #[tokio::test]
    async fn online_pipeline_merges_analyzers_enriches_and_records_metadata() {
        let temp = TempDir::new().unwrap();
        let sbom = sbom_fixture(&temp);
        let policy = policy_fixture(&temp, "allow");
        let config = online_config(&temp);
        let input = ScanInput::detect(&sbom, &config).unwrap();
        let mut store = Store::open(&config.database_path).unwrap();
        let provider = InventoryProvider {
            calls: AtomicUsize::new(0),
        };
        let mut engine = Engine::new(&config, &mut store, Some(&provider));
        let mut request = ScanRequest::new(input, policy.clone());
        request.run_id = Some(RunId::new("run:online").unwrap());
        request.as_of = Some("2026-03-04T05:06:07Z".parse().unwrap());
        let report = engine.scan(request).await.unwrap();

        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        let vulnerability = report
            .findings
            .values()
            .find(|f| f.id.as_str() == "finding:online")
            .unwrap();
        assert!(vulnerability.risk.is_some());
        assert!(vulnerability.applicability.is_some());
        assert!(
            vulnerability
                .evidence
                .iter()
                .any(|e| e.properties.contains_key("remediation.upgrade-plan"))
        );
        assert!(
            report
                .findings
                .values()
                .any(|f| f.kind == FindingKind::License)
        );
        assert!(
            report
                .findings
                .values()
                .any(|f| f.kind == FindingKind::OperationalRisk)
        );
        assert_eq!(report.run.started_at, "2026-03-04T05:06:07.000Z");
        assert_eq!(
            report.run.completed_at.as_deref(),
            Some("2026-03-04T05:06:07.000Z")
        );
        assert_eq!(report.run.metadata["offline"], Value::Bool(false));
        assert_eq!(report.run.metadata["new_findings_only"], Value::Bool(false));
        assert_eq!(
            report.run.metadata["policy"],
            Value::String(policy.display().to_string())
        );
        assert!(
            report.run.metadata["input"]
                .as_str()
                .unwrap()
                .starts_with("sbom:")
        );
    }

    #[tokio::test]
    async fn new_findings_only_uses_latest_for_asset_and_rejects_missing_or_unknown_baseline() {
        let temp = TempDir::new().unwrap();
        let sbom = sbom_fixture(&temp);
        let policy = policy_fixture(&temp, "deny");
        let config = online_config(&temp);
        let provider = InventoryProvider {
            calls: AtomicUsize::new(0),
        };
        let mut store = Store::open(&config.database_path).unwrap();

        let input = ScanInput::detect(&sbom, &config).unwrap();
        let mut engine = Engine::new(&config, &mut store, Some(&provider));
        let mut missing = ScanRequest::new(input, policy.clone());
        missing.new_findings_only = true;
        assert!(matches!(
            engine.scan(missing).await,
            Err(EngineError::MissingBaseline)
        ));

        let input = ScanInput::detect(&sbom, &config).unwrap();
        let mut unknown = ScanRequest::new(input, policy.clone());
        unknown.baseline = Some(RunId::new("run:absent").unwrap());
        assert!(matches!(
            engine.scan(unknown).await,
            Err(EngineError::BaselineNotFound(_))
        ));

        let input = ScanInput::detect(&sbom, &config).unwrap();
        let mut first = ScanRequest::new(input, policy.clone());
        first.run_id = Some(RunId::new("run:first").unwrap());
        first.as_of = Some("2026-01-01T00:00:00Z".parse().unwrap());
        let first_report = engine.scan(first).await.unwrap();
        assert!(first_report.policy_summary.denied > 0);

        let input = ScanInput::detect(&sbom, &config).unwrap();
        let mut latest = ScanRequest::new(input, policy);
        latest.run_id = Some(RunId::new("run:latest").unwrap());
        latest.as_of = Some("2026-02-01T00:00:00Z".parse().unwrap());
        latest.new_findings_only = true;
        let filtered = engine.scan(latest).await.unwrap();
        assert!(filtered.findings.is_empty());
        assert_eq!(filtered.policy_summary.denied, 0);
        assert_eq!(
            filtered.run.metadata["baseline"],
            Value::String("run:first".into())
        );
    }

    #[tokio::test]
    async fn implicit_baseline_ignores_newer_cross_asset_stable_finding() {
        let temp = TempDir::new().unwrap();
        let asset_a = sbom_fixture_named(&temp, "a.cdx.json", "asset-a");
        let asset_b = sbom_fixture_named(&temp, "b.cdx.json", "asset-b");
        let policy = policy_fixture(&temp, "deny");
        let config = online_config(&temp);
        let provider = InventoryProvider {
            calls: AtomicUsize::new(0),
        };
        let mut store = Store::open(&config.database_path).unwrap();
        let mut engine = Engine::new(&config, &mut store, Some(&provider));

        let mut first_a = ScanRequest::new(
            ScanInput::detect(&asset_a, &config).unwrap(),
            policy.clone(),
        );
        first_a.run_id = Some(RunId::new("run:asset-a-first").unwrap());
        first_a.as_of = Some("2026-01-01T00:00:00Z".parse().unwrap());
        let first_a = engine.scan(first_a).await.unwrap();
        assert!(
            first_a
                .findings
                .contains_key(&FindingId::new("finding:online").unwrap())
        );

        let mut newer_b = ScanRequest::new(
            ScanInput::detect(&asset_b, &config).unwrap(),
            policy.clone(),
        );
        newer_b.run_id = Some(RunId::new("run:asset-b-newer").unwrap());
        newer_b.as_of = Some("2026-02-01T00:00:00Z".parse().unwrap());
        engine.scan(newer_b).await.unwrap();

        let mut latest_a = ScanRequest::new(ScanInput::detect(&asset_a, &config).unwrap(), policy);
        latest_a.run_id = Some(RunId::new("run:asset-a-latest").unwrap());
        latest_a.as_of = Some("2026-03-01T00:00:00Z".parse().unwrap());
        latest_a.new_findings_only = true;
        let filtered = engine.scan(latest_a).await.unwrap();

        assert!(filtered.findings.is_empty());
        assert_eq!(
            filtered.run.metadata["baseline"],
            Value::String("run:asset-a-first".into())
        );
    }

    #[tokio::test]
    async fn explicit_baseline_rejects_different_asset_identity() {
        let temp = TempDir::new().unwrap();
        let asset_a = sbom_fixture_named(&temp, "a-explicit.cdx.json", "asset-a");
        let asset_b = sbom_fixture_named(&temp, "b-explicit.cdx.json", "asset-b");
        let policy = policy_fixture(&temp, "deny");
        let config = online_config(&temp);
        let provider = InventoryProvider {
            calls: AtomicUsize::new(0),
        };
        let mut store = Store::open(&config.database_path).unwrap();
        let mut engine = Engine::new(&config, &mut store, Some(&provider));

        let mut baseline = ScanRequest::new(
            ScanInput::detect(&asset_b, &config).unwrap(),
            policy.clone(),
        );
        baseline.run_id = Some(RunId::new("run:asset-b-explicit").unwrap());
        engine.scan(baseline).await.unwrap();

        let mut current = ScanRequest::new(ScanInput::detect(&asset_a, &config).unwrap(), policy);
        current.baseline = Some(RunId::new("run:asset-b-explicit").unwrap());
        current.new_findings_only = true;
        assert!(matches!(
            engine.scan(current).await,
            Err(EngineError::BaselineAssetMismatch { run_id, .. })
                if run_id.as_str() == "run:asset-b-explicit"
        ));
    }

    #[tokio::test]
    async fn duplicate_run_id_surfaces_persistence_failure() {
        let temp = TempDir::new().unwrap();
        let sbom = sbom_fixture(&temp);
        let policy = policy_fixture(&temp, "allow");
        let config = Config {
            offline: true,
            database_path: temp.path().join("scan.db"),
            ..Config::default()
        };
        let mut store = Store::open(&config.database_path).unwrap();
        let fake = FakeProvider {
            findings: BTreeMap::new(),
        };
        let id = RunId::new("run:duplicate").unwrap();
        for expected_error in [false, true] {
            let input = ScanInput::detect(&sbom, &config).unwrap();
            let mut request = ScanRequest::new(input, policy.clone());
            request.run_id = Some(id.clone());
            let result = Engine::new(&config, &mut store, Some(&fake))
                .scan(request)
                .await;
            if expected_error {
                assert!(matches!(result, Err(EngineError::Store(_))));
            } else {
                result.unwrap();
            }
        }
    }

    fn minimal_report() -> ScanReport {
        ScanReport {
            schema_version: "1".to_owned(),
            run: RunMetadata {
                id: RunId::new("run:baseline").unwrap(),
                started_at: "2026-01-01T00:00:00.000Z".to_owned(),
                completed_at: None,
                scanner_version: None,
                metadata: BTreeMap::new(),
            },
            inventory: Inventory {
                asset: Asset {
                    id: AssetId::new("asset:test").unwrap(),
                    name: "test".to_owned(),
                    kind: AssetKind::Sbom,
                    version: None,
                    metadata: BTreeMap::new(),
                },
                components: BTreeMap::new(),
                locations: BTreeSet::new(),
                dependencies: BTreeSet::new(),
            },
            findings: BTreeMap::new(),
            policy_decisions: BTreeSet::new(),
            policy_summary: PolicySummary::default(),
        }
    }

    fn minimal_finding(id: FindingId) -> Finding {
        serde_json::from_value(json!({
            "id": id,
            "kind": "sast",
            "rule_id": "rule:test",
            "severity": "low",
            "confidence": "high",
            "status": "open"
        }))
        .unwrap()
    }
}
