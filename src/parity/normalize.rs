//! Normalizes a hooray [`ScanReport`] into the parity canonical model.
//!
//! Field mapping (verified against `src/model.rs`, `src/license.rs`, and
//! `src/osv.rs`):
//!
//! * components come straight from the inventory; directness reuses
//!   [`DependencyGraph::classify`] instead of recomputing graph logic;
//! * vulnerability findings carry the OSV id in `advisory_id` (primary id),
//!   CVE/GHSA aliases in `aliases`, and fixed versions under
//!   `remediation.fixed_versions`;
//! * a CVE-shaped primary advisory id is additionally counted into `cves`;
//!   without this an advisory whose id *is* the CVE would vanish from all
//!   CVE-keyed metrics because OSV does not always repeat it as an alias;
//! * license findings take their path from evidence `path` properties
//!   (text-detected licenses) or the first resolvable evidence location
//!   (declared licenses), and their expression from the finding alias set
//!   (`license.rs` stores the SPDX expression there) with the evidence
//!   property as fallback.
//!
//! Parse errors never appear on the hooray side: input failures abort a scan
//! entirely (fail-closed), so the CLI reports them as operational errors.

use std::collections::{BTreeMap, BTreeSet};

use crate::graph::DependencyGraph;
use crate::model::{
    DependencyKind, Finding, FindingKind, Inventory, License, Location, LocationId, ScanReport,
    Scope,
};

use crate::parity::compare::ecosystem_of_purl;
use crate::parity::model::{
    CANONICAL_SCHEMA_VERSION, CanonicalComponent, CanonicalLicenseFinding, CanonicalReport,
    CanonicalVuln, Generator, ParityError, sorted_unique,
};

/// Hooray generator identity used in canonical output.
pub fn hooray_generator() -> Generator {
    Generator {
        name: "hooray".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    }
}

fn scope_label(scope: Scope) -> &'static str {
    match scope {
        Scope::Runtime => "runtime",
        Scope::Build => "build",
        Scope::Development => "development",
        Scope::Test => "test",
        Scope::Optional => "optional",
        Scope::Unknown => "unknown",
    }
}

fn directness_label(kind: DependencyKind) -> &'static str {
    match kind {
        DependencyKind::Direct => "direct",
        DependencyKind::Transitive => "transitive",
        DependencyKind::Disconnected => "disconnected",
    }
}

/// Severity rank used to pick the strongest label when several findings share
/// one primary advisory id.
fn severity_rank_of(label: &str) -> u8 {
    match label {
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => 0,
    }
}

/// License string precedence matches `license.rs`: SPDX expression first,
/// then name, then URL.
fn license_strings(licenses: &BTreeSet<License>) -> Vec<String> {
    sorted_unique(licenses.iter().filter_map(|license| {
        license
            .expression
            .clone()
            .or_else(|| license.name.clone())
            .or_else(|| license.url.clone())
    }))
}

fn location_index(inventory: &Inventory) -> BTreeMap<&LocationId, &Location> {
    let mut index = BTreeMap::new();
    for location in &inventory.locations {
        index.insert(&location.id, location);
    }
    for component in inventory.components.values() {
        for location in &component.locations {
            index.insert(&location.id, location);
        }
    }
    index
}

/// Resolves canonical `(path, expression, detector)` triples for one license
/// finding. Hooray fuses multiple detected license files on a component into
/// a single finding (identical identity inputs), so per-file expressions are
/// only recoverable when exactly one path-bearing evidence block exists;
/// otherwise each file keeps its verbatim detector string with an `unknown`
/// expression. Declared-license findings carry no path property and fall
/// back to the location-derived path plus alias/expression resolution.
fn license_finding_triples(
    finding: &Finding,
    locations: &BTreeMap<&LocationId, &Location>,
) -> Vec<(String, String, Option<String>)> {
    let mut paths = Vec::new();
    let mut detectors = Vec::new();
    for evidence in &finding.evidence {
        if let Some(path) = evidence.properties.get("path") {
            paths.push(path.clone());
            detectors.push(evidence.properties.get("detector").cloned());
        }
    }
    if paths.len() > 1 {
        return paths
            .into_iter()
            .zip(detectors)
            .map(|(path, detector)| (path, "unknown".to_owned(), detector))
            .collect();
    }
    let detector = (!paths.is_empty())
        .then(|| detectors.into_iter().flatten().next())
        .flatten();
    let path = license_finding_path(finding, locations);
    vec![(path, license_finding_expression(finding), detector)]
}

/// Resolves the file path attributed to a license finding: explicit evidence
/// `path` properties win, otherwise the first resolvable evidence location.
fn license_finding_path(finding: &Finding, locations: &BTreeMap<&LocationId, &Location>) -> String {
    for evidence in &finding.evidence {
        if let Some(path) = evidence.properties.get("path") {
            return path.clone();
        }
    }
    let mut location_ids: BTreeSet<&LocationId> = finding
        .evidence
        .iter()
        .flat_map(|evidence| evidence.locations.iter())
        .collect();
    if let Some(location_id) = &finding.location_id {
        location_ids.insert(location_id);
    }
    for location_id in location_ids {
        if let Some(location) = locations.get(location_id) {
            return location.path.clone();
        }
    }
    String::new()
}

/// Expression extraction mirrors `license.rs`: the alias set carries the SPDX
/// expression; declared-license evidence repeats it as a property. Findings
/// without any expression (unknown license text) use the literal `unknown`.
fn license_finding_expression(finding: &Finding) -> String {
    if let Some(alias) = finding.aliases.iter().next() {
        return alias.clone();
    }
    for evidence in &finding.evidence {
        if let Some(expression) = evidence.properties.get("expression") {
            return expression.clone();
        }
    }
    "unknown".to_owned()
}

#[derive(Default)]
struct VulnAccumulator {
    severity_rank: u8,
    severity_label: String,
    aliases: BTreeSet<String>,
    cves: BTreeSet<String>,
    affected_purls: BTreeSet<String>,
    fixed_versions: BTreeSet<String>,
}

impl VulnAccumulator {
    // Severity accumulates as MAX rank across every finding sharing an
    // advisory id. Xray's normalizer instead keeps the first-seen
    // non-empty label per issue, so when a provider reports conflicting
    // severities for one advisory the two sides can legitimately
    // disagree on the label; that asymmetry is accepted because the
    // scorecard compares vulnerability identity sets, not labels.
    fn push(&mut self, finding: &Finding, purl: Option<String>) {
        let label = finding.severity.as_str().to_owned();
        let rank = severity_rank_of(&label);
        if rank > self.severity_rank {
            self.severity_rank = rank;
            self.severity_label = label;
        }
        let primary = finding.advisory_id.as_deref().unwrap_or_default();
        for alias in &finding.aliases {
            if alias != primary {
                self.aliases.insert(alias.clone());
            }
            if alias.starts_with("CVE-") {
                self.cves.insert(alias.clone());
            }
        }
        // A CVE-shaped primary id counts as a CVE even when OSV did not list
        // it among the aliases (see module docs).
        if primary.starts_with("CVE-") {
            self.cves.insert(primary.to_owned());
        }
        if let Some(purl) = purl {
            self.affected_purls.insert(purl);
        }
        if let Some(remediation) = &finding.remediation {
            self.fixed_versions
                .extend(remediation.fixed_versions.iter().cloned());
        }
    }
}

/// Converts a validated engine report into canonical form.
///
/// `scan_mode` is supplied by the caller (`offline` or `osv-live`) because the
/// normalizer must not second-guess how the report was produced.
pub fn normalize_hooray(
    report: &ScanReport,
    case_id: &str,
    scan_mode: &str,
) -> Result<CanonicalReport, ParityError> {
    let graph = DependencyGraph::from_inventory(&report.inventory)?;
    let locations = location_index(&report.inventory);

    let mut components = Vec::new();
    for component in report.inventory.components.values() {
        let directness = graph.classify(&component.identity)?;
        components.push(CanonicalComponent {
            purl: component.purl.clone(),
            name: component.name.clone(),
            version: component.version.clone(),
            ecosystem: ecosystem_of_purl(&component.purl),
            licenses: license_strings(&component.licenses),
            scope: scope_label(component.scope).to_owned(),
            directness: directness_label(directness).to_owned(),
        });
    }
    components.sort();

    let mut accumulators: BTreeMap<String, VulnAccumulator> = BTreeMap::new();
    let mut license_triples: BTreeSet<(String, String, Option<String>)> = BTreeSet::new();
    for finding in report.findings.values() {
        match finding.kind {
            FindingKind::Vulnerability => {
                // Advisory-id-less vulnerabilities are intentionally
                // skipped: Xray keys every advisory by its issue id, so a
                // hooray finding without one has no comparison counterpart
                // and cannot be aggregated under a deterministic key.
                let Some(primary_id) = finding.advisory_id.clone() else {
                    continue;
                };
                let purl = finding
                    .component_id
                    .as_ref()
                    .and_then(|id| report.inventory.components.get(id))
                    .map(|component| component.purl.clone());
                accumulators
                    .entry(primary_id)
                    .or_default()
                    .push(finding, purl);
            }
            FindingKind::License => {
                for (path, expression, detector) in license_finding_triples(finding, &locations) {
                    license_triples.insert((path, expression, detector));
                }
            }
            _ => {}
        }
    }

    let vulnerabilities = accumulators
        .into_iter()
        .map(|(primary_id, acc)| CanonicalVuln {
            aliases: sorted_unique(acc.aliases),
            cves: sorted_unique(acc.cves),
            affected_purls: sorted_unique(acc.affected_purls),
            fixed_versions: sorted_unique(acc.fixed_versions),
            primary_id,
            severity_label: acc.severity_label,
        })
        .collect();

    let license_findings = license_triples
        .into_iter()
        .map(|(path, expression, detector)| CanonicalLicenseFinding {
            path,
            expression,
            detector,
        })
        .collect();

    Ok(CanonicalReport {
        schema_version: CANONICAL_SCHEMA_VERSION,
        case_id: case_id.to_owned(),
        generator: hooray_generator(),
        scan_mode: scan_mode.to_owned(),
        components,
        vulnerabilities,
        license_findings,
        parse_errors: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Asset, AssetId, Component, DependencyEdge, Evidence, Remediation, RuleId, RunId,
        RunMetadata, Severity, stable_component_id, stable_finding_id, stable_location_id,
    };

    fn base_inventory() -> Inventory {
        let asset_id = AssetId::new("asset:test").unwrap();
        let location = Location {
            id: stable_location_id(&asset_id, "./Cargo.lock", None).unwrap(),
            asset_id: asset_id.clone(),
            path: "./Cargo.lock".to_owned(),
            start: None,
            end: None,
        };
        let root_identity = stable_component_id("pkg:cargo/hooray-app@1.0.0").unwrap();
        let dep_identity = stable_component_id("pkg:npm/lodash@4.17.15").unwrap();
        let root = Component {
            identity: root_identity.clone(),
            name: "hooray-app".to_owned(),
            version: "1.0.0".to_owned(),
            purl: "pkg:cargo/hooray-app@1.0.0".to_owned(),
            scope: Scope::Runtime,
            provenance: Default::default(),
            licenses: BTreeSet::from([License {
                expression: Some("MIT OR Apache-2.0".to_owned()),
                name: None,
                url: None,
            }]),
            locations: BTreeSet::from([location]),
        };
        let dep = Component {
            identity: dep_identity.clone(),
            name: "lodash".to_owned(),
            version: "4.17.15".to_owned(),
            purl: "pkg:npm/lodash@4.17.15".to_owned(),
            scope: Scope::Runtime,
            provenance: Default::default(),
            licenses: BTreeSet::from([License {
                expression: None,
                name: Some("MIT".to_owned()),
                url: None,
            }]),
            locations: BTreeSet::new(),
        };
        Inventory {
            asset: Asset {
                id: asset_id,
                name: "test".to_owned(),
                kind: Default::default(),
                version: None,
                metadata: Default::default(),
            },
            components: BTreeMap::from([(root_identity, root), (dep_identity, dep)]),
            locations: BTreeSet::new(),
            dependencies: BTreeSet::from([DependencyEdge {
                from: stable_component_id("pkg:cargo/hooray-app@1.0.0").unwrap(),
                to: stable_component_id("pkg:npm/lodash@4.17.15").unwrap(),
                scope: Scope::Runtime,
                optional: false,
            }]),
        }
    }

    fn run_metadata() -> RunMetadata {
        RunMetadata {
            id: RunId::new("run:pinned-normalize-test").unwrap(),
            started_at: "2026-01-01T00:00:00Z".to_owned(),
            completed_at: None,
            scanner_version: None,
            metadata: Default::default(),
        }
    }

    fn report_with(inventory: Inventory, findings: Vec<Finding>) -> ScanReport {
        ScanReport {
            schema_version: "1".to_owned(),
            run: run_metadata(),
            inventory,
            findings: findings
                .into_iter()
                .map(|finding| (finding.id.clone(), finding))
                .collect(),
            policy_decisions: Default::default(),
            policy_summary: Default::default(),
        }
    }

    fn vuln_finding(component_id: crate::model::ComponentId) -> Finding {
        let rule = RuleId::new("osv:match").unwrap();
        Finding {
            id: stable_finding_id(FindingKind::Vulnerability, &rule, Some(&component_id), None),
            kind: FindingKind::Vulnerability,
            rule_id: rule,
            advisory_id: Some("GHSA-test-abcd".to_owned()),
            component_id: Some(component_id),
            location_id: None,
            aliases: BTreeSet::from(["CVE-2026-1234".to_owned(), "GHSA-test-abcd".to_owned()]),
            summary: None,
            details: None,
            severity: Severity::High,
            confidence: Default::default(),
            evidence: BTreeSet::new(),
            applicability: None,
            remediation: Some(Remediation {
                description: "upgrade".to_owned(),
                fixed_versions: BTreeSet::from(["4.17.21".to_owned()]),
                references: Default::default(),
            }),
            risk: None,
            first_seen: None,
            last_seen: None,
            modified: None,
            status: Default::default(),
        }
    }

    #[test]
    fn classifies_directness_and_ecosystems() {
        let canonical = normalize_hooray(
            &report_with(base_inventory(), Vec::new()),
            "case-a",
            "offline",
        )
        .unwrap();
        assert_eq!(canonical.case_id, "case-a");
        assert_eq!(canonical.scan_mode, "offline");
        assert_eq!(canonical.generator.name, "hooray");
        assert_eq!(canonical.components.len(), 2);
        assert!(canonical.components.is_sorted());
        let lodash = canonical
            .components
            .iter()
            .find(|c| c.ecosystem == "npm")
            .unwrap();
        assert_eq!(lodash.directness, "direct"); // one edge below the root
        let app = canonical
            .components
            .iter()
            .find(|c| c.ecosystem == "cargo")
            .unwrap();
        // Connected roots sit at depth 0, which classify reports as
        // "disconnected" (only reachable deps get Direct/Transitive).
        assert_eq!(app.directness, "disconnected");
        assert_eq!(app.licenses, vec!["MIT OR Apache-2.0".to_owned()]);
        assert_eq!(lodash.licenses, vec!["MIT".to_owned()]);
        assert_eq!(canonical.parse_errors.len(), 0);
    }

    #[test]
    fn maps_vulnerability_and_declared_license_findings() {
        let inventory = base_inventory();
        let dep_id = stable_component_id("pkg:npm/lodash@4.17.15").unwrap();
        let root_id = stable_component_id("pkg:cargo/hooray-app@1.0.0").unwrap();
        let license_rule = RuleId::new("license:detected").unwrap();
        let location_id = inventory
            .components
            .get(&root_id)
            .unwrap()
            .locations
            .iter()
            .next()
            .unwrap()
            .id
            .clone();
        let license_finding = Finding {
            id: stable_finding_id(FindingKind::License, &license_rule, Some(&root_id), None),
            kind: FindingKind::License,
            rule_id: license_rule,
            advisory_id: None,
            component_id: Some(root_id),
            location_id: None,
            aliases: BTreeSet::from(["MIT OR Apache-2.0".to_owned()]),
            summary: None,
            details: None,
            severity: Severity::Low,
            confidence: Default::default(),
            evidence: BTreeSet::from([Evidence {
                description: "declared".to_owned(),
                locations: BTreeSet::from([location_id]),
                references: Default::default(),
                properties: Default::default(),
                redacted: false,
            }]),
            applicability: None,
            remediation: None,
            risk: None,
            first_seen: None,
            last_seen: None,
            modified: None,
            status: Default::default(),
        };
        let canonical = normalize_hooray(
            &report_with(inventory, vec![vuln_finding(dep_id), license_finding]),
            "case-b",
            "osv-live",
        )
        .unwrap();
        assert_eq!(canonical.vulnerabilities.len(), 1);
        let vuln = &canonical.vulnerabilities[0];
        assert_eq!(vuln.primary_id, "GHSA-test-abcd");
        assert_eq!(vuln.cves, vec!["CVE-2026-1234".to_owned()]);
        assert!(!vuln.aliases.contains(&"GHSA-test-abcd".to_owned()));
        assert_eq!(
            vuln.affected_purls,
            vec!["pkg:npm/lodash@4.17.15".to_owned()]
        );
        assert_eq!(vuln.fixed_versions, vec!["4.17.21".to_owned()]);
        assert_eq!(vuln.severity_label, "high");

        assert_eq!(canonical.license_findings.len(), 1);
        assert_eq!(
            canonical.license_findings[0].expression,
            "MIT OR Apache-2.0"
        );
        assert_eq!(canonical.license_findings[0].path, "./Cargo.lock");
    }

    #[test]
    fn text_detected_license_path_comes_from_evidence_property() {
        let rule = RuleId::new("license:detected").unwrap();
        let root_id = stable_component_id("pkg:cargo/hooray-app@1.0.0").unwrap();
        let finding = Finding {
            id: stable_finding_id(FindingKind::License, &rule, Some(&root_id), None),
            kind: FindingKind::License,
            rule_id: rule,
            advisory_id: None,
            component_id: Some(root_id),
            location_id: None,
            aliases: BTreeSet::new(),
            summary: None,
            details: None,
            severity: Severity::Low,
            confidence: Default::default(),
            evidence: BTreeSet::from([Evidence {
                description: "LICENSE matched MIT canonical clauses".to_owned(),
                locations: BTreeSet::new(),
                references: Default::default(),
                properties: BTreeMap::from([
                    ("path".to_owned(), "./LICENSE".to_owned()),
                    ("detector".to_owned(), "MIT canonical clauses".to_owned()),
                ]),
                redacted: false,
            }]),
            applicability: None,
            remediation: None,
            risk: None,
            first_seen: None,
            last_seen: None,
            modified: None,
            status: Default::default(),
        };
        let canonical = normalize_hooray(
            &report_with(base_inventory(), vec![finding]),
            "case-c",
            "offline",
        )
        .unwrap();
        assert_eq!(
            canonical.license_findings,
            vec![CanonicalLicenseFinding {
                path: "./LICENSE".to_owned(),
                expression: "unknown".to_owned(),
                detector: Some("MIT canonical clauses".to_owned()),
            }]
        );
    }

    #[test]
    fn fused_multi_file_license_detection_keeps_per_file_detectors() {
        let rule = RuleId::new("license:detected").unwrap();
        let root_id = stable_component_id("pkg:cargo/hooray-app@1.0.0").unwrap();
        // Hooray fuses detections of multiple license files on one component
        // into a single finding; only the first alias survives. The
        // canonical form must keep one entry per file with its verbatim
        // detector string instead of fabricating per-file expressions.
        let finding = Finding {
            id: stable_finding_id(FindingKind::License, &rule, Some(&root_id), None),
            kind: FindingKind::License,
            rule_id: rule,
            advisory_id: None,
            component_id: Some(root_id),
            location_id: None,
            aliases: BTreeSet::from(["BSD-2-Clause".to_owned()]),
            summary: Some("License file suggests BSD-2-Clause".to_owned()),
            details: None,
            severity: Severity::Low,
            confidence: Default::default(),
            evidence: BTreeSet::from([
                Evidence {
                    description: "COPYING matched BSD redistribution clauses".to_owned(),
                    locations: BTreeSet::new(),
                    references: Default::default(),
                    properties: BTreeMap::from([
                        ("path".to_owned(), "COPYING".to_owned()),
                        (
                            "detector".to_owned(),
                            "BSD redistribution clauses".to_owned(),
                        ),
                    ]),
                    redacted: false,
                },
                Evidence {
                    description: "LICENSE matched MIT canonical clauses".to_owned(),
                    locations: BTreeSet::new(),
                    references: Default::default(),
                    properties: BTreeMap::from([
                        ("path".to_owned(), "LICENSE".to_owned()),
                        ("detector".to_owned(), "MIT canonical clauses".to_owned()),
                    ]),
                    redacted: false,
                },
            ]),
            applicability: None,
            remediation: None,
            risk: None,
            first_seen: None,
            last_seen: None,
            modified: None,
            status: Default::default(),
        };
        let canonical = normalize_hooray(
            &report_with(base_inventory(), vec![finding]),
            "case-e",
            "offline",
        )
        .unwrap();
        assert_eq!(
            canonical.license_findings,
            vec![
                CanonicalLicenseFinding {
                    path: "COPYING".to_owned(),
                    expression: "unknown".to_owned(),
                    detector: Some("BSD redistribution clauses".to_owned()),
                },
                CanonicalLicenseFinding {
                    path: "LICENSE".to_owned(),
                    expression: "unknown".to_owned(),
                    detector: Some("MIT canonical clauses".to_owned()),
                },
            ]
        );
    }

    #[test]
    fn cve_shaped_primary_id_counts_into_cves() {
        let dep_id = stable_component_id("pkg:npm/lodash@4.17.15").unwrap();
        let mut finding = vuln_finding(dep_id);
        finding.advisory_id = Some("CVE-2026-9999".to_owned());
        finding.aliases = BTreeSet::new(); // no CVE alias repeated by OSV
        finding.remediation = None;
        finding.severity = Severity::Medium;
        let canonical = normalize_hooray(
            &report_with(base_inventory(), vec![finding]),
            "case-d",
            "offline",
        )
        .unwrap();
        assert_eq!(canonical.vulnerabilities[0].cves, vec!["CVE-2026-9999"]);
        assert!(canonical.vulnerabilities[0].aliases.is_empty());
    }
}
