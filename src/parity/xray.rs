//! Normalizes JFrog Xray artifacts into the parity canonical model.
//!
//! Two tolerant input formats are supported:
//!
//! 1. **JFrog CLI audit JSON** (`jf audit --format json`): an array of scan
//!    response objects, each optionally carrying `vulnerabilities`. Every
//!    entry is walked defensively; unexpected shapes are counted in
//!    [`ParseSummary::skipped_entries`] with a reason instead of failing.
//! 2. **CycloneDX SBOM** (`jf audit --format cyclonedx`): typed minimal
//!    structs provide the full component inventory and licenses.
//!
//! When both artifacts are supplied, inventory and licenses come from the
//! SBOM side and vulnerabilities from the audit side; component references
//! inside vulnerabilities (`name:version` keys) are resolved against the SBOM
//! inventory by exact name/version. With no SBOM present, audit-only
//! components are synthesized as `pkg:generic/<name>@<version>` purls so the
//! canonical report still carries a usable (if ecosystem-less) inventory.
//!
//! Unknown fields never abort parsing; only structurally unusable entries are
//! skipped and reported.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::parity::compare::{ecosystem_of_purl, purl_match_key};
use crate::parity::model::{
    CanonicalComponent, CanonicalReport, CanonicalVuln, Generator, ParityError, sorted_unique,
};

/// Tolerant-parsing statistics for one Xray normalization run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseSummary {
    /// Components that made it into the canonical report.
    pub returned_components: usize,
    /// Vulnerabilities that made it into the canonical report.
    pub returned_vulnerabilities: usize,
    /// Entries skipped because their shape was unusable.
    pub skipped_entries: usize,
    /// Reasons for every skipped entry, in encounter order.
    pub skip_reasons: Vec<String>,
}

impl ParseSummary {
    fn skip(&mut self, reason: String) {
        self.skipped_entries += 1;
        self.skip_reasons.push(reason);
    }
}

/// The two optional Xray artifacts for one case.
#[derive(Debug, Clone, Copy, Default)]
pub struct XrayArtifacts<'a> {
    /// Contents of the `jf audit --format json` output, if captured.
    pub audit_json: Option<&'a str>,
    /// Contents of the `jf audit --format cyclonedx` output, if captured.
    pub sbom_json: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
struct CdxDocument {
    #[serde(default)]
    components: Vec<CdxComponent>,
}

#[derive(Debug, Deserialize)]
struct CdxComponent {
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    purl: Option<String>,
    #[serde(default)]
    licenses: Vec<CdxLicenseChoice>,
}

#[derive(Debug, Deserialize)]
struct CdxLicenseChoice {
    #[serde(default)]
    license: Option<CdxLicenseInfo>,
    #[serde(default)]
    expression: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CdxLicenseInfo {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

impl CdxLicenseChoice {
    fn label(&self) -> Option<String> {
        if let Some(expression) = &self.expression {
            return Some(expression.clone());
        }
        let info = self.license.as_ref()?;
        info.id.clone().or_else(|| info.name.clone())
    }
}

fn generic_purl(name: &str, version: &str) -> String {
    format!(
        "pkg:generic/{}@{}",
        crate::util::percent_encode(name, crate::util::is_purl_byte),
        version
    )
}

fn severity_label(raw: Option<&str>) -> String {
    match raw.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("low") => "low".to_owned(),
        Some("medium") => "medium".to_owned(),
        Some("high") => "high".to_owned(),
        Some("critical") => "critical".to_owned(),
        _ => "unknown".to_owned(),
    }
}

#[derive(Default)]
struct VulnAccumulator {
    severity_label: String,
    aliases: BTreeSet<String>,
    cves: BTreeSet<String>,
    affected_purls: BTreeSet<String>,
    fixed_versions: BTreeSet<String>,
}

/// Collects string arrays tolerantly: plain strings and `{cve: …}`-style
/// objects both contribute their first string value.
fn collect_strings(value: Option<&Value>, key: &str) -> Vec<String> {
    let Some(Value::Array(items)) = value else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| match item {
            Value::String(text) => Some(text.clone()),
            Value::Object(map) => map.get(key).and_then(Value::as_str).map(str::to_owned),
            _ => None,
        })
        .collect()
}

/// Extracts `(name, version)` component references from either an object map
/// keyed `name:version` or an array of `{name, version?, fixed_versions?}`.
fn extract_component_refs(value: Option<&Value>) -> Vec<(String, String, Vec<String>)> {
    let Some(value) = value else {
        return Vec::new();
    };
    match value {
        Value::Object(map) => map
            .iter()
            .map(|(key, entry)| {
                let (name, version) = match key.rsplit_once(':') {
                    Some((name, version)) => (name.to_owned(), version.to_owned()),
                    None => (key.clone(), String::new()),
                };
                let fixed = collect_strings(entry.get("fixed_versions"), "fixed_versions");
                (name, version, fixed)
            })
            .collect(),
        Value::Array(items) => items
            .iter()
            .filter_map(|item| {
                let object = item.as_object()?;
                let name = object.get("name").and_then(Value::as_str)?;
                let version = object
                    .get("version")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let fixed = collect_strings(object.get("fixed_versions"), "fixed_versions");
                Some((name.to_owned(), version.to_owned(), fixed))
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn parse_audit_vulnerabilities(
    document: &Value,
    summary: &mut ParseSummary,
    accumulators: &mut BTreeMap<String, VulnAccumulator>,
    resolve: impl Fn(&str, &str) -> Option<String>,
    synthesize_components: &mut BTreeMap<String, CanonicalComponent>,
) {
    let entries: Vec<&Value> = match document {
        Value::Array(items) => items.iter().collect(),
        Value::Object(_) => vec![document],
        other => {
            summary.skip(format!(
                "audit root was {other:?}, expected array or object"
            ));
            return;
        }
    };
    for entry in entries {
        let Some(response) = entry.as_object() else {
            summary.skip("audit entry was not an object".to_owned());
            continue;
        };
        let Some(vulnerabilities) = response.get("vulnerabilities") else {
            // A response without vulnerabilities is not an error; it simply
            // contributes nothing.
            continue;
        };
        let Some(vulnerabilities) = vulnerabilities.as_array() else {
            summary.skip("'vulnerabilities' was not an array".to_owned());
            continue;
        };
        for vulnerability in vulnerabilities {
            let Some(vuln) = vulnerability.as_object() else {
                summary.skip("vulnerability entry was not an object".to_owned());
                continue;
            };
            let Some(issue_id) = vuln.get("issue_id").and_then(Value::as_str) else {
                summary.skip("vulnerability without 'issue_id'".to_owned());
                continue;
            };
            let accumulator = accumulators.entry(issue_id.to_owned()).or_default();
            if accumulator.severity_label.is_empty() {
                accumulator.severity_label =
                    severity_label(vuln.get("severity").and_then(Value::as_str));
            }
            for cve in collect_strings(vuln.get("cves"), "cve") {
                accumulator.cves.insert(cve.clone());
                accumulator.aliases.insert(cve);
            }
            for alias in collect_strings(vuln.get("aliases"), "alias") {
                accumulator.aliases.insert(alias);
            }
            for (name, version, fixed) in extract_component_refs(vuln.get("components")) {
                if let Some(purl) = resolve(&name, &version) {
                    accumulator.affected_purls.insert(purl);
                } else {
                    let purl = generic_purl(&name, &version);
                    summary.skip(format!(
                        "component reference '{name}:{version}' resolved to synthesized {purl}"
                    ));
                    accumulator.affected_purls.insert(purl.clone());
                    synthesize_components
                        .entry(purl_match_key(&purl))
                        .or_insert_with(|| CanonicalComponent {
                            purl: purl.clone(),
                            name: name.clone(),
                            version: version.clone(),
                            ecosystem: "generic".to_owned(),
                            licenses: Vec::new(),
                            scope: "unknown".to_owned(),
                            directness: "disconnected".to_owned(),
                        });
                }
                accumulator.fixed_versions.extend(fixed);
            }
        }
    }
}

/// Builds the xray-side canonical report from the supplied artifacts.
///
/// At least one artifact must be present. The returned [`ParseSummary`] always
/// describes what was consumed and what was skipped.
pub fn build_xray_canonical(
    case_id: &str,
    cli_version: Option<&str>,
    artifacts: &XrayArtifacts<'_>,
) -> Result<(CanonicalReport, ParseSummary), ParityError> {
    if artifacts.audit_json.is_none() && artifacts.sbom_json.is_none() {
        return Err(ParityError::InvalidInput(
            "at least one of --xray-json or --xray-sbom is required".to_owned(),
        ));
    }
    let mut summary = ParseSummary::default();

    // Inventory from the SBOM side, deconflicted by purl match key.
    let mut components: BTreeMap<String, CanonicalComponent> = BTreeMap::new();
    let mut by_name_version: BTreeMap<(String, String), String> = BTreeMap::new();
    if let Some(sbom) = artifacts.sbom_json {
        let document: CdxDocument = serde_json::from_str(sbom)?;
        for raw in document.components {
            summary.returned_components += 1;
            let purl = raw.purl.clone().unwrap_or_else(|| {
                generic_purl(&raw.name, raw.version.as_deref().unwrap_or_default())
            });
            let licenses = sorted_unique(raw.licenses.iter().filter_map(CdxLicenseChoice::label));
            let component = CanonicalComponent {
                ecosystem: ecosystem_of_purl(&purl),
                version: raw.version.clone().unwrap_or_default(),
                purl: purl.clone(),
                name: raw.name,
                licenses,
                scope: "runtime".to_owned(),
                directness: "disconnected".to_owned(),
            };
            components
                .entry(purl_match_key(&purl))
                .and_modify(|existing| {
                    let merged = sorted_unique(
                        existing
                            .licenses
                            .iter()
                            .cloned()
                            .chain(component.licenses.iter().cloned()),
                    );
                    existing.licenses = merged;
                })
                .or_insert(component);
        }
        for component in components.values() {
            by_name_version.insert(
                (
                    component.name.to_ascii_lowercase(),
                    component.version.clone(),
                ),
                component.purl.clone(),
            );
        }
    }

    let sbom_present = !components.is_empty() || artifacts.sbom_json.is_some();
    let resolve = |name: &str, version: &str| -> Option<String> {
        if sbom_present {
            by_name_version
                .get(&(name.to_ascii_lowercase(), version.to_owned()))
                .cloned()
        } else {
            None
        }
    };

    let mut accumulators: BTreeMap<String, VulnAccumulator> = BTreeMap::new();
    let mut synthesized: BTreeMap<String, CanonicalComponent> = BTreeMap::new();
    if let Some(audit) = artifacts.audit_json {
        let document: Value = serde_json::from_str(audit)?;
        parse_audit_vulnerabilities(
            &document,
            &mut summary,
            &mut accumulators,
            resolve,
            &mut synthesized,
        );
    }
    for (key, component) in synthesized {
        components.entry(key).or_insert(component);
    }

    let vulnerabilities: Vec<CanonicalVuln> = accumulators
        .into_iter()
        .map(|(primary_id, acc)| {
            summary.returned_vulnerabilities += 1;
            CanonicalVuln {
                aliases: sorted_unique(acc.aliases),
                cves: sorted_unique(acc.cves),
                affected_purls: sorted_unique(acc.affected_purls),
                fixed_versions: sorted_unique(acc.fixed_versions),
                primary_id,
                severity_label: if acc.severity_label.is_empty() {
                    "unknown".to_owned()
                } else {
                    acc.severity_label
                },
            }
        })
        .collect();

    let mut components: Vec<CanonicalComponent> = components.into_values().collect();
    components.sort();

    let mut report = CanonicalReport::new(
        case_id,
        Generator {
            name: "xray".to_owned(),
            version: cli_version.unwrap_or("unknown").to_owned(),
        },
        "provider-replay",
    );
    report.components = components;
    report.vulnerabilities = vulnerabilities;
    Ok((report, summary))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_AUDIT: &str = r#"[
        {
            "vulnerabilities": [
                {
                    "issue_id": "XRAY-1001",
                    "severity": "High",
                    "cves": [{"cve": "CVE-2026-1111"}],
                    "components": {
                        "lodash:4.17.15": {"fixed_versions": ["4.17.21"]}
                    }
                },
                "garbage-entry"
            ]
        },
        {
            "vulnerabilities": [
                {"severity": "Critical", "cves": [{"cve": "CVE-2026-2222"}], "components": []}
            ]
        }
    ]"#;

    const FIXTURE_SBOM: &str = r#"{
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "name": "lodash",
                "version": "4.17.15",
                "purl": "pkg:npm/lodash@4.17.15",
                "licenses": [{"license": {"id": "MIT"}}]
            },
            {
                "name": "@org/widget",
                "version": "2.0.0",
                "purl": "pkg:npm/%40org/widget@2.0.0",
                "licenses": [{"expression": "MIT OR Apache-2.0"}]
            }
        ]
    }"#;

    #[test]
    fn merges_audit_and_sbom_sides() {
        let (report, summary) = build_xray_canonical(
            "case-a",
            Some("3.8.2"),
            &XrayArtifacts {
                audit_json: Some(FIXTURE_AUDIT),
                sbom_json: Some(FIXTURE_SBOM),
            },
        )
        .unwrap();
        assert_eq!(report.case_id, "case-a");
        assert_eq!(report.generator.name, "xray");
        assert_eq!(report.generator.version, "3.8.2");
        assert_eq!(report.scan_mode, "provider-replay");
        assert_eq!(report.components.len(), 2);
        assert!(report.components.is_sorted());
        let by_name = |name: &str| {
            report
                .components
                .iter()
                .find(|component| component.name == name)
                .unwrap()
        };
        let lodash = by_name("lodash");
        assert_eq!(lodash.ecosystem, "npm");
        assert_eq!(lodash.licenses, vec!["MIT".to_owned()]);
        let widget = by_name("@org/widget");
        assert_eq!(widget.licenses, vec!["MIT OR Apache-2.0".to_owned()]);

        // The second fixture response's vulnerability lacks an issue_id and
        // is therefore skipped; only XRAY-1001 survives.
        assert_eq!(report.vulnerabilities.len(), 1);
        let xray1001 = report
            .vulnerabilities
            .iter()
            .find(|v| v.primary_id == "XRAY-1001")
            .unwrap();
        assert_eq!(xray1001.cves, vec!["CVE-2026-1111".to_owned()]);
        assert_eq!(xray1001.severity_label, "high");
        assert_eq!(
            xray1001.affected_purls,
            vec!["pkg:npm/lodash@4.17.15".to_owned()]
        );
        assert_eq!(xray1001.fixed_versions, vec!["4.17.21".to_owned()]);
        // The issue id must not leak into its own alias list.
        assert!(!xray1001.aliases.contains(&"XRAY-1001".to_owned()));

        // Skipped: the "garbage-entry" string plus the issue_id-less
        // vulnerability in the second response.
        assert_eq!(summary.returned_components, 2);
        assert_eq!(summary.returned_vulnerabilities, 1);
        assert_eq!(summary.skipped_entries, 2);
        assert!(
            summary
                .skip_reasons
                .iter()
                .any(|r| r.contains("not an object"))
        );
        assert!(summary.skip_reasons.iter().any(|r| r.contains("issue_id")));
    }

    #[test]
    fn audit_only_synthesizes_generic_inventory() {
        let audit = r#"[{"vulnerabilities": [
            {"issue_id": "XRAY-2002", "cves": [{"cve": "CVE-2026-3333"}],
             "components": {"weird-pkg:0.1.0": {}}}
        ]}]"#;
        let (report, summary) = build_xray_canonical(
            "case-b",
            None,
            &XrayArtifacts {
                audit_json: Some(audit),
                sbom_json: None,
            },
        )
        .unwrap();
        assert_eq!(report.generator.version, "unknown");
        assert_eq!(report.components.len(), 1);
        let synthetic = report.components.first().unwrap();
        assert_eq!(synthetic.ecosystem, "generic");
        assert_eq!(synthetic.purl, "pkg:generic/weird-pkg@0.1.0");
        let vuln = &report.vulnerabilities[0];
        assert_eq!(vuln.severity_label, "unknown");
        assert_eq!(
            vuln.affected_purls,
            vec!["pkg:generic/weird-pkg@0.1.0".to_owned()]
        );
        assert_eq!(summary.skipped_entries, 1); // unresolved reference note
    }

    #[test]
    fn requires_at_least_one_artifact() {
        let error = build_xray_canonical("case-c", None, &XrayArtifacts::default()).unwrap_err();
        assert!(error.to_string().contains("at least one"));
    }

    #[test]
    fn tolerant_of_unknown_fields_and_shapes() {
        let weird = r#"{"unexpected": true}"#;
        let (report, summary) = build_xray_canonical(
            "case-d",
            None,
            &XrayArtifacts {
                audit_json: Some(weird),
                sbom_json: Some(FIXTURE_SBOM),
            },
        )
        .unwrap();
        assert_eq!(report.components.len(), 2);
        assert_eq!(report.vulnerabilities.len(), 0);
        assert_eq!(summary.returned_components, 2);
        assert_eq!(summary.returned_vulnerabilities, 0);
    }

    #[test]
    fn severity_mapping_covers_known_labels() {
        assert_eq!(severity_label(Some("Low")), "low");
        assert_eq!(severity_label(Some("MEDIUM")), "medium");
        assert_eq!(severity_label(Some("critical")), "critical");
        assert_eq!(severity_label(Some("Weird")), "unknown");
        assert_eq!(severity_label(None), "unknown");
    }

    #[test]
    fn parse_summary_serializes() {
        let summary = ParseSummary {
            returned_components: 3,
            returned_vulnerabilities: 1,
            skipped_entries: 2,
            skip_reasons: vec!["r1".into(), "r2".into()],
        };
        let back: ParseSummary =
            serde_json::from_str(&serde_json::to_string(&summary).unwrap()).unwrap();
        assert_eq!(back, summary);
    }
}
