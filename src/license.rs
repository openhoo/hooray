use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::{Component as PathComponent, Path, PathBuf},
};

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::model::{
    Confidence, Evidence, Finding, FindingKind, FindingStatus, Inventory, License, RuleId,
    Severity, stable_finding_id,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notice {
    pub path: String,
    pub sha256: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseAnalysis {
    pub findings: Vec<Finding>,
    pub notices: Vec<Notice>,
}

#[derive(Debug, Error)]
pub enum LicenseError {
    #[error("license root does not exist: {0}")]
    NotFound(PathBuf),
    #[error("license root contains or resolves through a symbolic link: {0}")]
    Symlink(PathBuf),
    #[error("path escapes license root: {0}")]
    PathTraversal(PathBuf),
    #[error("license or notice file {path} exceeds maximum {maximum} bytes")]
    FileTooLarge { path: PathBuf, maximum: u64 },
    #[error("I/O error for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid license rule identifier")]
    InvalidIdentifier,
}

pub fn analyze(
    inventory: &Inventory,
    root: Option<&Path>,
    max_file_bytes: u64,
) -> Result<LicenseAnalysis, LicenseError> {
    let files = match root {
        Some(root) => collect_license_files(root, max_file_bytes)?,
        None => Vec::new(),
    };
    analyze_with_files(inventory, files)
}

pub fn analyze_with_files(
    inventory: &Inventory,
    files: Vec<(String, Vec<u8>)>,
) -> Result<LicenseAnalysis, LicenseError> {
    let mut detected = Vec::new();
    let mut notices = Vec::new();
    for (path, bytes) in files {
        if is_notice_name(&path) {
            notices.push(Notice {
                path,
                sha256: format!("{:x}", Sha256::digest(&bytes)),
                text: String::from_utf8_lossy(&bytes).into_owned(),
            });
        } else if is_license_name(&path) {
            detected.push(detect_license_text(&path, &bytes));
        }
    }
    notices.sort_by(|a, b| a.path.cmp(&b.path));
    detected.sort_by(|a, b| a.path.cmp(&b.path));

    let invalid_rule =
        RuleId::new("license:invalid-spdx").map_err(|_| LicenseError::InvalidIdentifier)?;
    let unknown_rule =
        RuleId::new("license:unknown").map_err(|_| LicenseError::InvalidIdentifier)?;
    let detected_rule =
        RuleId::new("license:detected").map_err(|_| LicenseError::InvalidIdentifier)?;
    let mut findings = Vec::new();

    let asset_component = asset_component(inventory);

    for component in inventory.components.values() {
        if component.licenses.is_empty() {
            if asset_component.is_some_and(|candidate| candidate.identity == component.identity)
                && !detected.is_empty()
            {
                for detection in &detected {
                    let license = detection.expression.as_ref().map(|expression| License {
                        expression: Some(expression.clone()),
                        name: detection.name.clone(),
                        url: None,
                    });
                    findings.push(finding(
                        &detected_rule,
                        component,
                        license.as_ref(),
                        Severity::Low,
                        detection.confidence,
                        &format!(
                            "License file suggests {}",
                            detection
                                .expression
                                .as_deref()
                                .or(detection.name.as_deref())
                                .unwrap_or("an unknown or undetermined license")
                        ),
                        detection.evidence(),
                    ));
                }
            } else {
                findings.push(finding(&unknown_rule, component, None, Severity::Medium, Confidence::High,
                    "No license metadata or attributable license file was found",
                    Evidence { description: "Component has no declared licenses and no recognized LICENSE/COPYING text can be attributed to it".into(), locations: component.locations.iter().map(|v| v.id.clone()).collect(), references: BTreeSet::new(), properties: BTreeMap::from([("classification".into(), "unknown".into())]), redacted: false }));
            }
            continue;
        }
        for license in &component.licenses {
            match license.expression.as_deref() {
                Some(expression) if spdx::Expression::parse(expression).is_ok() => {
                    findings.push(finding(
                        &detected_rule,
                        component,
                        Some(license),
                        Severity::Low,
                        Confidence::High,
                        &format!("Valid SPDX license expression: {expression}"),
                        declared_evidence(component, license, true),
                    ));
                }
                Some(expression) => {
                    findings.push(finding(
                        &invalid_rule,
                        component,
                        Some(license),
                        Severity::High,
                        Confidence::High,
                        &format!("Invalid SPDX license expression: {expression}"),
                        declared_evidence(component, license, false),
                    ));
                }
                None if license
                    .name
                    .as_deref()
                    .is_some_and(|name| spdx::Expression::parse(name).is_ok()) =>
                {
                    findings.push(finding(
                        &detected_rule,
                        component,
                        Some(license),
                        Severity::Low,
                        Confidence::Medium,
                        &format!(
                            "License name is a valid SPDX expression: {}",
                            license.name.as_deref().unwrap()
                        ),
                        declared_evidence(component, license, true),
                    ));
                }
                None => {
                    findings.push(finding(
                        &unknown_rule,
                        component,
                        Some(license),
                        Severity::Medium,
                        Confidence::High,
                        "License metadata does not contain an SPDX expression",
                        declared_evidence(component, license, false),
                    ));
                }
            }
        }
    }
    findings.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(LicenseAnalysis { findings, notices })
}

fn asset_component(inventory: &Inventory) -> Option<&crate::model::Component> {
    let mut candidates = inventory.components.values().filter(|component| {
        component.name == inventory.asset.name
            && inventory
                .asset
                .version
                .as_deref()
                .is_none_or(|version| component.version == version)
            && !inventory
                .dependencies
                .iter()
                .any(|edge| edge.to == component.identity)
    });
    let candidate = candidates.next()?;
    candidates.next().is_none().then_some(candidate)
}

#[derive(Debug)]
struct Detection {
    path: String,
    expression: Option<String>,
    name: Option<String>,
    confidence: Confidence,
    matched: &'static str,
}
impl Detection {
    fn evidence(&self) -> Evidence {
        Evidence {
            description: format!("{} matched {}", self.path, self.matched),
            locations: BTreeSet::new(),
            references: BTreeSet::new(),
            properties: BTreeMap::from([
                ("path".into(), self.path.clone()),
                ("detector".into(), self.matched.into()),
            ]),
            redacted: false,
        }
    }
}

fn detect_license_text(path: &str, bytes: &[u8]) -> Detection {
    let text = String::from_utf8_lossy(bytes);
    let normalized = text
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let (expression, name, confidence, matched) = if normalized
        .contains("permission is hereby granted, free of charge, to any person obtaining a copy")
        && normalized.contains("the software is provided \"as is\"")
    {
        (
            Some("MIT".into()),
            Some("MIT License".into()),
            Confidence::High,
            "MIT canonical clauses",
        )
    } else if normalized.contains("apache license")
        && normalized.contains("version 2.0, january 2004")
        && normalized.contains("http://www.apache.org/licenses/")
    {
        (
            Some("Apache-2.0".into()),
            Some("Apache License 2.0".into()),
            Confidence::High,
            "Apache-2.0 title and canonical URL",
        )
    } else if normalized.contains("gnu general public license")
        && normalized.contains("version 3")
        && normalized
            .contains("either version 3 of the license, or (at your option) any later version")
    {
        (
            Some("GPL-3.0-or-later".into()),
            Some("GNU GPL v3 or later".into()),
            Confidence::High,
            "GPL-3.0-or-later grant",
        )
    } else if normalized.contains("gnu general public license") && normalized.contains("version 3")
    {
        (
            Some("GPL-3.0-only".into()),
            Some("GNU GPL v3".into()),
            Confidence::Medium,
            "GPL v3 title",
        )
    } else if normalized.contains("gnu lesser general public license")
        && normalized.contains("version 3")
    {
        (
            Some("LGPL-3.0-only".into()),
            Some("GNU LGPL v3".into()),
            Confidence::Medium,
            "LGPL v3 title",
        )
    } else if normalized.contains("mozilla public license version 2.0") {
        (
            Some("MPL-2.0".into()),
            Some("Mozilla Public License 2.0".into()),
            Confidence::High,
            "MPL-2.0 title",
        )
    } else if normalized.contains("redistribution and use in source and binary forms")
        && normalized.contains("neither the name")
    {
        (
            Some("BSD-3-Clause".into()),
            Some("BSD 3-Clause License".into()),
            Confidence::Medium,
            "BSD 3-Clause clauses",
        )
    } else if normalized.contains("redistribution and use in source and binary forms") {
        (
            Some("BSD-2-Clause".into()),
            Some("BSD 2-Clause License".into()),
            Confidence::Medium,
            "BSD redistribution clauses",
        )
    } else if normalized.contains("isc license")
        && normalized.contains(
            "permission to use, copy, modify, and/or distribute this software for any purpose",
        )
    {
        (
            Some("ISC".into()),
            Some("ISC License".into()),
            Confidence::High,
            "ISC canonical grant",
        )
    } else if normalized.contains("boost software license - version 1.0") {
        (
            Some("BSL-1.0".into()),
            Some("Boost Software License 1.0".into()),
            Confidence::High,
            "BSL-1.0 title",
        )
    } else if normalized.contains("the unlicense")
        && normalized
            .contains("this is free and unencumbered software released into the public domain")
    {
        (
            Some("Unlicense".into()),
            Some("The Unlicense".into()),
            Confidence::High,
            "Unlicense canonical dedication",
        )
    } else {
        (
            None,
            Some("unknown or undetermined license text".into()),
            Confidence::Low,
            "no canonical license signature",
        )
    };
    Detection {
        path: path.to_owned(),
        expression,
        name,
        confidence,
        matched,
    }
}

fn declared_evidence(
    component: &crate::model::Component,
    license: &License,
    valid: bool,
) -> Evidence {
    let mut properties = BTreeMap::from([("spdx_valid".into(), valid.to_string())]);
    if let Some(expression) = &license.expression {
        properties.insert("expression".into(), expression.clone());
    }
    if let Some(name) = &license.name {
        properties.insert("name".into(), name.clone());
    }
    if let Some(url) = &license.url {
        properties.insert("url".into(), url.clone());
    }
    Evidence {
        description: "Declared package license metadata".into(),
        locations: component.locations.iter().map(|v| v.id.clone()).collect(),
        references: license.url.iter().cloned().collect(),
        properties,
        redacted: false,
    }
}

fn finding(
    rule: &RuleId,
    component: &crate::model::Component,
    license: Option<&License>,
    severity: Severity,
    confidence: Confidence,
    summary: &str,
    evidence: Evidence,
) -> Finding {
    let mut aliases = BTreeSet::new();
    if let Some(expression) = license.and_then(|v| v.expression.as_ref()) {
        aliases.insert(expression.clone());
    }
    Finding {
        id: stable_finding_id(FindingKind::License, rule, Some(&component.identity), None),
        kind: FindingKind::License,
        rule_id: rule.clone(),
        advisory_id: None,
        component_id: Some(component.identity.clone()),
        location_id: None,
        aliases,
        summary: Some(summary.to_owned()),
        details: None,
        severity,
        confidence,
        evidence: BTreeSet::from([evidence]),
        applicability: None,
        remediation: None,
        risk: None,
        first_seen: None,
        last_seen: None,
        modified: None,
        status: FindingStatus::Open,
    }
}

fn collect_license_files(
    root: &Path,
    maximum: u64,
) -> Result<Vec<(String, Vec<u8>)>, LicenseError> {
    let metadata = fs::symlink_metadata(root).map_err(|source| match source.kind() {
        io::ErrorKind::NotFound => LicenseError::NotFound(root.to_owned()),
        _ => LicenseError::Io {
            path: root.to_owned(),
            source,
        },
    })?;
    if metadata.file_type().is_symlink() {
        return Err(LicenseError::Symlink(root.to_owned()));
    }
    let canonical = fs::canonicalize(root).map_err(|source| LicenseError::Io {
        path: root.to_owned(),
        source,
    })?;
    if canonical != root {
        return Err(LicenseError::Symlink(root.to_owned()));
    }
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(|error| LicenseError::Io {
            path: error.path().unwrap_or(root).to_owned(),
            source: io::Error::other(error),
        })?;
        if entry.file_type().is_symlink() {
            return Err(LicenseError::Symlink(entry.path().to_owned()));
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| LicenseError::PathTraversal(entry.path().to_owned()))?;
        let normalized = normalize_relative(relative)?;
        if !is_license_name(&normalized) && !is_notice_name(&normalized) {
            continue;
        }
        let length = entry
            .metadata()
            .map_err(|error| LicenseError::Io {
                path: entry.path().to_owned(),
                source: io::Error::other(error),
            })?
            .len();
        if length > maximum {
            return Err(LicenseError::FileTooLarge {
                path: entry.path().to_owned(),
                maximum,
            });
        }
        let bytes = fs::read(entry.path()).map_err(|source| LicenseError::Io {
            path: entry.path().to_owned(),
            source,
        })?;
        files.push((normalized, bytes));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

fn normalize_relative(path: &Path) -> Result<String, LicenseError> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            PathComponent::Normal(value) => parts.push(
                value
                    .to_str()
                    .ok_or_else(|| LicenseError::PathTraversal(path.to_owned()))?,
            ),
            PathComponent::CurDir => {}
            _ => return Err(LicenseError::PathTraversal(path.to_owned())),
        }
    }
    if parts.is_empty() {
        return Err(LicenseError::PathTraversal(path.to_owned()));
    }
    Ok(parts.join("/"))
}

fn is_license_name(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_uppercase();
    Regex::new(r"^(LICENSE|LICENCE|COPYING)([._-].*)?$")
        .expect("constant regex")
        .is_match(&name)
}
fn is_notice_name(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_uppercase();
    name == "NOTICE"
        || name.starts_with("NOTICE.")
        || name.starts_with("NOTICE-")
        || name == "THIRD-PARTY-NOTICES"
        || name.starts_with("THIRD-PARTY-NOTICES.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Asset, AssetId, AssetKind, Component, Scope, Source, SourceKind, stable_component_id,
    };
    use tempfile::tempdir;

    fn inventory(licenses: BTreeSet<License>) -> Inventory {
        let purl = "pkg:cargo/demo@1.0.0";
        let id = stable_component_id(purl).unwrap();
        Inventory {
            asset: Asset {
                id: AssetId::new("asset:test").unwrap(),
                name: "demo".into(),
                kind: AssetKind::Repository,
                version: Some("1.0.0".into()),
                metadata: BTreeMap::new(),
            },
            components: BTreeMap::from([(
                id.clone(),
                Component {
                    identity: id,
                    name: "demo".into(),
                    version: "1.0.0".into(),
                    purl: purl.into(),
                    scope: Scope::Runtime,
                    provenance: BTreeSet::from([Source {
                        kind: SourceKind::Manifest,
                        locator: "Cargo.toml".into(),
                        digest: None,
                    }]),
                    licenses,
                    locations: BTreeSet::new(),
                },
            )]),
            dependencies: BTreeSet::new(),
        }
    }

    #[test]
    fn validates_spdx_and_rejects_invalid_expression() {
        let valid = analyze_with_files(
            &inventory(BTreeSet::from([License {
                expression: Some("MIT OR Apache-2.0".into()),
                name: None,
                url: None,
            }])),
            vec![],
        )
        .unwrap();
        assert_eq!(valid.findings[0].severity, Severity::Low);
        let invalid = analyze_with_files(
            &inventory(BTreeSet::from([License {
                expression: Some("MIT OR definitely-not-spdx".into()),
                name: None,
                url: None,
            }])),
            vec![],
        )
        .unwrap();
        assert_eq!(invalid.findings[0].severity, Severity::High);
        assert_eq!(invalid.findings[0].rule_id.as_str(), "license:invalid-spdx");
    }

    #[test]
    fn detects_mit_text_and_notice_inventory() {
        let result = analyze_with_files(&inventory(BTreeSet::new()), vec![
            ("LICENSE".into(), b"MIT License\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software. THE SOFTWARE IS PROVIDED \"AS IS\"".to_vec()),
            ("NOTICE".into(), b"Copyright Example".to_vec()),
        ]).unwrap();
        assert_eq!(result.findings[0].confidence, Confidence::High);
        assert!(
            result.findings[0]
                .summary
                .as_deref()
                .unwrap()
                .contains("MIT")
        );
        assert_eq!(result.notices[0].text, "Copyright Example");
    }

    #[test]
    fn emits_unknown_when_no_metadata_or_license_file() {
        let result = analyze_with_files(&inventory(BTreeSet::new()), vec![]).unwrap();
        assert_eq!(result.findings[0].rule_id.as_str(), "license:unknown");
        assert_eq!(result.findings[0].severity, Severity::Medium);
    }

    #[test]
    fn attributes_root_license_without_licensing_unrelated_dependency() {
        let root_purl = "pkg:cargo/app@1.0.0";
        let dependency_purl = "pkg:cargo/unrelated@2.0.0";
        let root_id = stable_component_id(root_purl).unwrap();
        let dependency_id = stable_component_id(dependency_purl).unwrap();
        let inventory = Inventory {
            asset: Asset {
                id: AssetId::new("asset:app").unwrap(),
                name: "app".into(),
                kind: AssetKind::Repository,
                version: Some("1.0.0".into()),
                metadata: BTreeMap::new(),
            },
            components: BTreeMap::from([
                (
                    root_id.clone(),
                    Component {
                        identity: root_id.clone(),
                        name: "app".into(),
                        version: "1.0.0".into(),
                        purl: root_purl.into(),
                        scope: Scope::Runtime,
                        provenance: BTreeSet::new(),
                        licenses: BTreeSet::new(),
                        locations: BTreeSet::new(),
                    },
                ),
                (
                    dependency_id.clone(),
                    Component {
                        identity: dependency_id.clone(),
                        name: "unrelated".into(),
                        version: "2.0.0".into(),
                        purl: dependency_purl.into(),
                        scope: Scope::Runtime,
                        provenance: BTreeSet::new(),
                        licenses: BTreeSet::new(),
                        locations: BTreeSet::new(),
                    },
                ),
            ]),
            dependencies: BTreeSet::from([crate::model::DependencyEdge {
                from: root_id.clone(),
                to: dependency_id.clone(),
                scope: Scope::Runtime,
                optional: false,
            }]),
        };

        let result = analyze_with_files(
            &inventory,
            vec![(
                "LICENSE".into(),
                b"MIT License\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software. THE SOFTWARE IS PROVIDED \"AS IS\"".to_vec(),
            )],
        )
        .unwrap();

        let root = result
            .findings
            .iter()
            .find(|finding| finding.component_id.as_ref() == Some(&root_id))
            .unwrap();
        assert_eq!(root.rule_id.as_str(), "license:detected");
        assert!(root.aliases.contains("MIT"));

        let dependency = result
            .findings
            .iter()
            .find(|finding| finding.component_id.as_ref() == Some(&dependency_id))
            .unwrap();
        assert_eq!(dependency.rule_id.as_str(), "license:unknown");
        assert!(dependency.aliases.is_empty());
    }

    #[test]
    fn unrecognized_copying_is_low_confidence_evidence() {
        let result = analyze_with_files(
            &inventory(BTreeSet::new()),
            vec![("COPYING.custom".into(), b"proprietary terms".to_vec())],
        )
        .unwrap();
        assert_eq!(result.findings[0].confidence, Confidence::Low);
        assert!(
            result.findings[0]
                .summary
                .as_deref()
                .unwrap()
                .contains("unknown")
        );
    }

    #[test]
    fn collects_nested_notice_and_license_deterministically() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join("legal")).unwrap();
        fs::write(dir.path().join("legal/NOTICE.txt"), "notice").unwrap();
        fs::write(dir.path().join("LICENSE.md"), "license").unwrap();
        let files = collect_license_files(dir.path(), 1024).unwrap();
        assert_eq!(
            files.iter().map(|v| v.0.as_str()).collect::<Vec<_>>(),
            vec!["LICENSE.md", "legal/NOTICE.txt"]
        );
    }

    #[test]
    fn enforces_license_file_size_limit() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("LICENSE"), "oversized").unwrap();
        assert!(matches!(
            collect_license_files(dir.path(), 2),
            Err(LicenseError::FileTooLarge { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks_in_license_tree() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("LICENSE"), "secret").unwrap();
        symlink(outside.path().join("LICENSE"), dir.path().join("LICENSE")).unwrap();
        assert!(matches!(
            collect_license_files(dir.path(), 1024),
            Err(LicenseError::Symlink(_))
        ));
    }

    #[test]
    fn accepts_complex_spdx_declarations_and_preserves_evidence() {
        let license = License {
            expression: Some(
                "(MIT AND Apache-2.0) OR GPL-3.0-only WITH Classpath-exception-2.0".into(),
            ),
            name: Some("project choice".into()),
            url: Some("https://example.test/license".into()),
        };
        let result = analyze_with_files(&inventory(BTreeSet::from([license])), vec![]).unwrap();
        let finding = &result.findings[0];
        let evidence = finding.evidence.iter().next().unwrap();
        assert_eq!(finding.rule_id.as_str(), "license:detected");
        assert_eq!(finding.confidence, Confidence::High);
        assert!(
            finding
                .aliases
                .contains("(MIT AND Apache-2.0) OR GPL-3.0-only WITH Classpath-exception-2.0")
        );
        assert_eq!(evidence.properties["spdx_valid"], "true");
        assert_eq!(evidence.properties["name"], "project choice");
        assert!(evidence.references.contains("https://example.test/license"));
    }

    #[test]
    fn handles_name_only_and_missing_spdx_metadata() {
        let licenses = BTreeSet::from([
            License {
                expression: None,
                name: Some("Apache-2.0 OR MIT".into()),
                url: None,
            },
            License {
                expression: None,
                name: Some("Company internal terms".into()),
                url: Some("https://example.test/internal".into()),
            },
        ]);
        let result = analyze_with_files(&inventory(licenses), vec![]).unwrap();
        assert_eq!(result.findings.len(), 2);
        assert!(result.findings.iter().any(|finding| {
            finding.rule_id.as_str() == "license:detected"
                && finding.confidence == Confidence::Medium
        }));
        let unknown = result
            .findings
            .iter()
            .find(|finding| finding.rule_id.as_str() == "license:unknown")
            .unwrap();
        assert_eq!(unknown.severity, Severity::Medium);
        assert!(
            unknown
                .evidence
                .iter()
                .next()
                .unwrap()
                .references
                .contains("https://example.test/internal")
        );
    }

    #[test]
    fn declared_license_remains_authoritative_when_file_disagrees() {
        let result = analyze_with_files(
            &inventory(BTreeSet::from([License {
                expression: Some("MIT".into()),
                name: None,
                url: None,
            }])),
            vec![(
                "LICENSE".into(),
                b"Apache License Version 2.0, January 2004 http://www.apache.org/licenses/"
                    .to_vec(),
            )],
        )
        .unwrap();
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].aliases, BTreeSet::from(["MIT".into()]));
        assert!(
            result.findings[0]
                .summary
                .as_deref()
                .unwrap()
                .contains("MIT")
        );
    }

    #[test]
    fn recognizes_apache_bsd_and_gpl_variants() {
        let files = vec![
            ("LICENSE.apache".into(), b"Apache License Version 2.0, January 2004 http://www.apache.org/licenses/".to_vec()),
            ("COPYING-bsd3".into(), b"Redistribution and use in source and binary forms are permitted. Neither the name of the copyright holder".to_vec()),
            ("COPYING-bsd2".into(), b"Redistribution and use in source and binary forms are permitted.".to_vec()),
            ("COPYING-gpl-later".into(), b"GNU General Public License Version 3; either version 3 of the License, or (at your option) any later version".to_vec()),
            ("COPYING-gpl-only".into(), b"GNU General Public License Version 3".to_vec()),
        ];
        let result = analyze_with_files(&inventory(BTreeSet::new()), files).unwrap();
        let summaries = result
            .findings
            .iter()
            .map(|finding| finding.summary.as_deref().unwrap())
            .collect::<Vec<_>>();
        for expected in [
            "Apache-2.0",
            "BSD-3-Clause",
            "BSD-2-Clause",
            "GPL-3.0-or-later",
            "GPL-3.0-only",
        ] {
            assert!(
                summaries.iter().any(|summary| summary.contains(expected)),
                "missing {expected}"
            );
        }
    }

    #[test]
    fn handles_empty_and_non_utf8_legal_files_without_panicking() {
        let result = analyze_with_files(
            &inventory(BTreeSet::new()),
            vec![
                ("LICENSE".into(), Vec::new()),
                ("NOTICE.bin".into(), vec![b'n', 0xff, b't']),
            ],
        )
        .unwrap();
        assert_eq!(result.findings[0].confidence, Confidence::Low);
        assert_eq!(result.notices[0].text, "n\u{fffd}t");
        assert_eq!(result.notices[0].sha256.len(), 64);
    }

    #[test]
    fn notice_names_and_file_size_boundary_are_observable() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("NOTICE-legal"), b"1234").unwrap();
        fs::write(dir.path().join("THIRD-PARTY-NOTICES.txt"), b"third").unwrap();
        fs::write(dir.path().join("LICENSE.txt"), b"1234").unwrap();
        fs::write(dir.path().join("NOTICEBOARD"), b"ignored").unwrap();
        let files = collect_license_files(dir.path(), 4).unwrap_err();
        assert!(matches!(
            files,
            LicenseError::FileTooLarge { maximum: 4, .. }
        ));
        fs::remove_file(dir.path().join("THIRD-PARTY-NOTICES.txt")).unwrap();
        let files = collect_license_files(dir.path(), 4).unwrap();
        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|(_, bytes)| bytes.len() == 4));
    }

    #[test]
    fn missing_roots_and_invalid_relative_paths_are_rejected() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("missing");
        assert!(matches!(
            collect_license_files(&missing, 10),
            Err(LicenseError::NotFound(path)) if path == missing
        ));
        assert!(matches!(
            normalize_relative(Path::new("")),
            Err(LicenseError::PathTraversal(_))
        ));
        assert!(matches!(
            normalize_relative(Path::new("../LICENSE")),
            Err(LicenseError::PathTraversal(_))
        ));
        assert_eq!(
            normalize_relative(Path::new("./legal/LICENSE")).unwrap(),
            "legal/LICENSE"
        );
    }

    #[cfg(unix)]
    #[test]
    fn reports_unreadable_license_files_as_io_errors() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("LICENSE");
        fs::write(&path, b"secret").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        let result = collect_license_files(dir.path(), 1024);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(result, Err(LicenseError::Io { path: actual, .. }) if actual == path));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_utf8_license_paths() {
        use std::os::unix::ffi::OsStringExt;
        let path = PathBuf::from(std::ffi::OsString::from_vec(vec![b'L', 0xff]));
        assert!(matches!(
            normalize_relative(&path),
            Err(LicenseError::PathTraversal(_))
        ));
    }
}
