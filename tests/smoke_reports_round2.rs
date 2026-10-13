use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, NaiveDate};
use hooray::{
    analysis::{
        ApplicabilityAnalyzer, ApplicabilityInput, OsvAffectedRange, OsvEvent, OsvRangeType,
    },
    model::*,
    policy::Policy,
    remediation::nearest_fixed_version,
    report::{ReportFormat, render},
    risk::{RiskInput, RiskScorer},
    sbom::{SbomError, parse_cyclonedx},
};
use serde_json::json;

fn fixture() -> ScanReport {
    let inventory = parse_cyclonedx(br#"{"bomFormat":"CycloneDX","components":[{"bom-ref":"dep","name":"dep","version":"1.0.0","purl":"pkg:cargo/dep@1.0.0"}]}"#).unwrap();
    let component = inventory.components.values().next().unwrap();
    let finding: Finding = serde_json::from_value(json!({
        "id":"finding:round2", "kind":"vulnerability", "rule_id":"OSV-round2",
        "component_id":component.identity,"severity":"critical","confidence":"high"
    }))
    .unwrap();
    ScanReport {
        schema_version: "1".into(),
        run: RunMetadata {
            id: RunId::new("run:round2").unwrap(),
            started_at: "2026-10-13T12:00:00Z".into(),
            completed_at: None,
            scanner_version: None,
            metadata: BTreeMap::new(),
        },
        inventory,
        findings: BTreeMap::from([(finding.id.clone(), finding)]),
        policy_decisions: BTreeSet::new(),
        policy_summary: PolicySummary::default(),
    }
}

#[test]
fn normalized_inventory_rejects_version_contradicting_its_package_url() {
    let mut report = fixture();
    report.validate().unwrap();
    report
        .inventory
        .components
        .values_mut()
        .next()
        .unwrap()
        .version = "9.0.0".into();
    assert!(report.validate().is_err());
    for format in ReportFormat::ALL {
        assert!(render(&report, format).is_err(), "{format}");
    }
    let component = report.inventory.components.values_mut().next().unwrap();
    component.version = "1!2.0+local".into();
    component.purl = "pkg:pypi/dep@1%212.0%2Blocal".into();
    report.validate().unwrap();
    report
        .inventory
        .components
        .values_mut()
        .next()
        .unwrap()
        .purl = "pkg:pypi/dep".into();
    report.validate().unwrap();
}

#[test]
fn cyclonedx_root_reference_cannot_shadow_real_or_skipped_components() {
    let document = |root: &str, version: Option<&str>| {
        json!({
            "bomFormat":"CycloneDX", "metadata":{"component":{"bom-ref":root,"name":"application"}},
            "components":[{"bom-ref":"alias","name":"dep","version":version,"purl":version.map(|v|format!("pkg:cargo/dep@{v}"))},
                          {"bom-ref":"other","name":"other","version":"1.0.0","purl":"pkg:cargo/other@1.0.0"}],
            "dependencies":[{"ref":"alias","dependsOn":["other"]}]
        })
    };
    let valid =
        parse_cyclonedx(&serde_json::to_vec(&document("app", Some("1.0.0"))).unwrap()).unwrap();
    assert_eq!(valid.dependencies.len(), 1);
    let mut mirrored = document("alias", None);
    mirrored["metadata"]["component"]["name"] = json!("dep");
    let inventory = parse_cyclonedx(&serde_json::to_vec(&mirrored).unwrap()).unwrap();
    assert_eq!(inventory.components.len(), 1);
    assert!(inventory.dependencies.is_empty());
    for version in [Some("1.0.0"), None] {
        assert!(matches!(
            parse_cyclonedx(&serde_json::to_vec(&document("alias", version)).unwrap()),
            Err(SbomError::DuplicateBomRef(_))
        ));
    }
    assert!(matches!(
        parse_cyclonedx(&serde_json::to_vec(&document(" ", Some("1.0.0"))).unwrap()),
        Err(SbomError::InvalidComponent {
            field: "bom-ref",
            ..
        })
    ));
}

#[test]
fn cyclonedx_emitted_references_are_unique_across_native_id_types() {
    for format in [ReportFormat::CycloneDxVex, ReportFormat::GitLabCycloneDx] {
        let mut report = fixture();
        let conflicting_reference = if format == ReportFormat::CycloneDxVex {
            report.inventory.asset.id.as_str().to_owned()
        } else {
            format!(
                "asset:{}",
                hooray::util::sha256_hex(report.inventory.asset.id.as_str().as_bytes())
            )
        };
        let mut component = report.inventory.components.pop_first().unwrap().1;
        component.identity = ComponentId::new(&conflicting_reference).unwrap();
        let mut finding = report.findings.pop_first().unwrap().1;
        finding.id = FindingId::new(&conflicting_reference).unwrap();
        finding.component_id = Some(component.identity.clone());
        report.inventory.components =
            BTreeMap::from([(component.identity.clone(), component.clone())]);
        report.findings = BTreeMap::from([(finding.id.clone(), finding)]);
        report.validate().unwrap();
        let bytes = render(&report, format).unwrap();
        assert_eq!(bytes, render(&report, format).unwrap());
        let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let references: Vec<&str> = std::iter::once(
            document["metadata"]["component"]["bom-ref"]
                .as_str()
                .unwrap(),
        )
        .chain(
            document["components"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item["bom-ref"].as_str().unwrap()),
        )
        .chain(
            document["vulnerabilities"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|item| item["bom-ref"].as_str().unwrap()),
        )
        .collect();
        assert_eq!(
            references.iter().copied().collect::<BTreeSet<_>>().len(),
            references.len(),
            "{format} emitted duplicate bom-refs"
        );
        let parsed = parse_cyclonedx(&bytes).unwrap();
        assert_eq!(parsed.components.len(), 1);
        assert_eq!(document["components"][0]["bom-ref"], conflicting_reference);
        if format == ReportFormat::CycloneDxVex {
            assert_eq!(
                document["vulnerabilities"][0]["affects"][0]["ref"],
                component.identity.as_str()
            );
        }
    }
}

#[test]
fn skipped_sbom_source_still_requires_declared_dependency_targets() {
    let cdx = |target: &str| {
        json!({"bomFormat":"CycloneDX", "components":[
        {"bom-ref":"skipped","name":"no-version"},
        {"bom-ref":"dep","name":"dep","version":"1.0.0","purl":"pkg:cargo/dep@1.0.0"}],
        "dependencies":[{"ref":"skipped","dependsOn":[target]}]})
    };
    let spdx = |target: &str| {
        json!({"spdxVersion":"SPDX-2.3", "packages":[
        {"SPDXID":"skipped","name":"no-version"},
        {"SPDXID":"dep","name":"dep","versionInfo":"1.0.0"}],
        "relationships":[{"spdxElementId":"skipped","relationshipType":"DEPENDS_ON","relatedSpdxElement":target}]})
    };
    for document in [cdx("dep"), spdx("dep")] {
        let parsed = parse_cyclonedx(&serde_json::to_vec(&document).unwrap()).unwrap();
        assert_eq!(parsed.components.len(), 1);
        assert!(parsed.dependencies.is_empty());
    }
    for document in [cdx("missing"), spdx("missing")] {
        assert!(matches!(
            parse_cyclonedx(&serde_json::to_vec(&document).unwrap()),
            Err(SbomError::UnknownDependency { .. })
        ));
    }
}

fn applicability(kind: &str, version: &str, fixed: &str) -> ApplicabilityStatus {
    let mut component = fixture().inventory.components.pop_first().unwrap().1;
    component.version = version.into();
    component.purl = format!("pkg:{kind}/dep@{version}");
    let ranges = vec![OsvAffectedRange {
        range_type: OsvRangeType::Semver,
        ecosystem: Some(kind.into()),
        versions: Vec::new(),
        events: vec![
            OsvEvent {
                introduced: Some("0".into()),
                ..OsvEvent::default()
            },
            OsvEvent {
                fixed: Some(fixed.into()),
                ..OsvEvent::default()
            },
        ],
    }];
    ApplicabilityAnalyzer::analyze(ApplicabilityInput {
        component: &component,
        paths: None,
        evidence: &BTreeSet::new(),
        affected_ranges: &ranges,
    })
    .status
}

#[test]
fn known_ecosystem_versions_and_boundaries_cannot_fall_back_from_invalid_syntax() {
    assert_eq!(
        applicability("cargo", "1.0.0", "1.0.0"),
        ApplicabilityStatus::Fixed
    );
    for (kind, current, fixed) in [
        ("cargo", "1.0.0-", "1.0.0"),
        ("npm", "1.0.0+", "1.0.0"),
        ("cargo", "1.0.0~rc1", "1.0.0"),
        ("pypi", "1.0garbage", "1.0"),
        ("pypi", "1.0", "1.0garbage"),
    ] {
        assert_eq!(
            applicability(kind, current, fixed),
            ApplicabilityStatus::Unknown,
            "{kind} {current} / {fixed}"
        );
    }
    assert_eq!(
        applicability("generic", "1.1", "1.0"),
        ApplicabilityStatus::Fixed,
        "unsupported ecosystems retain their existing comparator"
    );
}

#[test]
fn semver_applicability_uses_complete_case_sensitive_prerelease_identifiers() {
    for kind in ["cargo", "npm", "golang"] {
        assert_eq!(
            applicability(kind, "1.0.0-alpha11", "1.0.0-alpha2"),
            ApplicabilityStatus::Affected,
            "{kind}"
        );
        assert_eq!(
            applicability(kind, "1.0.0-B", "1.0.0-a"),
            ApplicabilityStatus::Affected,
            "{kind}"
        );
    }
}

#[test]
fn blank_remediation_cannot_flip_fix_available_selectors_or_reduce_risk() {
    let mut report = fixture();
    let policy=Policy::from_yaml("version: 1\nrules:\n  - id: unfixed\n    outcome: deny\n    reason: fixes required\n    selectors: {fix_available: false}\n").unwrap();
    let selected = |report: &ScanReport| {
        policy
            .evaluate(
                &report.findings,
                &report.inventory,
                DateTime::parse_from_rfc3339("2026-10-13T12:00:00Z").unwrap(),
            )
            .unwrap()
            .summary
    };
    assert_eq!(selected(&report).denied, 1);
    for (description, versions) in [(" ", BTreeSet::new()), ("", BTreeSet::from([" ".into()]))] {
        let remediation = Remediation {
            description: description.into(),
            fixed_versions: versions,
            references: BTreeSet::new(),
        };
        report.findings.values_mut().next().unwrap().remediation = Some(remediation.clone());
        assert_eq!(selected(&report).denied, 1);
        let component = report.inventory.components.values().next().unwrap();
        let risk = RiskScorer::score(RiskInput {
            severity: Severity::Critical,
            confidence: Confidence::High,
            applicability: ApplicabilityStatus::Affected,
            component,
            direct: Some(true),
            remediation: Some(&remediation),
            evidence: &BTreeSet::new(),
            as_of: NaiveDate::from_ymd_opt(2026, 10, 13).unwrap(),
        });
        assert!(risk.factors["fix-availability"] >= 0);
    }
    report.findings.values_mut().next().unwrap().remediation = Some(Remediation {
        description: "upgrade the affected dependency".into(),
        fixed_versions: BTreeSet::new(),
        references: BTreeSet::new(),
    });
    assert_eq!(selected(&report).denied, 0);
}

#[test]
fn fixed_version_choices_are_installable_without_surrounding_whitespace() {
    assert_eq!(
        nearest_fixed_version(PackageEcosystem::Npm, "1.0.0", [" 1.0.1 "]),
        Some("1.0.1".into())
    );
}

#[test]
fn semver_upgrade_choices_reject_numeric_identifiers_with_leading_zeroes() {
    for ecosystem in [
        PackageEcosystem::Cargo,
        PackageEcosystem::Npm,
        PackageEcosystem::Go,
    ] {
        assert_eq!(
            nearest_fixed_version(ecosystem, "1.0.0", ["1.0.1-01", "1.01.0", "1.0.2"]),
            Some("1.0.2".into())
        );
    }
    assert_eq!(
        nearest_fixed_version(PackageEcosystem::Nuget, "1.0.0", ["1.01.0"]),
        Some("1.01.0".into()),
        "NuGet retains its numeric normalization"
    );
}
