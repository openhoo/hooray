use std::collections::{BTreeMap, BTreeSet};

use chrono::DateTime;
use hooray::{
    analysis::{
        ApplicabilityAnalyzer, ApplicabilityInput, OsvAffectedRange, OsvEvent, OsvRangeType,
    },
    graph::{DependencyGraph, VIRTUAL_ROOT_METADATA},
    model::*,
    policy::Policy,
    remediation::nearest_fixed_version,
    report::{ReportFormat, render},
    sbom::parse_cyclonedx,
};
use serde_json::{Value, json};

fn fixture() -> ScanReport {
    let inventory = parse_cyclonedx(
        br#"{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"name":"application"}},"components":[{"bom-ref":"root","name":"root","version":"1.0.0","purl":"pkg:cargo/root@1.0.0","scope":"required"},{"bom-ref":"dep","name":"dep","version":"1.0.0","purl":"pkg:cargo/dep@1.0.0","scope":"optional"}],"dependencies":[{"ref":"root","dependsOn":["dep"]}]}"#,
    )
    .unwrap();
    let dep = inventory
        .components
        .values()
        .find(|component| component.name == "dep")
        .unwrap();
    let finding_id = FindingId::new("finding:smoke").unwrap();
    let finding: Finding = serde_json::from_value(json!({
        "id": finding_id, "kind": "vulnerability", "rule_id": "OSV-smoke",
        "advisory_id": "CVE-2026-1234", "component_id": dep.identity,
        "severity": "critical", "confidence": "high",
        "summary": "<script>unsafe</script> & \"quoted\"",
        "details": "XML control \u{1}, CR\rLF\nUTF-8 🐉",
        "applicability": {"status": "unknown", "rationale": "no execution evidence"},
        "evidence": [{"description": "smoke evidence", "redacted": true,
                      "properties": {"authorization": "synthetic-redaction-value", "safe": "visible"}}]
    }))
    .unwrap();
    ScanReport {
        schema_version: "1".into(),
        run: RunMetadata {
            id: RunId::new("run:smoke").unwrap(),
            started_at: "2026-10-13T12:00:00Z".into(),
            completed_at: None,
            scanner_version: Some("0.9.0".into()),
            metadata: BTreeMap::from([("api_token".into(), json!("synthetic-redaction-value"))]),
        },
        inventory,
        findings: BTreeMap::from([(finding_id, finding)]),
        policy_decisions: BTreeSet::new(),
        policy_summary: PolicySummary::default(),
    }
}

struct SchemaRetriever;
impl jsonschema::Retrieve for SchemaRetriever {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let data = match uri.as_str() {
            "http://cyclonedx.org/schema/spdx.schema.json"
            | "https://cyclonedx.org/schema/spdx.schema.json" => {
                include_str!("fixtures/cyclonedx-1.6/spdx.schema.json")
            }
            "http://cyclonedx.org/schema/jsf-0.82.schema.json"
            | "https://cyclonedx.org/schema/jsf-0.82.schema.json" => {
                include_str!("fixtures/cyclonedx-1.6/jsf-0.82.schema.json")
            }
            _ => return Err(format!("unavailable offline schema: {uri}").into()),
        };
        Ok(serde_json::from_str(data)?)
    }
}

fn validate_cdx(value: &Value) {
    let schema: Value =
        serde_json::from_str(include_str!("fixtures/cyclonedx-1.6/bom-1.6.schema.json")).unwrap();
    let validator = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft7)
        .with_retriever(SchemaRetriever)
        .build(&schema)
        .unwrap();
    assert!(
        validator.is_valid(value),
        "{:?}",
        validator.iter_errors(value).collect::<Vec<_>>()
    );
}

#[test]
fn all_formats_smoke_escape_redact_and_preserve_policy_state() {
    let mut report = fixture();
    let policy = Policy::from_yaml("version: 1\ndefault_outcome: deny\n").unwrap();
    let evaluated = policy
        .evaluate(
            &report.findings,
            &report.inventory,
            DateTime::parse_from_rfc3339("2026-10-13T12:00:00Z").unwrap(),
        )
        .unwrap();
    report.policy_decisions = evaluated.decisions;
    report.policy_summary = evaluated.summary;
    for format in ReportFormat::ALL {
        let bytes = render(&report, format).unwrap();
        assert_eq!(bytes, render(&report, format).unwrap(), "{format}");
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains("synthetic-redaction-value"), "{format}");
        match format {
            ReportFormat::Junit => {
                let xml = roxmltree::Document::parse(text).unwrap();
                assert_eq!(xml.root_element().attribute("failures"), Some("1"));
            }
            ReportFormat::CycloneDxVex | ReportFormat::GitLabCycloneDx => {
                validate_cdx(&serde_json::from_slice(&bytes).unwrap());
            }
            ReportFormat::Html => assert!(!text.contains("<script>unsafe</script>")),
            _ => {}
        }
        if let Ok(directory) = std::env::var("HOORAY_SMOKE_EVIDENCE_DIR") {
            std::fs::write(
                std::path::Path::new(&directory).join(format!(
                    "{}.{}",
                    format.as_str(),
                    format.extension()
                )),
                bytes,
            )
            .unwrap();
        }
    }
}

#[test]
fn metadata_redaction_never_treats_component_or_finding_ids_as_keys() {
    let mut report = fixture();
    let mut finding = report.findings.pop_first().unwrap().1;
    finding.id = FindingId::new("finding:password").unwrap();
    report.findings.insert(finding.id.clone(), finding);
    let (previous_id, mut component) = report.inventory.components.pop_first().unwrap();
    component.identity = ComponentId::new("component:access-token").unwrap();
    let replacement_id = component.identity.clone();
    report
        .inventory
        .components
        .insert(replacement_id.clone(), component);
    report.inventory.dependencies = report
        .inventory
        .dependencies
        .iter()
        .cloned()
        .map(|mut edge| {
            if edge.from == previous_id {
                edge.from = replacement_id.clone();
            }
            if edge.to == previous_id {
                edge.to = replacement_id.clone();
            }
            edge
        })
        .collect();
    for finding in report.findings.values_mut() {
        if finding.component_id.as_ref() == Some(&previous_id) {
            finding.component_id = Some(replacement_id.clone());
        }
    }
    report.validate().unwrap();
    for format in ReportFormat::ALL {
        let bytes = render(&report, format).unwrap_or_else(|error| panic!("{format}: {error}"));
        assert!(
            !String::from_utf8(bytes)
                .unwrap()
                .contains("synthetic-redaction-value")
        );
    }
    let value: Value =
        serde_json::from_slice(&render(&report, ReportFormat::Json).unwrap()).unwrap();
    assert_eq!(
        value["report"]["findings"]["finding:password"]["id"],
        "finding:password"
    );
    assert_eq!(
        value["report"]["inventory"]["components"]["component:access-token"]["identity"],
        "component:access-token"
    );
}

#[test]
fn cyclonedx_multiple_expression_and_named_licenses_remain_schema_valid() {
    let cases = [
        vec![(Some("MIT OR Apache-2.0"), None), (Some("ISC"), None)],
        vec![
            (Some("MIT OR Apache-2.0"), None),
            (None, Some("Acme custom license")),
        ],
    ];
    for records in cases {
        let mut report = fixture();
        for component in report.inventory.components.values_mut() {
            component.licenses = records
                .iter()
                .map(|(expression, name)| License {
                    expression: expression.map(str::to_owned),
                    name: name.map(str::to_owned),
                    url: None,
                })
                .collect();
        }
        for format in [ReportFormat::GitLabCycloneDx, ReportFormat::CycloneDxVex] {
            let bytes = render(&report, format).unwrap();
            let document: Value = serde_json::from_slice(&bytes).unwrap();
            validate_cdx(&document);
            for component in document["components"].as_array().unwrap() {
                assert!(
                    component.get("licenses").is_some(),
                    "{format} dropped license evidence"
                );
                assert!(
                    component["licenses"]
                        .to_string()
                        .contains("MIT OR Apache-2.0")
                );
            }
        }
    }
}

#[test]
fn cyclonedx_dependency_targets_are_unique_across_scoped_edges() {
    let mut report = fixture();
    let mut duplicate = report.inventory.dependencies.first().unwrap().clone();
    duplicate.scope = Scope::Build;
    duplicate.optional = true;
    report.inventory.dependencies.insert(duplicate);
    for format in [ReportFormat::GitLabCycloneDx, ReportFormat::CycloneDxVex] {
        let document: Value = serde_json::from_slice(&render(&report, format).unwrap()).unwrap();
        validate_cdx(&document);
        assert!(
            document["dependencies"]
                .as_array()
                .unwrap()
                .iter()
                .all(|edge| edge["dependsOn"].as_array().unwrap().len() <= 1)
        );
    }
}

#[test]
fn fail_closed_exceptions_do_not_waive_an_independent_ordinary_denial() {
    let report = fixture();
    let policy = Policy::from_yaml(
        r#"
version: 1
fail_closed: {unknown_applicability: true, unknown_licenses: true}
rules:
  - id: deny-critical
    outcome: deny
    reason: critical vulnerabilities are prohibited
    selectors: {minimum_severity: critical}
exceptions:
  - id: accept-missing-applicability
    owner: security
    reason: evidence collection in progress
    ticket: SEC-1
    expires_at: '2026-10-14T12:00:00Z'
    selectors: {policy_id: fail-closed-applicability, finding_id: 'finding:smoke'}
  - id: accept-missing-license
    owner: security
    reason: evidence collection in progress
    ticket: SEC-2
    expires_at: '2026-10-14T12:00:00Z'
    selectors: {policy_id: fail-closed-license, finding_id: 'finding:smoke'}
"#,
    )
    .unwrap();
    let evaluated = policy
        .evaluate(
            &report.findings,
            &report.inventory,
            DateTime::parse_from_rfc3339("2026-10-13T12:00:00Z").unwrap(),
        )
        .unwrap();
    assert_eq!(evaluated.summary.denied, 1);
    assert_eq!(
        evaluated.decisions.first().unwrap().policy_id.as_str(),
        "deny-critical"
    );
}

#[test]
fn exact_purl_exception_accepts_qualifiers_and_still_rejects_globs() {
    let qualified = "pkg:maven/org.example/demo@1.0.0?type=jar";
    let yaml = |purl: &str| {
        format!(
            "version: 1\ndefault_outcome: deny\nexceptions:\n  - id: qualified-package\n    owner: security\n    reason: accepted package\n    ticket: SEC-3\n    expires_at: '2026-10-14T12:00:00Z'\n    selectors:\n      purl: '{purl}'\n"
        )
    };
    for purl in [qualified, "pkg:maven/org.example/demo?type=jar"] {
        let policy = Policy::from_yaml(&yaml(purl))
            .expect("literal purl qualifier delimiter is not a wildcard");
        let mut report = fixture();
        let component_id = report
            .findings
            .values()
            .next()
            .unwrap()
            .component_id
            .clone()
            .unwrap();
        report
            .inventory
            .components
            .get_mut(&component_id)
            .unwrap()
            .purl = purl.into();
        let evaluate = |report: &ScanReport| {
            policy
                .evaluate(
                    &report.findings,
                    &report.inventory,
                    DateTime::parse_from_rfc3339("2026-10-13T12:00:00Z").unwrap(),
                )
                .unwrap()
        };
        assert_eq!(evaluate(&report).summary.allowed, 1);
        report
            .inventory
            .components
            .get_mut(&component_id)
            .unwrap()
            .purl = "pkg:maven/org.example/demo@1.0.0?type=war".into();
        assert_eq!(evaluate(&report).summary.denied, 1);
    }
    for purl in [
        "pkg:maven/org.example/*@1.0.0",
        "pkg:cargo/demo@?",
        "pkg:cargo/demo@[1]",
    ] {
        assert!(Policy::from_yaml(&yaml(purl)).is_err(), "{purl}");
    }
}

#[test]
fn not_affected_vex_does_not_invent_negative_execution_evidence() {
    let mut report = fixture();
    report.findings.values_mut().next().unwrap().applicability = Some(Applicability {
        status: ApplicabilityStatus::NotAffected,
        rationale: Some("package ecosystem does not match advisory".into()),
    });
    let document: Value =
        serde_json::from_slice(&render(&report, ReportFormat::CycloneDxVex).unwrap()).unwrap();
    let analysis = &document["vulnerabilities"][0]["analysis"];
    assert_eq!(analysis["state"], "not_affected");
    assert!(analysis.get("justification").is_none());
}

#[test]
fn virtual_root_does_not_replace_a_real_component_with_the_same_id() {
    let mut report = fixture();
    report
        .inventory
        .asset
        .metadata
        .insert(VIRTUAL_ROOT_METADATA.into(), json!(true));
    report.inventory.dependencies.clear();
    report.inventory.components.clear();
    let id = ComponentId::new("hooray:virtual-root").unwrap();
    report.inventory.components.insert(
        id.clone(),
        Component {
            identity: id.clone(),
            name: "actual-package".into(),
            version: "1.0.0".into(),
            purl: "pkg:cargo/actual-package@1.0.0".into(),
            scope: Scope::Runtime,
            provenance: BTreeSet::new(),
            locations: BTreeSet::new(),
            licenses: BTreeSet::new(),
        },
    );
    let graph = DependencyGraph::from_inventory(&report.inventory).unwrap();
    assert_eq!(graph.classify(&id).unwrap(), DependencyKind::Direct);
    assert_eq!(
        graph.shortest_path(&id).unwrap().unwrap().components,
        vec![id]
    );
}

#[test]
fn malformed_osv_event_cannot_be_hidden_by_a_comparable_fixed_event() {
    let report = fixture();
    let component = report.inventory.components.values().next().unwrap();
    let outcome = |events| {
        let affected_ranges = vec![OsvAffectedRange {
            range_type: OsvRangeType::Semver,
            ecosystem: Some("cargo".into()),
            events,
            versions: Vec::new(),
        }];
        ApplicabilityAnalyzer::analyze(ApplicabilityInput {
            component,
            paths: None,
            affected_ranges: &affected_ranges,
            evidence: &BTreeSet::new(),
        })
    };
    assert_eq!(
        outcome(vec![
            OsvEvent {
                introduced: Some("0".into()),
                ..OsvEvent::default()
            },
            OsvEvent {
                fixed: Some("1.0.0".into()),
                ..OsvEvent::default()
            }
        ])
        .status,
        ApplicabilityStatus::Fixed
    );
    for events in [
        vec![
            OsvEvent {
                introduced: Some("unusable version".into()),
                ..OsvEvent::default()
            },
            OsvEvent {
                fixed: Some("1.0.0".into()),
                ..OsvEvent::default()
            },
        ],
        vec![
            OsvEvent {
                introduced: Some("0".into()),
                ..OsvEvent::default()
            },
            OsvEvent::default(),
            OsvEvent {
                fixed: Some("1.0.0".into()),
                ..OsvEvent::default()
            },
        ],
    ] {
        assert_eq!(outcome(events).status, ApplicabilityStatus::Unknown);
    }
}

#[test]
fn remediation_skips_malformed_semver_suffixes() {
    for ecosystem in [
        PackageEcosystem::Cargo,
        PackageEcosystem::Npm,
        PackageEcosystem::Go,
    ] {
        assert_eq!(
            nearest_fixed_version(
                ecosystem,
                "1.0.0",
                ["1.0.1-", "1.0.1+", "1.0.1+a..b", "1.0.1+a+b", "1.0.2"]
            ),
            Some("1.0.2".into())
        );
    }
}

#[test]
fn empty_inventory_reports_remain_valid_without_inventing_packages() {
    let mut report = fixture();
    report.inventory.components.clear();
    report.inventory.dependencies.clear();
    report.findings.values_mut().next().unwrap().component_id = None;
    for format in ReportFormat::ALL {
        let bytes = render(&report, format).unwrap();
        if matches!(
            format,
            ReportFormat::CycloneDxVex | ReportFormat::GitLabCycloneDx
        ) {
            validate_cdx(&serde_json::from_slice(&bytes).unwrap());
        }
        if matches!(
            format,
            ReportFormat::CycloneDxVex | ReportFormat::GitLabCycloneDx | ReportFormat::Spdx
        ) {
            assert!(matches!(
                parse_cyclonedx(&bytes),
                Err(hooray::sbom::SbomError::NoComponents)
            ));
        }
    }
}

#[test]
fn cyclonedx_roundtrip_preserves_each_component_scope() {
    for scope in [
        Scope::Runtime,
        Scope::Build,
        Scope::Development,
        Scope::Test,
        Scope::Optional,
        Scope::Unknown,
    ] {
        let mut report = fixture();
        for component in report.inventory.components.values_mut() {
            component.scope = scope;
        }
        for format in [ReportFormat::CycloneDxVex, ReportFormat::GitLabCycloneDx] {
            let parsed = parse_cyclonedx(&render(&report, format).unwrap()).unwrap();
            assert_eq!(
                parsed.components.keys().collect::<Vec<_>>(),
                report.inventory.components.keys().collect::<Vec<_>>()
            );
            assert!(
                parsed
                    .components
                    .values()
                    .all(|component| component.scope == scope),
                "{format}: {scope:?}"
            );
        }
    }
}

#[test]
fn duplicate_sbom_component_scopes_merge_conservatively_and_deterministically() {
    let document = |scopes: &[&str]| {
        json!({"bomFormat": "CycloneDX", "components": scopes.iter().enumerate().map(|(index, scope)| json!({
        "bom-ref": format!("duplicate-{index}"), "name": "dep", "version": "1.0.0", "purl": "pkg:cargo/dep@1.0.0", "scope": scope
    })).collect::<Vec<_>>()})
    };
    for scopes in [["required", "excluded"], ["excluded", "required"]] {
        let parsed = parse_cyclonedx(&serde_json::to_vec(&document(&scopes)).unwrap()).unwrap();
        assert_eq!(parsed.components.len(), 1);
        assert_eq!(
            parsed.components.values().next().unwrap().scope,
            Scope::Runtime
        );
    }
}

#[test]
fn cyclonedx_scope_property_does_not_override_conflicting_standard_evidence() {
    for properties in [
        json!([{"name": "hooray:scope", "value": "test"}]),
        json!([{"name": "hooray:scope", "value": "not-a-scope"}]),
        json!([{"name": "hooray:scope", "value": "runtime"}, {"name": "hooray:scope", "value": "test"}]),
    ] {
        let document = json!({"bomFormat": "CycloneDX", "components": [{
            "name": "dep", "version": "1.0.0", "purl": "pkg:cargo/dep@1.0.0", "scope": "required", "properties": properties
        }]});
        assert!(matches!(
            parse_cyclonedx(&serde_json::to_vec(&document).unwrap()),
            Err(hooray::sbom::SbomError::InvalidComponent { field: "scope", .. })
        ));
    }
}
