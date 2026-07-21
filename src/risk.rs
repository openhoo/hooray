use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, NaiveDate, Utc};

use crate::model::{
    ApplicabilityStatus, Component, ComponentId, Confidence, Evidence, Finding, FindingKind,
    FindingStatus, Inventory, Remediation, Risk, RuleId, Scope, Severity, stable_finding_id,
};

const DIRECT_COMPONENT: i32 = 1_000;
const TRANSITIVE_COMPONENT: i32 = 550;
const UNKNOWN_DIRECTNESS: i32 = 700;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskInput<'a> {
    pub severity: Severity,
    pub confidence: Confidence,
    pub applicability: ApplicabilityStatus,
    pub component: &'a Component,
    pub direct: Option<bool>,
    pub remediation: Option<&'a Remediation>,
    pub evidence: &'a BTreeSet<Evidence>,
    pub as_of: NaiveDate,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RiskScorer;

impl RiskScorer {
    pub fn score(input: RiskInput<'_>) -> Risk {
        let metadata = Metadata::new(input.evidence);
        let mut factors = BTreeMap::new();
        factors.insert("severity".to_owned(), severity_points(input.severity));
        factors.insert("confidence".to_owned(), confidence_points(input.confidence));
        factors.insert(
            "applicability".to_owned(),
            applicability_points(input.applicability),
        );
        factors.insert(
            "scope-exposure".to_owned(),
            scope_points(input.component.scope),
        );
        factors.insert(
            "dependency-directness".to_owned(),
            match input.direct {
                Some(true) => DIRECT_COMPONENT,
                Some(false) => TRANSITIVE_COMPONENT,
                None => UNKNOWN_DIRECTNESS,
            },
        );
        factors.insert(
            "fix-availability".to_owned(),
            fix_points(input.remediation, &metadata),
        );
        factors.insert(
            "component-age".to_owned(),
            age_points(&metadata, input.as_of),
        );
        factors.insert("release-cadence".to_owned(), cadence_points(&metadata));
        factors.insert("maintenance".to_owned(), maintenance_points(&metadata));

        let raw: i32 = factors.values().sum();
        let score = raw.clamp(0, i32::from(Risk::MAX_SCORE)) as u16;
        let mut risk = Risk::new(score).expect("clamped risk score is valid");
        risk.factors = factors;
        risk
    }
}

fn severity_points(severity: Severity) -> i32 {
    match severity {
        Severity::Unknown => 1_000,
        Severity::Low => 1_250,
        Severity::Medium => 2_250,
        Severity::High => 3_250,
        Severity::Critical => 4_250,
    }
}

fn confidence_points(confidence: Confidence) -> i32 {
    match confidence {
        Confidence::Low => 250,
        Confidence::Medium => 550,
        Confidence::High => 850,
        Confidence::Unknown => 400,
    }
}

fn applicability_points(status: ApplicabilityStatus) -> i32 {
    match status {
        ApplicabilityStatus::Affected => 1_650,
        ApplicabilityStatus::UnderInvestigation => 950,
        ApplicabilityStatus::Unknown => 700,
        ApplicabilityStatus::Fixed => -1_750,
        ApplicabilityStatus::NotAffected => -3_250,
    }
}

fn scope_points(scope: Scope) -> i32 {
    match scope {
        Scope::Runtime => 900,
        Scope::Build => 500,
        Scope::Development => 300,
        Scope::Test => 200,
        Scope::Optional => 350,
        Scope::Unknown => 450,
    }
}

fn fix_points(remediation: Option<&Remediation>, metadata: &Metadata<'_>) -> i32 {
    if remediation.is_some_and(|item| !item.fixed_versions.is_empty())
        || metadata.boolean("fix.available") == Some(true)
    {
        -600
    } else if metadata.boolean("fix.available") == Some(false) {
        500
    } else {
        100
    }
}

fn age_points(metadata: &Metadata<'_>, as_of: NaiveDate) -> i32 {
    let days = metadata
        .integer("component.age_days")
        .or_else(|| {
            metadata
                .date("component.first_published")
                .map(|date| (as_of - date).num_days())
        })
        .filter(|days| *days >= 0);
    match days {
        Some(0..=365) => 0,
        Some(366..=1_825) => 100,
        Some(1_826..=3_650) => 250,
        Some(_) => 400,
        None => 100,
    }
}

fn cadence_points(metadata: &Metadata<'_>) -> i32 {
    match metadata
        .integer("release.cadence_days")
        .filter(|days| *days >= 0)
    {
        Some(0..=30) => -150,
        Some(31..=90) => 0,
        Some(91..=365) => 150,
        Some(_) => 350,
        None => 100,
    }
}

fn maintenance_points(metadata: &Metadata<'_>) -> i32 {
    match metadata
        .value("maintenance.status")
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("active") | Some("maintained") => -250,
        Some("limited") | Some("best-effort") => 200,
        Some("stale") => 450,
        Some("abandoned") | Some("unmaintained") | Some("end-of-life") => 750,
        Some("deprecated") => 600,
        Some(_) | None => 100,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalRiskConfig {
    pub stale_after_days: i64,
    pub excessively_outdated_versions: i64,
}

impl Default for OperationalRiskConfig {
    fn default() -> Self {
        Self {
            stale_after_days: 730,
            excessively_outdated_versions: 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalRiskInput<'a> {
    pub inventory: &'a Inventory,
    pub evidence_by_component: &'a BTreeMap<ComponentId, BTreeSet<Evidence>>,
    pub as_of: DateTime<Utc>,
    pub config: OperationalRiskConfig,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct OperationalRiskAnalyzer;

impl OperationalRiskAnalyzer {
    pub fn analyze(input: OperationalRiskInput<'_>) -> BTreeMap<crate::model::FindingId, Finding> {
        let mut findings = BTreeMap::new();
        for component in input.inventory.components.values() {
            let Some(evidence) = input.evidence_by_component.get(&component.identity) else {
                continue;
            };
            let metadata = Metadata::new(evidence);
            let mut conditions = Vec::new();

            if matches!(
                metadata
                    .value("maintenance.status")
                    .map(str::to_ascii_lowercase)
                    .as_deref(),
                Some("abandoned" | "unmaintained" | "end-of-life")
            ) {
                conditions.push((
                    "abandoned",
                    Severity::High,
                    "Component provenance declares the project abandoned or unmaintained"
                        .to_owned(),
                ));
            }
            if metadata.boolean("package.yanked") == Some(true)
                || metadata.boolean("release.yanked") == Some(true)
            {
                conditions.push((
                    "yanked",
                    Severity::High,
                    "Component provenance declares this release yanked".to_owned(),
                ));
            }
            if metadata.boolean("package.deprecated") == Some(true)
                || metadata.boolean("release.deprecated") == Some(true)
                || metadata
                    .value("maintenance.status")
                    .is_some_and(|value| value.eq_ignore_ascii_case("deprecated"))
            {
                conditions.push((
                    "deprecated",
                    Severity::Medium,
                    "Component provenance declares this component or release deprecated".to_owned(),
                ));
            }
            if let Some(last_release) = metadata.date_time("release.last_published") {
                let age_days = input.as_of.signed_duration_since(last_release).num_days();
                if age_days >= input.config.stale_after_days {
                    conditions.push(("stale", Severity::Medium, format!("Last provenance-backed release was {age_days} days ago, meeting the {} day stale threshold", input.config.stale_after_days)));
                }
            }
            if let Some(versions_behind) = metadata.integer("release.versions_behind")
                && versions_behind >= input.config.excessively_outdated_versions
            {
                conditions.push(("excessively-outdated", Severity::Medium, format!("Provenance reports the component {versions_behind} releases behind, meeting the {} release threshold", input.config.excessively_outdated_versions)));
            }

            for (condition, severity, rationale) in conditions {
                let rule_id = RuleId::new(format!("operational-risk:{condition}"))
                    .expect("static operational risk rule identifier is non-empty");
                let id = stable_finding_id(
                    FindingKind::OperationalRisk,
                    &rule_id,
                    Some(&component.identity),
                    None,
                );
                let relevant_evidence: BTreeSet<_> = evidence
                    .iter()
                    .filter(|item| supports_condition(item, condition))
                    .cloned()
                    .collect();
                if relevant_evidence.is_empty() {
                    continue;
                }
                let risk = RiskScorer::score(RiskInput {
                    severity,
                    confidence: Confidence::High,
                    applicability: ApplicabilityStatus::Affected,
                    component,
                    direct: directness(input.inventory, &component.identity),
                    remediation: None,
                    evidence: &relevant_evidence,
                    as_of: input.as_of.date_naive(),
                });
                findings.insert(
                    id.clone(),
                    Finding {
                        id,
                        kind: FindingKind::OperationalRisk,
                        rule_id,
                        advisory_id: None,
                        component_id: Some(component.identity.clone()),
                        location_id: None,
                        aliases: BTreeSet::new(),
                        summary: Some(format!("{} component: {condition}", component.name)),
                        details: Some(rationale),
                        severity,
                        confidence: Confidence::High,
                        evidence: relevant_evidence,
                        applicability: Some(crate::model::Applicability {
                            status: ApplicabilityStatus::Affected,
                            rationale: Some(
                                "Finding is based only on explicit provenance metadata".to_owned(),
                            ),
                        }),
                        remediation: None,
                        risk: Some(risk),
                        first_seen: None,
                        last_seen: None,
                        modified: None,
                        status: FindingStatus::Open,
                    },
                );
            }
        }
        findings
    }
}

fn directness(inventory: &Inventory, component: &ComponentId) -> Option<bool> {
    let incoming: BTreeSet<_> = inventory.dependencies.iter().map(|edge| &edge.to).collect();
    let roots: BTreeSet<_> = inventory
        .components
        .keys()
        .filter(|id| !incoming.contains(id))
        .collect();
    if roots.contains(component) {
        return Some(true);
    }
    inventory
        .dependencies
        .iter()
        .any(|edge| &edge.to == component && roots.contains(&edge.from))
        .then_some(true)
        .or_else(|| incoming.contains(component).then_some(false))
}

fn supports_condition(evidence: &Evidence, condition: &str) -> bool {
    let keys: &[&str] = match condition {
        "abandoned" => &["maintenance.status"],
        "yanked" => &["package.yanked", "release.yanked"],
        "deprecated" => &[
            "package.deprecated",
            "release.deprecated",
            "maintenance.status",
        ],
        "stale" => &["release.last_published"],
        "excessively-outdated" => &["release.versions_behind"],
        _ => &[],
    };
    keys.iter()
        .any(|key| evidence.properties.contains_key(*key))
}

struct Metadata<'a> {
    values: BTreeMap<&'a str, BTreeSet<&'a str>>,
}

impl<'a> Metadata<'a> {
    fn new(evidence: &'a BTreeSet<Evidence>) -> Self {
        let mut values: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for item in evidence {
            for (key, value) in &item.properties {
                values.entry(key).or_default().insert(value);
            }
        }
        Self { values }
    }

    fn value(&self, key: &str) -> Option<&str> {
        let values = self.values.get(key)?;
        (values.len() == 1).then(|| *values.first().expect("non-empty metadata values"))
    }

    fn boolean(&self, key: &str) -> Option<bool> {
        match self.value(key)? {
            value if value.eq_ignore_ascii_case("true") || value == "1" => Some(true),
            value if value.eq_ignore_ascii_case("false") || value == "0" => Some(false),
            _ => None,
        }
    }

    fn integer(&self, key: &str) -> Option<i64> {
        self.value(key)?.parse().ok()
    }

    fn date(&self, key: &str) -> Option<NaiveDate> {
        let value = self.value(key)?;
        NaiveDate::parse_from_str(value, "%Y-%m-%d")
            .ok()
            .or_else(|| {
                DateTime::parse_from_rfc3339(value)
                    .ok()
                    .map(|date| date.date_naive())
            })
    }

    fn date_time(&self, key: &str) -> Option<DateTime<Utc>> {
        let value = self.value(key)?;
        DateTime::parse_from_rfc3339(value)
            .ok()
            .map(|date| date.with_timezone(&Utc))
            .or_else(|| {
                NaiveDate::parse_from_str(value, "%Y-%m-%d")
                    .ok()?
                    .and_hms_opt(0, 0, 0)
                    .map(|date| date.and_utc())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Asset, AssetId, AssetKind, DependencyEdge};
    use serde_json::Value;

    fn component(scope: Scope) -> Component {
        Component {
            identity: ComponentId::new("component:lib").unwrap(),
            name: "lib".into(),
            version: "1.0.0".into(),
            purl: "pkg:cargo/lib@1.0.0".into(),
            scope,
            provenance: BTreeSet::new(),
            licenses: BTreeSet::new(),
            locations: BTreeSet::new(),
        }
    }

    fn evidence(properties: &[(&str, &str)]) -> BTreeSet<Evidence> {
        properties
            .iter()
            .enumerate()
            .map(|(index, (key, value))| Evidence {
                description: format!("registry provenance {index}"),
                locations: BTreeSet::new(),
                references: BTreeSet::from(["https://registry.example/lib".into()]),
                properties: BTreeMap::from([((*key).into(), (*value).into())]),
                redacted: false,
            })
            .collect()
    }

    fn risk(
        severity: Severity,
        confidence: Confidence,
        applicability: ApplicabilityStatus,
        scope: Scope,
        properties: &[(&str, &str)],
    ) -> Risk {
        let component = component(scope);
        let evidence = evidence(properties);
        RiskScorer::score(RiskInput {
            severity,
            confidence,
            applicability,
            component: &component,
            direct: Some(true),
            remediation: None,
            evidence: &evidence,
            as_of: NaiveDate::from_ymd_opt(2026, 7, 21).unwrap(),
        })
    }

    #[test]
    fn severity_boundary_table_is_monotonic() {
        let mut previous = 0;
        for severity in [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            let score = risk(
                severity,
                Confidence::High,
                ApplicabilityStatus::Affected,
                Scope::Runtime,
                &[],
            )
            .score();
            assert!(score > previous, "{severity:?}");
            previous = score;
        }
    }

    #[test]
    fn applicability_boundary_table_preserves_unknown_risk() {
        let affected = risk(
            Severity::High,
            Confidence::High,
            ApplicabilityStatus::Affected,
            Scope::Runtime,
            &[],
        )
        .score();
        let investigating = risk(
            Severity::High,
            Confidence::High,
            ApplicabilityStatus::UnderInvestigation,
            Scope::Runtime,
            &[],
        )
        .score();
        let unknown = risk(
            Severity::High,
            Confidence::High,
            ApplicabilityStatus::Unknown,
            Scope::Runtime,
            &[],
        )
        .score();
        let fixed = risk(
            Severity::High,
            Confidence::High,
            ApplicabilityStatus::Fixed,
            Scope::Runtime,
            &[],
        )
        .score();
        let not_affected = risk(
            Severity::High,
            Confidence::High,
            ApplicabilityStatus::NotAffected,
            Scope::Runtime,
            &[],
        )
        .score();
        assert!(
            affected > investigating
                && investigating > unknown
                && unknown > fixed
                && fixed > not_affected
        );
        assert!(unknown > 0);
    }

    #[test]
    fn explicit_factors_sum_to_clamped_score() {
        let scored = risk(
            Severity::Critical,
            Confidence::High,
            ApplicabilityStatus::Affected,
            Scope::Runtime,
            &[
                ("maintenance.status", "abandoned"),
                ("fix.available", "false"),
                ("component.age_days", "5000"),
                ("release.cadence_days", "800"),
            ],
        );
        let sum: i32 = scored.factors.values().sum();
        assert_eq!(scored.score(), sum.clamp(0, 10_000) as u16);
        assert_eq!(scored.score(), 10_000);
        for key in [
            "severity",
            "confidence",
            "applicability",
            "scope-exposure",
            "dependency-directness",
            "fix-availability",
            "component-age",
            "release-cadence",
            "maintenance",
        ] {
            assert!(scored.factors.contains_key(key));
        }
    }

    #[test]
    fn contradictory_or_absent_metadata_uses_neutral_unknown_factors() {
        let absent = risk(
            Severity::Medium,
            Confidence::Unknown,
            ApplicabilityStatus::Unknown,
            Scope::Unknown,
            &[],
        );
        let contradictory = risk(
            Severity::Medium,
            Confidence::Unknown,
            ApplicabilityStatus::Unknown,
            Scope::Unknown,
            &[
                ("maintenance.status", "active"),
                ("maintenance.status", "abandoned"),
                ("fix.available", "true"),
                ("fix.available", "false"),
            ],
        );
        assert_eq!(absent.factors["maintenance"], 100);
        assert_eq!(contradictory.factors["maintenance"], 100);
        assert_eq!(contradictory.factors["fix-availability"], 100);
    }

    #[test]
    fn age_and_cadence_boundary_tables_are_deterministic() {
        for (days, expected) in [
            (365, 0),
            (366, 100),
            (1825, 100),
            (1826, 250),
            (3650, 250),
            (3651, 400),
        ] {
            assert_eq!(
                risk(
                    Severity::Low,
                    Confidence::Low,
                    ApplicabilityStatus::Unknown,
                    Scope::Test,
                    &[("component.age_days", &days.to_string())]
                )
                .factors["component-age"],
                expected
            );
        }
        for (days, expected) in [
            (30, -150),
            (31, 0),
            (90, 0),
            (91, 150),
            (365, 150),
            (366, 350),
        ] {
            assert_eq!(
                risk(
                    Severity::Low,
                    Confidence::Low,
                    ApplicabilityStatus::Unknown,
                    Scope::Test,
                    &[("release.cadence_days", &days.to_string())]
                )
                .factors["release-cadence"],
                expected
            );
        }
    }

    fn inventory(component: Component) -> Inventory {
        Inventory {
            asset: Asset {
                id: AssetId::new("asset:test").unwrap(),
                name: "test".into(),
                kind: AssetKind::Repository,
                version: None,
                metadata: BTreeMap::<String, Value>::new(),
            },
            components: BTreeMap::from([(component.identity.clone(), component)]),
            dependencies: BTreeSet::<DependencyEdge>::new(),
        }
    }

    fn operational(
        properties: &[(&str, &str)],
        config: OperationalRiskConfig,
    ) -> BTreeMap<crate::model::FindingId, Finding> {
        let component = component(Scope::Runtime);
        let inventory = inventory(component.clone());
        let evidence_by_component =
            BTreeMap::from([(component.identity.clone(), evidence(properties))]);
        OperationalRiskAnalyzer::analyze(OperationalRiskInput {
            inventory: &inventory,
            evidence_by_component: &evidence_by_component,
            as_of: DateTime::parse_from_rfc3339("2026-07-21T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            config,
        })
    }

    #[test]
    fn operational_analyzer_emits_every_supported_condition() {
        let findings = operational(
            &[
                ("maintenance.status", "abandoned"),
                ("package.yanked", "true"),
                ("package.deprecated", "true"),
                ("release.last_published", "2020-01-01T00:00:00Z"),
                ("release.versions_behind", "8"),
            ],
            OperationalRiskConfig::default(),
        );
        let rules: BTreeSet<_> = findings
            .values()
            .map(|finding| finding.rule_id.as_str())
            .collect();
        assert_eq!(
            rules,
            BTreeSet::from([
                "operational-risk:abandoned",
                "operational-risk:deprecated",
                "operational-risk:excessively-outdated",
                "operational-risk:stale",
                "operational-risk:yanked"
            ])
        );
        assert!(
            findings
                .values()
                .all(|finding| finding.confidence == Confidence::High
                    && !finding.evidence.is_empty()
                    && finding.risk.is_some())
        );
    }

    #[test]
    fn operational_analyzer_never_guesses_from_names_versions_or_missing_provenance() {
        assert!(operational(&[], OperationalRiskConfig::default()).is_empty());
        assert!(
            operational(
                &[
                    ("release.last_published", "not-a-date"),
                    ("release.versions_behind", "unknown"),
                    ("package.yanked", "false"),
                    ("package.deprecated", "false")
                ],
                OperationalRiskConfig::default()
            )
            .is_empty()
        );
    }

    #[test]
    fn stale_and_outdated_thresholds_are_inclusive() {
        let config = OperationalRiskConfig {
            stale_after_days: 10,
            excessively_outdated_versions: 5,
        };
        let below = operational(
            &[
                ("release.last_published", "2026-07-12T00:00:00Z"),
                ("release.versions_behind", "4"),
            ],
            config.clone(),
        );
        assert!(below.is_empty());
        let boundary = operational(
            &[
                ("release.last_published", "2026-07-11T00:00:00Z"),
                ("release.versions_behind", "5"),
            ],
            config,
        );
        assert_eq!(boundary.len(), 2);
    }

    #[test]
    fn contradictory_provenance_does_not_emit_a_finding() {
        let findings = operational(
            &[
                ("maintenance.status", "active"),
                ("maintenance.status", "abandoned"),
                ("package.yanked", "true"),
                ("package.yanked", "false"),
            ],
            OperationalRiskConfig::default(),
        );
        assert!(findings.is_empty());
    }
}
