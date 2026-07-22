use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::model::{
    Applicability, ApplicabilityStatus, Component, ComponentId, Evidence, Inventory, Scope,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsvRangeType {
    Ecosystem,
    Semver,
    Git,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OsvEvent {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
    pub last_affected: Option<String>,
    pub limit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsvAffectedRange {
    pub range_type: OsvRangeType,
    pub ecosystem: Option<String>,
    pub events: Vec<OsvEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicabilityInput<'a> {
    pub component: &'a Component,
    pub inventory: Option<&'a Inventory>,
    pub evidence: &'a BTreeSet<Evidence>,
    pub affected_ranges: &'a [OsvAffectedRange],
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ApplicabilityAnalyzer;

impl ApplicabilityAnalyzer {
    pub fn analyze(input: ApplicabilityInput<'_>) -> Applicability {
        let mut rationale = Vec::new();
        let ecosystem = purl_ecosystem(&input.component.purl);
        let evidence = EvidenceView::new(input.evidence);
        let version = version_parts(&input.component.version);
        let paths = input
            .inventory
            .map(|inventory| dependency_paths(inventory, &input.component.identity))
            .unwrap_or_default();
        let reachable = evidence.boolean("dependency.reachable");
        let imported = evidence
            .boolean("source.imported")
            .or_else(|| evidence.boolean("source.import.reachable"));

        rationale.push(format!(
            "component {} {} ({}) has {} dependency path(s)",
            input.component.name,
            input.component.version,
            input.component.scope_label(),
            paths.len()
        ));
        if let Some(path) = paths.first() {
            rationale.push(format!("shortest dependency path: {path}"));
        }
        describe_signal(&mut rationale, "dependency reachability", reachable);
        describe_signal(&mut rationale, "source/import evidence", imported);

        if let Some(expected) = evidence.value("package.ecosystem") {
            match ecosystem {
                Some(actual) if !expected.eq_ignore_ascii_case(actual) => {
                    rationale.push(format!(
                        "explicit package ecosystem {expected} does not match purl ecosystem {actual}"
                    ));
                    return applicability(ApplicabilityStatus::NotAffected, rationale);
                }
                Some(actual) => rationale.push(format!("package ecosystem matched {actual}")),
                None => rationale.push(format!(
                    "package ecosystem evidence says {expected}, but the purl ecosystem is unavailable"
                )),
            }
        }

        let matching_ranges: Vec<_> = input
            .affected_ranges
            .iter()
            .filter(|range| {
                range.ecosystem.as_deref().is_none_or(|expected| {
                    ecosystem.is_some_and(|actual| expected.eq_ignore_ascii_case(actual))
                })
            })
            .collect();
        if input
            .affected_ranges
            .iter()
            .any(|range| range.ecosystem.is_some())
            && matching_ranges.is_empty()
            && ecosystem.is_some()
        {
            rationale.push("no OSV affected range matches the component ecosystem".to_owned());
            return applicability(ApplicabilityStatus::NotAffected, rationale);
        }
        if matching_ranges.is_empty() {
            rationale.push("no applicable OSV version range was supplied".to_owned());
            return applicability(ApplicabilityStatus::Unknown, rationale);
        }

        let mut outcomes = BTreeSet::new();
        for range in matching_ranges {
            match evaluate_range(range, &input.component.version, version.as_deref()) {
                RangeOutcome::Affected(detail) => {
                    outcomes.insert(ApplicabilityStatus::Affected);
                    rationale.push(detail);
                }
                RangeOutcome::Fixed(detail) => {
                    outcomes.insert(ApplicabilityStatus::Fixed);
                    rationale.push(detail);
                }
                RangeOutcome::NotAffected(detail) => {
                    outcomes.insert(ApplicabilityStatus::NotAffected);
                    rationale.push(detail);
                }
                RangeOutcome::Unknown(detail) => {
                    outcomes.insert(ApplicabilityStatus::Unknown);
                    rationale.push(detail);
                }
            }
        }

        let contradictory_context = evidence.conflicts("dependency.reachable")
            || evidence.conflicts("source.imported")
            || evidence.conflicts("source.import.reachable")
            || evidence.conflicts("package.ecosystem")
            || matches!(
                (reachable, imported),
                (Some(true), Some(false)) | (Some(false), Some(true))
            );
        let contradictory_ranges = outcomes.len() > 1;
        if contradictory_context || contradictory_ranges {
            rationale
                .push("available evidence is contradictory and requires investigation".to_owned());
            return applicability(ApplicabilityStatus::UnderInvestigation, rationale);
        }

        if outcomes.contains(&ApplicabilityStatus::Affected) {
            if reachable == Some(false) && imported == Some(false) {
                rationale.push(
                    "version is affected, but both dependency and import evidence indicate no execution path"
                        .to_owned(),
                );
                return applicability(ApplicabilityStatus::NotAffected, rationale);
            }
            rationale.push(match input.component.scope {
                Scope::Runtime => "runtime scope increases exposure".to_owned(),
                Scope::Build | Scope::Development | Scope::Test => {
                    "non-runtime scope reduces exposure but does not negate an affected version".to_owned()
                }
                Scope::Optional => {
                    "optional scope does not negate an affected version without negative reachability evidence"
                        .to_owned()
                }
                Scope::Unknown => "scope is unknown and is not treated as suppression evidence".to_owned(),
            });
            return applicability(ApplicabilityStatus::Affected, rationale);
        }
        if outcomes.contains(&ApplicabilityStatus::Fixed) {
            return applicability(ApplicabilityStatus::Fixed, rationale);
        }
        if outcomes == BTreeSet::from([ApplicabilityStatus::NotAffected]) {
            return applicability(ApplicabilityStatus::NotAffected, rationale);
        }
        applicability(ApplicabilityStatus::Unknown, rationale)
    }
}

trait ScopeLabel {
    fn scope_label(&self) -> &'static str;
}

impl ScopeLabel for Component {
    fn scope_label(&self) -> &'static str {
        match self.scope {
            Scope::Runtime => "runtime scope",
            Scope::Build => "build scope",
            Scope::Development => "development scope",
            Scope::Test => "test scope",
            Scope::Optional => "optional scope",
            Scope::Unknown => "unknown scope",
        }
    }
}

fn applicability(status: ApplicabilityStatus, rationale: Vec<String>) -> Applicability {
    Applicability {
        status,
        rationale: Some(rationale.join("; ")),
    }
}

fn describe_signal(rationale: &mut Vec<String>, name: &str, signal: Option<bool>) {
    rationale.push(format!(
        "{name}: {}",
        match signal {
            Some(true) => "present",
            Some(false) => "explicitly absent",
            None => "unknown",
        }
    ));
}

struct EvidenceView<'a> {
    values: BTreeMap<&'a str, BTreeSet<&'a str>>,
}

impl<'a> EvidenceView<'a> {
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
        (values.len() == 1).then(|| *values.first().expect("non-empty evidence values"))
    }

    fn boolean(&self, key: &str) -> Option<bool> {
        let values = self.values.get(key)?;
        let parsed: BTreeSet<bool> = values
            .iter()
            .filter_map(|value| parse_bool(value))
            .collect();
        (parsed.len() == 1 && parsed.len() == values.len())
            .then(|| *parsed.first().expect("non-empty boolean evidence"))
    }

    fn conflicts(&self, key: &str) -> bool {
        self.values.get(key).is_some_and(|values| values.len() > 1)
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    if value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes") || value == "1" {
        Some(true)
    } else if value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("no")
        || value == "0"
    {
        Some(false)
    } else {
        None
    }
}

fn purl_ecosystem(purl: &str) -> Option<&str> {
    purl.strip_prefix("pkg:")?
        .split('/')
        .next()
        .filter(|v| !v.is_empty())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RangeOutcome {
    Affected(String),
    Fixed(String),
    NotAffected(String),
    Unknown(String),
}

fn evaluate_range(
    range: &OsvAffectedRange,
    version: &str,
    version_parts: Option<&[String]>,
) -> RangeOutcome {
    if range.range_type == OsvRangeType::Git {
        return RangeOutcome::Unknown(
            "git ranges require commit identity; package version was not guessed as a commit"
                .to_owned(),
        );
    }
    if version.trim().is_empty() {
        return RangeOutcome::Unknown("component version is absent".to_owned());
    }
    if range.events.is_empty() {
        return RangeOutcome::Unknown("OSV range contains no events".to_owned());
    }

    let mut active = false;
    let mut saw_comparable = false;
    let mut crossed_fixed: Option<&str> = None;
    let mut crossed_last_affected: Option<&str> = None;
    for event in &range.events {
        if let Some(introduced) = event.introduced.as_deref() {
            if introduced == "0" {
                active = true;
                saw_comparable = true;
                crossed_fixed = None;
                crossed_last_affected = None;
            } else if let Some(ordering) = compare_version_parts(version_parts, introduced) {
                saw_comparable = true;
                if ordering != Ordering::Less {
                    active = true;
                    crossed_fixed = None;
                    crossed_last_affected = None;
                }
            }
        }
        if let Some(fixed) = event.fixed.as_deref()
            && let Some(ordering) = compare_version_parts(version_parts, fixed)
        {
            saw_comparable = true;
            if ordering != Ordering::Less {
                active = false;
                crossed_fixed = Some(fixed);
            }
        }
        if let Some(last) = event.last_affected.as_deref()
            && let Some(ordering) = compare_version_parts(version_parts, last)
        {
            saw_comparable = true;
            if ordering == Ordering::Greater {
                active = false;
                crossed_last_affected = Some(last);
            } else if active {
                return RangeOutcome::Affected(format!(
                    "component version {version} is within a range ending at last-affected {last}"
                ));
            }
        }
        if let Some(limit) = event.limit.as_deref()
            && let Some(ordering) = compare_version_parts(version_parts, limit)
        {
            saw_comparable = true;
            if ordering != Ordering::Less {
                active = false;
                crossed_last_affected = Some(limit);
            }
        }
    }
    if active {
        RangeOutcome::Affected(format!(
            "component version {version} falls within the supplied OSV event interval"
        ))
    } else if let Some(fixed) = crossed_fixed {
        RangeOutcome::Fixed(format!(
            "component version {version} is at or after fixed event {fixed}"
        ))
    } else if let Some(boundary) = crossed_last_affected {
        RangeOutcome::NotAffected(format!(
            "component version {version} is after the affected boundary {boundary}"
        ))
    } else if saw_comparable {
        RangeOutcome::NotAffected(format!(
            "component version {version} precedes the introduced event"
        ))
    } else {
        RangeOutcome::Unknown(format!(
            "component version {version} could not be compared to the supplied OSV events"
        ))
    }
}

fn compare_version_parts(left: Option<&[String]>, right: &str) -> Option<Ordering> {
    let left = left?;
    let right = version_parts(right)?;
    compare_parsed_versions(left, &right)
}

#[cfg(test)]
fn compare_versions(left: &str, right: &str) -> Option<Ordering> {
    let left = version_parts(left)?;
    let right = version_parts(right)?;
    compare_parsed_versions(&left, &right)
}

fn compare_parsed_versions(left: &[String], right: &[String]) -> Option<Ordering> {
    let length = left.len().max(right.len());
    for index in 0..length {
        let lhs = left.get(index).map(String::as_str).unwrap_or("0");
        let rhs = right.get(index).map(String::as_str).unwrap_or("0");
        let ordering = match (lhs.parse::<u64>(), rhs.parse::<u64>()) {
            (Ok(lhs), Ok(rhs)) => lhs.cmp(&rhs),
            (Ok(_), Err(_)) => Ordering::Greater,
            (Err(_), Ok(_)) => Ordering::Less,
            (Err(_), Err(_)) => lhs.cmp(rhs),
        };
        if ordering != Ordering::Equal {
            return Some(ordering);
        }
    }
    Some(Ordering::Equal)
}

fn version_parts(version: &str) -> Option<Vec<String>> {
    let version = version.trim().trim_start_matches(['v', 'V']);
    if version.is_empty() || version.chars().any(char::is_whitespace) {
        return None;
    }
    let core = version.split_once('+').map_or(version, |(core, _)| core);
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut numeric = None;
    for character in core.chars() {
        if character.is_ascii_alphanumeric() {
            let is_numeric = character.is_ascii_digit();
            if numeric.is_some_and(|was_numeric| was_numeric != is_numeric) && !current.is_empty() {
                parts.push(std::mem::take(&mut current));
            }
            numeric = Some(is_numeric);
            current.push(character.to_ascii_lowercase());
        } else if matches!(character, '.' | '-' | '_' | ':') {
            if !current.is_empty() {
                parts.push(std::mem::take(&mut current));
            }
            numeric = None;
        } else {
            return None;
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    (!parts.is_empty()).then_some(parts)
}

fn dependency_paths(inventory: &Inventory, target: &ComponentId) -> Vec<String> {
    let incoming: BTreeSet<_> = inventory.dependencies.iter().map(|edge| &edge.to).collect();
    let roots: Vec<_> = inventory
        .components
        .keys()
        .filter(|id| !incoming.contains(id))
        .cloned()
        .collect();
    let mut queue: VecDeque<(ComponentId, Vec<ComponentId>)> = roots
        .into_iter()
        .map(|root| (root.clone(), vec![root]))
        .collect();
    let mut shortest: BTreeMap<ComponentId, usize> = BTreeMap::new();
    let mut results = Vec::new();
    while let Some((current, path)) = queue.pop_front() {
        if shortest
            .get(&current)
            .is_some_and(|length| *length < path.len())
        {
            continue;
        }
        shortest.insert(current.clone(), path.len());
        if &current == target {
            results.push(
                path.iter()
                    .map(|id| id.as_str())
                    .collect::<Vec<_>>()
                    .join(" -> "),
            );
            continue;
        }
        for edge in inventory
            .dependencies
            .iter()
            .filter(|edge| edge.from == current)
        {
            if !path.contains(&edge.to) {
                let mut next = path.clone();
                next.push(edge.to.clone());
                queue.push_back((edge.to.clone(), next));
            }
        }
    }
    results.sort_by_key(|path| (path.matches(" -> ").count(), path.clone()));
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Asset, AssetId, AssetKind, ComponentId, DependencyEdge};
    use serde_json::Value;

    fn component(version: &str, scope: Scope) -> Component {
        Component {
            identity: ComponentId::new("component:lib").unwrap(),
            name: "lib".into(),
            version: version.into(),
            purl: format!("pkg:cargo/lib@{version}"),
            scope,
            provenance: BTreeSet::new(),
            licenses: BTreeSet::new(),
            locations: BTreeSet::new(),
        }
    }

    fn inventory(component: Component, reachable: bool) -> Inventory {
        let root = Component {
            identity: ComponentId::new("component:root").unwrap(),
            name: "root".into(),
            version: "1".into(),
            purl: "pkg:cargo/root@1".into(),
            scope: Scope::Runtime,
            provenance: BTreeSet::new(),
            licenses: BTreeSet::new(),
            locations: BTreeSet::new(),
        };
        let mut components = BTreeMap::from([(component.identity.clone(), component.clone())]);
        let dependencies = if reachable {
            components.insert(root.identity.clone(), root.clone());
            BTreeSet::from([DependencyEdge {
                from: root.identity,
                to: component.identity,
                scope: Scope::Runtime,
                optional: false,
            }])
        } else {
            BTreeSet::new()
        };
        Inventory {
            asset: Asset {
                id: AssetId::new("asset:test").unwrap(),
                name: "test".into(),
                kind: AssetKind::Repository,
                version: None,
                metadata: BTreeMap::<String, Value>::new(),
            },
            components,
            locations: BTreeSet::new(),
            dependencies,
        }
    }

    fn range(events: Vec<OsvEvent>) -> Vec<OsvAffectedRange> {
        vec![OsvAffectedRange {
            range_type: OsvRangeType::Semver,
            ecosystem: Some("cargo".into()),
            events,
        }]
    }

    fn evidence(properties: &[(&str, &str)]) -> BTreeSet<Evidence> {
        properties
            .iter()
            .enumerate()
            .map(|(index, (key, value))| Evidence {
                description: format!("context-{index}"),
                locations: BTreeSet::new(),
                references: BTreeSet::new(),
                properties: BTreeMap::from([((*key).into(), (*value).into())]),
                redacted: false,
            })
            .collect()
    }

    fn analyze(version: &str, events: Vec<OsvEvent>, properties: &[(&str, &str)]) -> Applicability {
        let component = component(version, Scope::Runtime);
        let inventory = inventory(component.clone(), true);
        let evidence = evidence(properties);
        let ranges = range(events);
        ApplicabilityAnalyzer::analyze(ApplicabilityInput {
            component: &component,
            inventory: Some(&inventory),
            evidence: &evidence,
            affected_ranges: &ranges,
        })
    }

    #[test]
    fn osv_event_boundary_table() {
        let events = vec![OsvEvent {
            introduced: Some("1.2.0".into()),
            fixed: Some("2.0.0".into()),
            ..OsvEvent::default()
        }];
        for (version, expected) in [
            ("1.1.9", ApplicabilityStatus::NotAffected),
            ("1.2.0", ApplicabilityStatus::Affected),
            ("1.9.9", ApplicabilityStatus::Affected),
            ("2.0.0", ApplicabilityStatus::Fixed),
            ("2.1.0", ApplicabilityStatus::Fixed),
        ] {
            assert_eq!(
                analyze(version, events.clone(), &[]).status,
                expected,
                "{version}"
            );
        }
    }

    #[test]
    fn last_affected_and_limit_are_inclusive_and_exclusive() {
        let last = vec![OsvEvent {
            introduced: Some("0".into()),
            last_affected: Some("1.5".into()),
            ..OsvEvent::default()
        }];
        assert_eq!(
            analyze("1.5", last.clone(), &[]).status,
            ApplicabilityStatus::Affected
        );
        assert_eq!(
            analyze("1.5.1", last, &[]).status,
            ApplicabilityStatus::NotAffected
        );
        let limit = vec![OsvEvent {
            introduced: Some("0".into()),
            limit: Some("3.0".into()),
            ..OsvEvent::default()
        }];
        assert_eq!(
            analyze("2.9", limit.clone(), &[]).status,
            ApplicabilityStatus::Affected
        );
        assert_eq!(
            analyze("3.0", limit, &[]).status,
            ApplicabilityStatus::NotAffected
        );
    }

    #[test]
    fn multiple_introduced_and_fixed_intervals_are_evaluated_in_order() {
        let events = vec![
            OsvEvent {
                introduced: Some("0".into()),
                ..OsvEvent::default()
            },
            OsvEvent {
                fixed: Some("1.0".into()),
                ..OsvEvent::default()
            },
            OsvEvent {
                introduced: Some("2.0".into()),
                ..OsvEvent::default()
            },
            OsvEvent {
                fixed: Some("3.0".into()),
                ..OsvEvent::default()
            },
        ];
        assert_eq!(
            analyze("1.5", events.clone(), &[]).status,
            ApplicabilityStatus::Fixed
        );
        assert_eq!(
            analyze("2.5", events.clone(), &[]).status,
            ApplicabilityStatus::Affected
        );
        assert_eq!(
            analyze("3.0", events, &[]).status,
            ApplicabilityStatus::Fixed
        );
    }

    #[test]
    fn absent_or_unusable_range_is_unknown_not_suppressed() {
        let component = component("1.0", Scope::Unknown);
        let inventory = inventory(component.clone(), false);
        let evidence = BTreeSet::new();
        assert_eq!(
            ApplicabilityAnalyzer::analyze(ApplicabilityInput {
                component: &component,
                inventory: Some(&inventory),
                evidence: &evidence,
                affected_ranges: &[]
            })
            .status,
            ApplicabilityStatus::Unknown
        );
        let git = [OsvAffectedRange {
            range_type: OsvRangeType::Git,
            ecosystem: Some("cargo".into()),
            events: vec![OsvEvent {
                introduced: Some("abc".into()),
                ..OsvEvent::default()
            }],
        }];
        assert_eq!(
            ApplicabilityAnalyzer::analyze(ApplicabilityInput {
                component: &component,
                inventory: Some(&inventory),
                evidence: &evidence,
                affected_ranges: &git
            })
            .status,
            ApplicabilityStatus::Unknown
        );
    }

    #[test]
    fn contradictory_context_requires_investigation() {
        let events = vec![OsvEvent {
            introduced: Some("0".into()),
            ..OsvEvent::default()
        }];
        let result = analyze(
            "1.0",
            events,
            &[
                ("dependency.reachable", "true"),
                ("source.imported", "false"),
            ],
        );
        assert_eq!(result.status, ApplicabilityStatus::UnderInvestigation);
        assert!(result.rationale.unwrap().contains("contradictory"));
    }

    #[test]
    fn contradictory_values_for_the_same_signal_require_investigation() {
        let events = vec![OsvEvent {
            introduced: Some("0".into()),
            ..OsvEvent::default()
        }];
        let result = analyze(
            "1.0",
            events,
            &[
                ("dependency.reachable", "true"),
                ("dependency.reachable", "false"),
            ],
        );
        assert_eq!(result.status, ApplicabilityStatus::UnderInvestigation);
    }

    #[test]
    fn unknown_range_alongside_affected_range_is_not_suppressed() {
        let component = component("1.0", Scope::Runtime);
        let inventory = inventory(component.clone(), true);
        let evidence = BTreeSet::new();
        let ranges = [
            OsvAffectedRange {
                range_type: OsvRangeType::Semver,
                ecosystem: Some("cargo".into()),
                events: vec![OsvEvent {
                    introduced: Some("0".into()),
                    ..OsvEvent::default()
                }],
            },
            OsvAffectedRange {
                range_type: OsvRangeType::Git,
                ecosystem: Some("cargo".into()),
                events: vec![OsvEvent {
                    introduced: Some("abc".into()),
                    ..OsvEvent::default()
                }],
            },
        ];
        let result = ApplicabilityAnalyzer::analyze(ApplicabilityInput {
            component: &component,
            inventory: Some(&inventory),
            evidence: &evidence,
            affected_ranges: &ranges,
        });
        assert_eq!(result.status, ApplicabilityStatus::UnderInvestigation);
    }

    #[test]
    fn explicit_negative_execution_evidence_can_make_affected_version_not_affected() {
        let events = vec![OsvEvent {
            introduced: Some("0".into()),
            ..OsvEvent::default()
        }];
        assert_eq!(
            analyze(
                "1.0",
                events,
                &[
                    ("dependency.reachable", "false"),
                    ("source.imported", "false")
                ]
            )
            .status,
            ApplicabilityStatus::NotAffected
        );
    }

    #[test]
    fn ecosystem_mismatch_is_explainable_not_affected() {
        let events = vec![OsvEvent {
            introduced: Some("0".into()),
            ..OsvEvent::default()
        }];
        let result = analyze("1.0", events, &[("package.ecosystem", "npm")]);
        assert_eq!(result.status, ApplicabilityStatus::NotAffected);
        assert!(result.rationale.unwrap().contains("does not match"));
    }

    #[test]
    fn version_comparison_is_deterministic_at_numeric_and_prerelease_boundaries() {
        assert_eq!(compare_versions("1.10.0", "1.9.9"), Some(Ordering::Greater));
        assert_eq!(compare_versions("v2.0.0", "2.0"), Some(Ordering::Equal));
        assert_eq!(
            compare_versions("1.0.0-alpha", "1.0.0"),
            Some(Ordering::Less)
        );
        assert_eq!(compare_versions("invalid version", "1.0"), None);
    }

    #[test]
    fn dependency_path_is_included_without_being_treated_as_execution_proof() {
        let events = vec![OsvEvent {
            introduced: Some("0".into()),
            ..OsvEvent::default()
        }];
        let result = analyze("1.0", events, &[]);
        assert_eq!(result.status, ApplicabilityStatus::Affected);
        assert!(
            result
                .rationale
                .unwrap()
                .contains("component:root -> component:lib")
        );
    }
}
