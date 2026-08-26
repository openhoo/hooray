use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ops::ControlFlow;

use chrono::{DateTime, NaiveDate, Utc};

use crate::model::{
    Applicability, ApplicabilityStatus, Component, ComponentId, Evidence, Inventory,
    PackageEcosystem, Scope,
};
use crate::remediation::{VersionKey, package_ecosystem_for_purl_type};

/// Mirrors the enumeration bounds of graph path collection
/// (`engine::MAX_DEPENDENCY_PATHS` / `MAX_DEPENDENCY_DEPTH`): graphs with many
/// chained diamonds have exponentially many equal-length shortest paths, and
/// consumers of `dependency_paths` only use the count and one representative.
const MAX_DEPENDENCY_PATHS: usize = 32;
const MAX_DEPENDENCY_DEPTH: usize = 128;

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
        let evidence = EvidenceProperties::new(input.evidence);
        let version = version_parts(&input.component.version);
        // PyPI and Maven order versions by PEP 440 / Maven rules rather than
        // the generic token heuristic: parse the component version once here
        // so every range comparison reuses it. Components the scoped
        // comparator rejects stay on the legacy path everywhere below.
        let scoped = ScopedOrdering::for_component(ecosystem, &input.component.version);
        let (paths, paths_truncated) = input
            .inventory
            .map(|inventory| dependency_paths(inventory, &input.component.identity))
            .unwrap_or_default();
        let reachable = evidence.boolean("dependency.reachable");
        let imported = evidence
            .boolean("source.imported")
            .or_else(|| evidence.boolean("source.import.reachable"));

        rationale.push(format!(
            "component {} {} ({}) has {} dependency path(s){}",
            input.component.name,
            input.component.version,
            input.component.scope_label(),
            paths.len(),
            if paths_truncated { " (truncated)" } else { "" }
        ));
        if let Some(path) = paths.first() {
            rationale.push(format!("shortest dependency path: {path}"));
        }
        describe_signal(&mut rationale, "dependency reachability", reachable);
        describe_signal(&mut rationale, "source/import evidence", imported);

        let matching_ranges = match filter_ecosystem_ranges(
            &mut rationale,
            &evidence,
            ecosystem,
            input.affected_ranges,
        ) {
            ControlFlow::Break(result) => return result,
            ControlFlow::Continue(ranges) => ranges,
        };

        let mut outcomes = BTreeSet::new();
        for range in matching_ranges {
            let outcome = evaluate_range(
                range,
                &input.component.version,
                version.as_deref(),
                scoped.as_ref(),
            );
            outcomes.insert(outcome.status());
            rationale.push(outcome.detail().to_owned());
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

/// Resolves the ecosystem evidence gate and collects the affected ranges that
/// apply to the component's purl ecosystem. `ControlFlow::Break` carries a
/// finished `Applicability` for the early-exit paths.
fn filter_ecosystem_ranges<'a>(
    rationale: &mut Vec<String>,
    evidence: &EvidenceProperties<'_>,
    ecosystem: Option<&str>,
    affected_ranges: &'a [OsvAffectedRange],
) -> ControlFlow<Applicability, Vec<&'a OsvAffectedRange>> {
    if let Some(expected) = evidence.value("package.ecosystem") {
        match ecosystem {
            Some(actual) if !expected.eq_ignore_ascii_case(actual) => {
                rationale.push(format!(
                    "explicit package ecosystem {expected} does not match purl ecosystem {actual}"
                ));
                return ControlFlow::Break(applicability(
                    ApplicabilityStatus::NotAffected,
                    std::mem::take(rationale),
                ));
            }
            Some(actual) => rationale.push(format!("package ecosystem matched {actual}")),
            None => rationale.push(format!(
                "package ecosystem evidence says {expected}, but the purl ecosystem is unavailable"
            )),
        }
    }

    let matching_ranges: Vec<_> = affected_ranges
        .iter()
        .filter(|range| {
            range.ecosystem.as_deref().is_none_or(|expected| {
                ecosystem.is_some_and(|actual| expected.eq_ignore_ascii_case(actual))
            })
        })
        .collect();
    if affected_ranges
        .iter()
        .any(|range| range.ecosystem.is_some())
        && matching_ranges.is_empty()
        && ecosystem.is_some()
    {
        rationale.push("no OSV affected range matches the component ecosystem".to_owned());
        return ControlFlow::Break(applicability(
            ApplicabilityStatus::NotAffected,
            std::mem::take(rationale),
        ));
    }
    if matching_ranges.is_empty() {
        rationale.push("no applicable OSV version range was supplied".to_owned());
        return ControlFlow::Break(applicability(
            ApplicabilityStatus::Unknown,
            std::mem::take(rationale),
        ));
    }
    ControlFlow::Continue(matching_ranges)
}

/// Read-only view over the evidence properties collected for one component.
/// Shared by applicability analysis and risk scoring so both interpret the
/// same property grammar identically.
pub(crate) struct EvidenceProperties<'a> {
    values: BTreeMap<&'a str, BTreeSet<&'a str>>,
}

impl<'a> EvidenceProperties<'a> {
    pub(crate) fn new(evidence: &'a BTreeSet<Evidence>) -> Self {
        let mut values: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for item in evidence {
            for (key, value) in &item.properties {
                values.entry(key).or_default().insert(value);
            }
        }
        Self { values }
    }

    pub(crate) fn value(&self, key: &str) -> Option<&str> {
        let values = self.values.get(key)?;
        (values.len() == 1).then(|| *values.first().expect("non-empty evidence values"))
    }

    /// Parses every recorded value for `key` and yields one truth value only
    /// when all values parse and agree; accepts true/false, yes/no, and 1/0.
    pub(crate) fn boolean(&self, key: &str) -> Option<bool> {
        let values = self.values.get(key)?;
        let parsed: BTreeSet<bool> = values
            .iter()
            .filter_map(|value| parse_bool(value))
            .collect();
        (parsed.len() == 1 && parsed.len() == values.len())
            .then(|| *parsed.first().expect("non-empty boolean evidence"))
    }

    pub(crate) fn conflicts(&self, key: &str) -> bool {
        self.values.get(key).is_some_and(|values| values.len() > 1)
    }

    pub(crate) fn integer(&self, key: &str) -> Option<i64> {
        self.value(key)?.parse().ok()
    }

    pub(crate) fn date(&self, key: &str) -> Option<NaiveDate> {
        let value = self.value(key)?;
        NaiveDate::parse_from_str(value, "%Y-%m-%d")
            .ok()
            .or_else(|| {
                DateTime::parse_from_rfc3339(value)
                    .ok()
                    .map(|date| date.date_naive())
            })
    }

    pub(crate) fn date_time(&self, key: &str) -> Option<DateTime<Utc>> {
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

impl RangeOutcome {
    fn status(&self) -> ApplicabilityStatus {
        match self {
            RangeOutcome::Affected(_) => ApplicabilityStatus::Affected,
            RangeOutcome::Fixed(_) => ApplicabilityStatus::Fixed,
            RangeOutcome::NotAffected(_) => ApplicabilityStatus::NotAffected,
            RangeOutcome::Unknown(_) => ApplicabilityStatus::Unknown,
        }
    }

    fn detail(&self) -> &str {
        match self {
            RangeOutcome::Affected(detail)
            | RangeOutcome::Fixed(detail)
            | RangeOutcome::NotAffected(detail)
            | RangeOutcome::Unknown(detail) => detail,
        }
    }
}

/// Ecosystem-aware ordering context for PyPI and Maven components: carries
/// the component version parsed once through remediation's comparator so OSV
/// event boundaries compare under PEP 440 / Maven ordering.
#[derive(Debug, Clone)]
struct ScopedOrdering {
    ecosystem: PackageEcosystem,
    key: VersionKey,
}

impl ScopedOrdering {
    /// Builds the context when the purl ecosystem routes through remediation's
    /// comparator (PyPI, Maven only) and that comparator accepts the version;
    /// every other ecosystem keeps the legacy heuristic untouched.
    fn for_component(ecosystem: Option<&str>, version: &str) -> Option<Self> {
        let ecosystem = package_ecosystem_for_purl_type(ecosystem?).filter(|ecosystem| {
            matches!(ecosystem, PackageEcosystem::Pypi | PackageEcosystem::Maven)
        })?;
        let key = VersionKey::parse(ecosystem, version)?;
        Some(Self { ecosystem, key })
    }
}

/// Orders the component version against one OSV event boundary, preferring
/// the scoped comparator and falling back to the legacy heuristic whenever
/// either side cannot be parsed by it.
fn compare_scoped(
    scoped: Option<&ScopedOrdering>,
    version_parts: Option<&[String]>,
    boundary: &str,
) -> Option<Ordering> {
    if let Some(scoped) = scoped
        && let Some(boundary) = VersionKey::parse(scoped.ecosystem, boundary)
    {
        return Some(scoped.key.cmp(&boundary));
    }
    compare_version_parts(version_parts, boundary)
}

fn evaluate_range(
    range: &OsvAffectedRange,
    version: &str,
    version_parts: Option<&[String]>,
    scoped: Option<&ScopedOrdering>,
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

    let mut state = RangeState::default();
    for event in &range.events {
        if let Some(outcome) = apply_event(&mut state, event, version_parts, version, scoped) {
            return outcome;
        }
    }
    state.outcome(version)
}

/// Version-range walk state for one OSV affected range.
#[derive(Debug, Default)]
struct RangeState<'a> {
    active: bool,
    saw_comparable: bool,
    crossed_fixed: Option<&'a str>,
    crossed_last_affected: Option<&'a str>,
}

impl<'a> RangeState<'a> {
    /// Enters the interval introduced by an event and forgets any earlier
    /// boundary crossings.
    fn activate(&mut self) {
        self.active = true;
        self.saw_comparable = true;
        self.crossed_fixed = None;
        self.crossed_last_affected = None;
    }

    fn cross_introduced(
        &mut self,
        scoped: Option<&ScopedOrdering>,
        version_parts: Option<&[String]>,
        introduced: &str,
    ) {
        if let Some(ordering) = compare_scoped(scoped, version_parts, introduced) {
            self.saw_comparable = true;
            if ordering != Ordering::Less {
                self.activate();
            }
        }
    }

    fn cross_fixed(
        &mut self,
        scoped: Option<&ScopedOrdering>,
        version_parts: Option<&[String]>,
        fixed: &'a str,
    ) {
        if let Some(ordering) = compare_scoped(scoped, version_parts, fixed) {
            self.saw_comparable = true;
            if ordering != Ordering::Less {
                self.active = false;
                self.crossed_fixed = Some(fixed);
            }
        }
    }

    fn cross_last_affected(
        &mut self,
        scoped: Option<&ScopedOrdering>,
        version_parts: Option<&[String]>,
        last: &'a str,
        version: &str,
    ) -> Option<RangeOutcome> {
        if let Some(ordering) = compare_scoped(scoped, version_parts, last) {
            self.saw_comparable = true;
            if ordering == Ordering::Greater {
                self.active = false;
                self.crossed_last_affected = Some(last);
            } else if self.active {
                return Some(RangeOutcome::Affected(format!(
                    "component version {version} is within a range ending at last-affected {last}"
                )));
            }
        }
        None
    }

    fn cross_limit(
        &mut self,
        scoped: Option<&ScopedOrdering>,
        version_parts: Option<&[String]>,
        limit: &'a str,
    ) {
        if let Some(ordering) = compare_scoped(scoped, version_parts, limit) {
            self.saw_comparable = true;
            if ordering != Ordering::Less {
                self.active = false;
                self.crossed_last_affected = Some(limit);
            }
        }
    }

    /// Resolves the final outcome once every event has been applied.
    fn outcome(self, version: &str) -> RangeOutcome {
        if self.active {
            RangeOutcome::Affected(format!(
                "component version {version} falls within the supplied OSV event interval"
            ))
        } else if let Some(fixed) = self.crossed_fixed {
            RangeOutcome::Fixed(format!(
                "component version {version} is at or after fixed event {fixed}"
            ))
        } else if let Some(boundary) = self.crossed_last_affected {
            RangeOutcome::NotAffected(format!(
                "component version {version} is after the affected boundary {boundary}"
            ))
        } else if self.saw_comparable {
            RangeOutcome::NotAffected(format!(
                "component version {version} precedes the introduced event"
            ))
        } else {
            RangeOutcome::Unknown(format!(
                "component version {version} could not be compared to the supplied OSV events"
            ))
        }
    }
}

/// Applies one OSV event to the range walk; `Some` short-circuits evaluation
/// with an immediately decided outcome.
fn apply_event<'a>(
    state: &mut RangeState<'a>,
    event: &'a OsvEvent,
    version_parts: Option<&[String]>,
    version: &str,
    scoped: Option<&ScopedOrdering>,
) -> Option<RangeOutcome> {
    match event.introduced.as_deref() {
        Some("0") => state.activate(),
        Some(introduced) => state.cross_introduced(scoped, version_parts, introduced),
        None => {}
    }
    if let Some(fixed) = event.fixed.as_deref() {
        state.cross_fixed(scoped, version_parts, fixed);
    }
    if let Some(outcome) = event
        .last_affected
        .as_deref()
        .and_then(|last| state.cross_last_affected(scoped, version_parts, last, version))
    {
        return Some(outcome);
    }
    if let Some(limit) = event.limit.as_deref() {
        state.cross_limit(scoped, version_parts, limit);
    }
    None
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
        let ordering = match (left.get(index), right.get(index)) {
            (Some(lhs), Some(rhs)) => compare_version_identifiers(lhs, rhs),
            // One side ran out of identifiers: a surviving numeric identifier
            // keeps comparing against implicit zero padding (1.2 == 1.2.0),
            // while a surviving alphanumeric identifier outranks the exhausted
            // release (1.0.0 > 1.0.0-alpha).
            (Some(head), None) => match head.parse::<u64>() {
                Ok(number) => number.cmp(&0),
                Err(_) => Ordering::Less,
            },
            (None, Some(head)) => match head.parse::<u64>() {
                Ok(number) => 0u64.cmp(&number),
                Err(_) => Ordering::Greater,
            },
            (None, None) => Ordering::Equal,
        };
        if ordering != Ordering::Equal {
            return Some(ordering);
        }
    }
    Some(Ordering::Equal)
}

fn compare_version_identifiers(lhs: &str, rhs: &str) -> Ordering {
    match (lhs.parse::<u64>(), rhs.parse::<u64>()) {
        (Ok(lhs), Ok(rhs)) => lhs.cmp(&rhs),
        // Numeric identifiers rank below alphanumeric ones (semver rule 11).
        (Ok(_), Err(_)) => Ordering::Less,
        (Err(_), Ok(_)) => Ordering::Greater,
        (Err(_), Err(_)) => lhs.cmp(rhs),
    }
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

fn dependency_paths(inventory: &Inventory, target: &ComponentId) -> (Vec<String>, bool) {
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
        if results.len() >= MAX_DEPENDENCY_PATHS {
            break;
        }
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
        if path.len() >= MAX_DEPENDENCY_DEPTH {
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
    // Consumers only use the count and one representative shortest path, so
    // stopping at the cap keeps chained-diamond graphs linear instead of
    // exponential; remaining queue entries mean the collection was truncated.
    let truncated = results.len() >= MAX_DEPENDENCY_PATHS && !queue.is_empty();
    results.sort_by_key(|path| (path.matches(" -> ").count(), path.clone()));
    (results, truncated)
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

    fn analyze_in_ecosystem(
        purl_type: &str,
        version: &str,
        events: Vec<OsvEvent>,
    ) -> Applicability {
        let mut component = component(version, Scope::Runtime);
        component.purl = format!("pkg:{purl_type}/lib@{version}");
        let inventory = inventory(component.clone(), true);
        let evidence = evidence(&[]);
        let ranges = vec![OsvAffectedRange {
            range_type: OsvRangeType::Semver,
            ecosystem: Some(purl_type.into()),
            events,
        }];
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
    fn prerelease_identifiers_follow_semver_precedence_rules() {
        assert_eq!(
            compare_versions("1.0.0-alpha", "1.0.0-1"),
            Some(Ordering::Greater)
        );
        assert_eq!(
            compare_versions("1.0.0-1", "1.0.0-beta"),
            Some(Ordering::Less)
        );
        assert_eq!(compare_versions("1.2", "1.2.0"), Some(Ordering::Equal));
        assert_eq!(
            compare_versions("1.0.0", "1.0.0-alpha"),
            Some(Ordering::Greater)
        );
        assert_eq!(
            compare_versions("1.0.0-alpha", "1.0.0-alpha.1"),
            Some(Ordering::Less)
        );
    }

    #[test]
    fn prerelease_comparison_is_antisymmetric_for_spot_pair() {
        let forward = compare_versions("1.0.0-1", "1.0.0-beta");
        let backward = compare_versions("1.0.0-beta", "1.0.0-1");
        assert_eq!(forward, backward.map(Ordering::reverse));
    }

    #[test]
    fn pypi_post_release_versions_compare_below_the_next_patch() {
        // 1.0.post1 is a post-release of 1.0 and therefore still below the
        // next patch boundary 1.0.1; the legacy token heuristic ranked the
        // alphanumeric "post" above the numeric patch digit.
        let events = vec![
            OsvEvent {
                introduced: Some("1.0".into()),
                ..OsvEvent::default()
            },
            OsvEvent {
                limit: Some("1.0.1".into()),
                ..OsvEvent::default()
            },
        ];
        assert_eq!(
            analyze_in_ecosystem("pypi", "1.0.post1", events.clone()).status,
            ApplicabilityStatus::Affected
        );
        // Dual pin: a post-release stacked onto the boundary release itself
        // still ranks at or above that boundary, so the fixed side holds.
        let patched = vec![
            OsvEvent {
                introduced: Some("1.0".into()),
                ..OsvEvent::default()
            },
            OsvEvent {
                fixed: Some("1.0.2".into()),
                ..OsvEvent::default()
            },
        ];
        assert_eq!(
            analyze_in_ecosystem("pypi", "1.0.2.post1", patched).status,
            ApplicabilityStatus::Fixed
        );
    }

    #[test]
    fn pypi_epoch_versions_are_comparable_instead_of_unknown() {
        // Epoch-qualified versions carry a character the generic tokenizer
        // rejects, so only the scoped PEP 440 comparator can order them.
        let events = vec![OsvEvent {
            introduced: Some("1!0.4".into()),
            fixed: Some("1!0.6".into()),
            ..OsvEvent::default()
        }];
        assert_eq!(
            analyze_in_ecosystem("pypi", "1!0.5", events.clone()).status,
            ApplicabilityStatus::Affected
        );
        assert_eq!(
            analyze_in_ecosystem("pypi", "1!0.7", events).status,
            ApplicabilityStatus::Fixed
        );
    }

    #[test]
    fn maven_qualifier_ordering_delegates_to_the_scoped_comparator() {
        // Maven ranks qualifiers below ("alpha") and above ("sp") the plain
        // release; the legacy heuristic placed both on the same side of 1.0.
        let events = vec![OsvEvent {
            introduced: Some("0".into()),
            fixed: Some("1.0".into()),
            ..OsvEvent::default()
        }];
        assert_eq!(
            analyze_in_ecosystem("maven", "1.0-alpha", events.clone()).status,
            ApplicabilityStatus::Affected
        );
        assert_eq!(
            analyze_in_ecosystem("maven", "1.0-sp", events).status,
            ApplicabilityStatus::Fixed
        );
    }

    #[test]
    fn legacy_ecosystems_keep_semver_rule_11_outcomes() {
        // Prerelease identifiers sort below the plain release for ecosystems
        // that stay on the legacy comparator...
        let below = vec![OsvEvent {
            introduced: Some("0".into()),
            fixed: Some("1.0.0".into()),
            ..OsvEvent::default()
        }];
        assert_eq!(
            analyze_in_ecosystem("cargo", "1.0.0-alpha", below.clone()).status,
            ApplicabilityStatus::Affected
        );
        assert_eq!(
            analyze_in_ecosystem("npm", "1.0.0-alpha", below).status,
            ApplicabilityStatus::Affected
        );
        // ...while alphanumeric identifiers outrank numeric ones at the same
        // depth (semver rule 11), so beta sits above the fixed boundary -1.
        let pinned = vec![OsvEvent {
            introduced: Some("0".into()),
            fixed: Some("1.0.0-1".into()),
            ..OsvEvent::default()
        }];
        assert_eq!(
            analyze_in_ecosystem("cargo", "1.0.0-beta", pinned.clone()).status,
            ApplicabilityStatus::Fixed
        );
        assert_eq!(
            analyze_in_ecosystem("npm", "1.0.0-beta", pinned).status,
            ApplicabilityStatus::Fixed
        );
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

    fn graph_inventory(edges: &[(usize, usize)]) -> (Inventory, Vec<ComponentId>) {
        let highest = edges
            .iter()
            .flat_map(|(from, to)| [*from, *to])
            .max()
            .expect("graph has edges");
        let id = |index: usize| ComponentId::new(format!("component:n{index}")).unwrap();
        let mut components = BTreeMap::new();
        for index in 0..=highest {
            components.insert(
                id(index),
                Component {
                    identity: id(index),
                    name: format!("n{index}"),
                    version: "1".to_owned(),
                    purl: format!("pkg:cargo/n{index}@1"),
                    scope: Scope::Runtime,
                    provenance: BTreeSet::new(),
                    licenses: BTreeSet::new(),
                    locations: BTreeSet::new(),
                },
            );
        }
        let inventory = Inventory {
            asset: Asset {
                id: AssetId::new("asset:test").unwrap(),
                name: "test".into(),
                kind: AssetKind::Repository,
                version: None,
                metadata: BTreeMap::<String, Value>::new(),
            },
            components,
            locations: BTreeSet::new(),
            dependencies: edges
                .iter()
                .map(|(from, to)| DependencyEdge {
                    from: id(*from),
                    to: id(*to),
                    scope: Scope::Runtime,
                    optional: false,
                })
                .collect(),
        };
        (inventory, (0..=highest).map(id).collect())
    }

    #[test]
    fn dependency_paths_caps_chained_diamond_enumeration() {
        // Each chained diamond doubles the number of equal-length shortest
        // paths; unbounded enumeration would collect all 2^K of them even
        // though consumers only use the count and one representative.
        const DIAMONDS: usize = 18;
        let mut edges: Vec<(usize, usize)> = Vec::new();
        for i in 0..DIAMONDS {
            let previous = 3 * i;
            let (top, bottom, sink) = (3 * i + 1, 3 * i + 2, 3 * i + 3);
            edges.extend([
                (previous, top),
                (previous, bottom),
                (top, sink),
                (bottom, sink),
            ]);
        }
        let target = 3 * DIAMONDS;
        let (inventory, ids) = graph_inventory(&edges);
        let (paths, truncated) = dependency_paths(&inventory, &ids[target]);
        assert!(truncated);
        assert_eq!(paths.len(), MAX_DEPENDENCY_PATHS);
        for path in &paths {
            assert!(path.starts_with("component:n0 -> "));
            assert!(path.ends_with(&format!(" -> component:n{target}")));
            assert_eq!(path.matches(" -> ").count(), 2 * DIAMONDS);
        }
        // Enumeration order is deterministic across repeated calls.
        assert_eq!(
            dependency_paths(&inventory, &ids[target]),
            (paths.clone(), truncated)
        );
    }

    #[test]
    fn dependency_paths_preserves_all_shortest_paths_below_cap() {
        let (inventory, ids) = graph_inventory(&[(0, 1), (0, 2), (1, 3), (2, 3)]);
        let (paths, truncated) = dependency_paths(&inventory, &ids[3]);
        assert!(!truncated);
        assert_eq!(
            paths,
            vec![
                "component:n0 -> component:n1 -> component:n3".to_owned(),
                "component:n0 -> component:n2 -> component:n3".to_owned(),
            ]
        );
        // Linear chain yields exactly one path.
        let (inventory, ids) = graph_inventory(&[(0, 1), (1, 2)]);
        let (paths, truncated) = dependency_paths(&inventory, &ids[2]);
        assert!(!truncated);
        assert_eq!(
            paths,
            vec!["component:n0 -> component:n1 -> component:n2".to_owned()]
        );
    }
}
