use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use serde_json::Value;
use thiserror::Error;

macro_rules! stable_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl AsRef<str>) -> Result<Self, InvalidIdError> {
                let value = value.as_ref().trim();
                if value.is_empty() {
                    return Err(InvalidIdError);
                }
                Ok(Self(value.to_owned()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(D::Error::custom)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl FromStr for $name {
            type Err = InvalidIdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

stable_id!(AssetId);
stable_id!(ComponentId);
stable_id!(LocationId);
stable_id!(FindingId);
stable_id!(RuleId);
stable_id!(PolicyId);
stable_id!(RunId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("identifier must not be empty")]
pub struct InvalidIdError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset {
    pub id: AssetId,
    pub name: String,
    #[serde(default)]
    pub kind: AssetKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum AssetKind {
    Repository,
    Filesystem,
    ContainerImage,
    Sbom,
    Package,
    #[default]
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Source {
    pub kind: SourceKind,
    pub locator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    Manifest,
    Lockfile,
    Sbom,
    ContainerImage,
    Repository,
    #[default]
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Location {
    pub id: LocationId,
    pub asset_id: AssetId,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<Position>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<Position>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Position {
    pub line: u32,
    pub column: u32,
}

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Runtime,
    Build,
    Development,
    Test,
    Optional,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct License {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    pub identity: ComponentId,
    pub name: String,
    pub version: String,
    pub purl: String,
    #[serde(default)]
    pub scope: Scope,
    #[serde(default)]
    pub provenance: BTreeSet<Source>,
    #[serde(default)]
    pub licenses: BTreeSet<License>,
    #[serde(default)]
    pub locations: BTreeSet<Location>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub from: ComponentId,
    pub to: ComponentId,
    #[serde(default)]
    pub scope: Scope,
    #[serde(default)]
    pub optional: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DependencyKind {
    Direct,
    Transitive,
    Disconnected,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DependencyPath {
    pub components: Vec<ComponentId>,
}

impl DependencyPath {
    pub fn new(components: Vec<ComponentId>) -> Result<Self, ModelInvariantError> {
        if components.is_empty() {
            return Err(ModelInvariantError::EmptyDependencyPath);
        }
        Ok(Self { components })
    }

    pub fn root(&self) -> &ComponentId {
        &self.components[0]
    }

    pub fn target(&self) -> &ComponentId {
        &self.components[self.components.len() - 1]
    }

    pub fn edge_count(&self) -> usize {
        self.components.len() - 1
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyPaths {
    #[serde(default)]
    pub paths: Vec<DependencyPath>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inventory {
    pub asset: Asset,
    #[serde(default)]
    pub components: BTreeMap<ComponentId, Component>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub locations: BTreeSet<Location>,
    #[serde(default)]
    pub dependencies: BTreeSet<DependencyEdge>,
}

impl Inventory {
    pub fn validate(&self) -> Result<(), ModelInvariantError> {
        require_text("asset.name", &self.asset.name)?;
        let mut location_ids = BTreeSet::new();

        for location in &self.locations {
            validate_location(location, &self.asset.id, &mut location_ids)?;
        }

        for (id, component) in &self.components {
            if id != &component.identity {
                return Err(ModelInvariantError::ComponentIdentityMismatch(id.clone()));
            }
            require_text("component.name", &component.name)?;
            require_text("component.version", &component.version)?;
            require_text("component.purl", &component.purl)?;

            for source in &component.provenance {
                require_text("source.locator", &source.locator)?;
            }
            for location in &component.locations {
                validate_location(location, &self.asset.id, &mut location_ids)?;
            }
        }

        for edge in &self.dependencies {
            if !self.components.contains_key(&edge.from) {
                return Err(ModelInvariantError::UnknownComponent(edge.from.clone()));
            }
            if !self.components.contains_key(&edge.to) {
                return Err(ModelInvariantError::UnknownComponent(edge.to.clone()));
            }
            if edge.from == edge.to {
                return Err(ModelInvariantError::SelfDependency(edge.from.clone()));
            }
        }
        Ok(())
    }

    pub(crate) fn location_ids(&self) -> BTreeSet<&LocationId> {
        self.locations
            .iter()
            .chain(
                self.components
                    .values()
                    .flat_map(|component| component.locations.iter()),
            )
            .map(|location| &location.id)
            .collect()
    }
}

fn validate_location<'a>(
    location: &'a Location,
    asset_id: &AssetId,
    location_ids: &mut BTreeSet<&'a LocationId>,
) -> Result<(), ModelInvariantError> {
    require_text("location.path", &location.path)?;
    if &location.asset_id != asset_id {
        return Err(ModelInvariantError::ForeignLocation(location.id.clone()));
    }
    if !location_ids.insert(&location.id) {
        return Err(ModelInvariantError::DuplicateLocation(location.id.clone()));
    }
    if let (Some(start), Some(end)) = (location.start, location.end)
        && end < start
    {
        return Err(ModelInvariantError::InvalidLocationRange(
            location.id.clone(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ModelInvariantError {
    #[error("{0} must not be empty")]
    EmptyField(&'static str),
    #[error("component map key {0} does not match its identity")]
    ComponentIdentityMismatch(ComponentId),
    #[error("duplicate location id {0}")]
    DuplicateLocation(LocationId),
    #[error("location {0} belongs to a different asset")]
    ForeignLocation(LocationId),
    #[error("location {0} has an end before its start")]
    InvalidLocationRange(LocationId),
    #[error("dependency references unknown component {0}")]
    UnknownComponent(ComponentId),
    #[error("component {0} depends on itself")]
    SelfDependency(ComponentId),
    #[error("dependency path must contain at least one component")]
    EmptyDependencyPath,
    #[error("risk score {0} exceeds maximum 10000")]
    RiskOutOfRange(u16),
    #[error("finding map key {0} does not match its id")]
    FindingIdentityMismatch(FindingId),
    #[error("finding {0} references an unknown component")]
    FindingUnknownComponent(FindingId),
    #[error("finding {0} references an unknown location")]
    FindingUnknownLocation(FindingId),
    #[error("secret finding {0} contains evidence that is not redacted")]
    UnredactedSecretEvidence(FindingId),
    #[error("secret finding {0} contains a forbidden evidence property '{1}'")]
    RawSecretProperty(FindingId, String),
    #[error("policy {0} references an unknown finding")]
    PolicyUnknownFinding(PolicyId),
    #[error("policy summary does not match policy decisions")]
    PolicySummaryMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingKind {
    Vulnerability,
    License,
    Secret,
    Iac,
    Sast,
    Malware,
    OperationalRisk,
}

impl FindingKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Vulnerability => "vulnerability",
            Self::License => "license",
            Self::Secret => "secret",
            Self::Iac => "iac",
            Self::Sast => "sast",
            Self::Malware => "malware",
            Self::OperationalRisk => "operational-risk",
        }
    }
}

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Evidence {
    pub description: String,
    #[serde(default)]
    pub locations: BTreeSet<LocationId>,
    #[serde(default)]
    pub references: BTreeSet<String>,
    #[serde(default)]
    pub properties: BTreeMap<String, String>,
    #[serde(default)]
    pub redacted: bool,
}

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum ApplicabilityStatus {
    Affected,
    NotAffected,
    Fixed,
    UnderInvestigation,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Applicability {
    pub status: ApplicabilityStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Remediation {
    pub description: String,
    #[serde(default)]
    pub fixed_versions: BTreeSet<String>,
    #[serde(default)]
    pub references: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageEcosystem {
    Cargo,
    Npm,
    Pypi,
    Go,
    Maven,
    Nuget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManifestTool {
    Cargo,
    Npm,
    Pnpm,
    Yarn,
    Pip,
    Poetry,
    Go,
    Maven,
    Gradle,
    Nuget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradePlan {
    pub finding_id: FindingId,
    pub component_id: ComponentId,
    pub package: String,
    pub ecosystem: PackageEcosystem,
    pub current_version: String,
    pub fixed_version: String,
    pub dependency_kind: DependencyKind,
    #[serde(default)]
    pub paths: Vec<DependencyPath>,
    pub paths_truncated: bool,
    pub guidance: String,
    #[serde(default)]
    pub commands: BTreeMap<ManifestTool, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Risk {
    score: u16,
    #[serde(default)]
    pub factors: BTreeMap<String, i32>,
}

impl Risk {
    pub const MAX_SCORE: u16 = 10_000;

    pub fn new(score: u16) -> Result<Self, ModelInvariantError> {
        if score > Self::MAX_SCORE {
            return Err(ModelInvariantError::RiskOutOfRange(score));
        }
        Ok(Self {
            score,
            factors: BTreeMap::new(),
        })
    }

    pub const fn score(&self) -> u16 {
        self.score
    }
}

impl<'de> Deserialize<'de> for Risk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RiskWire {
            score: u16,
            #[serde(default)]
            factors: BTreeMap<String, i32>,
        }

        let wire = RiskWire::deserialize(deserializer)?;
        let mut risk = Self::new(wire.score).map_err(D::Error::custom)?;
        risk.factors = wire.factors;
        Ok(risk)
    }
}

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum FindingStatus {
    Open,
    Resolved,
    Suppressed,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub kind: FindingKind,
    pub rule_id: RuleId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisory_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component_id: Option<ComponentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location_id: Option<LocationId>,
    #[serde(default)]
    pub aliases: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub confidence: Confidence,
    #[serde(default)]
    pub evidence: BTreeSet<Evidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applicability: Option<Applicability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<Remediation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<Risk>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    #[serde(default)]
    pub status: FindingStatus,
}

pub fn stable_component_id(purl: &str) -> Result<ComponentId, InvalidIdError> {
    let purl = nonempty(purl)?;
    Ok(ComponentId(stable_prefixed_id("component", [purl])))
}

pub fn stable_location_id(
    asset_id: &AssetId,
    path: &str,
    start: Option<Position>,
) -> Result<LocationId, InvalidIdError> {
    let path = nonempty(path)?;
    let line = start
        .map(|position| position.line.to_string())
        .unwrap_or_default();
    let column = start
        .map(|position| position.column.to_string())
        .unwrap_or_default();
    Ok(LocationId(stable_prefixed_id(
        "location",
        [asset_id.as_str(), path, &line, &column],
    )))
}

pub fn stable_finding_id(
    kind: FindingKind,
    rule_id: &RuleId,
    component_id: Option<&ComponentId>,
    location_id: Option<&LocationId>,
) -> FindingId {
    FindingId(stable_prefixed_id(
        "finding",
        [
            kind.as_str(),
            rule_id.as_str(),
            component_id.map(ComponentId::as_str).unwrap_or(""),
            location_id.map(LocationId::as_str).unwrap_or(""),
        ],
    ))
}

fn stable_prefixed_id<'a>(prefix: &str, parts: impl IntoIterator<Item = &'a str>) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for part in parts {
        for byte in (part.len() as u64)
            .to_be_bytes()
            .into_iter()
            .chain(part.bytes())
        {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    format!("{prefix}:{hash:016x}")
}

fn nonempty(value: &str) -> Result<&str, InvalidIdError> {
    let value = value.trim();
    if value.is_empty() {
        Err(InvalidIdError)
    } else {
        Ok(value)
    }
}

fn require_text(field: &'static str, value: &str) -> Result<(), ModelInvariantError> {
    if value.trim().is_empty() {
        Err(ModelInvariantError::EmptyField(field))
    } else {
        Ok(())
    }
}

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = ParseSeverityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.eq_ignore_ascii_case("unknown") {
            Ok(Self::Unknown)
        } else if value.eq_ignore_ascii_case("low") {
            Ok(Self::Low)
        } else if value.eq_ignore_ascii_case("medium") {
            Ok(Self::Medium)
        } else if value.eq_ignore_ascii_case("high") {
            Ok(Self::High)
        } else if value.eq_ignore_ascii_case("critical") {
            Ok(Self::Critical)
        } else {
            Err(ParseSeverityError(value.to_owned()))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid severity '{0}'; expected unknown, low, medium, high, or critical")]
pub struct ParseSeverityError(String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub policy_id: PolicyId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<FindingId>,
    pub outcome: PolicyOutcome,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exception_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyOutcome {
    Allow,
    Warn,
    Deny,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySummary {
    pub allowed: u64,
    pub warned: u64,
    pub denied: u64,
}

impl PolicySummary {
    pub fn from_decisions(decisions: &BTreeSet<PolicyDecision>) -> Self {
        let mut summary = Self::default();
        for decision in decisions {
            match decision.outcome {
                PolicyOutcome::Allow => summary.allowed += 1,
                PolicyOutcome::Warn => summary.warned += 1,
                PolicyOutcome::Deny => summary.denied += 1,
            }
        }
        summary
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunMetadata {
    pub id: RunId,
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanner_version: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: String,
    pub run: RunMetadata,
    pub inventory: Inventory,
    #[serde(default)]
    pub findings: BTreeMap<FindingId, Finding>,
    #[serde(default)]
    pub policy_decisions: BTreeSet<PolicyDecision>,
    #[serde(default)]
    pub policy_summary: PolicySummary,
}

impl ScanReport {
    pub fn validate(&self) -> Result<(), ModelInvariantError> {
        require_text("schema_version", &self.schema_version)?;
        require_text("run.started_at", &self.run.started_at)?;
        self.inventory.validate()?;
        let location_ids = self.inventory.location_ids();

        for (id, finding) in &self.findings {
            if id != &finding.id {
                return Err(ModelInvariantError::FindingIdentityMismatch(id.clone()));
            }
            if finding
                .component_id
                .as_ref()
                .is_some_and(|component_id| !self.inventory.components.contains_key(component_id))
            {
                return Err(ModelInvariantError::FindingUnknownComponent(
                    finding.id.clone(),
                ));
            }
            if finding
                .location_id
                .as_ref()
                .is_some_and(|location_id| !location_ids.contains(location_id))
            {
                return Err(ModelInvariantError::FindingUnknownLocation(
                    finding.id.clone(),
                ));
            }
            for evidence in &finding.evidence {
                require_text("evidence.description", &evidence.description)?;
                if evidence
                    .locations
                    .iter()
                    .any(|location_id| !location_ids.contains(location_id))
                {
                    return Err(ModelInvariantError::FindingUnknownLocation(
                        finding.id.clone(),
                    ));
                }
                if finding.kind == FindingKind::Secret {
                    if !evidence.redacted {
                        return Err(ModelInvariantError::UnredactedSecretEvidence(
                            finding.id.clone(),
                        ));
                    }
                    if let Some(property) = evidence
                        .properties
                        .keys()
                        .find(|key| is_secret_property(key))
                    {
                        return Err(ModelInvariantError::RawSecretProperty(
                            finding.id.clone(),
                            property.clone(),
                        ));
                    }
                }
            }
        }

        for decision in &self.policy_decisions {
            require_text("policy.reason", &decision.reason)?;
            if decision
                .finding_id
                .as_ref()
                .is_some_and(|finding_id| !self.findings.contains_key(finding_id))
            {
                return Err(ModelInvariantError::PolicyUnknownFinding(
                    decision.policy_id.clone(),
                ));
            }
        }
        if self.policy_summary != PolicySummary::from_decisions(&self.policy_decisions) {
            return Err(ModelInvariantError::PolicySummaryMismatch);
        }
        Ok(())
    }
}

fn is_secret_property(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    [
        "secret",
        "raw",
        "value",
        "match",
        "content",
        "token",
        "password",
        "credential",
    ]
    .iter()
    .any(|sensitive| normalized.contains(sensitive))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset() -> Asset {
        Asset {
            id: AssetId::new("asset:app").unwrap(),
            name: "app".into(),
            kind: AssetKind::Repository,
            version: None,
            metadata: BTreeMap::new(),
        }
    }

    fn component() -> Component {
        let identity = stable_component_id("pkg:cargo/serde@1.0.0").unwrap();
        Component {
            identity,
            name: "serde".into(),
            version: "1.0.0".into(),
            purl: "pkg:cargo/serde@1.0.0".into(),
            scope: Scope::Runtime,
            provenance: BTreeSet::new(),
            licenses: BTreeSet::new(),
            locations: BTreeSet::new(),
        }
    }

    #[test]
    fn identifiers_trim_and_reject_empty_input_including_deserialization() {
        assert_eq!(RuleId::new("  RULE-1  ").unwrap().as_str(), "RULE-1");
        assert!(ComponentId::new(" \t ").is_err());
        assert!(serde_json::from_str::<FindingId>("\"   \"").is_err());
    }

    #[test]
    fn generated_ids_are_stable_and_length_delimited() {
        let component = ComponentId::new("component:abc").unwrap();
        let rule = RuleId::new("OSV-1").unwrap();
        assert_eq!(
            stable_finding_id(FindingKind::Vulnerability, &rule, Some(&component), None),
            stable_finding_id(FindingKind::Vulnerability, &rule, Some(&component), None),
        );
        assert_ne!(
            stable_prefixed_id("x", ["ab", "c"]),
            stable_prefixed_id("x", ["a", "bc"]),
        );
    }

    #[test]
    fn risk_rejects_out_of_range_values_from_code_and_json() {
        assert!(matches!(
            Risk::new(10_001),
            Err(ModelInvariantError::RiskOutOfRange(10_001))
        ));
        assert!(serde_json::from_str::<Risk>(r#"{"score":10001}"#).is_err());
        assert_eq!(Risk::new(10_000).unwrap().score(), 10_000);
    }

    #[test]
    fn inventory_locations_validate_and_deserialize_legacy_payloads() {
        let asset = asset();
        let location = Location {
            id: LocationId::new("location:global").unwrap(),
            asset_id: asset.id.clone(),
            path: "sample.py".into(),
            start: Some(Position { line: 1, column: 1 }),
            end: Some(Position { line: 1, column: 8 }),
        };
        let inventory = Inventory {
            asset: asset.clone(),
            components: BTreeMap::new(),
            locations: BTreeSet::from([location.clone()]),
            dependencies: BTreeSet::new(),
        };
        inventory.validate().unwrap();
        assert!(inventory.location_ids().contains(&location.id));

        let legacy: Inventory = serde_json::from_value(serde_json::json!({
            "asset": asset,
            "components": {},
            "dependencies": []
        }))
        .unwrap();
        assert!(legacy.locations.is_empty());

        let mut component = component();
        component.locations.insert(location.clone());
        let duplicate = Inventory {
            asset: inventory.asset.clone(),
            components: BTreeMap::from([(component.identity.clone(), component)]),
            locations: BTreeSet::from([location.clone()]),
            dependencies: BTreeSet::new(),
        };
        assert!(matches!(
            duplicate.validate(),
            Err(ModelInvariantError::DuplicateLocation(id)) if id == location.id
        ));

        for invalid in [
            Location {
                path: "".into(),
                ..location.clone()
            },
            Location {
                asset_id: AssetId::new("asset:other").unwrap(),
                ..location.clone()
            },
            Location {
                start: Some(Position { line: 2, column: 1 }),
                end: Some(Position { line: 1, column: 1 }),
                ..location.clone()
            },
        ] {
            let candidate = Inventory {
                asset: inventory.asset.clone(),
                components: BTreeMap::new(),
                locations: BTreeSet::from([invalid]),
                dependencies: BTreeSet::new(),
            };
            assert!(candidate.validate().is_err());
        }
    }

    #[test]
    fn inventory_rejects_unknown_graph_endpoints() {
        let component = component();
        let id = component.identity.clone();
        let inventory = Inventory {
            asset: asset(),
            components: BTreeMap::from([(id.clone(), component)]),
            locations: BTreeSet::new(),
            dependencies: BTreeSet::from([DependencyEdge {
                from: id,
                to: ComponentId::new("component:missing").unwrap(),
                scope: Scope::Runtime,
                optional: false,
            }]),
        };
        assert!(matches!(
            inventory.validate(),
            Err(ModelInvariantError::UnknownComponent(_))
        ));
    }

    #[test]
    fn report_rejects_unknown_finding_references() {
        let component = component();
        let component_id = component.identity.clone();
        let rule_id = RuleId::new("OSV-1").unwrap();
        let finding_id = stable_finding_id(
            FindingKind::Vulnerability,
            &rule_id,
            Some(&component_id),
            None,
        );
        let finding = Finding {
            id: finding_id.clone(),
            kind: FindingKind::Vulnerability,
            rule_id,
            advisory_id: Some("OSV-1".into()),
            component_id: Some(ComponentId::new("component:missing").unwrap()),
            location_id: None,
            aliases: BTreeSet::new(),
            summary: None,
            details: None,
            severity: Severity::High,
            confidence: Confidence::High,
            evidence: BTreeSet::new(),
            applicability: None,
            remediation: None,
            risk: None,
            first_seen: None,
            last_seen: None,
            modified: None,
            status: FindingStatus::Open,
        };
        let report = ScanReport {
            schema_version: "1".into(),
            run: RunMetadata {
                id: RunId::new("run:1").unwrap(),
                started_at: "2026-01-01T00:00:00Z".into(),
                completed_at: None,
                scanner_version: None,
                metadata: BTreeMap::new(),
            },
            inventory: Inventory {
                asset: asset(),
                components: BTreeMap::from([(component_id, component)]),
                locations: BTreeSet::new(),
                dependencies: BTreeSet::new(),
            },
            findings: BTreeMap::from([(finding_id, finding)]),
            policy_decisions: BTreeSet::new(),
            policy_summary: PolicySummary::default(),
        };
        assert!(matches!(
            report.validate(),
            Err(ModelInvariantError::FindingUnknownComponent(_))
        ));
    }

    #[test]
    fn secret_evidence_must_be_redacted_and_exclude_raw_properties() {
        let component = component();
        let component_id = component.identity.clone();
        let rule_id = RuleId::new("SECRET-1").unwrap();
        let finding_id =
            stable_finding_id(FindingKind::Secret, &rule_id, Some(&component_id), None);
        let evidence = Evidence {
            description: "credential pattern".into(),
            locations: BTreeSet::new(),
            references: BTreeSet::new(),
            properties: BTreeMap::from([("raw_secret".into(), "do-not-store".into())]),
            redacted: true,
        };
        let finding = Finding {
            id: finding_id.clone(),
            kind: FindingKind::Secret,
            rule_id,
            advisory_id: None,
            component_id: Some(component_id.clone()),
            location_id: None,
            aliases: BTreeSet::new(),
            summary: None,
            details: None,
            severity: Severity::Critical,
            confidence: Confidence::High,
            evidence: BTreeSet::from([evidence]),
            applicability: None,
            remediation: None,
            risk: None,
            first_seen: None,
            last_seen: None,
            modified: None,
            status: FindingStatus::Open,
        };
        let report = ScanReport {
            schema_version: "1".into(),
            run: RunMetadata {
                id: RunId::new("run:1").unwrap(),
                started_at: "2026-01-01T00:00:00Z".into(),
                completed_at: None,
                scanner_version: None,
                metadata: BTreeMap::new(),
            },
            inventory: Inventory {
                asset: asset(),
                components: BTreeMap::from([(component_id, component)]),
                locations: BTreeSet::new(),
                dependencies: BTreeSet::new(),
            },
            findings: BTreeMap::from([(finding_id, finding)]),
            policy_decisions: BTreeSet::new(),
            policy_summary: PolicySummary::default(),
        };
        assert!(matches!(
            report.validate(),
            Err(ModelInvariantError::RawSecretProperty(_, _))
        ));
    }

    #[test]
    fn ordered_collections_serialize_deterministically() {
        let first = serde_json::to_string(&BTreeSet::from(["z", "a"])).unwrap();
        let second = serde_json::to_string(&BTreeSet::from(["a", "z"])).unwrap();
        assert_eq!(first, second);
        assert_eq!(first, r#"["a","z"]"#);
    }
    #[test]
    fn dependency_path_contract_exposes_root_target_and_edge_count() {
        let path = DependencyPath::new(vec![
            ComponentId::new("root").unwrap(),
            ComponentId::new("middle").unwrap(),
            ComponentId::new("target").unwrap(),
        ])
        .unwrap();
        assert_eq!(path.root().as_str(), "root");
        assert_eq!(path.target().as_str(), "target");
        assert_eq!(path.edge_count(), 2);
        assert_eq!(
            DependencyPath::new(Vec::new()).unwrap_err(),
            ModelInvariantError::EmptyDependencyPath
        );
    }

    #[test]
    fn upgrade_plan_serializes_deterministically() {
        let plan = UpgradePlan {
            finding_id: FindingId::new("finding").unwrap(),
            component_id: ComponentId::new("component").unwrap(),
            package: "serde".into(),
            ecosystem: PackageEcosystem::Cargo,
            current_version: "1.0.0".into(),
            fixed_version: "1.0.1".into(),
            dependency_kind: DependencyKind::Direct,
            paths: Vec::new(),
            paths_truncated: false,
            guidance: "upgrade".into(),
            commands: BTreeMap::from([
                (ManifestTool::Yarn, "yarn".into()),
                (ManifestTool::Npm, "npm".into()),
            ]),
        };
        let json = serde_json::to_string(&plan).unwrap();
        assert!(json.find("\"npm\"").unwrap() < json.find("\"yarn\"").unwrap());
    }
}
