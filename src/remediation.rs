use std::{cmp::Ordering, collections::BTreeMap};

use thiserror::Error;

use crate::model::{
    ApplicabilityStatus, Component, DependencyKind, DependencyPaths, Finding, FindingKind,
    ManifestTool, PackageEcosystem, UpgradePlan,
};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RemediationError {
    #[error("finding {0} is not a vulnerability finding")]
    NotVulnerability(crate::model::FindingId),
    #[error("finding {0} does not reference component {1}")]
    ComponentMismatch(crate::model::FindingId, crate::model::ComponentId),
    #[error("finding {0} is not applicable for upgrade planning ({1:?})")]
    NonApplicable(crate::model::FindingId, ApplicabilityStatus),
    #[error("finding {0} has no remediation")]
    MissingRemediation(crate::model::FindingId),
    #[error("finding {0} has no concrete fixed version")]
    NoFixedVersion(crate::model::FindingId),
    #[error("unsupported package URL '{0}'")]
    UnsupportedPackageUrl(String),
}

pub fn plan_upgrade(
    finding: &Finding,
    component: &Component,
    dependency_kind: DependencyKind,
    dependency_paths: DependencyPaths,
) -> Result<UpgradePlan, RemediationError> {
    if finding.kind != FindingKind::Vulnerability {
        return Err(RemediationError::NotVulnerability(finding.id.clone()));
    }
    if let Some(applicability) = &finding.applicability
        && matches!(
            applicability.status,
            ApplicabilityStatus::NotAffected | ApplicabilityStatus::Fixed
        )
    {
        return Err(RemediationError::NonApplicable(
            finding.id.clone(),
            applicability.status,
        ));
    }
    if finding.component_id.as_ref() != Some(&component.identity) {
        return Err(RemediationError::ComponentMismatch(
            finding.id.clone(),
            component.identity.clone(),
        ));
    }
    let remediation = finding
        .remediation
        .as_ref()
        .ok_or_else(|| RemediationError::MissingRemediation(finding.id.clone()))?;
    let (ecosystem, package) = parse_purl(&component.purl)?;
    let fixed_version = nearest_fixed_version(
        ecosystem,
        &component.version,
        remediation.fixed_versions.iter().map(String::as_str),
    )
    .ok_or_else(|| RemediationError::NoFixedVersion(finding.id.clone()))?;
    let commands = manifest_commands(ecosystem, &package, &fixed_version);
    let guidance = match dependency_kind {
        DependencyKind::Direct => format!(
            "Upgrade the direct dependency {package} from {} to {fixed_version} and regenerate the lockfile.",
            component.version
        ),
        DependencyKind::Transitive => format!(
            "Upgrade the nearest direct dependency shown in the dependency path so that transitive dependency {package} resolves from {} to {fixed_version}; use an ecosystem override only when the direct dependency cannot yet resolve the fix.",
            component.version
        ),
        DependencyKind::Disconnected => format!(
            "Component {package} is not connected to a dependency root. Reconcile the inventory source, then upgrade from {} to {fixed_version} in the owning manifest.",
            component.version
        ),
    };
    Ok(UpgradePlan {
        finding_id: finding.id.clone(),
        component_id: component.identity.clone(),
        package,
        ecosystem,
        current_version: component.version.clone(),
        fixed_version,
        dependency_kind,
        paths: dependency_paths.paths,
        paths_truncated: dependency_paths.truncated,
        guidance,
        commands,
    })
}

pub fn nearest_fixed_version<'a>(
    ecosystem: PackageEcosystem,
    current: &str,
    candidates: impl IntoIterator<Item = &'a str>,
) -> Option<String> {
    let current_key = VersionKey::parse(ecosystem, current)?;
    let mut nearest_same_major: Option<(VersionKey, &str)> = None;
    let mut nearest_any: Option<(VersionKey, &str)> = None;
    for candidate in candidates {
        let Some(key) = VersionKey::parse(ecosystem, candidate) else {
            continue;
        };
        if key <= current_key {
            continue;
        }
        let choice = if key.major() == current_key.major() {
            &mut nearest_same_major
        } else {
            &mut nearest_any
        };
        let replace = choice.as_ref().is_none_or(|(selected_key, selected)| {
            key < *selected_key || (key == *selected_key && candidate < *selected)
        });
        if replace {
            *choice = Some((key, candidate));
        }
    }
    nearest_same_major
        .or(nearest_any)
        .map(|(_, version)| version.to_owned())
}

fn parse_purl(purl: &str) -> Result<(PackageEcosystem, String), RemediationError> {
    let package = purl
        .strip_prefix("pkg:")
        .and_then(|value| value.split(['?', '#']).next())
        .and_then(|value| value.rsplit_once('@').map(|(name, _)| name))
        .ok_or_else(|| RemediationError::UnsupportedPackageUrl(purl.to_owned()))?;
    let (kind, name) = package
        .split_once('/')
        .ok_or_else(|| RemediationError::UnsupportedPackageUrl(purl.to_owned()))?;
    if name.is_empty() {
        return Err(RemediationError::UnsupportedPackageUrl(purl.to_owned()));
    }
    let ecosystem = match kind.to_ascii_lowercase().as_str() {
        "cargo" => PackageEcosystem::Cargo,
        "npm" => PackageEcosystem::Npm,
        "pypi" => PackageEcosystem::Pypi,
        "golang" => PackageEcosystem::Go,
        "maven" => PackageEcosystem::Maven,
        "nuget" => PackageEcosystem::Nuget,
        _ => return Err(RemediationError::UnsupportedPackageUrl(purl.to_owned())),
    };
    Ok((
        ecosystem,
        percent_decode(name)
            .ok_or_else(|| RemediationError::UnsupportedPackageUrl(purl.to_owned()))?,
    ))
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes.get(index + 1..index + 3)?;
            let text = std::str::from_utf8(hex).ok()?;
            output.push(u8::from_str_radix(text, 16).ok()?);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).ok()
}

fn manifest_commands(
    ecosystem: PackageEcosystem,
    package_name: &str,
    version: &str,
) -> BTreeMap<ManifestTool, String> {
    let package = shell_quote(package_name);
    let quoted_version = shell_quote(version);
    match ecosystem {
        PackageEcosystem::Cargo => BTreeMap::from([(
            ManifestTool::Cargo,
            format!("cargo update -p {package} --precise {quoted_version}"),
        )]),
        PackageEcosystem::Npm => BTreeMap::from([
            (
                ManifestTool::Npm,
                format!("npm install --save-exact {package}@{quoted_version}"),
            ),
            (
                ManifestTool::Pnpm,
                format!("pnpm add --save-exact {package}@{quoted_version}"),
            ),
            (
                ManifestTool::Yarn,
                format!("yarn add --exact {package}@{quoted_version}"),
            ),
        ]),
        PackageEcosystem::Pypi => BTreeMap::from([
            (
                ManifestTool::Pip,
                format!("python -m pip install {package}=={quoted_version}"),
            ),
            (
                ManifestTool::Poetry,
                format!("poetry add {package}=={quoted_version}"),
            ),
        ]),
        PackageEcosystem::Go => BTreeMap::from([(
            ManifestTool::Go,
            format!("go get {package}@{quoted_version} && go mod tidy"),
        )]),
        PackageEcosystem::Maven => {
            let coordinate = package_name.replace('/', ":");
            let maven_coordinate = shell_quote(&coordinate);
            BTreeMap::from([(
                ManifestTool::Maven,
                format!(
                    "mvn versions:use-dep-version -Dincludes={maven_coordinate} -DdepVersion={quoted_version} -DforceVersion=true"
                ),
            )])
        }
        PackageEcosystem::Nuget => BTreeMap::from([(
            ManifestTool::Nuget,
            format!("dotnet add package {package} --version {quoted_version}"),
        )]),
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct VersionKey {
    epoch: u64,
    release: Vec<u64>,
    suffix: VersionSuffix,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VersionSuffix {
    Generic(Vec<VersionPart>),
    Maven(Vec<VersionPart>),
    Pep440(Pep440Suffix),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Pep440Suffix {
    pre: Option<(u8, u64)>,
    post: Option<u64>,
    dev: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VersionPart {
    Number(u64),
    Text(String),
}

impl VersionKey {
    fn parse(ecosystem: PackageEcosystem, value: &str) -> Option<Self> {
        match ecosystem {
            PackageEcosystem::Pypi => parse_pep440(value),
            PackageEcosystem::Maven => parse_maven(value),
            _ => parse_generic(ecosystem, value),
        }
    }

    fn major(&self) -> u64 {
        self.release.first().copied().unwrap_or(0)
    }
}

impl Ord for VersionKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.epoch
            .cmp(&other.epoch)
            .then_with(|| compare_release(&self.release, &other.release))
            .then_with(|| match (&self.suffix, &other.suffix) {
                (VersionSuffix::Pep440(left), VersionSuffix::Pep440(right)) => {
                    compare_pep440(left, right)
                }
                (VersionSuffix::Maven(left), VersionSuffix::Maven(right)) => {
                    compare_maven_parts(left, right)
                }
                (VersionSuffix::Generic(left), VersionSuffix::Generic(right)) => {
                    compare_prerelease(left, right)
                }
                _ => Ordering::Equal,
            })
    }
}

impl PartialOrd for VersionKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn parse_generic(ecosystem: PackageEcosystem, value: &str) -> Option<VersionKey> {
    let mut value = value.trim();
    if ecosystem == PackageEcosystem::Go {
        value = value.strip_prefix('v').unwrap_or(value);
    }
    let value = value.split('+').next()?;
    let (release, pre) = value.split_once(['-', '~']).unwrap_or((value, ""));
    let release = parse_numeric_release(release)?;
    Some(VersionKey {
        epoch: 0,
        release,
        suffix: VersionSuffix::Generic(tokenize(pre)),
    })
}

fn parse_pep440(value: &str) -> Option<VersionKey> {
    let mut value = value.trim().to_ascii_lowercase();
    if let Some(stripped) = value.strip_prefix('v') {
        value = stripped.to_owned();
    }
    let value = value.split('+').next()?;
    let (epoch, value) = if let Some((epoch, rest)) = value.split_once('!') {
        (epoch.parse().ok()?, rest)
    } else {
        (0, value)
    };
    let release_end = value
        .char_indices()
        .find_map(|(index, character)| {
            (!character.is_ascii_digit() && character != '.').then_some(index)
        })
        .unwrap_or(value.len());
    let release = parse_numeric_release(value[..release_end].trim_end_matches('.'))?;
    let suffix_text = value[release_end..].trim_matches(['.', '-', '_']);
    let parts = tokenize(suffix_text);
    let mut pre = None;
    let mut post = None;
    let mut dev = None;
    let mut index = 0;
    while index < parts.len() {
        let VersionPart::Text(label) = &parts[index] else {
            if index == 0 && post.is_none() {
                post = part_number(parts.get(index));
                index += 1;
                continue;
            }
            return None;
        };
        let number = part_number(parts.get(index + 1)).unwrap_or(0);
        match label.as_str() {
            "a" | "alpha" if pre.is_none() => pre = Some((0, number)),
            "b" | "beta" if pre.is_none() => pre = Some((1, number)),
            "c" | "rc" | "pre" | "preview" if pre.is_none() => pre = Some((2, number)),
            "post" | "rev" | "r" if post.is_none() => post = Some(number),
            "dev" if dev.is_none() => dev = Some(number),
            _ => return None,
        }
        index += if matches!(parts.get(index + 1), Some(VersionPart::Number(_))) {
            2
        } else {
            1
        };
    }
    Some(VersionKey {
        epoch,
        release,
        suffix: VersionSuffix::Pep440(Pep440Suffix { pre, post, dev }),
    })
}

fn parse_maven(value: &str) -> Option<VersionKey> {
    let value = value.trim().split('+').next()?.to_ascii_lowercase();
    let release_end = value
        .char_indices()
        .find_map(|(index, character)| {
            (!character.is_ascii_digit() && character != '.').then_some(index)
        })
        .unwrap_or(value.len());
    let release = parse_numeric_release(value[..release_end].trim_end_matches('.'))?;
    let mut suffix = tokenize(value[release_end..].trim_matches(['.', '-', '_']));
    suffix.retain(|part| {
        !matches!(part, VersionPart::Text(value) if matches!(value.as_str(), "final" | "ga" | "release"))
    });
    Some(VersionKey {
        epoch: 0,
        release,
        suffix: VersionSuffix::Maven(suffix),
    })
}

fn parse_numeric_release(value: &str) -> Option<Vec<u64>> {
    if value.is_empty() {
        return None;
    }
    let mut release = value
        .split('.')
        .map(str::parse)
        .collect::<Result<Vec<u64>, _>>()
        .ok()?;
    while release.last() == Some(&0) {
        release.pop();
    }
    if release.is_empty() {
        release.push(0);
    }
    Some(release)
}

fn part_number(part: Option<&VersionPart>) -> Option<u64> {
    match part {
        Some(VersionPart::Number(value)) => Some(*value),
        _ => None,
    }
}

fn compare_release(left: &[u64], right: &[u64]) -> Ordering {
    let length = left.len().max(right.len());
    (0..length)
        .map(|index| {
            left.get(index)
                .copied()
                .unwrap_or(0)
                .cmp(&right.get(index).copied().unwrap_or(0))
        })
        .find(|ordering| !ordering.is_eq())
        .unwrap_or(Ordering::Equal)
}

fn compare_pep440(left: &Pep440Suffix, right: &Pep440Suffix) -> Ordering {
    pep440_pre_key(left)
        .cmp(&pep440_pre_key(right))
        .then_with(|| left.post.cmp(&right.post))
        .then_with(|| match (left.dev, right.dev) {
            (Some(left), Some(right)) => left.cmp(&right),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        })
}

fn pep440_pre_key(value: &Pep440Suffix) -> (u8, u8, u64) {
    match value.pre {
        Some((kind, number)) => (1, kind, number),
        None if value.dev.is_some() && value.post.is_none() => (0, 0, 0),
        None => (2, 0, 0),
    }
}

fn compare_prerelease(left: &[VersionPart], right: &[VersionPart]) -> Ordering {
    match (left.is_empty(), right.is_empty()) {
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        _ => compare_parts(left, right),
    }
}

fn compare_maven_parts(left: &[VersionPart], right: &[VersionPart]) -> Ordering {
    match (left.first(), right.first()) {
        (None, None) => Ordering::Equal,
        (None, Some(VersionPart::Text(value))) => 5u8.cmp(&maven_qualifier_rank(value)),
        (Some(VersionPart::Text(value)), None) => maven_qualifier_rank(value).cmp(&5),
        (None, Some(VersionPart::Number(_))) => Ordering::Less,
        (Some(VersionPart::Number(_)), None) => Ordering::Greater,
        _ => compare_parts(left, right),
    }
}

fn compare_parts(left: &[VersionPart], right: &[VersionPart]) -> Ordering {
    for (left, right) in left.iter().zip(right) {
        let ordering = match (left, right) {
            (VersionPart::Number(a), VersionPart::Number(b)) => a.cmp(b),
            (VersionPart::Number(_), VersionPart::Text(_)) => Ordering::Less,
            (VersionPart::Text(_), VersionPart::Number(_)) => Ordering::Greater,
            (VersionPart::Text(a), VersionPart::Text(b)) => maven_qualifier_rank(a)
                .cmp(&maven_qualifier_rank(b))
                .then_with(|| a.cmp(b)),
        };
        if !ordering.is_eq() {
            return ordering;
        }
    }
    left.len().cmp(&right.len())
}

fn maven_qualifier_rank(value: &str) -> u8 {
    match value {
        "alpha" | "a" => 0,
        "beta" | "b" => 1,
        "milestone" | "m" => 2,
        "rc" | "cr" => 3,
        "snapshot" => 4,
        "final" | "ga" | "release" => 5,
        "sp" => 6,
        _ => 7,
    }
}

fn tokenize(value: &str) -> Vec<VersionPart> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut numeric = None;
    for character in value
        .chars()
        .map(|character| character.to_ascii_lowercase())
    {
        if !character.is_ascii_alphanumeric() {
            if !current.is_empty() {
                push_part(&mut parts, &mut current, numeric);
            }
            numeric = None;
            continue;
        }
        let is_numeric = character.is_ascii_digit();
        if numeric.is_some_and(|kind| kind != is_numeric) {
            push_part(&mut parts, &mut current, numeric);
        }
        numeric = Some(is_numeric);
        current.push(character);
    }
    if !current.is_empty() {
        push_part(&mut parts, &mut current, numeric);
    }
    parts
}

fn push_part(parts: &mut Vec<VersionPart>, current: &mut String, numeric: Option<bool>) {
    let value = std::mem::take(current);
    if numeric == Some(true) {
        parts.push(VersionPart::Number(value.parse().unwrap()));
    } else {
        parts.push(VersionPart::Text(value));
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::model::{
        Applicability, ApplicabilityStatus, Component, ComponentId, Confidence, DependencyKind,
        DependencyPaths, Finding, FindingId, FindingKind, FindingStatus, ManifestTool,
        PackageEcosystem, Remediation, RuleId, Scope, Severity,
    };

    use super::{RemediationError, nearest_fixed_version, plan_upgrade};

    fn component(purl: &str, version: &str) -> Component {
        Component {
            identity: ComponentId::new("component").unwrap(),
            name: "package".into(),
            version: version.into(),
            purl: purl.into(),
            scope: Scope::Runtime,
            provenance: BTreeSet::new(),
            licenses: BTreeSet::new(),
            locations: BTreeSet::new(),
        }
    }
    fn finding(component: &Component, fixed: &[&str]) -> Finding {
        Finding {
            id: FindingId::new("finding").unwrap(),
            kind: FindingKind::Vulnerability,
            rule_id: RuleId::new("rule").unwrap(),
            advisory_id: Some("CVE-1".into()),
            component_id: Some(component.identity.clone()),
            location_id: None,
            aliases: BTreeSet::new(),
            summary: None,
            details: None,
            severity: Severity::High,
            confidence: Confidence::High,
            evidence: BTreeSet::new(),
            applicability: None,
            remediation: Some(Remediation {
                description: "upgrade".into(),
                fixed_versions: fixed.iter().map(|value| (*value).into()).collect(),
                references: BTreeSet::new(),
            }),
            risk: None,
            first_seen: None,
            last_seen: None,
            modified: None,
            status: FindingStatus::Open,
        }
    }

    #[test]
    fn selects_nearest_non_downgrade_same_major_before_breaking_upgrade() {
        assert_eq!(
            nearest_fixed_version(
                PackageEcosystem::Cargo,
                "1.2.9",
                ["2.0.0", "1.10.0", "1.3.0"]
            ),
            Some("1.3.0".into())
        );
        assert_eq!(
            nearest_fixed_version(
                PackageEcosystem::Cargo,
                "1.2.9",
                ["0.9.0", "2.1.0", "2.0.0"]
            ),
            Some("2.0.0".into())
        );
    }

    #[test]
    fn version_order_handles_prereleases_go_prefix_pep440_epoch_and_numeric_segments() {
        assert_eq!(
            nearest_fixed_version(
                PackageEcosystem::Npm,
                "1.0.0-beta.2",
                ["1.0.0-beta.10", "1.0.0"]
            ),
            Some("1.0.0-beta.10".into())
        );
        assert_eq!(
            nearest_fixed_version(PackageEcosystem::Go, "v1.9.0", ["v1.10.0", "v2.0.0"]),
            Some("v1.10.0".into())
        );
        assert_eq!(
            nearest_fixed_version(PackageEcosystem::Pypi, "1!1.0", ["2.0", "1!1.1"]),
            Some("1!1.1".into())
        );
        assert_eq!(
            nearest_fixed_version(PackageEcosystem::Maven, "1.9", ["1.10", "2.0"]),
            Some("1.10".into())
        );
    }

    #[test]
    fn pypi_orders_dev_pre_final_and_post_releases() {
        assert_eq!(
            nearest_fixed_version(
                PackageEcosystem::Pypi,
                "1.0.dev1",
                ["1.0.post1", "1.0", "1.0rc1", "1.0.dev2"]
            ),
            Some("1.0.dev2".into())
        );
        assert_eq!(
            nearest_fixed_version(
                PackageEcosystem::Pypi,
                "1.0",
                ["1.0rc2", "1.0.post2", "1.0.post1"]
            ),
            Some("1.0.post1".into())
        );
    }

    #[test]
    fn maven_final_qualifier_equals_the_unqualified_release() {
        assert_eq!(
            nearest_fixed_version(PackageEcosystem::Maven, "1.0-rc1", ["1.0.1", "1.0.Final"]),
            Some("1.0.Final".into())
        );
        assert_eq!(
            nearest_fixed_version(PackageEcosystem::Maven, "1.0.Final", ["1.0", "1.0.1"]),
            Some("1.0.1".into())
        );
    }

    #[test]
    fn ignores_invalid_and_older_fixed_versions_without_inventing_one() {
        assert_eq!(
            nearest_fixed_version(PackageEcosystem::Nuget, "2.0.0", ["not-a-version", "1.9.9"]),
            None
        );
        let component = component("pkg:nuget/Newtonsoft.Json@2.0.0", "2.0.0");
        assert_eq!(
            plan_upgrade(
                &finding(&component, &["1.9.9"]),
                &component,
                DependencyKind::Direct,
                DependencyPaths {
                    paths: vec![],
                    truncated: false
                }
            )
            .unwrap_err(),
            RemediationError::NoFixedVersion(FindingId::new("finding").unwrap())
        );
    }

    #[test]
    fn rejects_non_applicable_findings() {
        let component = component("pkg:cargo/serde@1.0.0", "1.0.0");
        for status in [ApplicabilityStatus::NotAffected, ApplicabilityStatus::Fixed] {
            let mut finding = finding(&component, &["1.0.1"]);
            finding.applicability = Some(Applicability {
                status,
                rationale: None,
            });
            assert_eq!(
                plan_upgrade(
                    &finding,
                    &component,
                    DependencyKind::Direct,
                    DependencyPaths {
                        paths: vec![],
                        truncated: false,
                    },
                )
                .unwrap_err(),
                RemediationError::NonApplicable(finding.id, status)
            );
        }
    }

    #[test]
    fn emits_direct_and_transitive_guidance_and_preserves_path_truncation() {
        let component = component("pkg:cargo/serde@1.0.0", "1.0.0");
        let direct = plan_upgrade(
            &finding(&component, &["1.0.1"]),
            &component,
            DependencyKind::Direct,
            DependencyPaths {
                paths: vec![],
                truncated: false,
            },
        )
        .unwrap();
        assert!(direct.guidance.contains("direct dependency"));
        assert_eq!(
            direct.commands[&ManifestTool::Cargo],
            "cargo update -p 'serde' --precise '1.0.1'"
        );
        let transitive = plan_upgrade(
            &finding(&component, &["1.0.1"]),
            &component,
            DependencyKind::Transitive,
            DependencyPaths {
                paths: vec![],
                truncated: true,
            },
        )
        .unwrap();
        assert!(transitive.guidance.contains("nearest direct dependency"));
        assert!(transitive.paths_truncated);
    }

    #[test]
    fn emits_commands_for_every_supported_manifest_tool() {
        let cases = [
            (
                "pkg:npm/%40scope%2Fpkg@1.0.0",
                "1.0.1",
                vec![ManifestTool::Npm, ManifestTool::Pnpm, ManifestTool::Yarn],
            ),
            (
                "pkg:pypi/requests@1.0.0",
                "1.0.1",
                vec![ManifestTool::Pip, ManifestTool::Poetry],
            ),
            (
                "pkg:golang/github.com%2Facme%2Flib@v1.0.0",
                "v1.0.1",
                vec![ManifestTool::Go],
            ),
            (
                "pkg:maven/org.example%2Flib@1.0.0",
                "1.0.1",
                vec![ManifestTool::Maven],
            ),
            (
                "pkg:nuget/Newtonsoft.Json@1.0.0",
                "1.0.1",
                vec![ManifestTool::Nuget],
            ),
        ];
        for (purl, fixed, tools) in cases {
            let component = component(
                purl,
                if fixed.starts_with('v') {
                    "v1.0.0"
                } else {
                    "1.0.0"
                },
            );
            let plan = plan_upgrade(
                &finding(&component, &[fixed]),
                &component,
                DependencyKind::Direct,
                DependencyPaths {
                    paths: vec![],
                    truncated: false,
                },
            )
            .unwrap();
            assert_eq!(plan.commands.keys().copied().collect::<Vec<_>>(), tools);
            assert!(
                plan.commands
                    .values()
                    .all(|command| command.contains(fixed))
            );
        }
    }

    #[test]
    fn shell_quotes_untrusted_package_text_instead_of_executing_it() {
        let component = component("pkg:npm/bad%27%3Btouch%20pwned@1.0.0", "1.0.0");
        let plan = plan_upgrade(
            &finding(&component, &["1.0.1"]),
            &component,
            DependencyKind::Direct,
            DependencyPaths {
                paths: vec![],
                truncated: false,
            },
        )
        .unwrap();
        assert_eq!(
            plan.commands[&ManifestTool::Npm],
            "npm install --save-exact 'bad'\\'';touch pwned'@'1.0.1'"
        );
    }

    #[test]
    fn rejects_non_vulnerability_mismatched_component_and_unsupported_purl() {
        let cargo_component = component("pkg:cargo/serde@1.0.0", "1.0.0");
        let mut item = finding(&cargo_component, &["1.0.1"]);
        item.kind = FindingKind::License;
        assert!(matches!(
            plan_upgrade(
                &item,
                &cargo_component,
                DependencyKind::Direct,
                DependencyPaths {
                    paths: vec![],
                    truncated: false
                }
            ),
            Err(RemediationError::NotVulnerability(_))
        ));
        let mut item = finding(&cargo_component, &["1.0.1"]);
        item.component_id = Some(ComponentId::new("other").unwrap());
        assert!(matches!(
            plan_upgrade(
                &item,
                &cargo_component,
                DependencyKind::Direct,
                DependencyPaths {
                    paths: vec![],
                    truncated: false
                }
            ),
            Err(RemediationError::ComponentMismatch(_, _))
        ));
        let invalid = component("pkg:deb/debian/curl@1", "1");
        assert!(matches!(
            plan_upgrade(
                &finding(&invalid, &["2"]),
                &invalid,
                DependencyKind::Direct,
                DependencyPaths {
                    paths: vec![],
                    truncated: false
                }
            ),
            Err(RemediationError::UnsupportedPackageUrl(_))
        ));
    }
}
