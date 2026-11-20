//! Version and package matches from the ZIP maintainers' published advisories.
//! This is a pinned supplementary source, not a live feed or a statement
//! about exploitability, other registries, patches in forks, or other packages.

mod snapshot;

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

use crate::model::{
    Applicability, ApplicabilityStatus, Component, ComponentId, Confidence, Evidence, Finding,
    FindingId, FindingKind, FindingStatus, Inventory, Remediation, RuleId, Severity,
    stable_finding_id,
};
use crate::remediation::VersionKey;
use snapshot::Advisory;

/// Source API; revision is the Hooray commit recording the review, and the
/// SHA-256 identifies the exact bytes used by the matching implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PublisherMetadata {
    pub source: &'static str,
    pub revision: &'static str,
    pub sha256: &'static str,
}

pub const fn metadata() -> PublisherMetadata {
    PublisherMetadata {
        source: "https://api.github.com/repos/zip-rs/zip2/security-advisories",
        revision: "3ab0c95f1afc850b8f37c04087b5998c7776b1a1",
        sha256: "a5d4c51106a5734a8deed3c94836fe99dd251d50e56a1a415c6ec022a4e0334d",
    }
}
#[derive(Clone, Debug, Error)]
pub enum PublisherError {
    #[error("invalid embedded ZIP maintainer snapshot: {0}")]
    Snapshot(&'static str),
    #[error("publisher finding identity conflicts with an unrelated stored finding")]
    IdentityConflict,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublisherCoverage {
    OutOfScope,
    Unclassifiable,
    Evaluated { matched_advisories: usize },
}

fn coordinate(component: &Component) -> Result<VersionKey, PublisherCoverage> {
    let Some(path) = component.purl.strip_prefix("pkg:cargo/") else {
        return Err(PublisherCoverage::OutOfScope);
    };
    if component.name != "zip" && path.split(['@', '?', '#']).next() != Some("zip") {
        return Err(PublisherCoverage::OutOfScope);
    }
    // Another package source or subpath is not interchangeable with the
    // unqualified crates.io package; leave ambiguous identities unclassified.
    let ver = path
        .strip_prefix("zip@")
        .filter(|s| !s.contains(['?', '#']))
        .and_then(crate::util::percent_decode_strict)
        .filter(|v| component.name == "zip" && *v == component.version)
        .and_then(|v| snapshot::version(&v));
    ver.ok_or(PublisherCoverage::Unclassifiable)
}

/// Distinguishes an evaluated coordinate with zero known matches from an
/// unsupported package, version specifier, or contradictory inventory entry.
pub fn classify(component: &Component) -> Result<PublisherCoverage, PublisherError> {
    match coordinate(component) {
        Ok(v) => Ok(PublisherCoverage::Evaluated {
            matched_advisories: snapshot::advisories()?
                .iter()
                .filter(|a| a.applies(&v))
                .count(),
        }),
        Err(unsupported) => Ok(unsupported),
    }
}

fn evidence(component: &Component, a: &Advisory) -> Evidence {
    let mut properties = BTreeMap::from([
        ("package.purl".into(), component.purl.clone()),
        ("publisher.advisory".into(), a.id.into()),
        ("publisher.range".into(), a.range.into()),
        ("publisher.first_patched".into(), a.patch.into()),
        ("publisher.updated_at".into(), a.modified.into()),
        ("publisher.snapshot_sha256".into(), metadata().sha256.into()),
    ]);
    if let Some(cve) = a.cve {
        properties.insert("publisher.cve".into(), cve.into());
    }
    Evidence {
        description: format!(
            "The ZIP maintainers' package/version range for {} includes {}",
            a.id, component.purl
        ),
        locations: component.locations.iter().map(|l| l.id.clone()).collect(),
        references: BTreeSet::from([a.url.to_owned()]),
        properties,
        redacted: false,
    }
}

fn finding(component: &Component, a: &Advisory, e: Evidence) -> Finding {
    let rule_id = RuleId::new(format!("publisher:zip-rs/zip2:{}", a.id))
        .expect("nonempty publisher rule prefix");
    let kind = FindingKind::Vulnerability;
    let id = stable_finding_id(kind, &rule_id, Some(&component.identity), None);
    Finding {
        id,
        kind,
        rule_id,
        advisory_id: Some(a.id.into()),
        component_id: Some(component.identity.clone()),
        location_id: None,
        aliases: a.cve.into_iter().map(String::from).collect(),
        summary: Some(format!("ZIP maintainer advisory {}", a.id)),
        details: None,
        // Severity is not present in the pinned source.
        severity: Severity::Unknown,
        confidence: Confidence::High,
        applicability: Some(Applicability {
            status: ApplicabilityStatus::Affected,
            rationale: Some(format!(
                "Declared package version matches {} and precedes first patch {}",
                a.range, a.patch
            )),
        }),
        remediation: Some(Remediation {
            description: "The ZIP maintainers list this first patched version".into(),
            fixed_versions: BTreeSet::from([a.patch.into()]),
            references: e.references.clone(),
        }),
        evidence: BTreeSet::from([e]),
        risk: None,
        first_seen: None,
        last_seen: None,
        modified: Some(a.modified.into()),
        status: FindingStatus::Open,
    }
}

/// Add a new finding only for a package/version/advisory the collected findings
/// do not already identify. Preserve original IDs, severity, fix guidance and
/// policy outcomes when the sources overlap: keep the maintainer's range and
/// patch as separate attributed evidence.
pub fn augment(
    inventory: &Inventory,
    findings: &mut BTreeMap<FindingId, Finding>,
) -> Result<(), PublisherError> {
    let zip: BTreeMap<_, _> = inventory
        .components
        .values()
        .filter_map(|c| coordinate(c).ok().map(|v| (&c.identity, (c, v))))
        .collect();
    if zip.is_empty() {
        return Ok(());
    }
    let snapshot = snapshot::advisories()?;
    let mut by_alias: BTreeMap<&ComponentId, BTreeMap<String, BTreeSet<FindingId>>> =
        BTreeMap::new();
    for (key, f) in findings
        .iter()
        .filter(|(_, f)| f.kind == FindingKind::Vulnerability)
    {
        let Some((component, _)) = f.component_id.as_ref().and_then(|id| zip.get_key_value(id))
        else {
            continue;
        };
        let ids = by_alias.entry(component).or_default();
        for id in f.advisory_id.iter().chain(&f.aliases) {
            ids.entry(id.to_ascii_uppercase())
                .or_default()
                .insert(key.clone());
        }
    }
    for (id, (component, version)) in zip {
        let aliases = by_alias.entry(id).or_default();
        for a in snapshot.iter().filter(|a| a.applies(&version)) {
            let keys: Vec<_> = std::iter::once(a.id)
                .chain(a.cve)
                .map(str::to_ascii_uppercase)
                .collect();
            let mut existing: BTreeSet<_> = keys
                .iter()
                .filter_map(|k| aliases.get(k))
                .flatten()
                .cloned()
                .collect();
            let e = evidence(component, a);
            if existing.is_empty() {
                let new = finding(component, a, e);
                let std::collections::btree_map::Entry::Vacant(slot) =
                    findings.entry(new.id.clone())
                else {
                    return Err(PublisherError::IdentityConflict);
                };
                existing.insert(new.id.clone());
                slot.insert(new);
            } else {
                for id in &existing {
                    let f = findings
                        .get_mut(id)
                        .expect("index contains only IDs from findings");
                    f.evidence.insert(e.clone());
                    // Policy selectors also inspect aliases. Keep an existing
                    // finding intact; newly supplied GHSA/CVE identifiers are
                    // available in the attributed publisher evidence above.
                }
            }
            for key in keys {
                aliases
                    .entry(key)
                    .or_default()
                    .extend(existing.iter().cloned());
            }
        }
    }
    Ok(())
}
