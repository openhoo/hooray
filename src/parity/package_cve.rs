//! Record the CVE and package together at the source. An advisory's union of
//! CVEs and union of packages cannot later recover the original associations.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{compare::purl_match_key, model::CanonicalReport};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PackageCve {
    pub purl: String,
    pub cve: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageCveEvidence {
    pub pairs: BTreeSet<PackageCve>,
    /// Advisory IDs with a CVE but no unambiguous versioned package.
    pub unresolved_advisories: BTreeSet<String>,
}

pub(super) fn cve_id(s: &str) -> Option<String> {
    let id = s.trim().to_ascii_uppercase();
    let (year, number) = id.strip_prefix("CVE-")?.split_once('-')?;
    (year.len() == 4
        && number.len() >= 4
        && year
            .bytes()
            .chain(number.bytes())
            .all(|b| b.is_ascii_digit()))
    .then_some(id)
}

fn versioned_key(purl: &str) -> Option<String> {
    let version = crate::util::parse_purl_body(purl)?.version()?;
    let (kind, _) = purl.strip_prefix("pkg:")?.split_once('/')?;
    let body = purl.split(['?', '#']).next()?;
    let decoded = crate::util::percent_decode_strict(body)?;
    let version = crate::util::percent_decode_strict(version)?;
    if !kind.as_bytes().first()?.is_ascii_alphabetic()
        || !kind
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
        || decoded.contains(|c: char| c.is_control() || c.is_whitespace())
        || matches!(
            version.to_ascii_lowercase().as_str(),
            "unknown" | "noassertion" | "*" | "?"
        )
        || version.starts_with(['^', '>', '<', '='])
        || version.contains('*')
    {
        return None;
    }
    Some(purl_match_key(purl))
}

pub(super) fn version_agrees(purl: &str, declared: &str) -> bool {
    crate::util::parse_purl_body(purl)
        .and_then(|body| body.version())
        .and_then(crate::util::percent_decode_strict)
        .as_deref()
        == Some(declared)
}

impl PackageCveEvidence {
    pub(super) fn observe<'a>(
        &mut self,
        primary: &'a str,
        aliases: impl Iterator<Item = &'a str>,
        purl: Option<&str>,
    ) {
        let package = purl.and_then(versioned_key);
        for cve in std::iter::once(primary).chain(aliases).filter_map(cve_id) {
            if let Some(purl) = &package {
                self.pairs.insert(PackageCve {
                    purl: purl.clone(),
                    cve,
                });
            } else {
                self.unresolved_advisories.insert(primary.to_owned());
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageCveStatus {
    Match,
    Mismatch,
    #[default]
    Indeterminate,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageCveComparison {
    pub status: PackageCveStatus,
    pub matched: usize,
    pub missing_in_hooray: Vec<PackageCve>,
    pub extra_in_hooray: Vec<PackageCve>,
    pub reasons: Vec<String>,
}

pub(super) fn compare(left: &CanonicalReport, right: &CanonicalReport) -> PackageCveComparison {
    let mut result = PackageCveComparison::default();
    for (side, report) in [("hooray", left), ("xray", right)] {
        let mode_supported = match side {
            "hooray" => matches!(report.scan_mode.as_str(), "osv-live" | "provider-replay"),
            _ => report.scan_mode == "provider-replay",
        };
        if !mode_supported {
            result.reasons.push(format!(
                "{side}: scan mode '{}' did not measure advisory findings",
                report.scan_mode
            ));
        }
        if !report.parse_errors.is_empty() {
            result.reasons.push(format!(
                "{side}: {} parse errors",
                report.parse_errors.len()
            ));
        }
        if let Some(e) = &report.package_cve_evidence {
            // Never reconstruct missing pairs from the advisory-level unions.
            // Use those unions only to detect an incomplete capture.
            let inventory_keys: BTreeSet<_> = report
                .components
                .iter()
                .filter(|c| version_agrees(&c.purl, &c.version))
                .filter_map(|c| versioned_key(&c.purl))
                .collect();
            let mut observed_cves = BTreeSet::new();
            for pair in &e.pairs {
                observed_cves.insert(pair.cve.as_str());
                if !inventory_keys.contains(&pair.purl)
                    || cve_id(&pair.cve).as_ref() != Some(&pair.cve)
                {
                    result.reasons.push(format!(
                        "{side}: invalid recorded pair ({}, {})",
                        pair.purl, pair.cve
                    ));
                }
            }
            let canonical_cves: BTreeSet<_> = report
                .vulnerabilities
                .iter()
                .flat_map(|v| {
                    std::iter::once(&v.primary_id)
                        .chain(&v.cves)
                        .chain(&v.aliases)
                })
                .filter_map(|id| cve_id(id))
                .collect();
            for cve in canonical_cves {
                if !observed_cves.contains(cve.as_str()) {
                    result
                        .reasons
                        .push(format!("{side}: {cve} has no recorded package association"));
                }
            }
            for id in &e.unresolved_advisories {
                result
                    .reasons
                    .push(format!("{side}: {id} lacks an unambiguous versioned PURL"));
            }
        } else {
            result.reasons.push(format!(
                "{side}: package/CVE evidence not captured; use an advisory scan and re-record"
            ));
        }
    }
    // Without observations on both sides a directional difference would
    // mislabel absent evidence as a false positive or a false negative.
    if let (Some(l), Some(r)) = (&left.package_cve_evidence, &right.package_cve_evidence) {
        result.matched = l.pairs.intersection(&r.pairs).count();
        if result.reasons.is_empty() {
            // An unresolved observation can account for an apparent difference.
            // Report directional gaps only for two complete captures.
            result.missing_in_hooray = r.pairs.difference(&l.pairs).cloned().collect();
            result.extra_in_hooray = l.pairs.difference(&r.pairs).cloned().collect();
            result.status =
                if result.missing_in_hooray.is_empty() && result.extra_in_hooray.is_empty() {
                    PackageCveStatus::Match
                } else {
                    PackageCveStatus::Mismatch
                };
        }
    }
    result
}
