//! Match keys and comparison metrics between two canonical reports.
//!
//! All metrics are symmetric-friendly, total (no division by zero: empty
//! denominators yield `1.0`), and produce deterministically ordered diff
//! lists so repeated runs byte-match.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::parity::model::{CanonicalComponent, CanonicalReport};

/// Returns the canonical comparison form of a package URL.
///
/// * splits `pkg:<type>/rest`, lowercasing the type,
/// * lowercases namespace+name except for the `golang` type, whose module
///   paths are case-sensitive per the Go specification,
/// * strips all qualifiers (`?…`) and fragments (`#…`),
/// * keeps the version verbatim.
pub fn purl_match_key(purl: &str) -> String {
    let body = purl.strip_prefix("pkg:").unwrap_or(purl);
    let body = body.split('#').next().unwrap_or(body);
    let body = body.split('?').next().unwrap_or(body);
    let Some((type_part, rest)) = body.split_once('/') else {
        return format!("pkg:{}", body.to_ascii_lowercase());
    };
    let type_lower = type_part.to_ascii_lowercase();
    let (path, version) = match rest.rsplit_once('@') {
        Some((path, version)) => (path, Some(version)),
        None => (rest, None),
    };
    let path = if type_lower == "golang" {
        path.to_owned()
    } else {
        path.to_ascii_lowercase()
    };
    match version {
        Some(version) => format!("pkg:{type_lower}/{path}@{version}"),
        None => format!("pkg:{type_lower}/{path}"),
    }
}

/// Extracts the lowercase ecosystem from a purl's type segment.
pub fn ecosystem_of_purl(purl: &str) -> String {
    let body = purl.strip_prefix("pkg:").unwrap_or(purl);
    match body.split_once('/') {
        Some((type_part, _)) => type_part.to_ascii_lowercase(),
        None => body.to_ascii_lowercase(),
    }
}

fn jaccard(left: &BTreeSet<String>, right: &BTreeSet<String>) -> f64 {
    if left.is_empty() && right.is_empty() {
        return 1.0;
    }
    let intersection = left.intersection(right).count();
    let union = left.len() + right.len() - intersection;
    if union == 0 {
        return 1.0;
    }
    intersection as f64 / union as f64
}

fn component_key_map(report: &CanonicalReport) -> BTreeMap<String, &CanonicalComponent> {
    report
        .components
        .iter()
        .map(|component| (purl_match_key(&component.purl), component))
        .collect()
}

/// CVE id to severity label mapping; first occurrence wins because canonical
/// vulnerabilities are already sorted.
fn cve_severity_map(report: &CanonicalReport) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for vuln in &report.vulnerabilities {
        for cve in &vuln.cves {
            map.entry(cve.clone())
                .or_insert_with(|| vuln.severity_label.clone());
        }
    }
    map
}

fn cve_set(report: &CanonicalReport) -> BTreeSet<String> {
    report
        .vulnerabilities
        .iter()
        .flat_map(|vuln| vuln.cves.iter().cloned())
        .collect()
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        1.0
    } else {
        numerator as f64 / denominator as f64
    }
}

/// One severity label disagreement on a CVE matched on both sides.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SeverityMismatch {
    /// The CVE identifier.
    pub cve: String,
    /// Severity label on the hooray side.
    pub hooray: String,
    /// Severity label on the Xray side.
    pub xray: String,
}

/// Deterministic parity scorecard between a hooray and an Xray canonical
/// report.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Scorecard {
    /// |hooray ∩ xray| / |xray| over purl match keys (1.0 when xray empty).
    pub purl_recall: f64,
    /// |hooray ∩ xray| / |hooray| over purl match keys (1.0 when hooray empty).
    pub purl_precision: f64,
    /// Jaccard over CVE sets; empty-vs-empty is 1.0.
    pub cve_jaccard: f64,
    /// Fraction of CVE-matched pairs with equal severity labels (1.0 when no
    /// matched pairs exist).
    pub severity_agreement: f64,
    /// Jaccard over `(purl match key, license)` pairs restricted to components
    /// present on both sides (1.0 when the restriction is empty).
    pub license_agreement: f64,
    /// Purls (raw form of the lexicographically-first representative per match
    /// key) present in xray but missing from hooray, sorted by match key.
    pub missing_purls: Vec<String>,
    /// Purls present in hooray but absent from xray, sorted by match key.
    pub extra_purls: Vec<String>,
    /// CVEs reported by xray that hooray did not report, sorted.
    pub cves_missing_in_hooray: Vec<String>,
    /// CVEs reported by hooray that xray did not report, sorted.
    pub cves_extra_in_hooray: Vec<String>,
    /// Severity disagreements over CVEs matched on both sides, sorted by CVE.
    pub severity_mismatches: Vec<SeverityMismatch>,
}

/// Computes the full scorecard comparing `hooray` against `xray`.
pub fn scorecard(hooray: &CanonicalReport, xray: &CanonicalReport) -> Scorecard {
    let hooray_keys = component_key_map(hooray);
    let xray_keys = component_key_map(xray);

    let mut shared_keys = Vec::new();
    let mut missing_purls = Vec::new();
    let mut extra_purls = Vec::new();
    for (key, component) in &xray_keys {
        if hooray_keys.contains_key(key) {
            shared_keys.push(key.clone());
        } else {
            missing_purls.push(component.purl.clone());
        }
    }
    for (key, component) in &hooray_keys {
        if !xray_keys.contains_key(key) {
            extra_purls.push(component.purl.clone());
        }
    }

    let hooray_cves = cve_set(hooray);
    let xray_cves = cve_set(xray);
    let cve_jaccard = jaccard(&hooray_cves, &xray_cves);

    let hooray_severity = cve_severity_map(hooray);
    let xray_severity = cve_severity_map(xray);
    let mut severity_mismatches = Vec::new();
    let mut severity_matches = 0_usize;
    let mut severity_pairs = 0_usize;
    for (cve, xray_label) in &xray_severity {
        let Some(hooray_label) = hooray_severity.get(cve) else {
            continue;
        };
        severity_pairs += 1;
        if hooray_label == xray_label {
            severity_matches += 1;
        } else {
            severity_mismatches.push(SeverityMismatch {
                cve: cve.clone(),
                hooray: hooray_label.clone(),
                xray: xray_label.clone(),
            });
        }
    }

    let shared: BTreeSet<&String> = shared_keys.iter().collect();
    let license_pairs = |report_keys: &BTreeMap<String, &CanonicalComponent>| -> BTreeSet<String> {
        report_keys
            .iter()
            .filter(|(key, _)| shared.contains(key))
            .flat_map(|(key, component)| {
                component
                    .licenses
                    .iter()
                    .map(move |license| format!("{key}|{license}"))
            })
            .collect()
    };
    let license_agreement = jaccard(&license_pairs(&hooray_keys), &license_pairs(&xray_keys));

    Scorecard {
        purl_recall: ratio(
            hooray_keys
                .keys()
                .filter(|k| xray_keys.contains_key(*k))
                .count(),
            xray_keys.len(),
        ),
        purl_precision: ratio(shared_keys.len(), hooray_keys.len()),
        cve_jaccard,
        severity_agreement: ratio(severity_matches, severity_pairs),
        license_agreement,
        missing_purls,
        extra_purls,
        cves_missing_in_hooray: xray_cves.difference(&hooray_cves).cloned().collect(),
        cves_extra_in_hooray: hooray_cves.difference(&xray_cves).cloned().collect(),
        severity_mismatches,
    }
}

/// Applies one optional threshold to a metric value; returns `true` when the
/// threshold exists and the value falls below it.
pub fn violates(threshold: Option<f64>, value: f64) -> bool {
    threshold.is_some_and(|minimum| value < minimum)
}

/// One per-case result row of `hooray-parity check`.
#[derive(Debug, Serialize)]
pub struct CaseCheck {
    /// Corpus case identifier.
    pub case_id: String,
    /// `"ok"` or `"violation"`.
    pub status: String,
    /// Human-readable violation notes, deterministic order.
    pub notes: Vec<String>,
    /// Present once tier-2 processed the case's recording.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scorecard: Option<Scorecard>,
}

/// Strictest of an operator CLI gate and a recording-declared gate; `None`
/// when neither is configured.
pub fn effective_threshold(recording_gate: Option<f64>, cli_gate: Option<f64>) -> Option<f64> {
    match (recording_gate, cli_gate) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

/// Drift guard between a fresh offline scan and the recorded hooray side.
///
/// Components, license findings, and parse errors must match exactly;
/// vulnerabilities are exempt by construction because offline scans query no
/// advisory database and would always diverge from a recorded live run.
/// Generator identity, scan mode, and case id are metadata, not behavior,
/// and are likewise exempt.
pub fn drift_violations(fresh: &CanonicalReport, recorded: &CanonicalReport) -> Vec<String> {
    let mut violations = Vec::new();
    if fresh.components != recorded.components {
        violations.push("components differ from recording".to_owned());
    }
    if fresh.license_findings != recorded.license_findings {
        violations.push("license findings differ from recording".to_owned());
    }
    if fresh.parse_errors != recorded.parse_errors {
        violations.push("parse errors differ from recording".to_owned());
    }
    violations
}

/// Merges one recording's tier-2 outcome into the check results.
///
/// When a tier-1 row already exists for the case it is extended in place:
/// notes are appended, status escalates to `"violation"` when drift or
/// threshold notes exist or the tier-1 row itself already violates, and the
/// scorecard is attached. A recording for an unknown case appends a new row.
/// A duplicate recording for a case that already carries a scorecard appends
/// another row so both outcomes stay visible.
pub fn apply_recording_check(
    results: &mut Vec<CaseCheck>,
    recording_case_id: &str,
    drift_notes: Vec<String>,
    threshold_notes: Vec<String>,
    card: Scorecard,
) {
    let mut notes = drift_notes;
    notes.extend(threshold_notes);
    let has_tier1_violation = results
        .iter()
        .any(|r| r.case_id == recording_case_id && r.status == "violation");
    let violating = !notes.is_empty() || has_tier1_violation;
    match results
        .iter_mut()
        .find(|r| r.case_id == recording_case_id && r.scorecard.is_none())
    {
        Some(existing) => {
            existing.notes.extend(notes);
            if violating {
                existing.status = "violation".to_owned();
            }
            existing.scorecard = Some(card);
        }
        None => results.push(CaseCheck {
            case_id: recording_case_id.to_owned(),
            status: if violating { "violation" } else { "ok" }.to_owned(),
            notes,
            scorecard: Some(card),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parity::model::{CanonicalLicenseFinding, CanonicalVuln, Generator, ParseError};

    fn component(purl: &str, licenses: &[&str]) -> CanonicalComponent {
        CanonicalComponent {
            purl: purl.to_owned(),
            name: "name".to_owned(),
            version: "1.0.0".to_owned(),
            ecosystem: ecosystem_of_purl(purl),
            licenses: licenses.iter().map(|l| (*l).to_owned()).collect(),
            scope: "runtime".to_owned(),
            directness: "direct".to_owned(),
        }
    }

    fn vuln(primary: &str, cves: &[&str], severity: &str, purls: &[&str]) -> CanonicalVuln {
        CanonicalVuln {
            primary_id: primary.to_owned(),
            aliases: cves.iter().map(|c| (*c).to_owned()).collect(),
            cves: cves.iter().map(|c| (*c).to_owned()).collect(),
            affected_purls: purls.iter().map(|p| (*p).to_owned()).collect(),
            fixed_versions: Vec::new(),
            severity_label: severity.to_owned(),
        }
    }

    #[test]
    fn match_key_lowercases_type_namespace_and_name() {
        assert_eq!(
            purl_match_key("pkg:npm/Lodash@4.17.15"),
            "pkg:npm/lodash@4.17.15"
        );
        assert_eq!(
            purl_match_key("pkg:golang/github.com/GoAUTHORS/PKG@v1.2.3"),
            "pkg:golang/github.com/GoAUTHORS/PKG@v1.2.3"
        );
    }

    #[test]
    fn match_key_strips_qualifiers_fragments_and_keeps_version() {
        assert_eq!(
            purl_match_key("pkg:npm/%40org/name@1.2.3?vulnerabilities=1#sub/path"),
            "pkg:npm/%40org/name@1.2.3"
        );
        // Version itself stays verbatim, including unusual casing/characters.
        assert_eq!(
            purl_match_key("pkg:cargo/Serde@1.0.0-RC1"),
            "pkg:cargo/serde@1.0.0-RC1"
        );
    }

    #[test]
    fn match_key_handles_scoped_npm_and_missing_version() {
        assert_eq!(
            purl_match_key("pkg:npm/@babel/core@7.0.0"),
            "pkg:npm/@babel/core@7.0.0"
        );
        assert_eq!(purl_match_key("pkg:npm/left-pad"), "pkg:npm/left-pad");
    }

    #[test]
    fn empty_sets_score_full_marks() {
        let empty = CanonicalReport::new(
            "case",
            Generator {
                name: "a".into(),
                version: "1".into(),
            },
            "offline",
        );
        let card = scorecard(&empty, &empty);
        assert_eq!(card.purl_recall, 1.0);
        assert_eq!(card.purl_precision, 1.0);
        assert_eq!(card.cve_jaccard, 1.0);
        assert_eq!(card.severity_agreement, 1.0);
        assert_eq!(card.license_agreement, 1.0);
    }

    #[test]
    fn recall_uses_xray_denominator_and_precision_hooray() {
        let mut hooray = CanonicalReport::new(
            "case",
            Generator {
                name: "h".into(),
                version: "1".into(),
            },
            "offline",
        );
        let mut xray = hooray.clone();
        hooray.components.push(component("pkg:npm/a@1", &["MIT"]));
        hooray.components.push(component("pkg:npm/b@1", &[]));
        xray.components.push(component("pkg:npm/A@1", &[]));
        xray.components.push(component("pkg:npm/c@1", &[]));
        let card = scorecard(&hooray, &xray);
        // Shared: pkg:npm/a@1 only → recall 1/2, precision 1/2.
        assert!((card.purl_recall - 0.5).abs() < 1e-9);
        assert!((card.purl_precision - 0.5).abs() < 1e-9);
        assert_eq!(card.missing_purls, vec!["pkg:npm/c@1"]);
        assert_eq!(card.extra_purls, vec!["pkg:npm/b@1"]);
    }

    #[test]
    fn cve_metrics_cover_jaccard_and_severity_pairs() {
        let mut hooray = CanonicalReport::new(
            "case",
            Generator {
                name: "h".into(),
                version: "1".into(),
            },
            "offline",
        );
        hooray.vulnerabilities.push(vuln(
            "GHSA-1",
            &["CVE-2026-0001", "CVE-2026-0002"],
            "high",
            &["pkg:npm/a@1"],
        ));
        hooray
            .vulnerabilities
            .push(vuln("GHSA-2", &["CVE-2026-0003"], "low", &["pkg:npm/b@1"]));
        let mut xray = hooray.clone();
        xray.vulnerabilities[0].severity_label = "medium".to_owned();
        let card = scorecard(&hooray, &xray);
        assert_eq!(card.cve_jaccard, 1.0);
        // The mutated vuln flips BOTH its CVEs (0001, 0002) to "medium";
        // only 0003 agrees -> 1/3 agreement over matched pairs.
        assert!((card.severity_agreement - 1.0 / 3.0).abs() < 1e-9);
        assert_eq!(
            card.severity_mismatches,
            vec![
                SeverityMismatch {
                    cve: "CVE-2026-0001".to_owned(),
                    hooray: "high".to_owned(),
                    xray: "medium".to_owned(),
                },
                SeverityMismatch {
                    cve: "CVE-2026-0002".to_owned(),
                    hooray: "high".to_owned(),
                    xray: "medium".to_owned(),
                },
            ]
        );
        xray.vulnerabilities
            .push(vuln("GHSA-3", &["CVE-2026-0009"], "low", &[]));
        hooray.vulnerabilities.remove(1);
        let card = scorecard(&hooray, &xray);
        // Removing GHSA-2 from hooray leaves its CVE-2026-0003 plus
        // xray's new CVE-2026-0009 on the missing side.
        assert_eq!(
            card.cves_missing_in_hooray,
            vec!["CVE-2026-0003", "CVE-2026-0009"]
        );
        assert_eq!(card.cves_extra_in_hooray, Vec::<String>::new());
        // Intersection {0001,0002}, union {0001,0002,0003,0009}.
        assert!((card.cve_jaccard - 0.5).abs() < 1e-9);
    }

    #[test]
    fn empty_vs_empty_jaccard_is_one() {
        assert_eq!(jaccard(&BTreeSet::new(), &BTreeSet::new()), 1.0);
    }

    #[test]
    fn license_agreement_restricts_to_shared_components() {
        let mut hooray = CanonicalReport::new(
            "case",
            Generator {
                name: "h".into(),
                version: "1".into(),
            },
            "offline",
        );
        hooray
            .components
            .push(component("pkg:npm/shared@1", &["MIT"]));
        hooray
            .components
            .push(component("pkg:npm/h-only@1", &["GPL-3.0-only"]));
        let mut xray = hooray.clone();
        xray.components
            .retain(|component| component.purl != "pkg:npm/h-only@1");
        xray.components[0].licenses = vec!["MIT".into(), "Apache-2.0".into()];
        let card = scorecard(&hooray, &xray);
        // Shared component pairs: {shared|MIT}; xray adds {shared|Apache-2.0}.
        assert!((card.license_agreement - 0.5).abs() < 1e-9);
    }

    #[test]
    fn violates_only_below_explicit_thresholds() {
        assert!(!violates(None, 0.0));
        assert!(!violates(Some(0.5), 0.5));
        assert!(violates(Some(0.5), 0.499));
    }

    #[test]
    fn scorecard_serializes_deterministically() {
        let mut hooray = CanonicalReport::new(
            "case",
            Generator {
                name: "h".into(),
                version: "1".into(),
            },
            "offline",
        );
        hooray.license_findings.push(CanonicalLicenseFinding {
            path: "LICENSE".into(),
            expression: "MIT".into(),
            detector: None,
        });
        hooray.parse_errors.push(ParseError {
            path: "audit.json".into(),
            reason: "skipped".into(),
        });
        let card = scorecard(&hooray, &hooray);
        let first = serde_json::to_string(&card).unwrap();
        let second = serde_json::to_string(&scorecard(&hooray, &hooray)).unwrap();
        assert_eq!(first, second);
    }

    fn empty_report(name: &str) -> CanonicalReport {
        CanonicalReport::new(
            "case",
            Generator {
                name: name.to_owned(),
                version: "1".to_owned(),
            },
            "offline",
        )
    }

    #[test]
    fn effective_threshold_takes_strictest_gate() {
        assert_eq!(effective_threshold(Some(0.8), Some(0.9)), Some(0.9));
        assert_eq!(effective_threshold(Some(0.9), Some(0.8)), Some(0.9));
        assert_eq!(effective_threshold(Some(0.8), None), Some(0.8));
        assert_eq!(effective_threshold(None, Some(0.8)), Some(0.8));
        assert_eq!(effective_threshold(None, None), None);
    }

    #[test]
    fn drift_guard_exempts_vulnerabilities_and_metadata() {
        let recorded = empty_report("hooray");
        let mut fresh = recorded.clone();
        // A live recording carries vulnerabilities an offline re-scan cannot
        // reproduce; generator identity and case id legitimately vary.
        fresh
            .vulnerabilities
            .push(vuln("GHSA-1", &["CVE-2026-0001"], "high", &["pkg:npm/a@1"]));
        fresh.generator.version = "9.9.9".to_owned();
        fresh.case_id = "renamed".to_owned();
        assert!(drift_violations(&fresh, &recorded).is_empty());
    }

    #[test]
    fn drift_guard_reports_each_behavioral_section() {
        let recorded = empty_report("hooray");
        let mut fresh = recorded.clone();
        fresh.components.push(component("pkg:npm/a@1", &["MIT"]));
        fresh.license_findings.push(CanonicalLicenseFinding {
            path: "LICENSE".to_owned(),
            expression: "MIT".to_owned(),
            detector: None,
        });
        fresh.parse_errors.push(ParseError {
            path: "x".to_owned(),
            reason: "r".to_owned(),
        });
        let violations = drift_violations(&fresh, &recorded);
        assert_eq!(
            violations,
            vec![
                "components differ from recording".to_owned(),
                "license findings differ from recording".to_owned(),
                "parse errors differ from recording".to_owned(),
            ]
        );
    }

    #[test]
    fn recording_merge_attaches_scorecard_to_existing_tier1_row() {
        let mut results = vec![CaseCheck {
            case_id: "case-a".to_owned(),
            status: "ok".to_owned(),
            notes: Vec::new(),
            scorecard: None,
        }];
        apply_recording_check(
            &mut results,
            "case-a",
            Vec::new(),
            Vec::new(),
            Scorecard::default(),
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, "ok");
        assert!(results[0].scorecard.is_some());
    }

    #[test]
    fn recording_merge_escalates_status_on_violations() {
        let mut results = vec![CaseCheck {
            case_id: "case-a".to_owned(),
            status: "ok".to_owned(),
            notes: Vec::new(),
            scorecard: None,
        }];
        apply_recording_check(
            &mut results,
            "case-a",
            vec!["components differ from recording".to_owned()],
            vec!["cve jaccard 0.000 below threshold 1.000".to_owned()],
            Scorecard::default(),
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, "violation");
        assert_eq!(results[0].notes.len(), 2);
        assert!(results[0].scorecard.is_some());
    }

    #[test]
    fn recording_merge_escalates_when_only_tier1_already_violated() {
        let mut results = vec![CaseCheck {
            case_id: "case-a".to_owned(),
            status: "violation".to_owned(),
            notes: vec!["expected ecosystem missing".to_owned()],
            scorecard: None,
        }];
        apply_recording_check(
            &mut results,
            "case-a",
            Vec::new(),
            Vec::new(),
            Scorecard::default(),
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, "violation");
        assert_eq!(results[0].notes.len(), 1);
    }

    #[test]
    fn unknown_case_recording_pushes_new_row() {
        let mut results: Vec<CaseCheck> = Vec::new();
        apply_recording_check(
            &mut results,
            "case-b",
            Vec::new(),
            vec!["purl recall 0.500 below threshold 1.000".to_owned()],
            Scorecard::default(),
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].case_id, "case-b");
        assert_eq!(results[0].status, "violation");
        assert!(results[0].scorecard.is_some());
    }

    #[test]
    fn duplicate_recording_pushes_second_row_instead_of_overwriting() {
        let first = Scorecard {
            purl_recall: 1.0,
            ..Scorecard::default()
        };
        let second = Scorecard {
            purl_recall: 0.5,
            ..Scorecard::default()
        };
        let mut results: Vec<CaseCheck> = Vec::new();
        apply_recording_check(&mut results, "case-a", Vec::new(), Vec::new(), first);
        apply_recording_check(&mut results, "case-a", Vec::new(), Vec::new(), second);
        assert_eq!(results.len(), 2);
        assert!((results[0].scorecard.as_ref().unwrap().purl_recall - 1.0).abs() < 1e-9);
        assert!((results[1].scorecard.as_ref().unwrap().purl_recall - 0.5).abs() < 1e-9);
    }
}
