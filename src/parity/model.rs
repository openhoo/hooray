//! Canonical comparison model shared by both scanner sides.
//!
//! Everything in this module serializes deterministically: collections are
//! `BTree*`-backed or pre-sorted vectors, no clocks or random identifiers
//! appear, and the schema version is pinned to [`CANONICAL_SCHEMA_VERSION`].

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use thiserror::Error;

/// Schema version of the canonical report and recording formats.
pub const CANONICAL_SCHEMA_VERSION: u8 = 1;

/// Generator identity of one side of a comparison.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Generator {
    /// `"hooray"` or `"xray"`.
    pub name: String,
    /// Version string; `"unknown"` when the Xray CLI did not report one.
    pub version: String,
}

/// Canonical, tool-independent view of one scan result.
///
/// Components are sorted by purl, vulnerabilities by primary id then affected
/// purls, license findings by `(path, expression)`, and parse errors by path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalReport {
    /// Always [`CANONICAL_SCHEMA_VERSION`].
    pub schema_version: u8,
    /// Corpus case identifier this report belongs to.
    pub case_id: String,
    /// Tool that produced the underlying data.
    pub generator: Generator,
    /// `"offline"`, `"osv-live"`, or `"provider-replay"`.
    pub scan_mode: String,
    /// Dependency inventory sorted by purl.
    #[serde(default)]
    pub components: Vec<CanonicalComponent>,
    /// Vulnerability findings sorted deterministically.
    #[serde(default)]
    pub vulnerabilities: Vec<CanonicalVuln>,
    /// License findings sorted by `(path, expression)` and deduplicated.
    #[serde(default)]
    pub license_findings: Vec<CanonicalLicenseFinding>,
    /// Non-fatal parse errors. Hooray input failures abort a scan entirely
    /// (fail-closed), so hooray-side reports always carry an empty list; the
    /// CLI surfaces such failures as operational errors instead.
    #[serde(default)]
    pub parse_errors: Vec<ParseError>,
}

impl CanonicalReport {
    /// Creates an empty canonical report for `case_id` at the current schema
    /// version.
    pub fn new(
        case_id: impl Into<String>,
        generator: Generator,
        scan_mode: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: CANONICAL_SCHEMA_VERSION,
            case_id: case_id.into(),
            generator,
            scan_mode: scan_mode.into(),
            components: Vec::new(),
            vulnerabilities: Vec::new(),
            license_findings: Vec::new(),
            parse_errors: Vec::new(),
        }
    }
}

/// One inventory component in canonical form.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CanonicalComponent {
    /// Package URL verbatim from the source side.
    pub purl: String,
    /// Package name.
    pub name: String,
    /// Package version.
    pub version: String,
    /// Ecosystem parsed from the purl type, lowercased (e.g. `npm`).
    pub ecosystem: String,
    /// License identifiers/expressions, sorted and deduplicated.
    pub licenses: Vec<String>,
    /// `runtime` | `build` | `development` | `test` | `optional` | `unknown`.
    pub scope: String,
    /// `direct` | `transitive` | `disconnected`.
    pub directness: String,
}

/// One vulnerability advisory in canonical form.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CanonicalVuln {
    /// Primary advisory identifier (`GHSA-…`, `CVE-…`, `XRAY-…`).
    pub primary_id: String,
    /// Alias identifiers excluding [`Self::primary_id`], sorted.
    pub aliases: Vec<String>,
    /// CVE identifiers associated with the advisory, sorted.
    pub cves: Vec<String>,
    /// Affected package URLs, sorted.
    pub affected_purls: Vec<String>,
    /// Versions that fix the vulnerability, sorted and deduplicated.
    pub fixed_versions: Vec<String>,
    /// `unknown` | `low` | `medium` | `high` | `critical`.
    pub severity_label: String,
}

/// One license finding in canonical form.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CanonicalLicenseFinding {
    /// File path the license was attributed to (may be empty when the source
    /// carries no resolvable location).
    pub path: String,
    /// SPDX expression, license id/name, or `unknown`.
    pub expression: String,
    /// Verbatim detector signature description. Hooray fuses multiple
    /// detected license files on one component into a single finding, which
    /// makes per-file expressions unrecoverable; the detector string keeps
    /// each file's evidence visible without fabricating expressions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detector: Option<String>,
}

/// A tolerated, non-fatal parsing problem on the Xray side.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ParseError {
    /// Artifact path or synthetic label identifying the origin.
    pub path: String,
    /// Human-readable reason the entry was skipped.
    pub reason: String,
}

/// Errors raised by the parity harness modules.
#[derive(Debug, Error)]
pub enum ParityError {
    /// A recording or canonical document used an unsupported schema version.
    #[error("unsupported {context} schema_version {found}; expected {expected}")]
    UnsupportedSchemaVersion {
        /// Which document kind was rejected (`recording` or `canonical`).
        context: &'static str,
        /// Schema version found in the document.
        found: u8,
        /// The only supported schema version.
        expected: u8,
    },
    /// Recording/canonical case identifiers disagree across sections.
    #[error("case mismatch: expected '{expected}' but found '{found}'")]
    CaseMismatch {
        /// Case id the caller expected.
        expected: String,
        /// Case id found in the document.
        found: String,
    },
    /// JSON serialization/deserialization failure.
    #[error("json failed: {0}")]
    Json(#[from] serde_json::Error),
    /// Filesystem failure.
    #[error("io failed: {0}")]
    Io(#[from] std::io::Error),
    /// Dependency graph construction or classification failure.
    #[error("dependency analysis failed: {0}")]
    Graph(#[from] crate::graph::GraphError),
    /// Structurally invalid input that cannot be tolerated.
    #[error("invalid parity input: {0}")]
    InvalidInput(String),
}

impl fmt::Display for Generator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.name, self.version)
    }
}

/// Collects strings into a sorted, deduplicated vector.
pub(crate) fn sorted_unique(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let set: BTreeSet<String> = values.into_iter().collect();
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_report() -> CanonicalReport {
        let mut report = CanonicalReport::new(
            "npm-package-lock-basic",
            Generator {
                name: "hooray".into(),
                version: "0.5.1".into(),
            },
            "offline",
        );
        report.components.push(CanonicalComponent {
            purl: "pkg:npm/react@18.2.0".into(),
            name: "react".into(),
            version: "18.2.0".into(),
            ecosystem: "npm".into(),
            licenses: vec!["MIT".into()],
            scope: "runtime".into(),
            directness: "direct".into(),
        });
        report.vulnerabilities.push(CanonicalVuln {
            primary_id: "GHSA-test-0001".into(),
            aliases: vec!["CVE-2026-0001".into()],
            cves: vec!["CVE-2026-0001".into()],
            affected_purls: vec!["pkg:npm/react@18.2.0".into()],
            fixed_versions: vec!["18.2.1".into()],
            severity_label: "high".into(),
        });
        report.license_findings.push(CanonicalLicenseFinding {
            path: "LICENSE".into(),
            expression: "MIT".into(),
            detector: None,
        });
        report.parse_errors.push(ParseError {
            path: "audit.json".into(),
            reason: "entry was not an object".into(),
        });
        report
    }

    #[test]
    fn roundtrips_through_json() {
        let report = fixture_report();
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"schema_version\":1"));
        let back: CanonicalReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, report);
        assert_eq!(back.schema_version, CANONICAL_SCHEMA_VERSION);
    }

    #[test]
    fn pretty_output_is_deterministic() {
        let first = serde_json::to_string_pretty(&fixture_report()).unwrap();
        let second = serde_json::to_string_pretty(&fixture_report()).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn new_sets_schema_version_and_defaults() {
        let report = CanonicalReport::new(
            "case",
            Generator {
                name: "xray".into(),
                version: "unknown".into(),
            },
            "provider-replay",
        );
        assert_eq!(report.schema_version, 1);
        assert!(report.components.is_empty());
        assert!(report.parse_errors.is_empty());
    }

    #[test]
    fn generator_display_uses_slash() {
        let generator = Generator {
            name: "hooray".into(),
            version: "1.2.3".into(),
        };
        assert_eq!(generator.to_string(), "hooray/1.2.3");
    }

    #[test]
    fn sorted_unique_dedupes_and_sorts() {
        assert_eq!(
            sorted_unique(["b".to_owned(), "a".to_owned(), "b".to_owned()]),
            vec!["a".to_owned(), "b".to_owned()]
        );
    }
}
