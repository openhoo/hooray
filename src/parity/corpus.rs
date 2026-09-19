//! Corpus manifest model and case-artifact resolution.
//!
//! The single home for the `manifest.json` schema ([`CorpusManifest`],
//! [`CorpusCase`]) and the kind-aware resolution of a corpus case into a
//! scannable [`ScanInput`]. Both the `hooray-parity` binary and its
//! integration tests consume these definitions so tier-1 checks, tier-2
//! drift re-scans, and recordings always agree on how a case is classified.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;

use crate::config::Config;
use crate::input::ScanInput;
use crate::parity::model::CanonicalReport;

/// Corpus manifest describing every parity case (`manifest.json`).
#[derive(Debug, Deserialize)]
pub struct CorpusManifest {
    /// Manifest schema version; only [`CORPUS_SCHEMA_VERSION`] is accepted.
    #[serde(default = "default_corpus_schema_version")]
    pub schema_version: u8,
    /// Declared cases; may be empty while the corpus is being authored.
    #[serde(default)]
    pub cases: Vec<CorpusCase>,
}

/// The only corpus manifest schema version this harness understands.
pub const CORPUS_SCHEMA_VERSION: u8 = 1;

fn default_corpus_schema_version() -> u8 {
    CORPUS_SCHEMA_VERSION
}

/// Returns `true` when `case_id` is a plain directory name: non-empty and
/// free of path separators, `..` segments, and drive/absolute prefixes.
/// Case ids join onto the corpus root, so anything else could escape the
/// corpus or collide with another case's key.
pub fn is_valid_case_id(case_id: &str) -> bool {
    !case_id.is_empty()
        && case_id != "."
        && case_id != ".."
        && !case_id.contains('/')
        && !case_id.contains('\\')
        && !case_id.contains(':')
}

impl CorpusManifest {
    /// Parses and validates a manifest: the schema version must be
    /// supported and every case id must be a plain directory name.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let manifest: CorpusManifest =
            serde_json::from_str(text).context("invalid corpus manifest JSON")?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validates the manifest header and case ids.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.schema_version != CORPUS_SCHEMA_VERSION {
            bail!(
                "unsupported corpus manifest schema_version {}; expected {}",
                self.schema_version,
                CORPUS_SCHEMA_VERSION
            );
        }
        for case in &self.cases {
            if !is_valid_case_id(&case.case_id) {
                bail!(
                    "invalid corpus case_id {:?}: expected a plain directory name",
                    case.case_id
                );
            }
        }
        Ok(())
    }
}

/// One corpus case row in [`CorpusManifest`].
#[derive(Debug, Deserialize)]
pub struct CorpusCase {
    /// Directory (or artifact file) name below the corpus root.
    pub case_id: String,
    /// Case class: `project-directory`, `cyclonedx-sbom`, `spdx-sbom`, or
    /// `archive-zip`.
    pub kind: String,
    /// Ecosystems that must appear in the normalized component list.
    #[serde(default)]
    pub expected_ecosystems: Vec<String>,
    /// Minimum number of normalized components.
    #[serde(default)]
    pub min_components: usize,
    /// Whether at least one connected component is required.
    #[serde(default)]
    pub directness_comparable: bool,
}

/// Suffixes accepted when the case kind is unknown (ad-hoc CLI paths).
const ANY_ARTIFACT_SUFFIXES: [&str; 4] = [".cdx.json", ".cyclonedx.json", ".spdx.json", ".zip"];

/// Artifact suffixes accepted for one corpus case kind.
///
/// SBOM kinds additionally accept a bare `.json` because Xray exports
/// sometimes drop the format infix; ad-hoc scans without a known kind stay
/// strict so arbitrary JSON files are never misclassified as SBOMs.
fn artifact_suffixes(kind: Option<&str>) -> &'static [&'static str] {
    match kind {
        Some("cyclonedx-sbom") => &[".cdx.json", ".cyclonedx.json", ".json"],
        Some("spdx-sbom") => &[".spdx.json", ".json"],
        Some("archive-zip") => &[".zip"],
        _ => &ANY_ARTIFACT_SUFFIXES,
    }
}

/// Finds the wrapped artifact file inside a case directory, if any.
///
/// Wrapped SBOM/archive cases are directories containing the actual
/// artifact file. `kind` narrows the accepted suffixes when the caller
/// knows the corpus case class (`Some`) and must be `None` for ad-hoc
/// paths with no manifest-derived class. Suffixes are tried in declared
/// order — exact-format suffixes (`.cdx.json`, `.spdx.json`) always win
/// over the bare `.json` catch-all, so an unrelated JSON file can never
/// be substituted for the expected artifact. Within one suffix tier the
/// candidates sort deterministically so wrapped cases resolve identically
/// across machines.
pub fn find_artifact(kind: Option<&str>, dir: impl AsRef<Path>) -> Option<PathBuf> {
    let suffixes = artifact_suffixes(kind);
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir.as_ref())
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();
    files.sort();
    for suffix in suffixes {
        if let Some(candidate) = files
            .iter()
            .find(|path| path.to_string_lossy().ends_with(suffix))
        {
            return Some(candidate.clone());
        }
    }
    None
}

/// Resolves the scannable [`ScanInput`] for one corpus case.
pub fn scan_input_for_kind(
    kind: &str,
    path: impl AsRef<Path>,
    config: &Config,
) -> anyhow::Result<ScanInput> {
    // Hooray's fail-closed symlink checks require canonical absolute paths.
    let path = path.as_ref();
    let resolved = std::fs::canonicalize(path)
        .with_context(|| format!("failed to canonicalize case path {}", path.display()))?;
    match kind {
        "project-directory" => {
            if !resolved.is_dir() {
                bail!(
                    "corpus case kind 'project-directory' requires a directory, got file {}",
                    resolved.display()
                );
            }
            Ok(ScanInput::ProjectDirectory(resolved))
        }
        "cyclonedx-sbom" | "spdx-sbom" | "archive-zip" => {
            let artifact = if path.is_dir() {
                find_artifact(Some(kind), &resolved)
                    .with_context(|| format!("no {kind} artifact inside {}", path.display()))?
            } else {
                resolved
            };
            ScanInput::detect(&artifact, config)
                .with_context(|| format!("failed to classify {artifact:?} ({kind})"))
        }
        other => bail!("unknown corpus case kind '{other}'"),
    }
}

/// Pure tier-1 expectation check: compares one case's manifest expectations
/// against its freshly normalized canonical report and returns violation
/// notes (empty when every expectation holds).
pub fn corpus_case_notes(case: &CorpusCase, canonical: &CanonicalReport) -> Vec<String> {
    let mut notes = Vec::new();
    let mut observed: BTreeMap<&str, usize> = BTreeMap::new();
    for component in &canonical.components {
        *observed.entry(component.ecosystem.as_str()).or_insert(0) += 1;
    }
    for expected in &case.expected_ecosystems {
        if !observed.contains_key(expected.as_str()) {
            notes.push(format!("expected ecosystem '{expected}' was not observed"));
        }
    }
    if canonical.components.len() < case.min_components {
        notes.push(format!(
            "component count {} below required minimum {}",
            canonical.components.len(),
            case.min_components
        ));
    }
    if case.directness_comparable
        && !canonical
            .components
            .iter()
            .any(|component| component.directness != "disconnected")
    {
        notes.push("directness comparable case had no connected component".to_owned());
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_parse_rejects_unsupported_schema_version() {
        let text = r#"{"schema_version": 2, "cases": []}"#;
        let error = CorpusManifest::parse(text).unwrap_err();
        assert!(error.to_string().contains("schema_version 2"));
    }

    #[test]
    fn manifest_parse_rejects_path_like_case_ids() {
        for bad in ["../escape", "a/b", ".", "..", "c:abs"] {
            let text = format!(
                r#"{{"schema_version": 1, "cases": [{{"case_id": "{bad}", "kind": "project-directory"}}]}}"#
            );
            assert!(
                CorpusManifest::parse(&text).is_err(),
                "case_id {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn is_valid_case_id_rejects_separators() {
        for bad in ["a\\b", "a/b", "..", ".", "", "c:x"] {
            assert!(!is_valid_case_id(bad), "{bad:?} must be invalid");
        }
        assert!(is_valid_case_id("npm-basic"));
    }

    #[test]
    fn manifest_parse_defaults_schema_version_and_accepts_plain_ids() {
        let text = r#"{"cases": [{"case_id": "npm-basic", "kind": "project-directory"}]}"#;
        let manifest = CorpusManifest::parse(text).unwrap();
        assert_eq!(manifest.schema_version, CORPUS_SCHEMA_VERSION);
        assert_eq!(manifest.cases.len(), 1);
    }

    #[test]
    fn find_artifact_prefers_exact_suffix_over_json_catchall() {
        let dir = tempfile::tempdir().unwrap();
        // An alphabetically-earlier bare .json must not win over the
        // exact-format artifact.
        std::fs::write(dir.path().join("a.json"), "{}").unwrap();
        std::fs::write(dir.path().join("bom.cdx.json"), "{}").unwrap();
        let found = find_artifact(Some("cyclonedx-sbom"), dir.path()).unwrap();
        assert!(found.ends_with("bom.cdx.json"));
    }

    #[test]
    fn scan_input_for_kind_rejects_file_for_project_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("package-lock.json");
        std::fs::write(&file, "{}").unwrap();
        let error =
            scan_input_for_kind("project-directory", &file, &Config::default()).unwrap_err();
        assert!(error.to_string().contains("requires a directory"));
    }
}
