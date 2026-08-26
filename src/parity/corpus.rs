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
    /// Declared cases; may be empty while the corpus is being authored.
    #[serde(default)]
    pub cases: Vec<CorpusCase>,
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
/// paths with no manifest-derived class. Candidates sort deterministically
/// so wrapped cases resolve identically across machines.
pub fn find_artifact(kind: Option<&str>, dir: impl AsRef<Path>) -> Option<PathBuf> {
    let suffixes = artifact_suffixes(kind);
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(dir.as_ref())
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && suffixes
                    .iter()
                    .any(|suffix| path.to_string_lossy().ends_with(suffix))
        })
        .collect();
    candidates.sort();
    candidates.into_iter().next()
}

/// Resolves the scannable [`ScanInput`] for one corpus case.
///
/// `path` may be the case directory or a direct artifact file path;
/// resolution canonicalizes because hooray's fail-closed symlink checks
/// require canonical absolute inputs. Wrapped directories resolve their
/// artifact through the kind-aware [`find_artifact`].
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
        "project-directory" => Ok(ScanInput::ProjectDirectory(resolved)),
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
