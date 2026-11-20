//! Local repository admission for one explicit coverage profile: a lockfile ZIP
//! containing a crates.io `zip` coordinate reviewed against the pinned publisher
//! snapshot. An allow does not establish that other packages or binaries are safe.
mod scope;
mod snapshot;

use crate::{
    config::Config,
    engine::{Engine, ScanRequest},
    input::{ArchiveFormat, ScanInput},
    model::PolicySummary,
    publisher,
    store::Store,
};
use anyhow::{Context, Result, ensure};
use scope::Coverage;
use serde::Serialize;
use std::path::Path;

const SCOPE: &str = "cargo-lock-zip/crates-io/zip/publisher-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Allow,
    Deny,
    Unknown,
}

impl Outcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Unknown => "unknown",
        }
    }
}

/// Immutable evidence for the exact artifact and policy supplied to the native scanner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactDecision {
    pub artifact_sha256: String,
    pub policy_sha256: String,
    pub run_id: String,
    pub scope: String,
    pub scanner_version: String,
    pub publisher_source: String,
    pub publisher_revision: String,
    pub publisher_sha256: String,
    pub outcome: Outcome,
    pub reason: String,
    pub component_purl: Option<String>,
    pub matched_advisories: Option<u32>,
    pub policy_summary: PolicySummary,
    pub completed_at: String,
}

impl ArtifactDecision {
    pub fn allowed(&self) -> bool {
        self.outcome == Outcome::Allow
    }
}

fn digest(value: &str) -> Result<&str> {
    let raw = value.strip_prefix("sha256:").unwrap_or(value);
    ensure!(
        raw.len() == 64
            && raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "expected exactly 64 lowercase hexadecimal SHA-256 digits"
    );
    Ok(raw)
}

/// Hash local regular files with the same bounds and bytes used by an evaluation.
pub fn input_digests(artifact: &Path, policy: &Path) -> Result<(String, String)> {
    snapshot::digests(artifact, policy)
}

/// Returns the last native decision only if it still uses this scanner, scope and
/// publisher revision. Missing, stale or unfinished evaluations cannot release bytes.
pub fn lookup(
    store: &Store,
    artifact_sha256: &str,
    policy_sha256: &str,
) -> Result<Option<ArtifactDecision>> {
    let latest = store.latest_gate_decision(digest(artifact_sha256)?, digest(policy_sha256)?)?;
    let current = publisher::metadata();
    Ok(latest.filter(|d| {
        d.scope == SCOPE
            && d.scanner_version == env!("CARGO_PKG_VERSION")
            && d.publisher_source == current.source
            && d.publisher_revision == current.revision
            && d.publisher_sha256 == current.sha256
    }))
}

pub fn require_current_allow(
    store: &Store,
    artifact_sha256: &str,
    policy_sha256: &str,
) -> Result<ArtifactDecision> {
    let decision = lookup(store, artifact_sha256, policy_sha256)?
        .context("no current completed gate decision")?;
    ensure!(
        decision.allowed(),
        "artifact gate {}: {}",
        decision.outcome.as_str(),
        decision.reason
    );
    Ok(decision)
}

pub async fn evaluate(
    config: &Config,
    store: &mut Store,
    artifact: &Path,
    policy: &Path,
) -> Result<ArtifactDecision> {
    let defaults = Config::default();
    let profile = Config {
        offline: true,
        max_input_bytes: defaults.max_input_bytes.min(config.max_input_bytes),
        max_archive_bytes: defaults.max_archive_bytes.min(config.max_archive_bytes),
        max_archive_entries: defaults.max_archive_entries.min(config.max_archive_entries),
        ..defaults
    };
    // Hash with the invariant profile maximum so a tighter local scan budget can
    // leave a blocking attempt even when it prevents the actual scan.
    let input = snapshot::Snapshots::new(artifact, policy, Config::default().max_input_bytes)?;
    let attempt = store.start_gate_attempt(&input.artifact_sha256, &input.policy_sha256)?;
    ensure!(
        input.artifact.metadata()?.len() <= profile.max_input_bytes,
        "artifact exceeds configured gate input limit"
    );
    let policy = crate::engine::load_policy(&input.policy)?;
    let scan = ScanInput::Archive {
        path: input.artifact.clone(),
        format: ArchiveFormat::Zip,
    };
    let report = Engine::new(&profile, store, None)
        .scan(ScanRequest::new(scan, input.policy.clone()))
        .await?;
    let meta = publisher::metadata();
    ensure!(
        report.run.metadata.get("publisher_snapshot") == Some(&serde_json::to_value(meta)?),
        "scan has unexpected publisher identity"
    );
    let coverage = scope::inspect(&input.artifact, profile.max_input_bytes, &report)?;
    let (purl, matched, unknown) = match coverage {
        Coverage::Reviewed { purl, matched } => (Some(purl), Some(u32::try_from(matched)?), None),
        Coverage::Unknown(reason) => (None, None, Some(reason)),
    };
    let (outcome, reason) = if let Some(reason) = unknown {
        (Outcome::Unknown, reason)
    } else if matched.is_some_and(|m| m > 0) {
        (
            Outcome::Deny,
            "locked zip version matches the pinned publisher advisories",
        )
    } else if report.policy_summary.denied > 0 {
        (Outcome::Deny, "native policy denied one or more findings")
    } else if report
        .policy_decisions
        .iter()
        .any(|d| d.exception_id.is_some())
    {
        (
            Outcome::Unknown,
            "persistent admission cannot rely on expiring policy exceptions",
        )
    } else if policy.rules.iter().any(|r| r.selectors.risk.is_some()) {
        (
            Outcome::Unknown,
            "persistent admission does not support time-dependent risk rules",
        )
    } else {
        (
            Outcome::Allow,
            "no matching zip publisher advisories and no native policy denials",
        )
    };
    let decision = ArtifactDecision {
        run_id: report.run.id.to_string(),
        artifact_sha256: input.artifact_sha256,
        policy_sha256: input.policy_sha256,
        scope: SCOPE.into(),
        scanner_version: report
            .run
            .scanner_version
            .context("native scan has no version")?,
        publisher_source: meta.source.into(),
        publisher_revision: meta.revision.into(),
        publisher_sha256: meta.sha256.into(),
        outcome,
        reason: reason.into(),
        component_purl: purl,
        matched_advisories: matched,
        policy_summary: report.policy_summary,
        completed_at: report
            .run
            .completed_at
            .context("native scan is incomplete")?,
    };
    store.finish_gate_attempt(attempt, &decision)?;
    ensure!(
        lookup(store, &decision.artifact_sha256, &decision.policy_sha256)?.as_ref()
            == Some(&decision),
        "gate attempt superseded during evaluation"
    );
    Ok(decision)
}

#[cfg(test)]
mod tests;
