//! The only writers of gate state are the native evaluation path. A submitted
//! scan report, monitor decision, or API policy document cannot create a receipt.
use super::{Store, StoreError};
use crate::gate::{ArtifactDecision, Outcome};
use crate::model::PolicySummary;
use rusqlite::{OptionalExtension, params};

impl Store {
    pub(crate) fn start_gate_attempt(
        &mut self,
        artifact: &str,
        policy: &str,
    ) -> Result<i64, StoreError> {
        let now = crate::timestamp::utc_millis(time::UtcDateTime::now());
        Ok(self.connection.query_row(
            "INSERT INTO artifact_gate_attempts(artifact_sha256,policy_sha256,started_at)
             VALUES (?1,?2,?3) RETURNING attempt_id",
            params![artifact, policy, now],
            |row| row.get(0),
        )?)
    }

    pub(crate) fn finish_gate_attempt(
        &mut self,
        attempt: i64,
        d: &ArtifactDecision,
    ) -> Result<(), StoreError> {
        let count = |n: u64| i64::try_from(n).map_err(|_| StoreError::FindingCountOverflow);
        self.connection.execute(
            "INSERT INTO artifact_gate_decisions(attempt_id,run_id,scope,scanner_version,publisher_source,
             publisher_revision,publisher_sha256,outcome,reason,component_purl,matched_advisories,
             policy_allowed,policy_warned,policy_denied,completed_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            params![attempt, d.run_id, d.scope, d.scanner_version, d.publisher_source, d.publisher_revision,
                d.publisher_sha256, d.outcome.as_str(), d.reason, d.component_purl, d.matched_advisories,
                count(d.policy_summary.allowed)?, count(d.policy_summary.warned)?, count(d.policy_summary.denied)?, d.completed_at],
        )?;
        Ok(())
    }

    pub(crate) fn latest_gate_decision(
        &self,
        artifact: &str,
        policy: &str,
    ) -> Result<Option<ArtifactDecision>, StoreError> {
        // Select the latest ATTEMPT first. Applying completion or freshness filters
        // inside this subquery could resurrect a superseded allow.
        Ok(self.connection.query_row(
            "SELECT run_id, scope, scanner_version, publisher_source, publisher_revision, publisher_sha256,
                    outcome, reason, component_purl, matched_advisories, policy_allowed, policy_warned,
                    policy_denied, completed_at
             FROM artifact_gate_decisions WHERE attempt_id = (
                 SELECT attempt_id FROM artifact_gate_attempts WHERE artifact_sha256=?1 AND policy_sha256=?2
                 ORDER BY attempt_id DESC LIMIT 1)",
            params![artifact, policy],
            |row| Ok(ArtifactDecision {
                artifact_sha256: artifact.to_owned(), policy_sha256: policy.to_owned(),
                run_id: row.get(0)?, scope: row.get(1)?, scanner_version: row.get(2)?,
                publisher_source: row.get(3)?, publisher_revision: row.get(4)?, publisher_sha256: row.get(5)?,
                outcome: match row.get_ref(6)?.as_str()? {
                    "allow" => Outcome::Allow, "deny" => Outcome::Deny, "unknown" => Outcome::Unknown,
                    _ => return Err(rusqlite::Error::InvalidQuery),
                },
                reason: row.get(7)?, component_purl: row.get(8)?, matched_advisories: row.get(9)?,
                policy_summary: PolicySummary { allowed: read_count(row,10)?, warned: read_count(row,11)?, denied: read_count(row,12)? },
                completed_at: row.get(13)?,
            }),
        ).optional()?)
    }
}

fn read_count(row: &rusqlite::Row<'_>, idx: usize) -> rusqlite::Result<u64> {
    let n: i64 = row.get(idx)?;
    n.try_into()
        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(idx, n))
}
