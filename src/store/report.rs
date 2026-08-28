use std::collections::{BTreeMap, BTreeSet};

use crate::engine::REPORT_SCHEMA_VERSION;
use crate::model::{AssetId, Finding, FindingId, FindingKind, RunId, ScanReport};
use crate::monitor::FindingDiff;
use rusqlite::{
    Connection, OptionalExtension, Transaction, TransactionBehavior, params, params_from_iter,
    types::Value,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::{
    FindingFilter, FindingRecord, HistoryFilter, InventoryFilter, InventoryRecord, Store,
    StoreError, pagination, push_filter, push_filter_op,
};

impl Store {
    pub fn save_report(&mut self, report: &ScanReport) -> Result<(), StoreError> {
        reject_unredacted_secrets(&report.findings)?;
        report.validate()?;
        let sanitized = crate::report::sanitize_report(report)
            .map_err(|error| StoreError::Sanitization(error.to_string()))?;
        let report = &*sanitized;
        let report_json = serde_json::to_string(report)?;
        let finding_count =
            i64::try_from(report.findings.len()).map_err(|_| StoreError::FindingCountOverflow)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_report(&transaction, report, &report_json, finding_count)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn get_run(&self, run_id: &RunId) -> Result<Option<ScanReport>, StoreError> {
        report_query_one(
            &self.connection,
            "SELECT report_json FROM scan_runs WHERE run_id = ?1",
            [run_id.as_str()],
        )
    }

    pub fn latest_run(&self) -> Result<Option<ScanReport>, StoreError> {
        report_query_one(
            &self.connection,
            "SELECT report_json FROM scan_runs ORDER BY started_at DESC, run_id DESC LIMIT 1",
            [],
        )
    }

    pub fn latest_run_for_asset(
        &self,
        asset_id: &AssetId,
    ) -> Result<Option<ScanReport>, StoreError> {
        report_query_one(
            &self.connection,
            "SELECT report_json FROM scan_runs WHERE asset_id = ?1 ORDER BY started_at DESC, run_id DESC LIMIT 1",
            [asset_id.as_str()],
        )
    }

    pub fn list_runs(&self, limit: u32, offset: u64) -> Result<Vec<ScanReport>, StoreError> {
        self.query_history(&HistoryFilter::default(), limit, offset)
    }

    pub fn query_history(
        &self,
        filter: &HistoryFilter,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<ScanReport>, StoreError> {
        let (limit, offset) = pagination(limit, offset)?;
        let mut sql = String::from("SELECT report_json FROM scan_runs WHERE 1=1");
        let mut values = Vec::new();
        push_filter(
            &mut sql,
            &mut values,
            "asset_id",
            filter.asset_id.as_deref(),
        );
        push_filter_op(
            &mut sql,
            &mut values,
            "started_at",
            ">=",
            filter.started_from.as_deref(),
        );
        push_filter_op(
            &mut sql,
            &mut values,
            "started_at",
            "<=",
            filter.started_through.as_deref(),
        );
        sql.push_str(" ORDER BY started_at DESC, run_id DESC LIMIT ? OFFSET ?");
        values.push(Value::Integer(limit));
        values.push(Value::Integer(offset));
        let mut statement = self.connection.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(values), |row| row.get::<_, String>(0))?;
        let runs = deserialize_rows(rows)?;
        runs.iter().try_for_each(ensure_supported_report_schema)?;
        Ok(runs)
    }

    pub fn query_findings(
        &self,
        filter: &FindingFilter,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<FindingRecord>, StoreError> {
        let (limit, offset) = pagination(limit, offset)?;
        let mut sql = String::from(
            "SELECT f.run_id, r.started_at, f.finding_json FROM scan_findings f JOIN scan_runs r ON r.run_id=f.run_id WHERE 1=1",
        );
        let mut values = Vec::new();
        push_filter(
            &mut sql,
            &mut values,
            "f.run_id",
            filter.run_id.as_ref().map(RunId::as_str),
        );
        push_filter(
            &mut sql,
            &mut values,
            "f.finding_id",
            filter.finding_id.as_ref().map(FindingId::as_str),
        );
        push_filter(&mut sql, &mut values, "f.kind", filter.kind.as_deref());
        push_filter(
            &mut sql,
            &mut values,
            "f.severity",
            filter.severity.as_deref(),
        );
        push_filter(&mut sql, &mut values, "f.status", filter.status.as_deref());
        push_filter(
            &mut sql,
            &mut values,
            "f.rule_id",
            filter.rule_id.as_deref(),
        );
        push_filter(
            &mut sql,
            &mut values,
            "f.advisory_id",
            filter.advisory_id.as_deref(),
        );
        push_filter(
            &mut sql,
            &mut values,
            "f.component_id",
            filter.component_id.as_deref(),
        );
        sql.push_str(" ORDER BY r.started_at DESC, f.run_id DESC, f.finding_id LIMIT ? OFFSET ?");
        values.push(Value::Integer(limit));
        values.push(Value::Integer(offset));
        let mut statement = self.connection.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(values), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut records = Vec::new();
        for row in rows {
            let (run_id, started_at, json) = row?;
            records.push(FindingRecord {
                run_id,
                started_at,
                finding: serde_json::from_str(&json)?,
            });
        }
        Ok(records)
    }

    pub fn query_inventory(
        &self,
        filter: &InventoryFilter,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<InventoryRecord>, StoreError> {
        let (limit, offset) = pagination(limit, offset)?;
        let mut sql = String::from(
            "SELECT c.run_id,r.started_at,r.asset_id,c.component_json FROM scan_components c JOIN scan_runs r ON r.run_id=c.run_id WHERE 1=1",
        );
        let mut values = Vec::new();
        push_filter(
            &mut sql,
            &mut values,
            "c.run_id",
            filter.run_id.as_ref().map(RunId::as_str),
        );
        push_filter(
            &mut sql,
            &mut values,
            "r.asset_id",
            filter.asset_id.as_deref(),
        );
        push_filter(
            &mut sql,
            &mut values,
            "c.component_id",
            filter.component_id.as_deref(),
        );
        push_filter(&mut sql, &mut values, "c.name", filter.name.as_deref());
        push_filter(&mut sql, &mut values, "c.purl", filter.purl.as_deref());
        push_filter(&mut sql, &mut values, "c.scope", filter.scope.as_deref());
        sql.push_str(" ORDER BY r.started_at DESC,c.run_id DESC,c.component_id LIMIT ? OFFSET ?");
        values.push(Value::Integer(limit));
        values.push(Value::Integer(offset));
        let mut statement = self.connection.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(values), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        let mut records = Vec::new();
        for row in rows {
            let (run_id, started_at, asset_id, json) = row?;
            records.push(InventoryRecord {
                run_id,
                started_at,
                asset_id,
                component: serde_json::from_str(&json)?,
            });
        }
        Ok(records)
    }

    /// Partitions stable finding IDs between two stored runs with exactly the
    /// semantics advertised by `hooray history diff`: `introduced` holds IDs
    /// found only in `current_run_id`, `resolved` holds IDs found only in
    /// `previous_run_id`, and `unchanged` holds IDs present in both runs. A run
    /// missing from the store yields [`StoreError::RunNotFound`].
    pub fn diff_runs(
        &self,
        previous_run_id: &RunId,
        current_run_id: &RunId,
    ) -> Result<FindingDiff, StoreError> {
        let previous = self.finding_ids(previous_run_id)?;
        let current = self.finding_ids(current_run_id)?;
        Ok(FindingDiff {
            introduced: current.difference(&previous).cloned().collect(),
            resolved: previous.difference(&current).cloned().collect(),
            unchanged: previous.intersection(&current).cloned().collect(),
        })
    }

    pub fn delete_before(&mut self, timestamp: &str) -> Result<usize, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let deleted =
            transaction.execute("DELETE FROM scan_runs WHERE started_at < ?1", [timestamp])?;
        transaction.execute("INSERT INTO retention_events(occurred_at,cutoff_at,deleted_runs,details_json) VALUES (?1,?1,?2,'{}')", params![timestamp, i64::try_from(deleted).unwrap_or(i64::MAX)])?;
        transaction.execute("INSERT OR IGNORE INTO audit_events(event_id,occurred_at,actor,action,resource_type,resource_id,details_json) VALUES (?1,?2,'system','retention.delete','scan_run',?2,json_object('deleted_runs',?3))", params![format!("retention:{timestamp}:{deleted}"), timestamp, i64::try_from(deleted).unwrap_or(i64::MAX)])?;
        transaction.commit()?;
        Ok(deleted)
    }

    fn finding_ids(&self, run_id: &RunId) -> Result<BTreeSet<FindingId>, StoreError> {
        let exists = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM scan_runs WHERE run_id=?1)",
            [run_id.as_str()],
            |r| r.get::<_, bool>(0),
        )?;
        if !exists {
            return Err(StoreError::RunNotFound(run_id.to_string()));
        }
        let mut s = self
            .connection
            .prepare("SELECT finding_id FROM scan_findings WHERE run_id=?1 ORDER BY finding_id")?;
        let rows = s.query_map([run_id.as_str()], |r| r.get::<_, String>(0))?;
        let mut ids = BTreeSet::new();
        for row in rows {
            let value = row?;
            ids.insert(
                FindingId::new(value.clone()).map_err(|_| StoreError::InvalidFindingId(value))?,
            );
        }
        Ok(ids)
    }
}

pub(super) fn insert_report(
    t: &Transaction<'_>,
    r: &ScanReport,
    json: &str,
    count: i64,
) -> Result<(), StoreError> {
    insert_run(t, r, json, count)?;
    insert_assets(t, r)?;
    insert_components(t, r)?;
    insert_edges(t, r)?;
    insert_findings(t, r)?;
    insert_policy_decisions(t, r)?;
    Ok(())
}
fn insert_run(
    t: &Transaction<'_>,
    r: &ScanReport,
    json: &str,
    count: i64,
) -> Result<(), StoreError> {
    t.execute("INSERT INTO scan_runs(run_id,schema_version,started_at,completed_at,scanner_version,asset_id,finding_count,report_json) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",params![r.run.id.as_str(),r.schema_version,r.run.started_at,r.run.completed_at,r.run.scanner_version,r.inventory.asset.id.as_str(),count,json])?;
    Ok(())
}
fn insert_assets(t: &Transaction<'_>, r: &ScanReport) -> Result<(), StoreError> {
    t.execute("INSERT INTO scan_assets(run_id,asset_id,name,kind,version,metadata_json,asset_json) VALUES (?1,?2,?3,?4,?5,?6,?7)",params![r.run.id.as_str(),r.inventory.asset.id.as_str(),r.inventory.asset.name,json_scalar(&r.inventory.asset.kind)?,r.inventory.asset.version,serde_json::to_string(&r.inventory.asset.metadata)?,serde_json::to_string(&r.inventory.asset)?])?;
    Ok(())
}
fn insert_components(t: &Transaction<'_>, r: &ScanReport) -> Result<(), StoreError> {
    let mut statement = t.prepare_cached("INSERT INTO scan_components(run_id,component_id,name,version,purl,scope,component_json) VALUES (?1,?2,?3,?4,?5,?6,?7)")?;
    for c in r.inventory.components.values() {
        statement.execute(params![
            r.run.id.as_str(),
            c.identity.as_str(),
            c.name,
            c.version,
            c.purl,
            json_scalar(&c.scope)?,
            serde_json::to_string(c)?
        ])?;
    }
    Ok(())
}
fn insert_edges(t: &Transaction<'_>, r: &ScanReport) -> Result<(), StoreError> {
    let mut statement = t.prepare_cached("INSERT INTO scan_dependency_edges(run_id,from_component_id,to_component_id,scope,optional,edge_json) VALUES (?1,?2,?3,?4,?5,?6)")?;
    for e in &r.inventory.dependencies {
        statement.execute(params![
            r.run.id.as_str(),
            e.from.as_str(),
            e.to.as_str(),
            json_scalar(&e.scope)?,
            e.optional,
            serde_json::to_string(e)?
        ])?;
    }
    Ok(())
}
fn insert_findings(t: &Transaction<'_>, r: &ScanReport) -> Result<(), StoreError> {
    let mut finding_statement = t.prepare_cached("INSERT INTO scan_findings(run_id,finding_id,kind,severity,confidence,status,rule_id,advisory_id,component_id,location_id,first_seen,last_seen,finding_json) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)")?;
    let mut evidence_statement = t.prepare_cached("INSERT INTO scan_evidence(run_id,finding_id,ordinal,redacted,evidence_json) VALUES (?1,?2,?3,?4,?5)")?;
    let mut remediation_statement = t.prepare_cached(
        "INSERT INTO scan_remediations(run_id,finding_id,remediation_json) VALUES (?1,?2,?3)",
    )?;
    for f in r.findings.values() {
        finding_statement.execute(params![
            r.run.id.as_str(),
            f.id.as_str(),
            f.kind.as_str(),
            f.severity.as_str(),
            json_scalar(&f.confidence)?,
            json_scalar(&f.status)?,
            f.rule_id.as_str(),
            f.advisory_id,
            f.component_id.as_ref().map(|x| x.as_str()),
            f.location_id.as_ref().map(|x| x.as_str()),
            f.first_seen,
            f.last_seen,
            serde_json::to_string(f)?
        ])?;
        for (i, e) in f.evidence.iter().enumerate() {
            evidence_statement.execute(params![
                r.run.id.as_str(),
                f.id.as_str(),
                i64::try_from(i).unwrap_or(i64::MAX),
                e.redacted,
                serde_json::to_string(e)?
            ])?;
        }
        if let Some(rem) = &f.remediation {
            remediation_statement.execute(params![
                r.run.id.as_str(),
                f.id.as_str(),
                serde_json::to_string(rem)?
            ])?;
        }
    }
    Ok(())
}
fn insert_policy_decisions(t: &Transaction<'_>, r: &ScanReport) -> Result<(), StoreError> {
    let mut decision_statement = t.prepare_cached("INSERT INTO scan_policy_decisions(run_id,ordinal,policy_id,finding_id,outcome,exception_id,decision_json) VALUES (?1,?2,?3,?4,?5,?6,?7)")?;
    for (i, d) in r.policy_decisions.iter().enumerate() {
        decision_statement.execute(params![
            r.run.id.as_str(),
            i64::try_from(i).unwrap_or(i64::MAX),
            d.policy_id.as_str(),
            d.finding_id.as_ref().map(|x| x.as_str()),
            json_scalar(&d.outcome)?,
            d.exception_id,
            serde_json::to_string(d)?
        ])?;
    }
    Ok(())
}
fn json_scalar<T: Serialize>(v: &T) -> Result<String, StoreError> {
    match serde_json::to_value(v)? {
        JsonValue::String(value) => Ok(value),
        other => Err(StoreError::UnexpectedScalar(other)),
    }
}
pub(super) fn reject_unredacted_secrets(
    fs: &BTreeMap<FindingId, Finding>,
) -> Result<(), StoreError> {
    for f in fs.values() {
        if f.kind == FindingKind::Secret && f.evidence.iter().any(|e| !e.redacted) {
            return Err(StoreError::UnredactedSecret {
                finding_id: f.id.clone(),
            });
        }
    }
    Ok(())
}

pub(super) fn ensure_supported_report_schema(report: &ScanReport) -> Result<(), StoreError> {
    if report.schema_version == REPORT_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(StoreError::UnsupportedReportSchema(
            report.schema_version.clone(),
        ))
    }
}

fn report_query_one<P: rusqlite::Params>(
    c: &Connection,
    sql: &str,
    p: P,
) -> Result<Option<ScanReport>, StoreError> {
    let json = c.query_row(sql, p, |r| r.get::<_, String>(0)).optional()?;
    json.map(|v| {
        let report: ScanReport = serde_json::from_str(&v)?;
        ensure_supported_report_schema(&report)?;
        Ok(report)
    })
    .transpose()
}
fn deserialize_rows<T, F>(rows: rusqlite::MappedRows<'_, F>) -> Result<Vec<T>, StoreError>
where
    T: for<'de> Deserialize<'de>,
    F: FnMut(&rusqlite::Row<'_>) -> Result<String, rusqlite::Error>,
{
    let mut out = Vec::new();
    for row in rows {
        out.push(serde_json::from_str(&row?)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Evidence, PolicyDecision, PolicyId, PolicyOutcome, PolicySummary, Remediation,
    };
    use crate::store::fixtures::*;
    use tempfile::tempdir;

    #[test]
    fn exact_report_normalized_filters_and_constraints() {
        let mut s = Store::open_memory().unwrap();
        let mut r = report("run:1", "2026-01-01T00:00:00Z", &["finding:1"]);
        let f = r
            .findings
            .get_mut(&FindingId::new("finding:1").unwrap())
            .unwrap();
        f.evidence.insert(Evidence {
            description: "redacted proof".into(),
            locations: BTreeSet::new(),
            references: BTreeSet::from(["https://example.invalid/advisory".into()]),
            properties: BTreeMap::new(),
            redacted: true,
        });
        f.remediation = Some(Remediation {
            description: "upgrade".into(),
            fixed_versions: BTreeSet::from(["2.0.0".into()]),
            references: BTreeSet::new(),
        });
        r.policy_decisions.insert(PolicyDecision {
            policy_id: PolicyId::new("policy:deny-high").unwrap(),
            finding_id: Some(f.id.clone()),
            outcome: PolicyOutcome::Deny,
            reason: "high severity".into(),
            exception_id: None,
        });
        r.policy_summary = PolicySummary::from_decisions(&r.policy_decisions);
        s.save_report(&r).unwrap();
        assert_eq!(s.get_run(&r.run.id).unwrap(), Some(r.clone()));
        assert_eq!(
            s.query_findings(
                &FindingFilter {
                    severity: Some("high".into()),
                    ..Default::default()
                },
                10,
                0
            )
            .unwrap()[0]
                .finding
                .id,
            FindingId::new("finding:1").unwrap()
        );
        assert!(
            s.query_findings(
                &FindingFilter {
                    severity: Some("low".into()),
                    ..Default::default()
                },
                10,
                0
            )
            .unwrap()
            .is_empty()
        );
        let normalized:(i64,i64,i64)=s.connection.query_row("SELECT (SELECT count(*) FROM scan_evidence),(SELECT count(*) FROM scan_remediations),(SELECT count(*) FROM scan_policy_decisions)",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
        assert_eq!(normalized, (1, 1, 1));
        assert!(s.connection.execute("INSERT INTO scan_findings(run_id,finding_id,kind,severity,confidence,status,rule_id,finding_json) VALUES ('run:1',' ','sast','high','high','open','r','{}')",[]).is_err());
    }
    #[test]
    fn pagination_history_and_audit_are_deterministic() {
        let mut s = Store::open_memory().unwrap();
        for (id, t) in [
            ("r1", "2026-01-01Z"),
            ("r2", "2026-01-02Z"),
            ("r3", "2026-01-03Z"),
        ] {
            s.save_report(&report(id, t, &[])).unwrap();
        }
        assert_eq!(
            s.list_runs(2, 1)
                .unwrap()
                .iter()
                .map(|r| r.run.id.as_str())
                .collect::<Vec<_>>(),
            vec!["r2", "r1"]
        );
        assert_eq!(s.delete_before("2026-01-03Z").unwrap(), 2);
        let a = s.list_audit_events(10, 0).unwrap();
        assert_eq!(a[0].details["deleted_runs"], 2);
    }
    #[test]
    fn latest_run_for_asset_never_crosses_asset_identity() {
        let mut store = Store::open_memory().unwrap();
        store
            .save_report(&rich_report(
                "run:asset-a-old",
                "2026-01-01T00:00:00Z",
                "asset:a",
            ))
            .unwrap();
        store
            .save_report(&rich_report(
                "run:asset-b-new",
                "2026-01-03T00:00:00Z",
                "asset:b",
            ))
            .unwrap();
        store
            .save_report(&rich_report(
                "run:asset-a-new",
                "2026-01-02T00:00:00Z",
                "asset:a",
            ))
            .unwrap();

        assert_eq!(
            store
                .latest_run_for_asset(&AssetId::new("asset:a").unwrap())
                .unwrap()
                .unwrap()
                .run
                .id
                .as_str(),
            "run:asset-a-new"
        );
        assert!(
            store
                .latest_run_for_asset(&AssetId::new("asset:absent").unwrap())
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn location_round_trip_survives_file_reopen_and_duplicate_run() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested-store.sqlite");
        assert!(matches!(
            Store::open(dir.path()),
            Err(StoreError::Sqlite(_))
        ));
        let mut first = Store::open(&path).unwrap();
        assert_eq!(first.latest_run().unwrap(), None);
        let original = rich_report("run:file", "2026-01-01Z", "asset:file");
        first.save_report(&original).unwrap();

        let mut duplicate = original.clone();
        duplicate.run.started_at = "2027-01-01Z".into();
        duplicate.inventory.asset.name = "must-not-leak".into();
        assert!(matches!(
            first.save_report(&duplicate),
            Err(StoreError::Sqlite(_))
        ));
        drop(first);

        let reopened = Store::open(&path).unwrap();
        assert_eq!(
            reopened.get_run(&original.run.id).unwrap(),
            Some(original.clone())
        );
        assert_eq!(
            reopened.latest_run().unwrap(),
            reopened.get_run(&original.run.id).unwrap()
        );
        assert_eq!(
            reopened
                .connection
                .query_row("SELECT count(*) FROM scan_components", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            Store::open(&path).unwrap().list_runs(10, 0).unwrap().len(),
            1
        );
    }

    #[test]
    fn every_history_finding_and_inventory_filter_is_applied() {
        let mut s = Store::open_memory().unwrap();
        let rich = rich_report("run:rich", "2026-02-02Z", "asset:rich");
        s.save_report(&rich).unwrap();
        s.save_report(&report("run:plain", "2026-01-01Z", &[]))
            .unwrap();

        let histories = [
            HistoryFilter {
                asset_id: Some("asset:rich".into()),
                ..Default::default()
            },
            HistoryFilter {
                started_from: Some("2026-02-01Z".into()),
                ..Default::default()
            },
            HistoryFilter {
                started_through: Some("2026-02-02Z".into()),
                ..Default::default()
            },
            HistoryFilter {
                asset_id: Some("asset:rich".into()),
                started_from: Some("2026-02-02Z".into()),
                started_through: Some("2026-02-02Z".into()),
            },
        ];
        for filter in histories {
            assert_eq!(
                s.query_history(&filter, 10, 0).unwrap()[0].run.id,
                rich.run.id
            );
        }
        assert!(
            s.query_history(
                &HistoryFilter {
                    started_from: Some("2027".into()),
                    ..Default::default()
                },
                10,
                0,
            )
            .unwrap()
            .is_empty()
        );
        for mask in 0_u8..8 {
            let filter = HistoryFilter {
                asset_id: (mask & 1 != 0).then(|| "asset:rich".into()),
                started_from: (mask & 2 != 0).then(|| "2026-02-02Z".into()),
                started_through: (mask & 4 != 0).then(|| "2026-02-02Z".into()),
            };
            let rows = s.query_history(&filter, 10, 0).unwrap();
            let expected = if mask & 3 == 0 { 2 } else { 1 };
            assert_eq!(rows.len(), expected, "history filter mask {mask}");
        }

        let finding_id = FindingId::new("finding:rich").unwrap();
        let finding_filters = [
            FindingFilter {
                run_id: Some(rich.run.id.clone()),
                ..Default::default()
            },
            FindingFilter {
                finding_id: Some(finding_id.clone()),
                ..Default::default()
            },
            FindingFilter {
                kind: Some("vulnerability".into()),
                ..Default::default()
            },
            FindingFilter {
                severity: Some("high".into()),
                ..Default::default()
            },
            FindingFilter {
                status: Some("suppressed".into()),
                ..Default::default()
            },
            FindingFilter {
                rule_id: Some("rule:finding:rich".into()),
                ..Default::default()
            },
            FindingFilter {
                advisory_id: Some("GHSA-test".into()),
                ..Default::default()
            },
            FindingFilter {
                component_id: Some("component:rich".into()),
                ..Default::default()
            },
            FindingFilter {
                run_id: Some(rich.run.id.clone()),
                finding_id: Some(finding_id.clone()),
                kind: Some("vulnerability".into()),
                severity: Some("high".into()),
                status: Some("suppressed".into()),
                rule_id: Some("rule:finding:rich".into()),
                advisory_id: Some("GHSA-test".into()),
                component_id: Some("component:rich".into()),
            },
        ];
        for filter in finding_filters {
            let rows = s.query_findings(&filter, 10, 0).unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].finding.id, finding_id);
        }
        for mask in 0_u16..256 {
            let filter = FindingFilter {
                run_id: (mask & 1 != 0).then(|| rich.run.id.clone()),
                finding_id: (mask & 2 != 0).then(|| finding_id.clone()),
                kind: (mask & 4 != 0).then(|| "vulnerability".into()),
                severity: (mask & 8 != 0).then(|| "high".into()),
                status: (mask & 16 != 0).then(|| "suppressed".into()),
                rule_id: (mask & 32 != 0).then(|| "rule:finding:rich".into()),
                advisory_id: (mask & 64 != 0).then(|| "GHSA-test".into()),
                component_id: (mask & 128 != 0).then(|| "component:rich".into()),
            };
            assert_eq!(
                s.query_findings(&filter, 10, 0).unwrap().len(),
                1,
                "finding filter mask {mask}"
            );
        }

        let inventory_filters = [
            InventoryFilter {
                run_id: Some(rich.run.id.clone()),
                ..Default::default()
            },
            InventoryFilter {
                asset_id: Some("asset:rich".into()),
                ..Default::default()
            },
            InventoryFilter {
                component_id: Some("component:rich".into()),
                ..Default::default()
            },
            InventoryFilter {
                name: Some("rich-component".into()),
                ..Default::default()
            },
            InventoryFilter {
                purl: Some("pkg:cargo/rich@1.0.0".into()),
                ..Default::default()
            },
            InventoryFilter {
                scope: Some("runtime".into()),
                ..Default::default()
            },
            InventoryFilter {
                run_id: Some(rich.run.id.clone()),
                asset_id: Some("asset:rich".into()),
                component_id: Some("component:rich".into()),
                name: Some("rich-component".into()),
                purl: Some("pkg:cargo/rich@1.0.0".into()),
                scope: Some("runtime".into()),
            },
        ];
        for filter in inventory_filters {
            let rows = s.query_inventory(&filter, 10, 0).unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].component.identity.as_str(), "component:rich");
        }
        assert!(
            s.query_inventory(
                &InventoryFilter {
                    scope: Some("build".into()),
                    ..Default::default()
                },
                10,
                0,
            )
            .unwrap()
            .is_empty()
        );
        for mask in 0_u8..64 {
            let filter = InventoryFilter {
                run_id: (mask & 1 != 0).then(|| rich.run.id.clone()),
                asset_id: (mask & 2 != 0).then(|| "asset:rich".into()),
                component_id: (mask & 4 != 0).then(|| "component:rich".into()),
                name: (mask & 8 != 0).then(|| "rich-component".into()),
                purl: (mask & 16 != 0).then(|| "pkg:cargo/rich@1.0.0".into()),
                scope: (mask & 32 != 0).then(|| "runtime".into()),
            };
            assert_eq!(
                s.query_inventory(&filter, 10, 0).unwrap().len(),
                1,
                "inventory filter mask {mask}"
            );
        }
    }

    #[test]
    fn retention_cascades_normalized_rows_and_records_zero_deletions() {
        let mut s = Store::open_memory().unwrap();
        s.save_report(&rich_report("old", "2026-01-01Z", "asset:old"))
            .unwrap();
        s.save_report(&rich_report("new", "2026-03-01Z", "asset:new"))
            .unwrap();
        assert_eq!(s.delete_before("2026-02-01Z").unwrap(), 1);

        let counts: (i64, i64, i64) = s.connection.query_row(
            "SELECT (SELECT count(*) FROM scan_runs WHERE run_id='old'),(SELECT count(*) FROM scan_components WHERE run_id='old'),(SELECT count(*) FROM scan_findings WHERE run_id='old')",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).unwrap();
        assert_eq!(counts, (0, 0, 0));
        assert!(s.get_run(&RunId::new("new").unwrap()).unwrap().is_some());
        assert_eq!(s.delete_before("2020").unwrap(), 0);
        let retention: Vec<(i64, String)> = s
            .connection
            .prepare("SELECT deleted_runs,cutoff_at FROM retention_events ORDER BY sequence")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            retention,
            vec![(1, "2026-02-01Z".into()), (0, "2020".into())]
        );
        assert_eq!(s.list_audit_events(10, 0).unwrap().len(), 2);
    }
    #[test]
    fn malformed_stored_json_and_normalized_identifiers_are_reported() {
        let mut s = Store::open_memory().unwrap();
        let r = rich_report("corrupt", "2026-01-01Z", "asset:corrupt");
        s.save_report(&r).unwrap();

        s.connection
            .execute(
                "UPDATE scan_runs SET report_json='{}' WHERE run_id='corrupt'",
                [],
            )
            .unwrap();
        assert!(matches!(
            s.get_run(&r.run.id),
            Err(StoreError::Serialization(_))
        ));
        assert!(matches!(
            s.list_runs(10, 0),
            Err(StoreError::Serialization(_))
        ));
        s.connection
            .execute(
                "UPDATE scan_runs SET report_json=?1 WHERE run_id='corrupt'",
                [serde_json::to_string(&r).unwrap()],
            )
            .unwrap();

        s.connection
            .execute(
                "UPDATE scan_findings SET finding_json='{}' WHERE run_id='corrupt'",
                [],
            )
            .unwrap();
        assert!(matches!(
            s.query_findings(&FindingFilter::default(), 10, 0),
            Err(StoreError::Serialization(_))
        ));
        s.connection
            .execute(
                "UPDATE scan_findings SET finding_json=?1 WHERE run_id='corrupt'",
                [serde_json::to_string(r.findings.values().next().unwrap()).unwrap()],
            )
            .unwrap();
        s.connection
            .execute(
                "UPDATE scan_components SET component_json='{}' WHERE run_id='corrupt'",
                [],
            )
            .unwrap();
        assert!(matches!(
            s.query_inventory(&InventoryFilter::default(), 10, 0),
            Err(StoreError::Serialization(_))
        ));

        s.connection
            .pragma_update(None, "ignore_check_constraints", "ON")
            .unwrap();
        s.connection
            .execute(
                "UPDATE scan_findings SET finding_id=' ' WHERE run_id='corrupt'",
                [],
            )
            .unwrap();
        assert!(matches!(
            s.diff_runs(&r.run.id, &r.run.id),
            Err(StoreError::InvalidFindingId(_))
        ));
    }
    #[test]
    fn unsupported_report_schema_version_is_rejected_on_read() {
        let mut s = Store::open_memory().unwrap();
        // Earlier started_at than the rejected row keeps DESC-order assertions
        // meaningful and proves supported rows remain readable.
        let control = rich_report("run:supported:v1", "2025-12-31Z", "asset:v1");
        s.save_report(&control).unwrap();
        let r = rich_report("legacy:v2", "2026-01-01Z", "asset:v2");
        let mut fabricated = serde_json::to_value(&r).unwrap();
        fabricated["schema_version"] = serde_json::Value::String("2".into());
        s.connection
            .execute(
                "INSERT INTO scan_runs(run_id,schema_version,started_at,completed_at,scanner_version,asset_id,finding_count,report_json) VALUES (?1,'2',?2,?2,'test',?3,1,?4)",
                params![
                    r.run.id.as_str(),
                    r.run.started_at,
                    r.inventory.asset.id.as_str(),
                    serde_json::to_string(&fabricated).unwrap()
                ],
            )
            .unwrap();
        assert!(matches!(
            s.get_run(&r.run.id),
            Err(StoreError::UnsupportedReportSchema(version)) if version == "2"
        ));
        assert!(matches!(
            s.latest_run(),
            Err(StoreError::UnsupportedReportSchema(_))
        ));
        assert!(matches!(
            s.latest_run_for_asset(&r.inventory.asset.id),
            Err(StoreError::UnsupportedReportSchema(_))
        ));
        assert!(matches!(
            s.list_runs(10, 0),
            Err(StoreError::UnsupportedReportSchema(_))
        ));
        assert!(matches!(
            s.query_history(&HistoryFilter::default(), 10, 0),
            Err(StoreError::UnsupportedReportSchema(_))
        ));
        assert_eq!(s.get_run(&control.run.id).unwrap(), Some(control));
    }

    #[test]
    fn diff_reports_missing_runs_and_all_set_partitions() {
        let mut s = Store::open_memory().unwrap();
        let missing = RunId::new("missing").unwrap();
        assert!(
            matches!(s.diff_runs(&missing, &missing), Err(StoreError::RunNotFound(id)) if id == "missing")
        );
        s.save_report(&report("before", "t1", &["same", "resolved"]))
            .unwrap();
        s.save_report(&report("after", "t2", &["same", "introduced"]))
            .unwrap();
        let diff = s
            .diff_runs(
                &RunId::new("before").unwrap(),
                &RunId::new("after").unwrap(),
            )
            .unwrap();
        assert_eq!(diff.introduced, vec![FindingId::new("introduced").unwrap()]);
        assert_eq!(diff.resolved, vec![FindingId::new("resolved").unwrap()]);
        assert_eq!(diff.unchanged, vec![FindingId::new("same").unwrap()]);
    }

    #[test]
    fn secret_redaction_is_enforced() {
        let mut s = Store::open_memory().unwrap();
        let mut r = report("secret", "t", &[]);
        let mut f = finding("f");
        f.kind = FindingKind::Secret;
        f.evidence.insert(Evidence {
            description: "raw".into(),
            locations: BTreeSet::new(),
            references: BTreeSet::new(),
            properties: BTreeMap::new(),
            redacted: false,
        });
        r.findings.insert(f.id.clone(), f);
        assert!(matches!(
            s.save_report(&r),
            Err(StoreError::UnredactedSecret { .. })
        ));
    }

    #[test]
    fn sensitive_free_form_values_are_redacted_before_persistence() {
        let mut store = Store::open_memory().unwrap();
        let mut report = rich_report("run:redacted", "2026-01-01Z", "asset:redacted");
        report
            .run
            .metadata
            .insert("api_key".to_owned(), serde_json::json!("raw-run-secret"));
        report.inventory.asset.metadata.insert(
            "deployment".to_owned(),
            serde_json::json!({"clientSecret":"raw-asset-secret","region":"eu"}),
        );

        store.save_report(&report).unwrap();
        let stored = store.get_run(&report.run.id).unwrap().unwrap();
        let serialized = serde_json::to_string(&stored).unwrap();
        assert!(serialized.contains("[REDACTED]"));
        assert!(serialized.contains("eu"));
        assert!(!serialized.contains("raw-run-secret"));
        assert!(!serialized.contains("raw-asset-secret"));

        let raw: (String, String) = store
            .connection
            .query_row(
                "SELECT r.report_json, a.asset_json FROM scan_runs r JOIN scan_assets a USING (run_id) WHERE r.run_id=?1",
                [report.run.id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        for value in [raw.0, raw.1] {
            assert!(!value.contains("raw-run-secret"));
            assert!(!value.contains("raw-asset-secret"));
        }
    }
}
