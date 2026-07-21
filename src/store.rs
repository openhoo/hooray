use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use rusqlite::{
    Connection, OptionalExtension, Transaction, TransactionBehavior, params, params_from_iter,
    types::Value,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use thiserror::Error;

use crate::model::{
    AssetId, Finding, FindingId, FindingKind, ModelInvariantError, RunId, ScanReport,
};

const CORE_SCHEMA: &str = include_str!("../migrations/001_init.sql");
const MONITOR_SCHEMA: &str = include_str!("../migrations/002_monitor.sql");
const CURRENT_DATABASE_VERSION: i64 = 2;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_PAGE_SIZE: u32 = 1_000;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("SQLite store operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("report serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid report: {0}")]
    InvalidReport(#[from] ModelInvariantError),
    #[error("secret finding '{finding_id}' contains unredacted evidence")]
    UnredactedSecret { finding_id: FindingId },
    #[error("finding count exceeds SQLite's signed integer range")]
    FindingCountOverflow,
    #[error("page limit must be between 1 and {MAX_PAGE_SIZE}, got {0}")]
    InvalidPageLimit(u32),
    #[error("page offset exceeds SQLite's signed integer range: {0}")]
    InvalidPageOffset(u64),
    #[error("scan run '{0}' was not found")]
    RunNotFound(String),
    #[error("stored finding identifier is invalid: {0}")]
    InvalidFindingId(String),
    #[error("database schema version {found} is newer than supported version {supported}")]
    UnsupportedSchemaVersion { found: i64, supported: i64 },
    #[error("database migration history is invalid: {0}")]
    InvalidMigrationHistory(String),
    #[error("stored monitor data is invalid: {0}")]
    InvalidMonitorData(String),
    #[error(
        "optimistic update conflict for {resource_type} '{resource_id}': expected version {expected}, current version {actual:?}"
    )]
    VersionConflict {
        resource_type: &'static str,
        resource_id: String,
        expected: u64,
        actual: Option<u64>,
    },
    #[error("stored version is outside the supported range")]
    VersionOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportDiff {
    pub introduced: Vec<FindingId>,
    pub resolved: Vec<FindingId>,
    pub unchanged: Vec<FindingId>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistoryFilter {
    pub asset_id: Option<String>,
    pub started_from: Option<String>,
    pub started_through: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FindingFilter {
    pub run_id: Option<RunId>,
    pub finding_id: Option<FindingId>,
    pub kind: Option<String>,
    pub severity: Option<String>,
    pub status: Option<String>,
    pub rule_id: Option<String>,
    pub advisory_id: Option<String>,
    pub component_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingRecord {
    pub run_id: String,
    pub started_at: String,
    pub finding: Finding,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InventoryFilter {
    pub run_id: Option<RunId>,
    pub asset_id: Option<String>,
    pub component_id: Option<String>,
    pub name: Option<String>,
    pub purl: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryRecord {
    pub run_id: String,
    pub started_at: String,
    pub asset_id: String,
    pub component: crate::model::Component,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedDocument {
    pub id: String,
    pub version: u64,
    pub document: JsonValue,
    pub updated_at: String,
    pub updated_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub sequence: i64,
    pub event_id: String,
    pub occurred_at: String,
    pub actor: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub details: JsonValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorTarget {
    pub target_id: String,
    pub source: String,
    pub interval_seconds: u64,
    pub next_due_at: String,
    pub source_fingerprint: Option<String>,
    pub inventory: Option<JsonValue>,
    pub advisory_digest: Option<String>,
    pub policy_digest: Option<String>,
    pub finding_ids: Vec<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorCursor {
    pub name: String,
    pub cursor: Option<String>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub advisory_digest: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorEvent {
    pub event_id: String,
    pub target_id: String,
    pub dedupe_key: String,
    pub kind: String,
    pub payload: JsonValue,
    pub created_at: String,
    pub attempts: u64,
    pub next_attempt_at: Option<String>,
    pub delivered_at: Option<String>,
    pub dead_lettered_at: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MonitorEventFilter {
    pub target_id: Option<String>,
    pub due_through: Option<String>,
    pub include_delivered: bool,
    pub include_dead_lettered: bool,
}

#[derive(Debug, Clone)]
pub struct StoreFactory {
    path: Arc<PathBuf>,
}

impl StoreFactory {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: Arc::new(path.into()),
        }
    }

    pub fn open(&self) -> Result<Store, StoreError> {
        Store::open(self.path.as_ref())
    }
}

pub struct Store {
    connection: Connection,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let connection = Connection::open(path)?;
        configure_connection(&connection, true)?;
        Self::initialize(connection)
    }

    pub fn open_memory() -> Result<Self, StoreError> {
        let connection = Connection::open_in_memory()?;
        configure_connection(&connection, false)?;
        Self::initialize(connection)
    }

    fn initialize(mut connection: Connection) -> Result<Self, StoreError> {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY NOT NULL CHECK (version > 0),
                name TEXT NOT NULL UNIQUE CHECK (length(trim(name)) > 0),
                applied_at TEXT NOT NULL CHECK (length(trim(applied_at)) > 0)
             ) STRICT;",
        )?;
        let found: Option<i64> =
            transaction.query_row("SELECT max(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })?;
        if found.is_none() && table_exists(&transaction, "scan_runs")? {
            migrate_legacy_v1(&transaction)?;
        }
        let versions = migration_versions(&transaction)?;
        validate_migration_versions(&versions)?;
        let found = versions.last().copied().unwrap_or(0);
        if found > CURRENT_DATABASE_VERSION {
            return Err(StoreError::UnsupportedSchemaVersion {
                found,
                supported: CURRENT_DATABASE_VERSION,
            });
        }
        if found < 1 {
            transaction.execute_batch(CORE_SCHEMA)?;
            transaction.execute("INSERT INTO schema_migrations(version, name, applied_at) VALUES (1, 'core', '1970-01-01T00:00:00Z')", [])?;
        }
        if found < 2 {
            transaction.execute_batch(MONITOR_SCHEMA)?;
            transaction.execute("INSERT INTO schema_migrations(version, name, applied_at) VALUES (2, 'monitor', '1970-01-01T00:00:00Z')", [])?;
        }
        transaction.commit()?;
        Ok(Self { connection })
    }

    pub fn save_report(&mut self, report: &ScanReport) -> Result<(), StoreError> {
        reject_unredacted_secrets(&report.findings)?;
        report.validate()?;
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
        deserialize_rows(rows)
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

    pub fn diff_runs(
        &self,
        previous_run_id: &RunId,
        current_run_id: &RunId,
    ) -> Result<ReportDiff, StoreError> {
        let previous = self.finding_ids(previous_run_id)?;
        let current = self.finding_ids(current_run_id)?;
        Ok(ReportDiff {
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

    pub fn get_policy(&self, id: &str) -> Result<Option<VersionedDocument>, StoreError> {
        self.get_document("policy_documents", "document_id", id)
    }
    pub fn get_exception(&self, id: &str) -> Result<Option<VersionedDocument>, StoreError> {
        self.get_document("policy_exceptions", "exception_id", id)
    }

    pub fn put_policy(
        &mut self,
        id: &str,
        document: &JsonValue,
        expected_version: u64,
        updated_at: &str,
        updated_by: &str,
    ) -> Result<VersionedDocument, StoreError> {
        self.put_document(
            "policy_documents",
            "document_id",
            "policy",
            id,
            document,
            None,
            expected_version,
            updated_at,
            updated_by,
        )
    }

    pub fn put_exception(
        &mut self,
        id: &str,
        document: &JsonValue,
        expires_at: Option<&str>,
        expected_version: u64,
        updated_at: &str,
        updated_by: &str,
    ) -> Result<VersionedDocument, StoreError> {
        self.put_document(
            "policy_exceptions",
            "exception_id",
            "exception",
            id,
            document,
            expires_at,
            expected_version,
            updated_at,
            updated_by,
        )
    }

    fn get_document(
        &self,
        table: &'static str,
        id_column: &'static str,
        id: &str,
    ) -> Result<Option<VersionedDocument>, StoreError> {
        let sql = format!(
            "SELECT version,document_json,updated_at,updated_by FROM {table} WHERE {id_column}=?1"
        );
        let row = self
            .connection
            .query_row(&sql, [id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .optional()?;
        row.map(|(version, json, updated_at, updated_by)| {
            Ok(VersionedDocument {
                id: id.to_owned(),
                version: u64::try_from(version).map_err(|_| StoreError::VersionOverflow)?,
                document: serde_json::from_str(&json)?,
                updated_at,
                updated_by,
            })
        })
        .transpose()
    }

    #[allow(clippy::too_many_arguments)]
    fn put_document(
        &mut self,
        table: &'static str,
        id_column: &'static str,
        resource_type: &'static str,
        id: &str,
        document: &JsonValue,
        expires_at: Option<&str>,
        expected_version: u64,
        updated_at: &str,
        updated_by: &str,
    ) -> Result<VersionedDocument, StoreError> {
        let json = serde_json::to_string(document)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<i64> = transaction
            .query_row(
                &format!("SELECT version FROM {table} WHERE {id_column}=?1"),
                [id],
                |row| row.get(0),
            )
            .optional()?;
        let actual = current
            .map(|v| u64::try_from(v).map_err(|_| StoreError::VersionOverflow))
            .transpose()?;
        if actual.unwrap_or(0) != expected_version {
            return Err(StoreError::VersionConflict {
                resource_type,
                resource_id: id.to_owned(),
                expected: expected_version,
                actual,
            });
        }
        let version = expected_version
            .checked_add(1)
            .ok_or(StoreError::VersionOverflow)?;
        let version_i64 = i64::try_from(version).map_err(|_| StoreError::VersionOverflow)?;
        if table == "policy_exceptions" {
            transaction.execute("INSERT INTO policy_exceptions(exception_id,version,document_json,expires_at,updated_at,updated_by) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(exception_id) DO UPDATE SET version=excluded.version,document_json=excluded.document_json,expires_at=excluded.expires_at,updated_at=excluded.updated_at,updated_by=excluded.updated_by",params![id,version_i64,json,expires_at,updated_at,updated_by])?;
        } else {
            transaction.execute("INSERT INTO policy_documents(document_id,version,document_json,updated_at,updated_by) VALUES (?1,?2,?3,?4,?5) ON CONFLICT(document_id) DO UPDATE SET version=excluded.version,document_json=excluded.document_json,updated_at=excluded.updated_at,updated_by=excluded.updated_by",params![id,version_i64,json,updated_at,updated_by])?;
        }
        transaction.execute("INSERT INTO audit_events(event_id,occurred_at,actor,action,resource_type,resource_id,details_json) VALUES (?1,?2,?3,'document.put',?4,?5,json_object('version',?6))",params![format!("{resource_type}:{id}:{version}"),updated_at,updated_by,resource_type,id,version_i64])?;
        transaction.commit()?;
        Ok(VersionedDocument {
            id: id.to_owned(),
            version,
            document: document.clone(),
            updated_at: updated_at.to_owned(),
            updated_by: updated_by.to_owned(),
        })
    }

    pub fn list_audit_events(
        &self,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<AuditEvent>, StoreError> {
        let (limit, offset) = pagination(limit, offset)?;
        let mut s=self.connection.prepare("SELECT sequence,event_id,occurred_at,actor,action,resource_type,resource_id,details_json FROM audit_events ORDER BY sequence DESC LIMIT ?1 OFFSET ?2")?;
        let rows = s.query_map(params![limit, offset], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get::<_, String>(7)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (sequence, event_id, occurred_at, actor, action, resource_type, resource_id, json) =
                row?;
            out.push(AuditEvent {
                sequence,
                event_id,
                occurred_at,
                actor,
                action,
                resource_type,
                resource_id,
                details: serde_json::from_str(&json)?,
            });
        }
        Ok(out)
    }

    pub fn upsert_monitor_target(&mut self, target: &MonitorTarget) -> Result<(), StoreError> {
        let findings = serde_json::to_string(&target.finding_ids)?;
        let inventory = target
            .inventory
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let interval =
            i64::try_from(target.interval_seconds).map_err(|_| StoreError::VersionOverflow)?;
        self.connection.execute("INSERT INTO monitor_targets(target_id,source,interval_seconds,next_due_at,source_fingerprint,inventory_json,advisory_digest,policy_digest,finding_ids_json,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(target_id) DO UPDATE SET source=excluded.source,interval_seconds=excluded.interval_seconds,next_due_at=excluded.next_due_at,source_fingerprint=excluded.source_fingerprint,inventory_json=excluded.inventory_json,advisory_digest=excluded.advisory_digest,policy_digest=excluded.policy_digest,finding_ids_json=excluded.finding_ids_json,updated_at=excluded.updated_at",params![target.target_id,target.source,interval,target.next_due_at,target.source_fingerprint,inventory,target.advisory_digest,target.policy_digest,findings,target.updated_at])?;
        Ok(())
    }
    pub fn get_monitor_target(&self, id: &str) -> Result<Option<MonitorTarget>, StoreError> {
        self.connection.query_row("SELECT target_id,source,interval_seconds,next_due_at,source_fingerprint,inventory_json,advisory_digest,policy_digest,finding_ids_json,updated_at FROM monitor_targets WHERE target_id=?1",[id],read_monitor_target).optional().map_err(Into::into)
    }
    pub fn list_due_monitor_targets(
        &self,
        through: &str,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<MonitorTarget>, StoreError> {
        let (limit, offset) = pagination(limit, offset)?;
        let mut s=self.connection.prepare("SELECT target_id,source,interval_seconds,next_due_at,source_fingerprint,inventory_json,advisory_digest,policy_digest,finding_ids_json,updated_at FROM monitor_targets WHERE next_due_at<=?1 ORDER BY next_due_at,target_id LIMIT ?2 OFFSET ?3")?;
        let rows = s.query_map(params![through, limit, offset], read_monitor_target)?;
        collect_sql_rows(rows)
    }
    pub fn update_monitor_target(&mut self, target: &MonitorTarget) -> Result<bool, StoreError> {
        let findings = serde_json::to_string(&target.finding_ids)?;
        let inventory = target
            .inventory
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let interval =
            i64::try_from(target.interval_seconds).map_err(|_| StoreError::VersionOverflow)?;
        Ok(self.connection.execute("UPDATE monitor_targets SET source=?2,interval_seconds=?3,next_due_at=?4,source_fingerprint=?5,inventory_json=?6,advisory_digest=?7,policy_digest=?8,finding_ids_json=?9,updated_at=?10 WHERE target_id=?1",params![target.target_id,target.source,interval,target.next_due_at,target.source_fingerprint,inventory,target.advisory_digest,target.policy_digest,findings,target.updated_at])?==1)
    }
    pub fn get_monitor_cursor(&self, name: &str) -> Result<Option<MonitorCursor>, StoreError> {
        self.connection.query_row("SELECT name,cursor,etag,last_modified,advisory_digest,updated_at FROM monitor_cursors WHERE name=?1",[name],|r|Ok(MonitorCursor{name:r.get(0)?,cursor:r.get(1)?,etag:r.get(2)?,last_modified:r.get(3)?,advisory_digest:r.get(4)?,updated_at:r.get(5)?})).optional().map_err(Into::into)
    }
    pub fn set_monitor_cursor(&mut self, c: &MonitorCursor) -> Result<(), StoreError> {
        self.connection.execute("INSERT INTO monitor_cursors(name,cursor,etag,last_modified,advisory_digest,updated_at) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(name) DO UPDATE SET cursor=excluded.cursor,etag=excluded.etag,last_modified=excluded.last_modified,advisory_digest=excluded.advisory_digest,updated_at=excluded.updated_at",params![c.name,c.cursor,c.etag,c.last_modified,c.advisory_digest,c.updated_at])?;
        Ok(())
    }
    pub fn append_monitor_event(&mut self, e: &MonitorEvent) -> Result<bool, StoreError> {
        let payload = serde_json::to_string(&e.payload)?;
        let attempts = i64::try_from(e.attempts).map_err(|_| StoreError::VersionOverflow)?;
        Ok(self.connection.execute("INSERT OR IGNORE INTO monitor_events(event_id,target_id,dedupe_key,kind,payload_json,created_at,attempts,next_attempt_at,delivered_at,dead_lettered_at,last_error) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",params![e.event_id,e.target_id,e.dedupe_key,e.kind,payload,e.created_at,attempts,e.next_attempt_at,e.delivered_at,e.dead_lettered_at,e.last_error])?==1)
    }
    pub fn claim_monitor_events(
        &mut self,
        due_through: &str,
        lease_until: &str,
        limit: u32,
    ) -> Result<Vec<MonitorEvent>, StoreError> {
        let (limit, _) = pagination(limit, 0)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let event_ids = {
            let mut statement = transaction.prepare(
                "SELECT event_id FROM monitor_events WHERE coalesce(next_attempt_at,created_at)<=?1 AND delivered_at IS NULL AND dead_lettered_at IS NULL ORDER BY coalesce(next_attempt_at,created_at),created_at,event_id LIMIT ?2",
            )?;
            statement
                .query_map(params![due_through, limit], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        for event_id in &event_ids {
            transaction.execute(
                "UPDATE monitor_events SET next_attempt_at=?2 WHERE event_id=?1 AND coalesce(next_attempt_at,created_at)<=?3 AND delivered_at IS NULL AND dead_lettered_at IS NULL",
                params![event_id, lease_until, due_through],
            )?;
        }
        let mut events = Vec::with_capacity(event_ids.len());
        {
            let mut statement = transaction.prepare("SELECT event_id,target_id,dedupe_key,kind,payload_json,created_at,attempts,next_attempt_at,delivered_at,dead_lettered_at,last_error FROM monitor_events WHERE event_id=?1")?;
            for event_id in event_ids {
                events.push(statement.query_row([event_id], read_monitor_event)?);
            }
        }
        transaction.commit()?;
        Ok(events)
    }
    pub fn list_monitor_events(
        &self,
        f: &MonitorEventFilter,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<MonitorEvent>, StoreError> {
        let (limit, offset) = pagination(limit, offset)?;
        let mut sql = String::from(
            "SELECT event_id,target_id,dedupe_key,kind,payload_json,created_at,attempts,next_attempt_at,delivered_at,dead_lettered_at,last_error FROM monitor_events WHERE 1=1",
        );
        let mut v = Vec::new();
        push_filter(&mut sql, &mut v, "target_id", f.target_id.as_deref());
        push_filter_op(
            &mut sql,
            &mut v,
            "coalesce(next_attempt_at,created_at)",
            "<=",
            f.due_through.as_deref(),
        );
        if !f.include_delivered {
            sql.push_str(" AND delivered_at IS NULL");
        }
        if !f.include_dead_lettered {
            sql.push_str(" AND dead_lettered_at IS NULL");
        }
        sql.push_str(
            " ORDER BY coalesce(next_attempt_at,created_at),created_at,event_id LIMIT ? OFFSET ?",
        );
        v.push(Value::Integer(limit));
        v.push(Value::Integer(offset));
        let mut s = self.connection.prepare(&sql)?;
        let rows = s.query_map(params_from_iter(v), read_monitor_event)?;
        collect_sql_rows(rows)
    }
    pub fn update_monitor_event(&mut self, e: &MonitorEvent) -> Result<bool, StoreError> {
        let payload = serde_json::to_string(&e.payload)?;
        let attempts = i64::try_from(e.attempts).map_err(|_| StoreError::VersionOverflow)?;
        Ok(self.connection.execute("UPDATE monitor_events SET target_id=?2,dedupe_key=?3,kind=?4,payload_json=?5,created_at=?6,attempts=?7,next_attempt_at=?8,delivered_at=?9,dead_lettered_at=?10,last_error=?11 WHERE event_id=?1",params![e.event_id,e.target_id,e.dedupe_key,e.kind,payload,e.created_at,attempts,e.next_attempt_at,e.delivered_at,e.dead_lettered_at,e.last_error])?==1)
    }
    pub fn prune_monitor_before(&mut self, timestamp: &str) -> Result<usize, StoreError> {
        Ok(self.connection.execute("DELETE FROM monitor_events WHERE created_at<?1 AND (delivered_at IS NOT NULL OR dead_lettered_at IS NOT NULL)",[timestamp])?)
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

fn configure_connection(c: &Connection, wal: bool) -> Result<(), rusqlite::Error> {
    c.busy_timeout(BUSY_TIMEOUT)?;
    c.pragma_update(None, "foreign_keys", "ON")?;
    c.pragma_update(None, "synchronous", "NORMAL")?;
    if wal {
        c.pragma_update(None, "journal_mode", "WAL")?;
    }
    Ok(())
}
fn table_exists(t: &Transaction<'_>, name: &str) -> Result<bool, rusqlite::Error> {
    t.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [name],
        |r| r.get(0),
    )
}
fn migrate_legacy_v1(t: &Transaction<'_>) -> Result<(), StoreError> {
    let mut s = t.prepare("SELECT report_json FROM scan_runs ORDER BY started_at,run_id")?;
    let rows = s.query_map([], |r| r.get::<_, String>(0))?;
    let mut reports = Vec::new();
    for row in rows {
        reports.push(serde_json::from_str::<ScanReport>(&row?)?);
    }
    drop(s);
    t.execute_batch("DROP TABLE scan_findings; DROP TABLE scan_runs;")?;
    t.execute_batch(CORE_SCHEMA)?;
    for report in reports {
        reject_unredacted_secrets(&report.findings)?;
        report.validate()?;
        let json = serde_json::to_string(&report)?;
        let count =
            i64::try_from(report.findings.len()).map_err(|_| StoreError::FindingCountOverflow)?;
        insert_report(t, &report, &json, count)?;
    }
    t.execute("INSERT INTO schema_migrations(version,name,applied_at) VALUES (1,'core','1970-01-01T00:00:00Z')",[])?;
    Ok(())
}
fn insert_report(
    t: &Transaction<'_>,
    r: &ScanReport,
    json: &str,
    count: i64,
) -> Result<(), StoreError> {
    t.execute("INSERT INTO scan_runs(run_id,schema_version,started_at,completed_at,scanner_version,asset_id,finding_count,report_json) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",params![r.run.id.as_str(),r.schema_version,r.run.started_at,r.run.completed_at,r.run.scanner_version,r.inventory.asset.id.as_str(),count,json])?;
    t.execute("INSERT INTO scan_assets(run_id,asset_id,name,kind,version,metadata_json,asset_json) VALUES (?1,?2,?3,?4,?5,?6,?7)",params![r.run.id.as_str(),r.inventory.asset.id.as_str(),r.inventory.asset.name,json_scalar(&r.inventory.asset.kind)?,r.inventory.asset.version,serde_json::to_string(&r.inventory.asset.metadata)?,serde_json::to_string(&r.inventory.asset)?])?;
    for c in r.inventory.components.values() {
        t.execute("INSERT INTO scan_components(run_id,component_id,name,version,purl,scope,component_json) VALUES (?1,?2,?3,?4,?5,?6,?7)",params![r.run.id.as_str(),c.identity.as_str(),c.name,c.version,c.purl,json_scalar(&c.scope)?,serde_json::to_string(c)?])?;
    }
    for e in &r.inventory.dependencies {
        t.execute("INSERT INTO scan_dependency_edges(run_id,from_component_id,to_component_id,scope,optional,edge_json) VALUES (?1,?2,?3,?4,?5,?6)",params![r.run.id.as_str(),e.from.as_str(),e.to.as_str(),json_scalar(&e.scope)?,e.optional,serde_json::to_string(e)?])?;
    }
    for f in r.findings.values() {
        t.execute("INSERT INTO scan_findings(run_id,finding_id,kind,severity,confidence,status,rule_id,advisory_id,component_id,location_id,first_seen,last_seen,finding_json) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",params![r.run.id.as_str(),f.id.as_str(),f.kind.as_str(),f.severity.as_str(),json_scalar(&f.confidence)?,json_scalar(&f.status)?,f.rule_id.as_str(),f.advisory_id,f.component_id.as_ref().map(|x|x.as_str()),f.location_id.as_ref().map(|x|x.as_str()),f.first_seen,f.last_seen,serde_json::to_string(f)?])?;
        for (i, e) in f.evidence.iter().enumerate() {
            t.execute("INSERT INTO scan_evidence(run_id,finding_id,ordinal,redacted,evidence_json) VALUES (?1,?2,?3,?4,?5)",params![r.run.id.as_str(),f.id.as_str(),i64::try_from(i).unwrap_or(i64::MAX),e.redacted,serde_json::to_string(e)?])?;
        }
        if let Some(rem) = &f.remediation {
            t.execute("INSERT INTO scan_remediations(run_id,finding_id,remediation_json) VALUES (?1,?2,?3)",params![r.run.id.as_str(),f.id.as_str(),serde_json::to_string(rem)?])?;
        }
    }
    for (i, d) in r.policy_decisions.iter().enumerate() {
        t.execute("INSERT INTO scan_policy_decisions(run_id,ordinal,policy_id,finding_id,outcome,exception_id,decision_json) VALUES (?1,?2,?3,?4,?5,?6,?7)",params![r.run.id.as_str(),i64::try_from(i).unwrap_or(i64::MAX),d.policy_id.as_str(),d.finding_id.as_ref().map(|x|x.as_str()),json_scalar(&d.outcome)?,d.exception_id,serde_json::to_string(d)?])?;
    }
    Ok(())
}
fn json_scalar<T: Serialize>(v: &T) -> Result<String, serde_json::Error> {
    let value = serde_json::to_value(v)?;
    Ok(value.as_str().unwrap_or_default().to_owned())
}
fn pagination(limit: u32, offset: u64) -> Result<(i64, i64), StoreError> {
    if limit == 0 || limit > MAX_PAGE_SIZE {
        return Err(StoreError::InvalidPageLimit(limit));
    }
    Ok((
        i64::from(limit),
        i64::try_from(offset).map_err(|_| StoreError::InvalidPageOffset(offset))?,
    ))
}
fn reject_unredacted_secrets(fs: &BTreeMap<FindingId, Finding>) -> Result<(), StoreError> {
    for f in fs.values() {
        if f.kind == FindingKind::Secret && f.evidence.iter().any(|e| !e.redacted) {
            return Err(StoreError::UnredactedSecret {
                finding_id: f.id.clone(),
            });
        }
    }
    Ok(())
}
fn report_query_one<P: rusqlite::Params>(
    c: &Connection,
    sql: &str,
    p: P,
) -> Result<Option<ScanReport>, StoreError> {
    let json = c.query_row(sql, p, |r| r.get::<_, String>(0)).optional()?;
    json.map(|v| serde_json::from_str(&v).map_err(Into::into))
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
fn push_filter(sql: &mut String, v: &mut Vec<Value>, column: &str, value: Option<&str>) {
    push_filter_op(sql, v, column, "=", value)
}
fn push_filter_op(
    sql: &mut String,
    v: &mut Vec<Value>,
    column: &str,
    op: &str,
    value: Option<&str>,
) {
    if let Some(value) = value {
        sql.push_str(" AND ");
        sql.push_str(column);
        sql.push(' ');
        sql.push_str(op);
        sql.push_str(" ?");
        v.push(Value::Text(value.to_owned()));
    }
}
fn migration_versions(t: &Transaction<'_>) -> Result<Vec<i64>, rusqlite::Error> {
    let mut s = t.prepare("SELECT version FROM schema_migrations ORDER BY version")?;
    let rows = s.query_map([], |r| r.get(0))?;
    rows.collect()
}
fn validate_migration_versions(versions: &[i64]) -> Result<(), StoreError> {
    for (expected, actual) in (1_i64..).zip(versions.iter().copied()) {
        if expected != actual {
            return Err(StoreError::InvalidMigrationHistory(format!(
                "expected version {expected}, found {actual}"
            )));
        }
    }
    Ok(())
}
fn monitor_data_error(index: usize, error: impl std::fmt::Display) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        rusqlite::types::Type::Text,
        Box::new(StoreError::InvalidMonitorData(error.to_string())),
    )
}
fn read_monitor_target(r: &rusqlite::Row<'_>) -> Result<MonitorTarget, rusqlite::Error> {
    let interval: i64 = r.get(2)?;
    let interval_seconds = u64::try_from(interval).map_err(|e| monitor_data_error(2, e))?;
    let inventory: Option<String> = r.get(5)?;
    let inventory = inventory
        .map(|x| serde_json::from_str(&x).map_err(|e| monitor_data_error(5, e)))
        .transpose()?;
    let findings: String = r.get(8)?;
    let finding_ids = serde_json::from_str(&findings).map_err(|e| monitor_data_error(8, e))?;
    Ok(MonitorTarget {
        target_id: r.get(0)?,
        source: r.get(1)?,
        interval_seconds,
        next_due_at: r.get(3)?,
        source_fingerprint: r.get(4)?,
        inventory,
        advisory_digest: r.get(6)?,
        policy_digest: r.get(7)?,
        finding_ids,
        updated_at: r.get(9)?,
    })
}
fn read_monitor_event(r: &rusqlite::Row<'_>) -> Result<MonitorEvent, rusqlite::Error> {
    let payload: String = r.get(4)?;
    let payload = serde_json::from_str(&payload).map_err(|e| monitor_data_error(4, e))?;
    let attempts: i64 = r.get(6)?;
    let attempts = u64::try_from(attempts).map_err(|e| monitor_data_error(6, e))?;
    Ok(MonitorEvent {
        event_id: r.get(0)?,
        target_id: r.get(1)?,
        dedupe_key: r.get(2)?,
        kind: r.get(3)?,
        payload,
        created_at: r.get(5)?,
        attempts,
        next_attempt_at: r.get(7)?,
        delivered_at: r.get(8)?,
        dead_lettered_at: r.get(9)?,
        last_error: r.get(10)?,
    })
}
fn collect_sql_rows<T, F>(rows: rusqlite::MappedRows<'_, F>) -> Result<Vec<T>, StoreError>
where
    F: FnMut(&rusqlite::Row<'_>) -> Result<T, rusqlite::Error>,
{
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Asset, AssetId, AssetKind, Component, ComponentId, Confidence, DependencyEdge, Evidence,
        FindingStatus, Inventory, PolicyDecision, PolicyId, PolicyOutcome, PolicySummary,
        Remediation, RuleId, RunMetadata, Scope, Severity,
    };
    use std::{
        collections::{BTreeMap, BTreeSet},
        thread,
    };
    use tempfile::tempdir;

    fn finding(id: &str) -> Finding {
        Finding {
            id: FindingId::new(id).unwrap(),
            kind: FindingKind::Sast,
            rule_id: RuleId::new(format!("rule:{id}")).unwrap(),
            advisory_id: None,
            component_id: None,
            location_id: None,
            aliases: BTreeSet::new(),
            summary: None,
            details: None,
            severity: Severity::High,
            confidence: Confidence::High,
            evidence: BTreeSet::new(),
            applicability: None,
            remediation: None,
            risk: None,
            first_seen: None,
            last_seen: None,
            modified: None,
            status: FindingStatus::Open,
        }
    }
    fn report(id: &str, time: &str, ids: &[&str]) -> ScanReport {
        ScanReport {
            schema_version: "1".into(),
            run: RunMetadata {
                id: RunId::new(id).unwrap(),
                started_at: time.into(),
                completed_at: Some(time.into()),
                scanner_version: Some("test".into()),
                metadata: BTreeMap::new(),
            },
            inventory: Inventory {
                asset: Asset {
                    id: AssetId::new("asset:test").unwrap(),
                    name: "test".into(),
                    kind: AssetKind::Repository,
                    version: None,
                    metadata: BTreeMap::new(),
                },
                components: BTreeMap::new(),
                dependencies: BTreeSet::<DependencyEdge>::new(),
            },
            findings: ids
                .iter()
                .map(|id| {
                    let f = finding(id);
                    (f.id.clone(), f)
                })
                .collect(),
            policy_decisions: BTreeSet::new(),
            policy_summary: PolicySummary::default(),
        }
    }

    fn component(id: &str, name: &str, purl: &str, scope: Scope) -> Component {
        Component {
            identity: ComponentId::new(id).unwrap(),
            name: name.into(),
            version: "1.0.0".into(),
            purl: purl.into(),
            scope,
            provenance: BTreeSet::new(),
            licenses: BTreeSet::new(),
            locations: BTreeSet::new(),
        }
    }

    fn rich_report(id: &str, time: &str, asset_id: &str) -> ScanReport {
        let mut r = report(id, time, &["finding:rich"]);
        r.inventory.asset.id = AssetId::new(asset_id).unwrap();
        r.inventory.asset.name = format!("asset-{id}");
        let c = component(
            "component:rich",
            "rich-component",
            "pkg:cargo/rich@1.0.0",
            Scope::Runtime,
        );
        r.inventory.components.insert(c.identity.clone(), c.clone());
        let f = r
            .findings
            .get_mut(&FindingId::new("finding:rich").unwrap())
            .unwrap();
        f.kind = FindingKind::Vulnerability;
        f.advisory_id = Some("GHSA-test".into());
        f.component_id = Some(c.identity);
        f.status = FindingStatus::Suppressed;
        r
    }

    fn target(id: &str, due: &str) -> MonitorTarget {
        MonitorTarget {
            target_id: id.into(),
            source: "repo".into(),
            interval_seconds: 60,
            next_due_at: due.into(),
            source_fingerprint: Some("fingerprint".into()),
            inventory: Some(serde_json::json!({"components": 1})),
            advisory_digest: Some("advisories".into()),
            policy_digest: Some("policy".into()),
            finding_ids: vec!["finding:1".into()],
            updated_at: "2026-01-01Z".into(),
        }
    }

    fn event(id: &str, target_id: &str, due: Option<&str>) -> MonitorEvent {
        MonitorEvent {
            event_id: id.into(),
            target_id: target_id.into(),
            dedupe_key: format!("dedupe:{id}"),
            kind: "changed".into(),
            payload: serde_json::json!({"event": id}),
            created_at: "2026-01-01Z".into(),
            attempts: 0,
            next_attempt_at: due.map(str::to_owned),
            delivered_at: None,
            dead_lettered_at: None,
            last_error: None,
        }
    }

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
    fn optimistic_documents_conflict_and_audit() {
        let mut s = Store::open_memory().unwrap();
        let d = serde_json::json!({"deny":true});
        assert_eq!(
            s.put_policy("default", &d, 0, "2026-01-01Z", "security")
                .unwrap()
                .version,
            1
        );
        assert!(matches!(
            s.put_policy("default", &d, 0, "2026-01-02Z", "security"),
            Err(StoreError::VersionConflict {
                actual: Some(1),
                ..
            })
        ));
        assert_eq!(
            s.list_audit_events(10, 0).unwrap()[0].resource_id,
            "default"
        );
    }
    #[test]
    fn monitor_roundtrip_dedupe_and_order() {
        let mut s = Store::open_memory().unwrap();
        for (id, due) in [("b", "2026-01-02Z"), ("a", "2026-01-02Z")] {
            s.upsert_monitor_target(&MonitorTarget {
                target_id: id.into(),
                source: "repo".into(),
                interval_seconds: 60,
                next_due_at: due.into(),
                source_fingerprint: None,
                inventory: None,
                advisory_digest: None,
                policy_digest: None,
                finding_ids: vec![],
                updated_at: "2026-01-01Z".into(),
            })
            .unwrap();
        }
        assert_eq!(
            s.list_due_monitor_targets("2026-01-02Z", 10, 0)
                .unwrap()
                .iter()
                .map(|x| x.target_id.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        let e = MonitorEvent {
            event_id: "e1".into(),
            target_id: "a".into(),
            dedupe_key: "d1".into(),
            kind: "changed".into(),
            payload: serde_json::json!({"x":1}),
            created_at: "2026-01-01Z".into(),
            attempts: 0,
            next_attempt_at: None,
            delivered_at: None,
            dead_lettered_at: None,
            last_error: None,
        };
        assert!(s.append_monitor_event(&e).unwrap());
        assert!(
            !s.append_monitor_event(&MonitorEvent {
                event_id: "e2".into(),
                ..e
            })
            .unwrap()
        );
    }
    #[test]
    fn migrates_v1_fixture_transactionally() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db");
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch("CREATE TABLE scan_runs(run_id TEXT PRIMARY KEY NOT NULL,schema_version TEXT NOT NULL,started_at TEXT NOT NULL,completed_at TEXT,finding_count INTEGER NOT NULL,report_json TEXT NOT NULL) STRICT; CREATE TABLE scan_findings(run_id TEXT NOT NULL,finding_id TEXT NOT NULL,kind TEXT NOT NULL,severity TEXT NOT NULL,rule_id TEXT NOT NULL,component_id TEXT,location_id TEXT,PRIMARY KEY(run_id,finding_id),FOREIGN KEY(run_id) REFERENCES scan_runs(run_id) ON DELETE CASCADE) STRICT, WITHOUT ROWID;").unwrap();
            let r = report("legacy", "2026-01-01Z", &["f1"]);
            c.execute(
                "INSERT INTO scan_runs VALUES (?1,'1','2026-01-01Z',NULL,1,?2)",
                params![r.run.id.as_str(), serde_json::to_string(&r).unwrap()],
            )
            .unwrap();
            c.execute("INSERT INTO scan_findings(run_id,finding_id,kind,severity,rule_id) VALUES ('legacy','f1','sast','high','r')",[]).unwrap();
        }
        let s = Store::open(&path).unwrap();
        assert!(s.get_run(&RunId::new("legacy").unwrap()).unwrap().is_some());
        assert_eq!(
            s.connection
                .query_row("SELECT max(version) FROM schema_migrations", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
    }
    #[test]
    fn rejects_gapped_and_future_migration_histories() {
        for (version, error_kind) in [(2, "gap"), (3, "future")] {
            let dir = tempdir().unwrap();
            let path = dir.path().join(format!("{error_kind}.db"));
            let c = Connection::open(&path).unwrap();
            c.execute_batch("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY NOT NULL CHECK(version>0),name TEXT NOT NULL UNIQUE,applied_at TEXT NOT NULL) STRICT;").unwrap();
            c.execute(
                "INSERT INTO schema_migrations VALUES (?1,'bad','t')",
                [version],
            )
            .unwrap();
            drop(c);
            let error = Store::open(&path).err().unwrap();
            if version == 2 {
                assert!(matches!(error, StoreError::InvalidMigrationHistory(_)));
            } else {
                assert!(matches!(
                    error,
                    StoreError::InvalidMigrationHistory(_)
                        | StoreError::UnsupportedSchemaVersion { .. }
                ));
            }
        }
    }
    #[test]
    fn factory_connections_handle_busy_without_corruption() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db");
        let factory = StoreFactory::new(path);
        let mut first = factory.open().unwrap();
        let second = factory.clone();
        let tx = first.connection.transaction().unwrap();
        tx.execute("INSERT INTO audit_events(event_id,occurred_at,actor,action,resource_type,resource_id,details_json) VALUES ('held','t','a','x','r','1','{}')",[]).unwrap();
        let handle = thread::spawn(move || {
            let mut s = second.open().unwrap();
            s.put_policy("p", &serde_json::json!({}), 0, "t2", "a")
        });
        thread::sleep(Duration::from_millis(50));
        tx.commit().unwrap();
        assert!(handle.join().unwrap().is_ok());
        let s = factory.open().unwrap();
        assert_eq!(s.get_policy("p").unwrap().unwrap().version, 1);
        assert_eq!(
            s.connection
                .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
    }
    #[test]
    fn file_reopen_duplicate_run_and_factory_paths_preserve_committed_state() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested-store.sqlite");
        assert!(matches!(
            Store::open(dir.path()),
            Err(StoreError::Sqlite(_))
        ));
        let factory = StoreFactory::new(&path);
        let mut first = factory.open().unwrap();
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
        assert_eq!(factory.open().unwrap().list_runs(10, 0).unwrap().len(), 1);
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
    fn pagination_rejects_zero_oversize_and_unrepresentable_offsets() {
        let s = Store::open_memory().unwrap();
        for limit in [0, MAX_PAGE_SIZE + 1] {
            assert!(matches!(
                s.list_runs(limit, 0),
                Err(StoreError::InvalidPageLimit(value)) if value == limit
            ));
            assert!(matches!(
                s.query_findings(&FindingFilter::default(), limit, 0),
                Err(StoreError::InvalidPageLimit(value)) if value == limit
            ));
            assert!(matches!(
                s.query_inventory(&InventoryFilter::default(), limit, 0),
                Err(StoreError::InvalidPageLimit(value)) if value == limit
            ));
            assert!(matches!(
                s.list_audit_events(limit, 0),
                Err(StoreError::InvalidPageLimit(value)) if value == limit
            ));
            assert!(matches!(
                s.list_due_monitor_targets("z", limit, 0),
                Err(StoreError::InvalidPageLimit(value)) if value == limit
            ));
            assert!(matches!(
                s.list_monitor_events(&MonitorEventFilter::default(), limit, 0),
                Err(StoreError::InvalidPageLimit(value)) if value == limit
            ));
        }
        if i64::try_from(u64::MAX).is_err() {
            assert!(matches!(
                s.query_history(&HistoryFilter::default(), 1, u64::MAX),
                Err(StoreError::InvalidPageOffset(u64::MAX))
            ));
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
    fn monitor_event_claim_is_exactly_once_across_connections() {
        use std::sync::{Arc, Barrier};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("claims.db");
        let mut setup = Store::open(&path).unwrap();
        setup
            .upsert_monitor_target(&target("target", "2026-01-01Z"))
            .unwrap();
        setup
            .append_monitor_event(&event("event", "target", Some("2026-01-01Z")))
            .unwrap();
        drop(setup);

        let barrier = Arc::new(Barrier::new(3));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let mut store = Store::open(path).unwrap();
                    barrier.wait();
                    store
                        .claim_monitor_events("2026-01-01Z", "2026-01-02Z", 1)
                        .unwrap()
                        .len()
                })
            })
            .collect();
        barrier.wait();
        assert_eq!(
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .sum::<usize>(),
            1
        );
    }

    #[test]
    fn policy_and_exception_lifecycle_missing_conflicts_and_audit_pagination() {
        let mut s = Store::open_memory().unwrap();
        assert_eq!(s.get_policy("missing").unwrap(), None);
        assert_eq!(s.get_exception("missing").unwrap(), None);
        let p1 = s
            .put_policy("p", &serde_json::json!({"deny": true}), 0, "t1", "alice")
            .unwrap();
        let p2 = s
            .put_policy("p", &serde_json::json!({"deny": false}), 1, "t2", "bob")
            .unwrap();
        assert_eq!(p2.version, 2);
        assert_eq!(s.get_policy("p").unwrap(), Some(p2.clone()));
        let e1 = s
            .put_exception(
                "e",
                &serde_json::json!({"reason": "approved"}),
                Some("t9"),
                0,
                "t3",
                "alice",
            )
            .unwrap();
        let e2 = s
            .put_exception(
                "e",
                &serde_json::json!({"reason": "extended"}),
                None,
                1,
                "t4",
                "bob",
            )
            .unwrap();
        assert_eq!(e1.version, 1);
        assert_eq!(s.get_exception("e").unwrap(), Some(e2));
        assert!(matches!(
            s.put_exception("missing", &serde_json::json!({}), None, 1, "t", "a"),
            Err(StoreError::VersionConflict { actual: None, .. })
        ));
        assert!(matches!(
            s.put_policy("p", &serde_json::json!({}), p1.version, "t", "a"),
            Err(StoreError::VersionConflict {
                actual: Some(2),
                ..
            })
        ));
        assert_eq!(
            s.list_audit_events(2, 1)
                .unwrap()
                .iter()
                .map(|e| e.resource_id.as_str())
                .collect::<Vec<_>>(),
            vec!["e", "p"]
        );
        s.connection
            .execute("DELETE FROM policy_documents WHERE document_id='p'", [])
            .unwrap();
        s.connection
            .execute("DELETE FROM policy_exceptions WHERE exception_id='e'", [])
            .unwrap();
        assert_eq!(s.get_policy("p").unwrap(), None);
        assert_eq!(s.get_exception("e").unwrap(), None);
    }

    #[test]
    fn monitor_missing_updates_filters_terminal_states_and_pruning() {
        let mut s = Store::open_memory().unwrap();
        assert_eq!(s.get_monitor_target("missing").unwrap(), None);
        assert_eq!(s.get_monitor_cursor("missing").unwrap(), None);
        assert!(!s.update_monitor_target(&target("missing", "t")).unwrap());
        assert!(
            !s.update_monitor_event(&event("missing", "missing", None))
                .unwrap()
        );

        let mut t = target("target", "2026-01-03Z");
        s.upsert_monitor_target(&t).unwrap();
        t.source = "updated".into();
        t.next_due_at = "2026-01-02Z".into();
        assert!(s.update_monitor_target(&t).unwrap());
        assert_eq!(s.get_monitor_target("target").unwrap(), Some(t.clone()));
        assert!(
            s.list_due_monitor_targets("2026-01-01Z", 10, 0)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            s.list_due_monitor_targets("2026-01-02Z", 10, 0).unwrap()[0],
            t
        );

        let mut cursor = MonitorCursor {
            name: "osv".into(),
            cursor: Some("1".into()),
            etag: None,
            last_modified: None,
            advisory_digest: None,
            updated_at: "t1".into(),
        };
        s.set_monitor_cursor(&cursor).unwrap();
        cursor.cursor = Some("2".into());
        cursor.etag = Some("etag".into());
        s.set_monitor_cursor(&cursor).unwrap();
        assert_eq!(s.get_monitor_cursor("osv").unwrap(), Some(cursor));

        let pending = event("pending", "target", Some("2026-01-02Z"));
        let mut delivered = event("delivered", "target", None);
        delivered.delivered_at = Some("2026-01-03Z".into());
        let mut dead = event("dead", "target", None);
        dead.dead_lettered_at = Some("2026-01-03Z".into());
        for e in [&pending, &delivered, &dead] {
            assert!(s.append_monitor_event(e).unwrap());
        }
        assert_eq!(
            s.list_monitor_events(&MonitorEventFilter::default(), 10, 0)
                .unwrap()
                .iter()
                .map(|e| e.event_id.as_str())
                .collect::<Vec<_>>(),
            vec!["pending"]
        );
        assert_eq!(
            s.list_monitor_events(
                &MonitorEventFilter {
                    target_id: Some("target".into()),
                    due_through: Some("2026-01-02Z".into()),
                    include_delivered: true,
                    include_dead_lettered: true
                },
                10,
                0
            )
            .unwrap()
            .len(),
            3
        );
        assert!(
            s.list_monitor_events(
                &MonitorEventFilter {
                    target_id: Some("other".into()),
                    include_delivered: true,
                    include_dead_lettered: true,
                    ..Default::default()
                },
                10,
                0
            )
            .unwrap()
            .is_empty()
        );
        assert_eq!(
            s.list_monitor_events(
                &MonitorEventFilter {
                    include_delivered: true,
                    ..Default::default()
                },
                10,
                0
            )
            .unwrap()
            .iter()
            .map(|e| e.event_id.as_str())
            .collect::<Vec<_>>(),
            vec!["delivered", "pending"]
        );
        assert_eq!(
            s.list_monitor_events(
                &MonitorEventFilter {
                    include_dead_lettered: true,
                    ..Default::default()
                },
                10,
                0
            )
            .unwrap()
            .iter()
            .map(|e| e.event_id.as_str())
            .collect::<Vec<_>>(),
            vec!["dead", "pending"]
        );
        let mut updated = pending.clone();
        updated.attempts = 2;
        updated.last_error = Some("temporary".into());
        assert!(s.update_monitor_event(&updated).unwrap());
        assert_eq!(
            s.list_monitor_events(&MonitorEventFilter::default(), 10, 0)
                .unwrap()[0]
                .attempts,
            2
        );
        assert_eq!(s.prune_monitor_before("2026-02-01Z").unwrap(), 2);
        assert_eq!(
            s.list_monitor_events(
                &MonitorEventFilter {
                    include_delivered: true,
                    include_dead_lettered: true,
                    ..Default::default()
                },
                10,
                0
            )
            .unwrap()
            .len(),
            1
        );
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
    fn malformed_documents_audit_and_monitor_rows_fail_closed() {
        let mut s = Store::open_memory().unwrap();
        s.put_policy("p", &serde_json::json!({}), 0, "t", "actor")
            .unwrap();
        s.connection
            .pragma_update(None, "ignore_check_constraints", "ON")
            .unwrap();
        s.connection
            .execute(
                "UPDATE policy_documents SET document_json='not-json' WHERE document_id='p'",
                [],
            )
            .unwrap();
        assert!(matches!(
            s.get_policy("p"),
            Err(StoreError::Serialization(_))
        ));
        s.connection
            .execute(
                "UPDATE policy_documents SET document_json='{}',version=-1 WHERE document_id='p'",
                [],
            )
            .unwrap();
        assert!(matches!(
            s.get_policy("p"),
            Err(StoreError::VersionOverflow)
        ));
        s.connection
            .execute("UPDATE audit_events SET details_json='not-json'", [])
            .unwrap();
        assert!(matches!(
            s.list_audit_events(10, 0),
            Err(StoreError::Serialization(_))
        ));

        s.upsert_monitor_target(&target("target", "t")).unwrap();
        s.connection
            .execute(
                "UPDATE monitor_targets SET finding_ids_json='[1]' WHERE target_id='target'",
                [],
            )
            .unwrap();
        assert!(matches!(
            s.get_monitor_target("target"),
            Err(StoreError::Sqlite(_))
        ));
        s.connection.execute("UPDATE monitor_targets SET finding_ids_json='[]',inventory_json='not-json' WHERE target_id='target'", []).unwrap();
        assert!(matches!(
            s.get_monitor_target("target"),
            Err(StoreError::Sqlite(_))
        ));
        s.connection.execute("UPDATE monitor_targets SET finding_ids_json='[]',interval_seconds=-1 WHERE target_id='target'", []).unwrap();
        assert!(matches!(
            s.list_due_monitor_targets("z", 10, 0),
            Err(StoreError::Sqlite(_))
        ));
        s.connection
            .execute(
                "UPDATE monitor_targets SET interval_seconds=60 WHERE target_id='target'",
                [],
            )
            .unwrap();
        s.append_monitor_event(&event("event", "target", None))
            .unwrap();
        s.connection
            .execute(
                "UPDATE monitor_events SET payload_json='not-json' WHERE event_id='event'",
                [],
            )
            .unwrap();
        assert!(matches!(
            s.list_monitor_events(&MonitorEventFilter::default(), 10, 0),
            Err(StoreError::Sqlite(_))
        ));
        s.connection
            .execute(
                "UPDATE monitor_events SET payload_json='{}',attempts=-1 WHERE event_id='event'",
                [],
            )
            .unwrap();
        assert!(matches!(
            s.list_monitor_events(&MonitorEventFilter::default(), 10, 0),
            Err(StoreError::Sqlite(_))
        ));
    }

    #[test]
    fn numeric_overflow_inputs_are_rejected_before_sqlite_mutation() {
        let mut s = Store::open_memory().unwrap();
        let mut t = target("overflow", "t");
        t.interval_seconds = u64::MAX;
        assert!(matches!(
            s.upsert_monitor_target(&t),
            Err(StoreError::VersionOverflow)
        ));
        assert_eq!(s.get_monitor_target("overflow").unwrap(), None);
        let mut e = event("overflow", "overflow", None);
        e.attempts = u64::MAX;
        assert!(matches!(
            s.append_monitor_event(&e),
            Err(StoreError::VersionOverflow)
        ));

        s.connection
            .execute(
                "INSERT INTO policy_documents VALUES ('max',?1,'{}','t','a')",
                [i64::MAX],
            )
            .unwrap();
        assert!(matches!(
            s.put_policy("max", &serde_json::json!({}), i64::MAX as u64, "t2", "a"),
            Err(StoreError::VersionOverflow)
        ));
    }

    #[test]
    fn corrupt_initial_schema_report_aborts_migration_without_destroying_source_tables() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("corrupt-initial.db");
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch("CREATE TABLE scan_runs(run_id TEXT PRIMARY KEY NOT NULL,schema_version TEXT NOT NULL,started_at TEXT NOT NULL,completed_at TEXT,finding_count INTEGER NOT NULL,report_json TEXT NOT NULL) STRICT; CREATE TABLE scan_findings(run_id TEXT NOT NULL,finding_id TEXT NOT NULL,kind TEXT NOT NULL,severity TEXT NOT NULL,rule_id TEXT NOT NULL,component_id TEXT,location_id TEXT,PRIMARY KEY(run_id,finding_id),FOREIGN KEY(run_id) REFERENCES scan_runs(run_id) ON DELETE CASCADE) STRICT, WITHOUT ROWID;").unwrap();
            c.execute(
                "INSERT INTO scan_runs VALUES ('broken','1','t',NULL,0,'{}')",
                [],
            )
            .unwrap();
        }
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::Serialization(_))
        ));
        let c = Connection::open(&path).unwrap();
        assert_eq!(
            c.query_row(
                "SELECT report_json FROM scan_runs WHERE run_id='broken'",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "{}"
        );
        assert!(!c.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations')", [], |r| r.get::<_, bool>(0)).unwrap());
    }

    #[test]
    fn contiguous_future_schema_version_is_rejected_as_unsupported() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("future.db");
        let c = Connection::open(&path).unwrap();
        c.execute_batch("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY NOT NULL CHECK(version>0),name TEXT NOT NULL UNIQUE,applied_at TEXT NOT NULL) STRICT; INSERT INTO schema_migrations VALUES (1,'one','t'),(2,'two','t'),(3,'three','t');").unwrap();
        drop(c);
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::UnsupportedSchemaVersion {
                found: 3,
                supported: 2
            })
        ));
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
}
