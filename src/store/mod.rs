//! SQLite persistence for scan reports and monitor state.
//!
//! Destructive verbs follow a fixed naming convention so callers can predict
//! behavior from the name alone: `remove_*` deletes a single identified row
//! and reports whether it existed; `prune_*` bulk-deletes rows older than a
//! cutoff and returns how many were removed; `delete_*` is the retained
//! report-history spelling of the same time-based retention over
//! `scan_runs`, recorded in `retention_events`. Existing names are public
//! API and are not renamed to enforce the convention retroactively.
use std::{
    io,
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{Connection, Transaction, TransactionBehavior, types::Value};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use thiserror::Error;

use crate::model::{Finding, FindingId, ModelInvariantError, RunId, ScanReport};

mod document;
mod monitor;
mod report;

use self::report::{ensure_supported_report_schema, insert_report, reject_unredacted_secrets};

const CORE_SCHEMA: &str = include_str!("../../migrations/001_init.sql");
const MONITOR_SCHEMA: &str = include_str!("../../migrations/002_monitor.sql");
const CURRENT_DATABASE_VERSION: i64 = 2;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_PAGE_SIZE: u32 = 1_000;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("SQLite store operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("report serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("report redaction failed: {0}")]
    Sanitization(String),
    #[error("failed to create private SQLite database {path}: {source}")]
    DatabaseCreate {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
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
    #[error("monitor target '{target_id}' already exists")]
    MonitorTargetExists { target_id: String },
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
    #[error("expected a string scalar, found {0}")]
    UnexpectedScalar(JsonValue),
    #[error("unsupported report schema version: {0}")]
    UnsupportedReportSchema(String),
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

pub struct Store {
    connection: Connection,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        create_private_database_if_missing(path)?;
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
}

#[cfg(unix)]
fn create_private_database_if_missing(path: &Path) -> Result<(), StoreError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    if path == Path::new(":memory:") {
        return Ok(());
    }
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(file) => {
            drop(file);
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(source) => Err(StoreError::DatabaseCreate {
            path: path.to_owned(),
            source,
        }),
    }
}

#[cfg(not(unix))]
fn create_private_database_if_missing(_path: &Path) -> Result<(), StoreError> {
    Ok(())
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
        let report = serde_json::from_str::<ScanReport>(&row?)?;
        ensure_supported_report_schema(&report)?;
        reports.push(report);
    }
    drop(s);
    t.execute_batch("DROP TABLE scan_findings; DROP TABLE scan_runs;")?;
    t.execute_batch(CORE_SCHEMA)?;
    for report in reports {
        reject_unredacted_secrets(&report.findings)?;
        report.validate()?;
        let sanitized = crate::report::sanitize_report(&report)
            .map_err(|error| StoreError::Sanitization(error.to_string()))?;
        let report = &*sanitized;
        let json = serde_json::to_string(report)?;
        let count =
            i64::try_from(report.findings.len()).map_err(|_| StoreError::FindingCountOverflow)?;
        insert_report(t, report, &json, count)?;
    }
    t.execute("INSERT INTO schema_migrations(version,name,applied_at) VALUES (1,'core','1970-01-01T00:00:00Z')",[])?;
    Ok(())
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

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use crate::model::{
        Asset, AssetId, AssetKind, Component, ComponentId, Confidence, DependencyEdge, FindingKind,
        FindingStatus, Inventory, Location, LocationId, PolicySummary, Position, RuleId,
        RunMetadata, Scope, Severity,
    };
    use std::collections::{BTreeMap, BTreeSet};

    pub(crate) fn finding(id: &str) -> Finding {
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
    pub(crate) fn report(id: &str, time: &str, ids: &[&str]) -> ScanReport {
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
                locations: BTreeSet::new(),
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

    pub(crate) fn component(id: &str, name: &str, purl: &str, scope: Scope) -> Component {
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

    pub(crate) fn rich_report(id: &str, time: &str, asset_id: &str) -> ScanReport {
        let mut r = report(id, time, &["finding:rich"]);
        r.inventory.asset.id = AssetId::new(asset_id).unwrap();
        r.inventory.asset.name = format!("asset-{id}");
        r.inventory.locations.insert(Location {
            id: LocationId::new("location:rich").unwrap(),
            asset_id: r.inventory.asset.id.clone(),
            path: "sample.py".into(),
            start: Some(Position { line: 1, column: 1 }),
            end: Some(Position { line: 1, column: 8 }),
        });
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

    pub(crate) fn target(id: &str, due: &str) -> MonitorTarget {
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

    pub(crate) fn event(id: &str, target_id: &str, due: Option<&str>) -> MonitorEvent {
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
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use rusqlite::params;
    use std::thread;
    use tempfile::tempdir;

    #[cfg(unix)]
    #[test]
    fn newly_created_database_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("private.db");
        let store = Store::open(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
            0,
            "scan history must not be readable by group or other users"
        );
        drop(store);
    }

    #[test]
    fn migrates_v1_fixture_transactionally() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db");
        let r = report("legacy", "2026-01-01Z", &["f1"]);
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch("CREATE TABLE scan_runs(run_id TEXT PRIMARY KEY NOT NULL,schema_version TEXT NOT NULL,started_at TEXT NOT NULL,completed_at TEXT,finding_count INTEGER NOT NULL,report_json TEXT NOT NULL) STRICT; CREATE TABLE scan_findings(run_id TEXT NOT NULL,finding_id TEXT NOT NULL,kind TEXT NOT NULL,severity TEXT NOT NULL,rule_id TEXT NOT NULL,component_id TEXT,location_id TEXT,PRIMARY KEY(run_id,finding_id),FOREIGN KEY(run_id) REFERENCES scan_runs(run_id) ON DELETE CASCADE) STRICT, WITHOUT ROWID;").unwrap();
            c.execute(
                "INSERT INTO scan_runs VALUES (?1,'1','2026-01-01Z',NULL,1,?2)",
                params![r.run.id.as_str(), serde_json::to_string(&r).unwrap()],
            )
            .unwrap();
            c.execute("INSERT INTO scan_findings(run_id,finding_id,kind,severity,rule_id) VALUES ('legacy','f1','sast','high','r')",[]).unwrap();
        }
        let s = Store::open(&path).unwrap();
        assert_eq!(s.get_run(&RunId::new("legacy").unwrap()).unwrap(), Some(r));
        assert_eq!(
            s.connection
                .query_row("SELECT max(version) FROM schema_migrations", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
    }
    #[test]
    fn fails_closed_before_drop_on_foreign_legacy_report_schema() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db");
        let r = report("legacy", "2026-01-01Z", &["f1"]);
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch("CREATE TABLE scan_runs(run_id TEXT PRIMARY KEY NOT NULL,schema_version TEXT NOT NULL,started_at TEXT NOT NULL,completed_at TEXT,finding_count INTEGER NOT NULL,report_json TEXT NOT NULL) STRICT; CREATE TABLE scan_findings(run_id TEXT NOT NULL,finding_id TEXT NOT NULL,kind TEXT NOT NULL,severity TEXT NOT NULL,rule_id TEXT NOT NULL,component_id TEXT,location_id TEXT,PRIMARY KEY(run_id,finding_id),FOREIGN KEY(run_id) REFERENCES scan_runs(run_id) ON DELETE CASCADE) STRICT, WITHOUT ROWID;").unwrap();
            let mut json = serde_json::to_value(&r).unwrap();
            json["schema_version"] = serde_json::Value::String("2".into());
            c.execute(
                "INSERT INTO scan_runs VALUES (?1,'2','2026-01-01Z',NULL,1,?2)",
                params![r.run.id.as_str(), serde_json::to_string(&json).unwrap()],
            )
            .unwrap();
        }
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::UnsupportedReportSchema(version)) if version == "2"
        ));
        let survivor = Connection::open(&path).unwrap();
        assert_eq!(
            survivor
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='scan_runs')",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
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
        use std::sync::{Arc, Barrier};

        let dir = tempdir().unwrap();
        let path = dir.path().join("db");
        let mut first = Store::open(&path).unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let barrier = Arc::new(Barrier::new(2));
        let handle = {
            let barrier = barrier.clone();
            let path = path.clone();
            thread::spawn(move || {
                let mut s = Store::open(&path).unwrap();
                ready_tx.send(()).unwrap();
                // Resumes only once the parent holds the uncommitted write
                // transaction below, so put_policy deterministically hits the
                // BUSY_TIMEOUT retry path instead of racing a timing sleep.
                barrier.wait();
                s.put_policy("p", &serde_json::json!({}), 0, "t2", "a")
            })
        };
        // The writer's connection exists before the lock below is taken.
        ready_rx.recv().unwrap();
        let tx = first.connection.transaction().unwrap();
        tx.execute("INSERT INTO audit_events(event_id,occurred_at,actor,action,resource_type,resource_id,details_json) VALUES ('held','t','a','x','r','1','{}')",[]).unwrap();
        barrier.wait();
        tx.commit().unwrap();
        assert!(handle.join().unwrap().is_ok());
        let s = Store::open(&path).unwrap();
        assert_eq!(s.get_policy("p").unwrap().unwrap().version, 1);
        assert_eq!(
            s.connection
                .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
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
}
