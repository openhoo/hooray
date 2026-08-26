use rusqlite::{OptionalExtension, TransactionBehavior, params};

use serde_json::Value as JsonValue;

use super::{AuditEvent, Store, StoreError, VersionedDocument, pagination};

/// Write-side metadata shared by every versioned document put.
struct DocumentWrite<'a> {
    expires_at: Option<&'a str>,
    expected_version: u64,
    updated_at: &'a str,
    updated_by: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DocumentKind {
    Policy,
    Exception,
}

impl DocumentKind {
    fn table(self) -> &'static str {
        match self {
            Self::Policy => "policy_documents",
            Self::Exception => "policy_exceptions",
        }
    }

    fn id_column(self) -> &'static str {
        match self {
            Self::Policy => "document_id",
            Self::Exception => "exception_id",
        }
    }

    fn resource_type(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Exception => "exception",
        }
    }
}

impl Store {
    pub fn get_policy(&self, id: &str) -> Result<Option<VersionedDocument>, StoreError> {
        self.get_document(DocumentKind::Policy, id)
    }
    pub fn get_exception(&self, id: &str) -> Result<Option<VersionedDocument>, StoreError> {
        self.get_document(DocumentKind::Exception, id)
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
            DocumentKind::Policy,
            id,
            document,
            DocumentWrite {
                expires_at: None,
                expected_version,
                updated_at,
                updated_by,
            },
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
            DocumentKind::Exception,
            id,
            document,
            DocumentWrite {
                expires_at,
                expected_version,
                updated_at,
                updated_by,
            },
        )
    }

    fn get_document(
        &self,
        kind: DocumentKind,
        id: &str,
    ) -> Result<Option<VersionedDocument>, StoreError> {
        let sql = format!(
            "SELECT version,document_json,updated_at,updated_by FROM {} WHERE {}=?1",
            kind.table(),
            kind.id_column()
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

    fn put_document(
        &mut self,
        kind: DocumentKind,
        id: &str,
        document: &JsonValue,
        write: DocumentWrite<'_>,
    ) -> Result<VersionedDocument, StoreError> {
        let DocumentWrite {
            expires_at,
            expected_version,
            updated_at,
            updated_by,
        } = write;
        let resource_type = kind.resource_type();
        let json = serde_json::to_string(document)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<i64> = transaction
            .query_row(
                &format!(
                    "SELECT version FROM {} WHERE {}=?1",
                    kind.table(),
                    kind.id_column()
                ),
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
        match kind {
            DocumentKind::Exception => {
                transaction.execute("INSERT INTO policy_exceptions(exception_id,version,document_json,expires_at,updated_at,updated_by) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(exception_id) DO UPDATE SET version=excluded.version,document_json=excluded.document_json,expires_at=excluded.expires_at,updated_at=excluded.updated_at,updated_by=excluded.updated_by",params![id,version_i64,json,expires_at,updated_at,updated_by])?;
            }
            DocumentKind::Policy => {
                transaction.execute("INSERT INTO policy_documents(document_id,version,document_json,updated_at,updated_by) VALUES (?1,?2,?3,?4,?5) ON CONFLICT(document_id) DO UPDATE SET version=excluded.version,document_json=excluded.document_json,updated_at=excluded.updated_at,updated_by=excluded.updated_by",params![id,version_i64,json,updated_at,updated_by])?;
            }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MonitorEventFilter;
    use crate::store::fixtures::{event, target};

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
}
