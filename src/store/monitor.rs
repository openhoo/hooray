use std::collections::HashMap;

use rusqlite::{OptionalExtension, TransactionBehavior, params, params_from_iter, types::Value};

use super::{
    MonitorCursor, MonitorEvent, MonitorEventFilter, MonitorTarget, Store, StoreError, pagination,
    push_filter, push_filter_op,
};
use crate::monitor::encode_time;

fn monitor_data_error(index: usize, error: impl std::fmt::Display) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        rusqlite::types::Type::Text,
        Box::new(StoreError::InvalidMonitorData(error.to_string())),
    )
}
const MONITOR_TARGET_COLUMNS: &str = "target_id,source,interval_seconds,next_due_at,source_fingerprint,inventory_json,advisory_digest,policy_digest,finding_ids_json,updated_at";

/// Precomputed column values for a [`MonitorTarget`] write: everything that
/// needs serialization or range conversion before it can be bound.
struct MonitorTargetEnc {
    interval_seconds: i64,
    inventory_json: Option<String>,
    findings_json: String,
}

fn encode_monitor_target(t: &MonitorTarget) -> Result<MonitorTargetEnc, StoreError> {
    Ok(MonitorTargetEnc {
        interval_seconds: i64::try_from(t.interval_seconds)
            .map_err(|_| StoreError::VersionOverflow)?,
        inventory_json: t
            .inventory
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?,
        findings_json: serde_json::to_string(&t.finding_ids)?,
    })
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

/// Builds a fresh registration target that is immediately due.
///
/// Enforces the registration-time invariant for identifiers and stamps
/// `next_due_at`/`updated_at` from one `now` so the target is schedulable
/// on the next due-listing pass.
impl MonitorTarget {
    pub fn new(
        target_id: String,
        source: String,
        interval_seconds: u64,
        now: i64,
    ) -> Result<Self, StoreError> {
        if target_id.trim().is_empty() {
            return Err(StoreError::InvalidMonitorData(
                "monitor target id must not be blank".into(),
            ));
        }
        let now = encode_time(now);
        Ok(Self {
            target_id,
            source,
            interval_seconds,
            next_due_at: now.clone(),
            source_fingerprint: None,
            inventory: None,
            advisory_digest: None,
            policy_digest: None,
            finding_ids: Vec::new(),
            updated_at: now,
        })
    }
}

impl Store {
    pub fn upsert_monitor_target(&mut self, target: &MonitorTarget) -> Result<(), StoreError> {
        let enc = encode_monitor_target(target)?;
        self.connection.execute("INSERT INTO monitor_targets(target_id,source,interval_seconds,next_due_at,source_fingerprint,inventory_json,advisory_digest,policy_digest,finding_ids_json,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(target_id) DO UPDATE SET source=excluded.source,interval_seconds=excluded.interval_seconds,next_due_at=excluded.next_due_at,source_fingerprint=excluded.source_fingerprint,inventory_json=excluded.inventory_json,advisory_digest=excluded.advisory_digest,policy_digest=excluded.policy_digest,finding_ids_json=excluded.finding_ids_json,updated_at=excluded.updated_at",params![target.target_id,target.source,enc.interval_seconds,target.next_due_at,target.source_fingerprint,enc.inventory_json,target.advisory_digest,target.policy_digest,enc.findings_json,target.updated_at])?;
        Ok(())
    }
    pub fn get_monitor_target(&self, id: &str) -> Result<Option<MonitorTarget>, StoreError> {
        self.connection
            .query_row(
                &format!("SELECT {MONITOR_TARGET_COLUMNS} FROM monitor_targets WHERE target_id=?1"),
                [id],
                read_monitor_target,
            )
            .optional()
            .map_err(Into::into)
    }
    pub fn list_due_monitor_targets(
        &self,
        through: &str,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<MonitorTarget>, StoreError> {
        let (limit, offset) = pagination(limit, offset)?;
        let mut s=self.connection.prepare(&format!("SELECT {MONITOR_TARGET_COLUMNS} FROM monitor_targets WHERE next_due_at<=?1 ORDER BY next_due_at,target_id LIMIT ?2 OFFSET ?3"))?;
        let rows = s.query_map(params![through, limit, offset], read_monitor_target)?;
        collect_sql_rows(rows)
    }
    pub fn update_monitor_target(&mut self, target: &MonitorTarget) -> Result<bool, StoreError> {
        let enc = encode_monitor_target(target)?;
        Ok(self.connection.execute("UPDATE monitor_targets SET source=?2,interval_seconds=?3,next_due_at=?4,source_fingerprint=?5,inventory_json=?6,advisory_digest=?7,policy_digest=?8,finding_ids_json=?9,updated_at=?10 WHERE target_id=?1",params![target.target_id,target.source,enc.interval_seconds,target.next_due_at,target.source_fingerprint,enc.inventory_json,target.advisory_digest,target.policy_digest,enc.findings_json,target.updated_at])?==1)
    }
    pub fn add_monitor_target(&mut self, target: &MonitorTarget) -> Result<(), StoreError> {
        if target.target_id.trim().is_empty() {
            return Err(StoreError::InvalidMonitorData(
                "monitor target id must not be blank".into(),
            ));
        }
        if target.source.trim().is_empty() {
            return Err(StoreError::InvalidMonitorData(
                "monitor target source must not be blank".into(),
            ));
        }
        if target.interval_seconds == 0 {
            return Err(StoreError::InvalidMonitorData(
                "monitor target interval must be greater than zero".into(),
            ));
        }
        if target.next_due_at.trim().is_empty() || target.updated_at.trim().is_empty() {
            return Err(StoreError::InvalidMonitorData(
                "monitor target timestamps must not be blank".into(),
            ));
        }
        if self.get_monitor_target(&target.target_id)?.is_some() {
            return Err(StoreError::MonitorTargetExists {
                target_id: target.target_id.clone(),
            });
        }
        let enc = encode_monitor_target(target)?;
        if let Err(error) = self.connection.execute("INSERT INTO monitor_targets(target_id,source,interval_seconds,next_due_at,source_fingerprint,inventory_json,advisory_digest,policy_digest,finding_ids_json,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",params![target.target_id,target.source,enc.interval_seconds,target.next_due_at,target.source_fingerprint,enc.inventory_json,target.advisory_digest,target.policy_digest,enc.findings_json,target.updated_at]) {
            // All CHECK constraints are pre-validated above and existence was
            // rejected before the insert, so a constraint violation here can
            // only be the primary key (for example a concurrent registration).
            if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                return Err(StoreError::MonitorTargetExists {
                    target_id: target.target_id.clone(),
                });
            }
            return Err(error.into());
        }
        Ok(())
    }
    pub fn list_monitor_targets(
        &self,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<MonitorTarget>, StoreError> {
        let (limit, offset) = pagination(limit, offset)?;
        let mut s=self.connection.prepare(&format!("SELECT {MONITOR_TARGET_COLUMNS} FROM monitor_targets ORDER BY target_id LIMIT ?1 OFFSET ?2"))?;
        let rows = s.query_map(params![limit, offset], read_monitor_target)?;
        collect_sql_rows(rows)
    }
    pub fn remove_monitor_target(&mut self, target_id: &str) -> Result<bool, StoreError> {
        Ok(self.connection.execute(
            "DELETE FROM monitor_targets WHERE target_id=?1",
            [target_id],
        )? == 1)
    }
    pub fn get_monitor_cursor(&self, name: &str) -> Result<Option<MonitorCursor>, StoreError> {
        self.connection.query_row("SELECT name,cursor,etag,last_modified,advisory_digest,updated_at FROM monitor_cursors WHERE name=?1",[name],|r|Ok(MonitorCursor{name:r.get(0)?,cursor:r.get(1)?,etag:r.get(2)?,last_modified:r.get(3)?,advisory_digest:r.get(4)?,updated_at:r.get(5)?})).optional().map_err(Into::into)
    }
    pub fn set_monitor_cursor(&mut self, cursor: &MonitorCursor) -> Result<(), StoreError> {
        self.connection.execute("INSERT INTO monitor_cursors(name,cursor,etag,last_modified,advisory_digest,updated_at) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(name) DO UPDATE SET cursor=excluded.cursor,etag=excluded.etag,last_modified=excluded.last_modified,advisory_digest=excluded.advisory_digest,updated_at=excluded.updated_at",params![cursor.name,cursor.cursor,cursor.etag,cursor.last_modified,cursor.advisory_digest,cursor.updated_at])?;
        Ok(())
    }
    pub fn append_monitor_event(&mut self, event: &MonitorEvent) -> Result<bool, StoreError> {
        let payload = serde_json::to_string(&event.payload)?;
        let attempts = i64::try_from(event.attempts).map_err(|_| StoreError::VersionOverflow)?;
        Ok(self.connection.execute("INSERT OR IGNORE INTO monitor_events(event_id,target_id,dedupe_key,kind,payload_json,created_at,attempts,next_attempt_at,delivered_at,dead_lettered_at,last_error) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",params![event.event_id,event.target_id,event.dedupe_key,event.kind,payload,event.created_at,attempts,event.next_attempt_at,event.delivered_at,event.dead_lettered_at,event.last_error])?==1)
    }
    /// Claims up to `limit` due events for delivery, leasing them until
    /// `lease_until`.
    ///
    /// Exactly-once across connections: an event is returned to at most one
    /// caller even when several race (`UPDATE .. RETURNING` under a single
    /// Immediate transaction; the due predicates skip rows another caller
    /// leased between the pre-select and the write). Idle polls never take
    /// the write lock. Events stay claimed - and invisible to later claims -
    /// until `lease_until` passes, so callers must persist delivery results
    /// (or restamp the lease) before it expires.
    pub fn claim_monitor_events(
        &mut self,
        due_through: &str,
        lease_until: &str,
        limit: u32,
    ) -> Result<Vec<MonitorEvent>, StoreError> {
        let (limit, _) = pagination(limit, 0)?;
        // Pre-select due ids on the plain connection first: idle polls must
        // not take the write lock, so the Immediate transaction below is only
        // opened when there is something to claim.
        let event_ids = {
            let mut statement = self.connection.prepare(
                "SELECT event_id FROM monitor_events WHERE coalesce(next_attempt_at,created_at)<=?1 AND delivered_at IS NULL AND dead_lettered_at IS NULL ORDER BY coalesce(next_attempt_at,created_at),created_at,event_id LIMIT ?2",
            )?;
            statement
                .query_map(params![due_through, limit], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        if event_ids.is_empty() {
            return Ok(Vec::new());
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Set-based claim: one UPDATE ... RETURNING claims exactly the rows
        // this transaction transitions. The due predicates mirror the
        // pre-select, so a concurrent connection that leased a row between
        // the pre-select and this Immediate transaction (writers serialize
        // on the write lock) updates nothing for that row and it is not
        // returned - exactly-once across connections.
        let placeholders = vec!["?"; event_ids.len()].join(",");
        let mut statement = transaction.prepare(&format!(
            "UPDATE monitor_events SET next_attempt_at=?1 WHERE event_id IN ({placeholders}) AND coalesce(next_attempt_at,created_at)<=?{due} AND delivered_at IS NULL AND dead_lettered_at IS NULL RETURNING event_id,target_id,dedupe_key,kind,payload_json,created_at,attempts,next_attempt_at,delivered_at,dead_lettered_at,last_error",
            due = event_ids.len() + 2,
        ))?;
        let rows = statement.query_map(
            params_from_iter(
                std::iter::once(lease_until)
                    .chain(event_ids.iter().map(String::as_str))
                    .chain(std::iter::once(due_through)),
            ),
            read_monitor_event,
        )?;
        let mut claimed: HashMap<String, MonitorEvent> = HashMap::with_capacity(event_ids.len());
        for row in rows {
            let event = row?;
            claimed.insert(event.event_id.clone(), event);
        }
        drop(statement);
        let mut events = Vec::with_capacity(event_ids.len());
        for id in &event_ids {
            // Rows the predicate skipped were claimed by a concurrent
            // connection; they are intentionally absent from this batch.
            if let Some(event) = claimed.remove(id) {
                events.push(event);
            }
        }
        transaction.commit()?;
        Ok(events)
    }
    pub fn list_monitor_events(
        &self,
        filter: &MonitorEventFilter,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<MonitorEvent>, StoreError> {
        let (limit, offset) = pagination(limit, offset)?;
        let mut sql = String::from(
            "SELECT event_id,target_id,dedupe_key,kind,payload_json,created_at,attempts,next_attempt_at,delivered_at,dead_lettered_at,last_error FROM monitor_events WHERE 1=1",
        );
        let mut v = Vec::new();
        push_filter(&mut sql, &mut v, "target_id", filter.target_id.as_deref());
        push_filter_op(
            &mut sql,
            &mut v,
            "coalesce(next_attempt_at,created_at)",
            "<=",
            filter.due_through.as_deref(),
        );
        if !filter.include_delivered {
            sql.push_str(" AND delivered_at IS NULL");
        }
        if !filter.include_dead_lettered {
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
        // claim_monitor_events leases rows only via next_attempt_at (no token), so a
        // worker whose delivery outlives its lease can race a re-claim. A writer that
        // observed no terminal state must not overwrite a terminal state recorded by a
        // newer claim owner; returning false lets the caller surface the lost claim.
        // Tradeoff: non-terminal bookkeeping (attempts/backoff/last_error) may still
        // interleave between concurrently failing workers, which at-least-once
        // delivery tolerates.
        Ok(self.connection.execute("UPDATE monitor_events SET target_id=?2,dedupe_key=?3,kind=?4,payload_json=?5,created_at=?6,attempts=?7,next_attempt_at=?8,delivered_at=?9,dead_lettered_at=?10,last_error=?11 WHERE event_id=?1 AND (?9 IS NOT NULL OR delivered_at IS NULL) AND (?10 IS NOT NULL OR dead_lettered_at IS NULL)",params![e.event_id,e.target_id,e.dedupe_key,e.kind,payload,e.created_at,attempts,e.next_attempt_at,e.delivered_at,e.dead_lettered_at,e.last_error])?==1)
    }
    pub fn prune_monitor_before(&mut self, timestamp: &str) -> Result<usize, StoreError> {
        Ok(self.connection.execute("DELETE FROM monitor_events WHERE created_at<?1 AND (delivered_at IS NOT NULL OR dead_lettered_at IS NOT NULL)",[timestamp])?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::fixtures::*;

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
    fn stale_expired_lease_write_back_cannot_erase_newer_delivery() {
        let mut s = Store::open_memory().unwrap();
        s.upsert_monitor_target(&target("target", "2026-01-01Z"))
            .unwrap();
        s.append_monitor_event(&event("event", "target", Some("2026-01-01Z")))
            .unwrap();
        // Worker A claims the event with a lease that expires before it finishes.
        let claimed_a = s
            .claim_monitor_events("2026-01-01Z", "2026-01-02Z", 1)
            .unwrap();
        assert_eq!(claimed_a.len(), 1);
        // After that lease expires, worker B re-claims and records delivery.
        let claimed_b = s
            .claim_monitor_events("2026-01-03Z", "2026-01-04Z", 1)
            .unwrap();
        assert_eq!(claimed_b.len(), 1);
        let mut delivered = claimed_b[0].clone();
        delivered.delivered_at = Some("2026-01-03Z".into());
        delivered.next_attempt_at = Some("2026-01-03Z".into());
        assert!(s.update_monitor_event(&delivered).unwrap());
        // Stale worker A writes back its pre-delivery snapshot: this must not
        // erase the newer delivery record or reschedule duplicate delivery.
        let mut stale = claimed_a[0].clone();
        stale.attempts = 1;
        stale.last_error = Some("temporary".into());
        stale.next_attempt_at = Some("2026-01-05Z".into());
        assert!(!s.update_monitor_event(&stale).unwrap());
        let events = s
            .list_monitor_events(
                &MonitorEventFilter {
                    include_delivered: true,
                    ..Default::default()
                },
                10,
                0,
            )
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].delivered_at.as_deref(), Some("2026-01-03Z"));
        assert_eq!(events[0].attempts, 0);
        assert_eq!(events[0].last_error, None);
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
    fn add_monitor_target_inserts_and_lists_in_deterministic_order() {
        let mut s = Store::open_memory().unwrap();
        assert!(s.list_monitor_targets(10, 0).unwrap().is_empty());
        s.add_monitor_target(&target("zeta", "2026-01-01Z"))
            .unwrap();
        s.add_monitor_target(&target("alpha", "2026-01-02Z"))
            .unwrap();
        assert_eq!(
            s.list_monitor_targets(10, 0)
                .unwrap()
                .iter()
                .map(|t| t.target_id.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "zeta"]
        );
        assert_eq!(s.list_monitor_targets(1, 1).unwrap()[0].target_id, "zeta");
        assert!(matches!(
            s.list_monitor_targets(0, 0),
            Err(StoreError::InvalidPageLimit(0))
        ));
    }

    #[test]
    fn duplicate_add_monitor_target_fails_cleanly() {
        let mut s = Store::open_memory().unwrap();
        s.add_monitor_target(&target("target", "2026-01-01Z"))
            .unwrap();
        assert!(matches!(
            s.add_monitor_target(&target("target", "2026-01-02Z")),
            Err(StoreError::MonitorTargetExists { target_id }) if target_id == "target"
        ));
    }

    #[test]
    fn add_monitor_target_rejects_invalid_registrations() {
        let mut s = Store::open_memory().unwrap();
        let mut invalid = target(" ", "2026-01-01Z");
        assert!(matches!(
            s.add_monitor_target(&invalid),
            Err(StoreError::InvalidMonitorData(_))
        ));
        invalid.target_id = "blank-source".into();
        invalid.source = "  ".into();
        assert!(matches!(
            s.add_monitor_target(&invalid),
            Err(StoreError::InvalidMonitorData(_))
        ));
        invalid.source = "repo".into();
        invalid.interval_seconds = 0;
        assert!(matches!(
            s.add_monitor_target(&invalid),
            Err(StoreError::InvalidMonitorData(_))
        ));
        assert!(s.list_monitor_targets(10, 0).unwrap().is_empty());
    }

    #[test]
    fn monitor_target_new_rejects_blank_id_and_stamps_registration_times() {
        assert!(matches!(
            MonitorTarget::new("   ".into(), "repo".into(), 60, 1_700_000_000),
            Err(StoreError::InvalidMonitorData(msg)) if msg.contains("id must not be blank")
        ));
        let encoded = format!("{:020}", 1_700_000_000_u64 ^ (1_u64 << 63));
        let target = MonitorTarget::new("alpha".into(), "repo".into(), 60, 1_700_000_000).unwrap();
        assert_eq!(target.next_due_at, encoded);
        assert_eq!(target.updated_at, encoded);
        assert_eq!(target.interval_seconds, 60);
        assert!(target.source_fingerprint.is_none());
        assert!(target.finding_ids.is_empty());
    }

    #[test]
    fn remove_monitor_target_reports_presence_then_absence_and_cascades_events() {
        let mut s = Store::open_memory().unwrap();
        assert!(!s.remove_monitor_target("target").unwrap());
        s.add_monitor_target(&target("target", "2026-01-02Z"))
            .unwrap();
        s.append_monitor_event(&event("pending", "target", None))
            .unwrap();
        assert!(s.remove_monitor_target("target").unwrap());
        assert_eq!(s.get_monitor_target("target").unwrap(), None);
        assert!(!s.remove_monitor_target("target").unwrap());
        assert!(
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
            .is_empty()
        );
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
}
