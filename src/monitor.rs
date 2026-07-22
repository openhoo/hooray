use std::{collections::BTreeSet, future::Future, pin::Pin, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::model::{FindingId, Inventory};

pub const MAX_TARGET_ID_BYTES: usize = 256;
pub const MAX_SOURCE_BYTES: usize = 4096;
pub const MAX_CURSOR_BYTES: usize = 16 * 1024;
pub const MAX_ETAG_BYTES: usize = 4096;
pub const MAX_ERROR_BYTES: usize = 2048;
pub const MAX_DUE_TARGETS: usize = 10_000;
pub const MAX_DUE_EVENTS: usize = 10_000;
pub const MAX_BACKOFF_SECONDS: i64 = 86_400;
pub type MonitorFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorTarget {
    pub id: String,
    pub source: String,
    pub interval_seconds: i64,
    pub next_due_at: i64,
    pub source_fingerprint: Option<String>,
    pub inventory: Option<Inventory>,
    pub advisory_digest: Option<String>,
    pub policy_digest: Option<String>,
    #[serde(default)]
    pub finding_ids: BTreeSet<FindingId>,
    pub updated_at: i64,
}

impl MonitorTarget {
    pub fn validate(&self) -> Result<(), MonitorError> {
        validate_text("target id", &self.id, MAX_TARGET_ID_BYTES)?;
        validate_text("target source", &self.source, MAX_SOURCE_BYTES)?;
        if self.interval_seconds <= 0 || self.interval_seconds > MAX_BACKOFF_SECONDS {
            return Err(MonitorError::InvalidInterval(self.interval_seconds));
        }
        validate_optional_text(
            "source fingerprint",
            self.source_fingerprint.as_deref(),
            MAX_ETAG_BYTES,
        )?;
        validate_optional_text(
            "advisory digest",
            self.advisory_digest.as_deref(),
            MAX_ETAG_BYTES,
        )?;
        validate_optional_text(
            "policy digest",
            self.policy_digest.as_deref(),
            MAX_ETAG_BYTES,
        )?;
        if let Some(inventory) = &self.inventory {
            inventory.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisoryCursor {
    pub cursor: Option<String>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub digest: Option<String>,
    pub updated_at: Option<i64>,
}

impl AdvisoryCursor {
    pub fn validate(&self) -> Result<(), MonitorError> {
        validate_optional_text("advisory cursor", self.cursor.as_deref(), MAX_CURSOR_BYTES)?;
        validate_optional_text("advisory ETag", self.etag.as_deref(), MAX_ETAG_BYTES)?;
        validate_optional_text(
            "advisory Last-Modified",
            self.last_modified.as_deref(),
            MAX_ETAG_BYTES,
        )?;
        validate_optional_text("advisory digest", self.digest.as_deref(), MAX_ETAG_BYTES)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryRefresh {
    pub cursor: AdvisoryCursor,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evaluation {
    pub inventory: Inventory,
    pub finding_ids: BTreeSet<FindingId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingDiff {
    pub introduced: Vec<FindingId>,
    pub resolved: Vec<FindingId>,
    pub unchanged: Vec<FindingId>,
}

impl FindingDiff {
    fn between(previous: &BTreeSet<FindingId>, current: &BTreeSet<FindingId>) -> Self {
        Self {
            introduced: current.difference(previous).cloned().collect(),
            resolved: previous.difference(current).cloned().collect(),
            unchanged: previous.intersection(current).cloned().collect(),
        }
    }

    fn has_changes(&self) -> bool {
        !self.introduced.is_empty() || !self.resolved.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertPayload {
    pub target_id: String,
    pub evaluated_at: i64,
    pub source_fingerprint: String,
    pub advisory_digest: String,
    pub policy_digest: String,
    pub diff: FindingDiff,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertEvent {
    pub id: String,
    pub dedupe_key: String,
    pub target_id: String,
    pub payload: AlertPayload,
    pub created_at: i64,
    pub attempts: u32,
    pub next_attempt_at: i64,
    pub delivered_at: Option<i64>,
    pub dead_lettered_at: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub initial_backoff_seconds: i64,
    pub max_backoff_seconds: i64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 8,
            initial_backoff_seconds: 5,
            max_backoff_seconds: 3600,
        }
    }
}

impl RetryPolicy {
    fn validate(self) -> Result<(), MonitorError> {
        if self.max_attempts == 0 {
            return Err(MonitorError::InvalidRetryPolicy(
                "max_attempts must be positive",
            ));
        }
        if self.initial_backoff_seconds <= 0
            || self.max_backoff_seconds < self.initial_backoff_seconds
            || self.max_backoff_seconds > MAX_BACKOFF_SECONDS
        {
            return Err(MonitorError::InvalidRetryPolicy(
                "backoff bounds are invalid",
            ));
        }
        Ok(())
    }

    fn delay_after(self, attempts: u32) -> i64 {
        let shift = attempts.saturating_sub(1).min(62);
        self.initial_backoff_seconds
            .saturating_mul(1_i64.checked_shl(shift).unwrap_or(i64::MAX))
            .min(self.max_backoff_seconds)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitorConfig {
    pub batch_size: usize,
    pub event_batch_size: usize,
    pub poll_interval: Duration,
    pub retention_seconds: i64,
    pub retry: RetryPolicy,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            event_batch_size: 100,
            poll_interval: Duration::from_secs(30),
            retention_seconds: 30 * 86_400,
            retry: RetryPolicy::default(),
        }
    }
}

impl MonitorConfig {
    fn validate(self) -> Result<(), MonitorError> {
        if self.batch_size == 0 || self.batch_size > MAX_DUE_TARGETS {
            return Err(MonitorError::InvalidBatchSize(self.batch_size));
        }
        if self.event_batch_size == 0 || self.event_batch_size > MAX_DUE_EVENTS {
            return Err(MonitorError::InvalidEventBatchSize(self.event_batch_size));
        }
        if self.poll_interval.is_zero() || self.retention_seconds <= 0 {
            return Err(MonitorError::InvalidSchedule);
        }
        self.retry.validate()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunSummary {
    pub targets_considered: usize,
    pub targets_scanned: usize,
    pub targets_reevaluated: usize,
    pub events_created: usize,
    pub events_delivered: usize,
    pub events_retried: usize,
    pub events_dead_lettered: usize,
    pub records_pruned: usize,
}

#[derive(Debug, Error)]
pub enum MonitorError {
    #[error("{0} must not be empty")]
    EmptyField(&'static str),
    #[error("{field} exceeds its {maximum}-byte limit")]
    InputTooLong { field: &'static str, maximum: usize },
    #[error("monitor interval must be between 1 and {MAX_BACKOFF_SECONDS} seconds, got {0}")]
    InvalidInterval(i64),
    #[error("invalid target batch size {0}")]
    InvalidBatchSize(usize),
    #[error("invalid event batch size {0}")]
    InvalidEventBatchSize(usize),
    #[error("monitor schedule must use positive poll and retention durations")]
    InvalidSchedule,
    #[error("invalid retry policy: {0}")]
    InvalidRetryPolicy(&'static str),
    #[error("monitor persistence failed: {0}")]
    Persistence(String),
    #[error("monitor runner failed: {0}")]
    Runner(String),
    #[error("monitor notifier failed")]
    Notification,
    #[error("invalid inventory: {0}")]
    InvalidInventory(#[from] crate::model::ModelInvariantError),
}

pub trait Clock: Send + Sync {
    fn now(&self) -> i64;
    fn sleep(&self, duration: Duration) -> MonitorFuture<'_, ()>;
}

#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        chrono::Utc::now().timestamp()
    }

    fn sleep(&self, duration: Duration) -> MonitorFuture<'_, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}

pub trait MonitorRunner: Send + Sync {
    fn refresh_advisories<'a>(
        &'a self,
        cursor: &'a AdvisoryCursor,
    ) -> MonitorFuture<'a, Result<AdvisoryRefresh, MonitorError>>;

    fn policy_digest(&self) -> Result<String, MonitorError>;

    fn source_fingerprint<'a>(
        &'a self,
        target: &'a MonitorTarget,
    ) -> MonitorFuture<'a, Result<String, MonitorError>>;

    fn evaluate<'a>(
        &'a self,
        target: &'a MonitorTarget,
    ) -> MonitorFuture<'a, Result<Evaluation, MonitorError>>;
}

pub trait Notifier: Send + Sync {
    fn notify<'a>(&'a self, event: &'a AlertEvent) -> MonitorFuture<'a, Result<(), String>>;
}

pub trait MonitorRepository: Send {
    fn advisory_cursor(&mut self) -> Result<AdvisoryCursor, MonitorError>;
    fn save_advisory_cursor(&mut self, cursor: &AdvisoryCursor) -> Result<(), MonitorError>;
    fn due_targets(&mut self, now: i64, limit: usize) -> Result<Vec<MonitorTarget>, MonitorError>;
    fn save_target(&mut self, target: &MonitorTarget) -> Result<(), MonitorError>;
    fn enqueue_event(&mut self, event: &AlertEvent) -> Result<bool, MonitorError>;
    fn claim_events(
        &mut self,
        now: i64,
        lease_until: i64,
        limit: usize,
    ) -> Result<Vec<AlertEvent>, MonitorError>;
    fn save_event(&mut self, event: &AlertEvent) -> Result<(), MonitorError>;
    fn prune_before(&mut self, cutoff: i64) -> Result<usize, MonitorError>;
}

impl MonitorRepository for crate::store::Store {
    fn advisory_cursor(&mut self) -> Result<AdvisoryCursor, MonitorError> {
        self.get_monitor_cursor("advisories")
            .map_err(store_error)?
            .map(cursor_from_store)
            .transpose()
            .map(|cursor| cursor.unwrap_or_default())
    }

    fn save_advisory_cursor(&mut self, cursor: &AdvisoryCursor) -> Result<(), MonitorError> {
        let stored = crate::store::MonitorCursor {
            name: "advisories".to_owned(),
            cursor: cursor.cursor.clone(),
            etag: cursor.etag.clone(),
            last_modified: cursor.last_modified.clone(),
            advisory_digest: cursor.digest.clone(),
            updated_at: encode_time(cursor.updated_at.unwrap_or_default()),
        };
        self.set_monitor_cursor(&stored).map_err(store_error)
    }

    fn due_targets(&mut self, now: i64, limit: usize) -> Result<Vec<MonitorTarget>, MonitorError> {
        let limit = u32::try_from(limit).map_err(|_| MonitorError::InvalidBatchSize(limit))?;
        self.list_due_monitor_targets(&encode_time(now), limit, 0)
            .map_err(store_error)?
            .into_iter()
            .map(target_from_store)
            .collect()
    }

    fn save_target(&mut self, target: &MonitorTarget) -> Result<(), MonitorError> {
        let stored = target_to_store(target)?;
        if !self.update_monitor_target(&stored).map_err(store_error)? {
            self.upsert_monitor_target(&stored).map_err(store_error)?;
        }
        Ok(())
    }

    fn enqueue_event(&mut self, event: &AlertEvent) -> Result<bool, MonitorError> {
        self.append_monitor_event(&event_to_store(event)?)
            .map_err(store_error)
    }

    fn claim_events(
        &mut self,
        now: i64,
        lease_until: i64,
        limit: usize,
    ) -> Result<Vec<AlertEvent>, MonitorError> {
        let limit = u32::try_from(limit).map_err(|_| MonitorError::InvalidEventBatchSize(limit))?;
        self.claim_monitor_events(&encode_time(now), &encode_time(lease_until), limit)
            .map_err(store_error)?
            .into_iter()
            .map(event_from_store)
            .collect()
    }

    fn save_event(&mut self, event: &AlertEvent) -> Result<(), MonitorError> {
        if self
            .update_monitor_event(&event_to_store(event)?)
            .map_err(store_error)?
        {
            Ok(())
        } else {
            Err(MonitorError::Persistence(format!(
                "monitor event '{}' disappeared",
                event.id
            )))
        }
    }

    fn prune_before(&mut self, cutoff: i64) -> Result<usize, MonitorError> {
        self.prune_monitor_before(&encode_time(cutoff))
            .map_err(store_error)
    }
}

fn target_to_store(target: &MonitorTarget) -> Result<crate::store::MonitorTarget, MonitorError> {
    Ok(crate::store::MonitorTarget {
        target_id: target.id.clone(),
        source: target.source.clone(),
        interval_seconds: u64::try_from(target.interval_seconds)
            .map_err(|_| MonitorError::InvalidInterval(target.interval_seconds))?,
        next_due_at: encode_time(target.next_due_at),
        source_fingerprint: target.source_fingerprint.clone(),
        inventory: target
            .inventory
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(json_error)?,
        advisory_digest: target.advisory_digest.clone(),
        policy_digest: target.policy_digest.clone(),
        finding_ids: target.finding_ids.iter().map(ToString::to_string).collect(),
        updated_at: encode_time(target.updated_at),
    })
}

fn target_from_store(target: crate::store::MonitorTarget) -> Result<MonitorTarget, MonitorError> {
    Ok(MonitorTarget {
        id: target.target_id,
        source: target.source,
        interval_seconds: i64::try_from(target.interval_seconds)
            .map_err(|_| MonitorError::InvalidInterval(i64::MAX))?,
        next_due_at: decode_time("next_due_at", &target.next_due_at)?,
        source_fingerprint: target.source_fingerprint,
        inventory: target
            .inventory
            .map(serde_json::from_value)
            .transpose()
            .map_err(json_error)?,
        advisory_digest: target.advisory_digest,
        policy_digest: target.policy_digest,
        finding_ids: target
            .finding_ids
            .into_iter()
            .map(|id| {
                FindingId::new(&id).map_err(|_| {
                    MonitorError::Persistence("stored finding id is invalid".to_owned())
                })
            })
            .collect::<Result<_, _>>()?,
        updated_at: decode_time("updated_at", &target.updated_at)?,
    })
}

fn cursor_from_store(cursor: crate::store::MonitorCursor) -> Result<AdvisoryCursor, MonitorError> {
    Ok(AdvisoryCursor {
        cursor: cursor.cursor,
        etag: cursor.etag,
        last_modified: cursor.last_modified,
        digest: cursor.advisory_digest,
        updated_at: Some(decode_time("cursor.updated_at", &cursor.updated_at)?),
    })
}

fn event_to_store(event: &AlertEvent) -> Result<crate::store::MonitorEvent, MonitorError> {
    Ok(crate::store::MonitorEvent {
        event_id: event.id.clone(),
        target_id: event.target_id.clone(),
        dedupe_key: event.dedupe_key.clone(),
        kind: "finding-diff".to_owned(),
        payload: serde_json::to_value(&event.payload).map_err(json_error)?,
        created_at: encode_time(event.created_at),
        attempts: u64::from(event.attempts),
        next_attempt_at: Some(encode_time(event.next_attempt_at)),
        delivered_at: event.delivered_at.map(encode_time),
        dead_lettered_at: event.dead_lettered_at.map(encode_time),
        last_error: event.last_error.clone(),
    })
}

fn event_from_store(event: crate::store::MonitorEvent) -> Result<AlertEvent, MonitorError> {
    Ok(AlertEvent {
        id: event.event_id,
        dedupe_key: event.dedupe_key,
        target_id: event.target_id,
        payload: serde_json::from_value(event.payload).map_err(json_error)?,
        created_at: decode_time("event.created_at", &event.created_at)?,
        attempts: u32::try_from(event.attempts).map_err(|_| {
            MonitorError::Persistence("stored event attempt count is invalid".to_owned())
        })?,
        next_attempt_at: event
            .next_attempt_at
            .as_deref()
            .map(|value| decode_time("event.next_attempt_at", value))
            .transpose()?
            .unwrap_or_default(),
        delivered_at: event
            .delivered_at
            .as_deref()
            .map(|value| decode_time("event.delivered_at", value))
            .transpose()?,
        dead_lettered_at: event
            .dead_lettered_at
            .as_deref()
            .map(|value| decode_time("event.dead_lettered_at", value))
            .transpose()?,
        last_error: event.last_error,
    })
}

fn encode_time(timestamp: i64) -> String {
    format!("{:020}", (timestamp as u64) ^ (1_u64 << 63))
}

fn decode_time(field: &'static str, value: &str) -> Result<i64, MonitorError> {
    let encoded: u64 = value
        .parse()
        .map_err(|_| MonitorError::Persistence(format!("stored {field} timestamp is invalid")))?;
    Ok((encoded ^ (1_u64 << 63)) as i64)
}

fn store_error(error: crate::store::StoreError) -> MonitorError {
    MonitorError::Persistence(error.to_string())
}

fn json_error(error: serde_json::Error) -> MonitorError {
    MonitorError::Persistence(error.to_string())
}

pub struct MonitorService<R, C, W, N> {
    repository: R,
    clock: Arc<C>,
    runner: Arc<W>,
    notifier: Arc<N>,
    config: MonitorConfig,
}

impl<R, C, W, N> MonitorService<R, C, W, N>
where
    R: MonitorRepository,
    C: Clock,
    W: MonitorRunner,
    N: Notifier,
{
    pub fn new(
        repository: R,
        clock: Arc<C>,
        runner: Arc<W>,
        notifier: Arc<N>,
        config: MonitorConfig,
    ) -> Result<Self, MonitorError> {
        config.validate()?;
        Ok(Self {
            repository,
            clock,
            runner,
            notifier,
            config,
        })
    }

    pub fn repository(&self) -> &R {
        &self.repository
    }

    pub fn repository_mut(&mut self) -> &mut R {
        &mut self.repository
    }

    pub async fn run_once(&mut self) -> Result<RunSummary, MonitorError> {
        let now = self.clock.now();
        let old_cursor = self.repository.advisory_cursor()?;
        old_cursor.validate()?;
        let mut refresh = self.runner.refresh_advisories(&old_cursor).await?;
        refresh.cursor.updated_at = Some(now);
        refresh.cursor.validate()?;
        self.repository.save_advisory_cursor(&refresh.cursor)?;

        let advisory_digest = refresh.cursor.digest.clone().unwrap_or_default();
        validate_text("advisory digest", &advisory_digest, MAX_ETAG_BYTES)?;
        let policy_digest = self.runner.policy_digest()?;
        validate_text("policy digest", &policy_digest, MAX_ETAG_BYTES)?;

        let mut summary = RunSummary::default();
        let mut targets = self.repository.due_targets(now, self.config.batch_size)?;
        targets.sort_by(|left, right| {
            (left.next_due_at, &left.id).cmp(&(right.next_due_at, &right.id))
        });
        for mut target in targets {
            target.validate()?;
            summary.targets_considered += 1;
            let fingerprint = match self.runner.source_fingerprint(&target).await {
                Ok(fingerprint) => fingerprint,
                Err(_) => {
                    target.next_due_at =
                        now.saturating_add(self.config.retry.initial_backoff_seconds);
                    target.updated_at = now;
                    self.repository.save_target(&target)?;
                    continue;
                }
            };
            validate_text("source fingerprint", &fingerprint, MAX_ETAG_BYTES)?;
            let source_changed = target.source_fingerprint.as_deref() != Some(fingerprint.as_str());
            let advisory_changed = refresh.changed
                || target.advisory_digest.as_deref() != Some(advisory_digest.as_str());
            let policy_changed = target.policy_digest.as_deref() != Some(policy_digest.as_str());

            let inventory = if source_changed
                || advisory_changed
                || policy_changed
                || target.inventory.is_none()
            {
                summary.targets_scanned +=
                    usize::from(source_changed || target.inventory.is_none());
                summary.targets_reevaluated += 1;
                match self.runner.evaluate(&target).await {
                    Ok(evaluation) => {
                        evaluation.inventory.validate()?;
                        let diff =
                            FindingDiff::between(&target.finding_ids, &evaluation.finding_ids);
                        if diff.has_changes() {
                            let payload = AlertPayload {
                                target_id: target.id.clone(),
                                evaluated_at: now,
                                source_fingerprint: fingerprint.clone(),
                                advisory_digest: advisory_digest.clone(),
                                policy_digest: policy_digest.clone(),
                                diff,
                            };
                            let dedupe_key = digest_json(&(
                                &payload.target_id,
                                &payload.source_fingerprint,
                                &payload.advisory_digest,
                                &payload.policy_digest,
                                &payload.diff,
                            ))?;
                            let event = AlertEvent {
                                id: format!("event-{dedupe_key}"),
                                dedupe_key,
                                target_id: target.id.clone(),
                                payload,
                                created_at: now,
                                attempts: 0,
                                next_attempt_at: now,
                                delivered_at: None,
                                dead_lettered_at: None,
                                last_error: None,
                            };
                            if self.repository.enqueue_event(&event)? {
                                summary.events_created += 1;
                            }
                        }
                        target.finding_ids = evaluation.finding_ids;
                        evaluation.inventory
                    }
                    Err(_) => {
                        target.next_due_at =
                            now.saturating_add(self.config.retry.initial_backoff_seconds);
                        target.updated_at = now;
                        self.repository.save_target(&target)?;
                        continue;
                    }
                }
            } else if let Some(inventory) = target.inventory.clone() {
                inventory
            } else {
                unreachable!("inventory absence is handled by the evaluation branch")
            };

            target.inventory = Some(inventory);
            target.source_fingerprint = Some(fingerprint);
            target.advisory_digest = Some(advisory_digest.clone());
            target.policy_digest = Some(policy_digest.clone());
            target.next_due_at = advance_due(target.next_due_at, target.interval_seconds, now);
            target.updated_at = now;
            self.repository.save_target(&target)?;
        }

        self.deliver_events(now, &mut summary).await?;
        summary.records_pruned = self
            .repository
            .prune_before(now.saturating_sub(self.config.retention_seconds))?;
        Ok(summary)
    }

    pub async fn run_until_shutdown<F>(&mut self, shutdown: F) -> Result<(), MonitorError>
    where
        F: Future<Output = ()> + Send,
    {
        tokio::pin!(shutdown);
        let mut failure_count = 0_u32;
        loop {
            tokio::select! {
                () = &mut shutdown => return Ok(()),
                result = self.run_once() => {
                    if result.is_ok() {
                        failure_count = 0;
                    } else {
                        failure_count = failure_count.saturating_add(1);
                    }
                },
            }
            let delay = if failure_count == 0 {
                self.config.poll_interval
            } else {
                Duration::from_secs(self.config.retry.delay_after(failure_count) as u64)
            };
            tokio::select! {
                () = &mut shutdown => return Ok(()),
                () = self.clock.sleep(delay) => {}
            }
        }
    }

    async fn deliver_events(
        &mut self,
        now: i64,
        summary: &mut RunSummary,
    ) -> Result<(), MonitorError> {
        let lease_until = now.saturating_add(self.config.retry.max_backoff_seconds);
        let mut events =
            self.repository
                .claim_events(now, lease_until, self.config.event_batch_size)?;
        events
            .sort_by(|left, right| (left.created_at, &left.id).cmp(&(right.created_at, &right.id)));
        for mut event in events {
            if event.delivered_at.is_some() || event.dead_lettered_at.is_some() {
                continue;
            }
            match self.notifier.notify(&event).await {
                Ok(()) => {
                    event.delivered_at = Some(now);
                    event.next_attempt_at = now;
                    event.last_error = None;
                    summary.events_delivered += 1;
                }
                Err(error) => {
                    event.attempts = event.attempts.saturating_add(1);
                    event.last_error = Some(redact_error(&error));
                    if event.attempts >= self.config.retry.max_attempts {
                        event.dead_lettered_at = Some(now);
                        event.next_attempt_at = now;
                        summary.events_dead_lettered += 1;
                    } else {
                        event.next_attempt_at =
                            now.saturating_add(self.config.retry.delay_after(event.attempts));
                        summary.events_retried += 1;
                    }
                }
            }
            self.repository.save_event(&event)?;
        }
        Ok(())
    }
}

fn advance_due(previous_due: i64, interval: i64, now: i64) -> i64 {
    if previous_due > now {
        return previous_due;
    }
    let elapsed = now.saturating_sub(previous_due);
    let intervals = elapsed / interval + 1;
    previous_due.saturating_add(interval.saturating_mul(intervals))
}

fn digest_json(value: &impl Serialize) -> Result<String, MonitorError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| MonitorError::Persistence(error.to_string()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn validate_text(field: &'static str, value: &str, maximum: usize) -> Result<(), MonitorError> {
    if value.trim().is_empty() {
        return Err(MonitorError::EmptyField(field));
    }
    if value.len() > maximum {
        return Err(MonitorError::InputTooLong { field, maximum });
    }
    Ok(())
}

fn validate_optional_text(
    field: &'static str,
    value: Option<&str>,
    maximum: usize,
) -> Result<(), MonitorError> {
    if let Some(value) = value {
        validate_text(field, value, maximum)?;
    }
    Ok(())
}

fn redact_error(error: &str) -> String {
    let sanitized: String = error
        .chars()
        .take(MAX_ERROR_BYTES)
        .map(|character| {
            if character.is_control() && character != ' ' {
                ' '
            } else {
                character
            }
        })
        .collect();
    let mut words = sanitized.split_whitespace();
    let mut result = Vec::new();
    while let Some(word) = words.next() {
        let lowercase = word.to_ascii_lowercase();
        if lowercase == "bearer" {
            let _ = words.next();
            result.push("Bearer [REDACTED]".to_owned());
        } else if ["token=", "password=", "secret="]
            .iter()
            .any(|marker| lowercase.starts_with(marker))
        {
            let name = word.split_once('=').map_or("secret", |(name, _)| name);
            result.push(format!("{name}=[REDACTED]"));
        } else {
            result.push(word.to_owned());
        }
    }
    result.join(" ")
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, VecDeque},
        sync::{
            Mutex,
            atomic::{AtomicI64, AtomicUsize, Ordering},
        },
    };

    use super::*;
    use crate::model::{Asset, AssetId, AssetKind};

    #[derive(Default)]
    struct MemoryRepository {
        cursor: AdvisoryCursor,
        targets: BTreeMap<String, MonitorTarget>,
        events: BTreeMap<String, AlertEvent>,
    }

    impl MonitorRepository for MemoryRepository {
        fn advisory_cursor(&mut self) -> Result<AdvisoryCursor, MonitorError> {
            Ok(self.cursor.clone())
        }
        fn save_advisory_cursor(&mut self, cursor: &AdvisoryCursor) -> Result<(), MonitorError> {
            self.cursor = cursor.clone();
            Ok(())
        }
        fn due_targets(
            &mut self,
            now: i64,
            limit: usize,
        ) -> Result<Vec<MonitorTarget>, MonitorError> {
            let mut values: Vec<_> = self
                .targets
                .values()
                .filter(|target| target.next_due_at <= now)
                .cloned()
                .collect();
            values.sort_by(|left, right| {
                (left.next_due_at, &left.id).cmp(&(right.next_due_at, &right.id))
            });
            values.truncate(limit);
            Ok(values)
        }
        fn save_target(&mut self, target: &MonitorTarget) -> Result<(), MonitorError> {
            self.targets.insert(target.id.clone(), target.clone());
            Ok(())
        }
        fn enqueue_event(&mut self, event: &AlertEvent) -> Result<bool, MonitorError> {
            if self
                .events
                .values()
                .any(|stored| stored.dedupe_key == event.dedupe_key)
            {
                return Ok(false);
            }
            self.events.insert(event.id.clone(), event.clone());
            Ok(true)
        }
        fn claim_events(
            &mut self,
            now: i64,
            lease_until: i64,
            limit: usize,
        ) -> Result<Vec<AlertEvent>, MonitorError> {
            let mut values: Vec<_> = self
                .events
                .values_mut()
                .filter(|event| {
                    event.next_attempt_at <= now
                        && event.delivered_at.is_none()
                        && event.dead_lettered_at.is_none()
                })
                .collect();
            values.sort_by(|left, right| {
                (left.next_attempt_at, left.created_at, &left.id).cmp(&(
                    right.next_attempt_at,
                    right.created_at,
                    &right.id,
                ))
            });
            values.truncate(limit);
            Ok(values
                .into_iter()
                .map(|event| {
                    event.next_attempt_at = lease_until;
                    event.clone()
                })
                .collect())
        }
        fn save_event(&mut self, event: &AlertEvent) -> Result<(), MonitorError> {
            self.events.insert(event.id.clone(), event.clone());
            Ok(())
        }
        fn prune_before(&mut self, cutoff: i64) -> Result<usize, MonitorError> {
            let before = self.events.len();
            self.events.retain(|_, event| {
                event.created_at >= cutoff
                    || (event.delivered_at.is_none() && event.dead_lettered_at.is_none())
            });
            Ok(before - self.events.len())
        }
    }

    struct FakeClock(AtomicI64);
    impl FakeClock {
        fn new(now: i64) -> Self {
            Self(AtomicI64::new(now))
        }
        fn set(&self, now: i64) {
            self.0.store(now, Ordering::SeqCst);
        }
    }
    impl Clock for FakeClock {
        fn now(&self) -> i64 {
            self.0.load(Ordering::SeqCst)
        }
        fn sleep(&self, _duration: Duration) -> MonitorFuture<'_, ()> {
            Box::pin(std::future::pending())
        }
    }

    struct YieldClock {
        now: i64,
        sleeps: AtomicUsize,
    }
    impl Clock for YieldClock {
        fn now(&self) -> i64 {
            self.now
        }
        fn sleep(&self, _duration: Duration) -> MonitorFuture<'_, ()> {
            Box::pin(async move {
                self.sleeps.fetch_add(1, Ordering::SeqCst);
                tokio::task::yield_now().await;
            })
        }
    }

    #[derive(Default)]
    struct FailingRepository {
        cycles: usize,
    }
    impl MonitorRepository for FailingRepository {
        fn advisory_cursor(&mut self) -> Result<AdvisoryCursor, MonitorError> {
            self.cycles += 1;
            Err(MonitorError::Persistence("transient".into()))
        }
        fn save_advisory_cursor(&mut self, _: &AdvisoryCursor) -> Result<(), MonitorError> {
            Ok(())
        }
        fn due_targets(&mut self, _: i64, _: usize) -> Result<Vec<MonitorTarget>, MonitorError> {
            Ok(vec![])
        }
        fn save_target(&mut self, _: &MonitorTarget) -> Result<(), MonitorError> {
            Ok(())
        }
        fn enqueue_event(&mut self, _: &AlertEvent) -> Result<bool, MonitorError> {
            Ok(false)
        }
        fn claim_events(
            &mut self,
            _: i64,
            _: i64,
            _: usize,
        ) -> Result<Vec<AlertEvent>, MonitorError> {
            Ok(vec![])
        }
        fn save_event(&mut self, _: &AlertEvent) -> Result<(), MonitorError> {
            Ok(())
        }
        fn prune_before(&mut self, _: i64) -> Result<usize, MonitorError> {
            Ok(0)
        }
    }

    struct FakeRunner {
        refreshes: Mutex<VecDeque<AdvisoryRefresh>>,
        policy: Mutex<String>,
        fingerprint: Mutex<String>,
        findings: Mutex<BTreeSet<FindingId>>,
        scans: AtomicUsize,
        evaluations: AtomicUsize,
        seen_cursors: Mutex<Vec<AdvisoryCursor>>,
    }

    impl FakeRunner {
        fn new() -> Self {
            Self {
                refreshes: Mutex::new(VecDeque::from([refresh("cursor-1", "adv-1", true)])),
                policy: Mutex::new("policy-1".into()),
                fingerprint: Mutex::new("source-1".into()),
                findings: Mutex::new(ids(&["finding-a"])),
                scans: AtomicUsize::new(0),
                evaluations: AtomicUsize::new(0),
                seen_cursors: Mutex::new(Vec::new()),
            }
        }
    }

    impl MonitorRunner for FakeRunner {
        fn refresh_advisories<'a>(
            &'a self,
            cursor: &'a AdvisoryCursor,
        ) -> MonitorFuture<'a, Result<AdvisoryRefresh, MonitorError>> {
            Box::pin(async move {
                self.seen_cursors.lock().unwrap().push(cursor.clone());
                Ok(self
                    .refreshes
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or_else(|| AdvisoryRefresh {
                        cursor: cursor.clone(),
                        changed: false,
                    }))
            })
        }
        fn policy_digest(&self) -> Result<String, MonitorError> {
            Ok(self.policy.lock().unwrap().clone())
        }
        fn source_fingerprint<'a>(
            &'a self,
            _target: &'a MonitorTarget,
        ) -> MonitorFuture<'a, Result<String, MonitorError>> {
            Box::pin(async move { Ok(self.fingerprint.lock().unwrap().clone()) })
        }
        fn evaluate<'a>(
            &'a self,
            _target: &'a MonitorTarget,
        ) -> MonitorFuture<'a, Result<Evaluation, MonitorError>> {
            Box::pin(async move {
                self.scans.fetch_add(1, Ordering::SeqCst);
                self.evaluations.fetch_add(1, Ordering::SeqCst);
                Ok(Evaluation {
                    inventory: inventory(),
                    finding_ids: self.findings.lock().unwrap().clone(),
                })
            })
        }
    }

    struct FakeNotifier {
        results: Mutex<VecDeque<Result<(), String>>>,
        calls: AtomicUsize,
    }
    impl FakeNotifier {
        fn succeeding() -> Self {
            Self {
                results: Mutex::new(VecDeque::new()),
                calls: AtomicUsize::new(0),
            }
        }
    }
    impl Notifier for FakeNotifier {
        fn notify<'a>(&'a self, _event: &'a AlertEvent) -> MonitorFuture<'a, Result<(), String>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.results.lock().unwrap().pop_front().unwrap_or(Ok(()))
            })
        }
    }

    fn inventory() -> Inventory {
        Inventory {
            asset: Asset {
                id: AssetId::new("asset").unwrap(),
                name: "asset".into(),
                kind: AssetKind::Repository,
                version: None,
                metadata: BTreeMap::new(),
            },
            components: BTreeMap::new(),
            locations: BTreeSet::new(),
            dependencies: BTreeSet::new(),
        }
    }
    fn ids(values: &[&str]) -> BTreeSet<FindingId> {
        values
            .iter()
            .map(|value| FindingId::new(value).unwrap())
            .collect()
    }
    fn refresh(cursor: &str, digest: &str, changed: bool) -> AdvisoryRefresh {
        AdvisoryRefresh {
            cursor: AdvisoryCursor {
                cursor: Some(cursor.into()),
                etag: Some(format!("etag-{cursor}")),
                last_modified: None,
                digest: Some(digest.into()),
                updated_at: None,
            },
            changed,
        }
    }
    fn target(due: i64) -> MonitorTarget {
        MonitorTarget {
            id: "target".into(),
            source: "repo".into(),
            interval_seconds: 10,
            next_due_at: due,
            source_fingerprint: None,
            inventory: None,
            advisory_digest: None,
            policy_digest: None,
            finding_ids: BTreeSet::new(),
            updated_at: 0,
        }
    }
    fn service(
        repository: MemoryRepository,
        clock: Arc<FakeClock>,
        runner: Arc<FakeRunner>,
        notifier: Arc<FakeNotifier>,
        retry: RetryPolicy,
    ) -> MonitorService<MemoryRepository, FakeClock, FakeRunner, FakeNotifier> {
        MonitorService::new(
            repository,
            clock,
            runner,
            notifier,
            MonitorConfig {
                retry,
                retention_seconds: 100,
                ..MonitorConfig::default()
            },
        )
        .unwrap()
    }

    #[tokio::test]
    async fn run_is_idempotent_and_due_schedule_does_not_drift() {
        let mut repository = MemoryRepository::default();
        repository.targets.insert("target".into(), target(95));
        let clock = Arc::new(FakeClock::new(100));
        let runner = Arc::new(FakeRunner::new());
        let notifier = Arc::new(FakeNotifier::succeeding());
        let mut service = service(
            repository,
            clock.clone(),
            runner.clone(),
            notifier.clone(),
            RetryPolicy::default(),
        );
        let first = service.run_once().await.unwrap();

        assert_eq!(
            (
                first.targets_scanned,
                first.events_created,
                first.events_delivered
            ),
            (1, 1, 1)
        );
        assert_eq!(service.repository().targets["target"].next_due_at, 105);
        let second = service.run_once().await.unwrap();
        assert_eq!(second.targets_considered, 0);
        assert_eq!(service.repository().events.len(), 1);
        assert_eq!(notifier.calls.load(Ordering::SeqCst), 1);
        clock.set(105);
        let third = service.run_once().await.unwrap();
        assert_eq!(
            (
                third.targets_scanned,
                third.targets_reevaluated,
                third.events_created
            ),
            (0, 0, 0)
        );
        assert_eq!(service.repository().targets["target"].next_due_at, 115);
    }
    #[tokio::test]
    async fn daemon_survives_transient_cycle_failures_and_retries() {
        let clock = Arc::new(YieldClock {
            now: 100,
            sleeps: AtomicUsize::new(0),
        });
        let mut service = MonitorService::new(
            FailingRepository::default(),
            clock.clone(),
            Arc::new(FakeRunner::new()),
            Arc::new(FakeNotifier::succeeding()),
            MonitorConfig::default(),
        )
        .unwrap();
        service
            .run_until_shutdown(async {
                while clock.sleeps.load(Ordering::SeqCst) < 2 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        assert!(service.repository().cycles >= 2);
    }

    #[tokio::test]
    async fn advisory_cursor_resumes_with_http_metadata() {
        let repository = MemoryRepository {
            cursor: AdvisoryCursor {
                cursor: Some("resume".into()),
                etag: Some("old-etag".into()),
                last_modified: Some("yesterday".into()),
                digest: Some("old".into()),
                updated_at: Some(1),
            },
            ..MemoryRepository::default()
        };
        let clock = Arc::new(FakeClock::new(100));
        let runner = Arc::new(FakeRunner::new());
        runner.refreshes.lock().unwrap().clear();
        runner
            .refreshes
            .lock()
            .unwrap()
            .push_back(refresh("next", "new", true));
        let mut service = service(
            repository,
            clock,
            runner.clone(),
            Arc::new(FakeNotifier::succeeding()),
            RetryPolicy::default(),
        );
        service.run_once().await.unwrap();
        assert_eq!(
            runner.seen_cursors.lock().unwrap()[0].cursor.as_deref(),
            Some("resume")
        );
        assert_eq!(
            runner.seen_cursors.lock().unwrap()[0].etag.as_deref(),
            Some("old-etag")
        );
        assert_eq!(service.repository().cursor.cursor.as_deref(), Some("next"));
        assert_eq!(service.repository().cursor.updated_at, Some(100));
    }

    #[tokio::test]
    async fn advisory_or_policy_change_reevaluates_unchanged_inventory_without_scan() {
        let mut repository = MemoryRepository::default();
        let mut saved = target(100);
        saved.inventory = Some(inventory());
        saved.source_fingerprint = Some("source-1".into());
        saved.advisory_digest = Some("adv-0".into());
        saved.finding_ids = ids(&["finding-a", "finding-old"]);
        repository.targets.insert(saved.id.clone(), saved);
        let runner = Arc::new(FakeRunner::new());
        runner
            .findings
            .lock()
            .unwrap()
            .insert(FindingId::new("finding-b").unwrap());
        let mut service = service(
            repository,
            Arc::new(FakeClock::new(100)),
            runner.clone(),
            Arc::new(FakeNotifier::succeeding()),
            RetryPolicy::default(),
        );
        let summary = service.run_once().await.unwrap();
        assert_eq!(
            (summary.targets_scanned, summary.targets_reevaluated),
            (0, 1)
        );
        assert_eq!(runner.scans.load(Ordering::SeqCst), 1);
        let payload = &service.repository().events.values().next().unwrap().payload;
        assert_eq!(
            payload.diff.introduced,
            vec![FindingId::new("finding-b").unwrap()]
        );
        assert_eq!(
            payload.diff.resolved,
            vec![FindingId::new("finding-old").unwrap()]
        );
        assert_eq!(
            payload.diff.unchanged,
            vec![FindingId::new("finding-a").unwrap()]
        );
    }

    #[tokio::test]
    async fn policy_change_alone_reevaluates_without_rescanning() {
        let mut repository = MemoryRepository {
            cursor: refresh("cursor", "adv-1", false).cursor,
            ..MemoryRepository::default()
        };
        let mut saved = target(100);
        saved.inventory = Some(inventory());
        saved.source_fingerprint = Some("source-1".into());
        saved.advisory_digest = Some("adv-1".into());
        saved.policy_digest = Some("policy-old".into());
        saved.finding_ids = ids(&["finding-a"]);
        repository.targets.insert(saved.id.clone(), saved);
        let runner = Arc::new(FakeRunner::new());
        runner.refreshes.lock().unwrap().clear();
        runner
            .refreshes
            .lock()
            .unwrap()
            .push_back(refresh("cursor", "adv-1", false));
        let mut service = service(
            repository,
            Arc::new(FakeClock::new(100)),
            runner.clone(),
            Arc::new(FakeNotifier::succeeding()),
            RetryPolicy::default(),
        );
        let summary = service.run_once().await.unwrap();
        assert_eq!(
            (
                summary.targets_scanned,
                summary.targets_reevaluated,
                summary.events_created
            ),
            (0, 1, 0)
        );
        assert_eq!(runner.evaluations.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn retry_uses_bounded_exponential_backoff_then_dead_letters() {
        let event_id = "event-dedupe".to_owned();
        let dedupe_key = "dedupe".to_owned();
        let mut repository = MemoryRepository::default();
        let event = AlertEvent {
            id: event_id.clone(),
            dedupe_key: dedupe_key.clone(),
            target_id: "target".into(),
            payload: AlertPayload {
                target_id: "target".into(),
                evaluated_at: 0,
                source_fingerprint: "s".into(),
                advisory_digest: "a".into(),
                policy_digest: "p".into(),
                diff: FindingDiff {
                    introduced: vec![],
                    resolved: vec![],
                    unchanged: vec![],
                },
            },
            created_at: 100,
            attempts: 0,
            next_attempt_at: 0,
            delivered_at: None,
            dead_lettered_at: None,
            last_error: None,
        };
        repository.events.insert(event.id.clone(), event);
        let clock = Arc::new(FakeClock::new(100));
        let runner = Arc::new(FakeRunner::new());
        let notifier = Arc::new(FakeNotifier {
            results: Mutex::new(VecDeque::from([
                Err("token=supersecret\nfailed".into()),
                Err("again".into()),
                Err("final".into()),
            ])),
            calls: AtomicUsize::new(0),
        });
        let retry = RetryPolicy {
            max_attempts: 3,
            initial_backoff_seconds: 10,
            max_backoff_seconds: 15,
        };
        let mut service = service(repository, clock.clone(), runner, notifier, retry);
        service.run_once().await.unwrap();
        let stored = &service.repository().events[&event_id];
        assert_eq!((stored.attempts, stored.next_attempt_at), (1, 110));
        assert_eq!(
            stored.last_error.as_deref(),
            Some("token=[REDACTED] failed")
        );
        assert_eq!(stored.dedupe_key, dedupe_key);
        clock.set(110);
        service.run_once().await.unwrap();
        assert_eq!(
            (
                service.repository().events[&event_id].attempts,
                service.repository().events[&event_id].next_attempt_at
            ),
            (2, 125)
        );
        clock.set(125);
        let summary = service.run_once().await.unwrap();
        assert_eq!(
            (summary.events_dead_lettered, summary.records_pruned),
            (1, 0)
        );
        let stored = &service.repository().events[&event_id];
        assert_eq!((stored.attempts, stored.next_attempt_at), (3, 125));
        assert_eq!(stored.dead_lettered_at, Some(125));
        assert_eq!(stored.last_error.as_deref(), Some("final"));
        assert_eq!(stored.dedupe_key, dedupe_key);
    }

    #[tokio::test]
    async fn retention_prunes_terminal_events_but_preserves_pending_delivery() {
        let mut repository = MemoryRepository::default();
        for (id, delivered) in [
            ("old-delivered", Some(1)),
            ("old-pending", None),
            ("recent", Some(95)),
        ] {
            repository.events.insert(
                id.into(),
                AlertEvent {
                    id: id.into(),
                    dedupe_key: id.into(),
                    target_id: "target".into(),
                    payload: AlertPayload {
                        target_id: "target".into(),
                        evaluated_at: 0,
                        source_fingerprint: "s".into(),
                        advisory_digest: "a".into(),
                        policy_digest: "p".into(),
                        diff: FindingDiff {
                            introduced: vec![],
                            resolved: vec![],
                            unchanged: vec![],
                        },
                    },
                    created_at: if id == "recent" { 95 } else { 1 },
                    attempts: 0,
                    next_attempt_at: 1000,
                    delivered_at: delivered,
                    dead_lettered_at: None,
                    last_error: None,
                },
            );
        }
        let mut service = MonitorService::new(
            repository,
            Arc::new(FakeClock::new(100)),
            Arc::new(FakeRunner::new()),
            Arc::new(FakeNotifier::succeeding()),
            MonitorConfig {
                retention_seconds: 10,
                ..MonitorConfig::default()
            },
        )
        .unwrap();
        let summary = service.run_once().await.unwrap();
        assert_eq!(summary.records_pruned, 1);
        assert!(!service.repository().events.contains_key("old-delivered"));
        assert!(service.repository().events.contains_key("old-pending"));
        assert!(service.repository().events.contains_key("recent"));
    }

    #[tokio::test]
    async fn sqlite_repository_persists_target_cursor_event_and_retention() {
        let mut store = crate::store::Store::open_memory().unwrap();
        let initial = target(100);
        store
            .upsert_monitor_target(&target_to_store(&initial).unwrap())
            .unwrap();
        let clock = Arc::new(FakeClock::new(100));
        let runner = Arc::new(FakeRunner::new());
        let notifier = Arc::new(FakeNotifier::succeeding());
        let mut service = MonitorService::new(
            store,
            clock.clone(),
            runner,
            notifier,
            MonitorConfig {
                retention_seconds: 100,
                ..MonitorConfig::default()
            },
        )
        .unwrap();
        let summary = service.run_once().await.unwrap();
        assert_eq!(
            (
                summary.targets_scanned,
                summary.events_created,
                summary.events_delivered
            ),
            (1, 1, 1)
        );
        let stored = service
            .repository()
            .get_monitor_target("target")
            .unwrap()
            .unwrap();
        assert_eq!(
            decode_time("next_due_at", &stored.next_due_at).unwrap(),
            110
        );
        assert_eq!(stored.finding_ids, vec!["finding-a"]);
        let cursor = service
            .repository()
            .get_monitor_cursor("advisories")
            .unwrap()
            .unwrap();
        assert_eq!(cursor.cursor.as_deref(), Some("cursor-1"));
        let events = service
            .repository()
            .list_monitor_events(
                &crate::store::MonitorEventFilter {
                    include_delivered: true,
                    ..Default::default()
                },
                10,
                0,
            )
            .unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].delivered_at.is_some());
        clock.set(1000);
        let summary = service.run_once().await.unwrap();
        assert_eq!(summary.records_pruned, 1);
    }
}
