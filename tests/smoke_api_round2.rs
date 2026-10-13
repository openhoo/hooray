//! Second-pass controls for previously uncovered persistence and enrichment edges.
use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use hooray::{
    api,
    config::Config,
    integrations::{IntegrationGenerator, IntegrationLimits},
    model::{ApplicabilityStatus, Inventory, ScanReport, stable_component_id},
    monitor::{
        AdvisoryCursor, AdvisoryRefresh, AlertEvent, Clock, Evaluation, MonitorConfig,
        MonitorError, MonitorFuture, MonitorRunner, MonitorService, Notifier,
    },
    osv::OsvClient,
    store::{MonitorEvent, MonitorEventFilter, MonitorTarget, Store},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{net::TcpListener, sync::oneshot};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn inventory(purl: &str, version: &str) -> Inventory {
    let id = stable_component_id(purl).unwrap();
    let inventory = serde_json::from_value(json!({
        "asset": {"id": "asset:round2", "name": "Round two", "kind": "repository"},
        "components": {id.as_str(): {
            "identity": id, "name": "smoke", "version": version,
            "purl": purl, "scope": "runtime"
        }}
    }))
    .unwrap();
    Inventory::validate(&inventory).unwrap();
    inventory
}

async fn osv_fixture(detail: Value, purl: &str, version: &str) -> hooray::model::Finding {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{"vulns": [{"id": "SMOKE-ROUND2"}]}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/vulns/SMOKE-ROUND2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(detail))
        .expect(1)
        .mount(&server)
        .await;
    let findings = OsvClient::new(&server.uri(), 2)
        .unwrap()
        .scan(&inventory(purl, version))
        .await
        .unwrap();
    assert_eq!(findings.len(), 1);
    findings.into_values().next().unwrap()
}

#[tokio::test]
async fn osv_keeps_explicit_affected_versions_without_range_events() {
    for ranges in [json!([]), json!([{"type": "UNRECOGNIZED", "events": []}])] {
        let unlisted_status = if ranges.as_array().unwrap().is_empty() {
            ApplicabilityStatus::NotAffected
        } else {
            ApplicabilityStatus::Unknown
        };
        let detail = json!({
            "id": "SMOKE-ROUND2",
            "affected": [{
                "package": {"purl": "pkg:cargo/smoke"},
                "versions": [" 1.2.3 "], "ranges": ranges
            }]
        });
        let finding = osv_fixture(detail.clone(), "pkg:cargo/smoke@1.2.3", "1.2.3").await;
        assert_eq!(
            finding.applicability.unwrap().status,
            ApplicabilityStatus::Affected,
            "explicit membership is independent of range availability"
        );
        let unlisted = osv_fixture(detail, "pkg:cargo/smoke@9.0.0", "9.0.0").await;
        assert_eq!(
            unlisted.applicability.unwrap().status,
            unlisted_status,
            "an unsupported range must not create a negative verdict; a versions-only list retains exact-list semantics"
        );
        assert!(unlisted.remediation.is_none());
    }
}

#[tokio::test]
async fn osv_package_qualifiers_are_independent_of_component_subpaths() {
    let detail = json!({
        "id": "SMOKE-ROUND2",
        "affected": [{
            "package": {"purl": "pkg:cargo/smoke?arch=x86_64"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]
        }]
    });
    let finding = osv_fixture(
        detail.clone(),
        "pkg:cargo/smoke@1.2.3?arch=x86_64#src/module",
        "1.2.3",
    )
    .await;
    assert_eq!(
        finding.applicability.unwrap().status,
        ApplicabilityStatus::Affected
    );
    assert!(
        finding
            .remediation
            .unwrap()
            .fixed_versions
            .contains("2.0.0")
    );
    let different_arch = osv_fixture(
        detail,
        "pkg:cargo/smoke@1.2.3?arch=aarch64#src/module",
        "1.2.3",
    )
    .await;
    assert_eq!(
        different_arch.applicability.unwrap().status,
        ApplicabilityStatus::Unknown
    );
    assert!(different_arch.remediation.is_none());
}

fn event() -> MonitorEvent {
    MonitorEvent {
        event_id: "event:round2".into(),
        target_id: "target:round2".into(),
        dedupe_key: "dedupe:round2".into(),
        kind: "changed".into(),
        payload: json!({}),
        created_at: "0001".into(),
        attempts: 0,
        next_attempt_at: Some("0001".into()),
        delivered_at: None,
        dead_lettered_at: None,
        last_error: None,
    }
}

#[test]
fn expired_monitor_claim_cannot_reset_a_newer_retry_or_delivery() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("round2.sqlite3");
    let mut old_worker = Store::open(&database).unwrap();
    old_worker
        .add_monitor_target(
            &MonitorTarget::new("target:round2".into(), "repo".into(), 60, 0).unwrap(),
        )
        .unwrap();
    old_worker.append_monitor_event(&event()).unwrap();
    let mut old_claim = old_worker
        .claim_monitor_events("0001", "0002", 1)
        .unwrap()
        .remove(0);
    let mut current_worker = Store::open(&database).unwrap();
    let mut current_claim = current_worker
        .claim_monitor_events("0003", "0004", 1)
        .unwrap()
        .remove(0);
    assert_eq!((old_claim.attempts, current_claim.attempts), (1, 2));
    current_claim.last_error = Some("newer transient failure".into());
    current_claim.next_attempt_at = Some("0005".into());
    assert!(current_worker.update_monitor_event(&current_claim).unwrap());

    old_claim.last_error = Some("older transient failure".into());
    old_claim.next_attempt_at = Some("0009".into());
    assert!(
        !old_worker.update_monitor_event(&old_claim).unwrap(),
        "an expired claim must not roll back attempts or replace the current retry schedule"
    );
    let stored = current_worker
        .list_monitor_events(&MonitorEventFilter::default(), 10, 0)
        .unwrap();
    assert_eq!(stored, vec![current_claim.clone()]);

    let mut final_claim = current_worker
        .claim_monitor_events("0005", "0006", 1)
        .unwrap()
        .remove(0);
    assert_eq!(final_claim.attempts, 3);
    final_claim.delivered_at = Some("0005".into());
    final_claim.next_attempt_at = Some("0005".into());
    assert!(current_worker.update_monitor_event(&final_claim).unwrap());
    old_claim.delivered_at = Some("0009".into());
    old_claim.last_error = None;
    assert!(
        !old_worker.update_monitor_event(&old_claim).unwrap(),
        "a stale success must not replace a newer terminal receipt"
    );
    drop(old_worker);
    drop(current_worker);
    let reopened = Store::open(&database).unwrap();
    let stored = reopened
        .list_monitor_events(
            &MonitorEventFilter {
                include_delivered: true,
                ..Default::default()
            },
            10,
            0,
        )
        .unwrap();
    assert_eq!(stored, vec![final_claim]);
}

fn diagnostic_report() -> ScanReport {
    let report: ScanReport = serde_json::from_value(json!({
        "schema_version": "1",
        "run": {"id": "run:round2", "started_at": "2026-10-13T00:00:00Z"},
        "inventory": {
            "asset": {"id": "asset:round2", "name": "Round two", "kind": "repository"},
            "locations": [
                {"id": "location:other", "asset_id": "asset:round2", "path": "/repo/other.rs", "start": {"line": 1, "column": 1}},
                {"id": "location:target", "asset_id": "asset:round2", "path": "/repo/target file.rs", "start": {"line": 4, "column": 2}}
            ]
        },
        "findings": {
            "finding:other": {"id": "finding:other", "kind": "sast", "rule_id": "rule:other", "location_id": "location:other", "severity": "critical"},
            "finding:unlocated": {"id": "finding:unlocated", "kind": "sast", "rule_id": "rule:unlocated", "severity": "high"},
            "finding:target": {"id": "finding:target", "kind": "sast", "rule_id": "rule:target", "location_id": "location:target", "severity": "low"}
        }
    })).unwrap();
    report.validate().unwrap();
    report
}

#[test]
fn lsp_selects_the_requested_document_before_applying_the_limit() {
    for cap in [1, 10] {
        let generator = IntegrationGenerator::new(IntegrationLimits {
            max_annotations: cap,
            ..IntegrationLimits::default()
        })
        .unwrap();
        let artifact = generator
            .lsp_publish_diagnostics(&diagnostic_report(), "file:///repo/target%20file.rs")
            .unwrap();
        let value: Value = serde_json::from_slice(&artifact.body).unwrap();
        let diagnostics = value["params"]["diagnostics"].as_array().unwrap();
        assert_eq!(
            diagnostics.len(),
            1,
            "unrelated or unlocated findings must not occupy the document's selection budget"
        );
        assert_eq!(diagnostics[0]["data"]["findingId"], "finding:target");
        assert_eq!(value["params"]["hoorayTruncation"]["total"], 1);
        assert_eq!(value["params"]["hoorayTruncation"]["included"], 1);
        assert!(!artifact.truncated);

        let missing = generator
            .lsp_publish_diagnostics(&diagnostic_report(), "file:///repo/missing.rs")
            .unwrap();
        let value: Value = serde_json::from_slice(&missing.body).unwrap();
        assert_eq!(value["params"]["diagnostics"], json!([]));
        assert_eq!(value["params"]["hoorayTruncation"]["total"], 0);
        assert!(!missing.truncated);
    }

    let mut report = diagnostic_report();
    let mut second =
        report.findings[&hooray::model::FindingId::new("finding:target").unwrap()].clone();
    second.id = hooray::model::FindingId::new("finding:target-second").unwrap();
    second.severity = hooray::model::Severity::High;
    report.findings.insert(second.id.clone(), second);
    report.validate().unwrap();
    let artifact = IntegrationGenerator::new(IntegrationLimits {
        max_annotations: 1,
        ..IntegrationLimits::default()
    })
    .unwrap()
    .lsp_publish_diagnostics(&report, "file:///repo/target%20file.rs")
    .unwrap();
    let value: Value = serde_json::from_slice(&artifact.body).unwrap();
    assert_eq!(value["params"]["diagnostics"].as_array().unwrap().len(), 1);
    assert_eq!(
        value["params"]["diagnostics"][0]["data"]["findingId"],
        "finding:target-second"
    );
    assert_eq!(
        value["params"]["hoorayTruncation"],
        json!({"total": 2, "included": 1, "omitted": 1, "truncated": true})
    );
    assert!(artifact.truncated);
}

struct Round2Clock;

impl Clock for Round2Clock {
    fn now(&self) -> i64 {
        100
    }
    fn sleep(&self, _: Duration) -> MonitorFuture<'_, ()> {
        Box::pin(async {})
    }
}

struct TransitionRunner {
    competing_database: Option<PathBuf>,
}

impl MonitorRunner for TransitionRunner {
    fn refresh_advisories<'a>(
        &'a self,
        _: &'a AdvisoryCursor,
    ) -> MonitorFuture<'a, Result<AdvisoryRefresh, MonitorError>> {
        Box::pin(async {
            Ok(AdvisoryRefresh {
                cursor: AdvisoryCursor {
                    digest: Some("round2-advisories".into()),
                    ..Default::default()
                },
                changed: true,
            })
        })
    }
    fn policy_digest(&self) -> Result<String, MonitorError> {
        Ok("round2-policy".into())
    }
    fn source_fingerprint<'a>(
        &'a self,
        _: &'a hooray::monitor::MonitorTarget,
    ) -> MonitorFuture<'a, Result<String, MonitorError>> {
        Box::pin(async { Ok("round2-source".into()) })
    }
    fn evaluate<'a>(
        &'a self,
        target: &'a hooray::monitor::MonitorTarget,
    ) -> MonitorFuture<'a, Result<Evaluation, MonitorError>> {
        Box::pin(async move {
            if let Some(database) = &self.competing_database {
                let mut competing = Store::open(database).unwrap();
                let mut winner =
                    MonitorTarget::new(target.id.clone(), "winner".into(), 60, 101).unwrap();
                winner.finding_ids = vec!["finding:winner".into()];
                competing.upsert_monitor_target(&winner).unwrap();
            }
            Ok(Evaluation {
                inventory: serde_json::from_value(json!({
                    "asset": {"id": "asset:round2", "name": "Round two", "kind": "repository"}
                }))
                .unwrap(),
                finding_ids: BTreeSet::from([
                    hooray::model::FindingId::new("finding:round2").unwrap()
                ]),
            })
        })
    }
}

struct CountingNotifier(AtomicUsize);

impl Notifier for CountingNotifier {
    fn notify<'a>(&'a self, _: &'a AlertEvent) -> MonitorFuture<'a, Result<(), String>> {
        Box::pin(async {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
    }
}

#[tokio::test]
async fn stale_monitor_evaluation_cannot_publish_an_uncommitted_transition() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("competing.sqlite3");
    let mut store = Store::open(&database).unwrap();
    store
        .add_monitor_target(
            &MonitorTarget::new("target:round2".into(), "repo".into(), 60, 100).unwrap(),
        )
        .unwrap();
    let notifier = Arc::new(CountingNotifier(AtomicUsize::new(0)));
    let mut service = MonitorService::new(
        store,
        Arc::new(Round2Clock),
        Arc::new(TransitionRunner {
            competing_database: Some(database.clone()),
        }),
        Arc::clone(&notifier),
        MonitorConfig::default(),
    )
    .unwrap();
    assert!(
        service.run_once().await.is_err(),
        "the stale target write must conflict"
    );
    let reopened = Store::open(&database).unwrap();
    let target = reopened
        .get_monitor_target("target:round2")
        .unwrap()
        .unwrap();
    assert_eq!(target.finding_ids, vec!["finding:winner"]);
    assert!(
        reopened
            .list_monitor_events(
                &MonitorEventFilter {
                    include_delivered: true,
                    include_dead_lettered: true,
                    ..Default::default()
                },
                10,
                0
            )
            .unwrap()
            .is_empty(),
        "a failed compare-and-swap must leave no alert for the stale transition"
    );
    assert_eq!(notifier.0.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn monitor_transition_rolls_back_when_alert_persistence_fails_then_retries() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("atomic.sqlite3");
    let mut store = Store::open(&database).unwrap();
    let original = MonitorTarget::new("target:round2".into(), "repo".into(), 60, 100).unwrap();
    store.add_monitor_target(&original).unwrap();
    let control = rusqlite::Connection::open(&database).unwrap();
    control.execute_batch("CREATE TRIGGER round2_alert_failure BEFORE INSERT ON monitor_events BEGIN SELECT RAISE(ABORT, 'controlled insert failure'); END;").unwrap();
    let notifier = Arc::new(CountingNotifier(AtomicUsize::new(0)));
    let mut service = MonitorService::new(
        store,
        Arc::new(Round2Clock),
        Arc::new(TransitionRunner {
            competing_database: None,
        }),
        Arc::clone(&notifier),
        MonitorConfig::default(),
    )
    .unwrap();
    assert!(service.run_once().await.is_err());
    let reopened = Store::open(&database).unwrap();
    assert_eq!(
        reopened.get_monitor_target("target:round2").unwrap(),
        Some(original)
    );
    assert!(
        reopened
            .list_monitor_events(&MonitorEventFilter::default(), 10, 0)
            .unwrap()
            .is_empty()
    );
    assert_eq!(notifier.0.load(Ordering::Relaxed), 0);

    control
        .execute_batch("DROP TRIGGER round2_alert_failure;")
        .unwrap();
    let summary = service.run_once().await.unwrap();
    assert_eq!((summary.events_created, summary.events_delivered), (1, 1));
    assert_eq!(notifier.0.load(Ordering::Relaxed), 1);
    let target = reopened
        .get_monitor_target("target:round2")
        .unwrap()
        .unwrap();
    assert_eq!(target.finding_ids, vec!["finding:round2"]);
    assert_eq!(
        reopened
            .list_monitor_events(
                &MonitorEventFilter {
                    include_delivered: true,
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

#[tokio::test]
async fn api_validation_errors_redact_synthetic_credential_values() {
    let token = "aaaaaaaaaaaaaaaa";
    let digest = Sha256::digest(token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let config = Config {
        offline: true,
        auth_bearer_sha256: Some(serde_json::from_value(json!(digest)).unwrap()),
        ..Config::default()
    };
    let state = api::ApiState::new(Store::open_memory().unwrap(), config).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(api::serve(listener, state, async move {
        let _ = shutdown_rx.await;
    }));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let secret = "aaaaaaaaaaaaaaaaaa";
    let bad_body = client.post(format!("{base}/v1/scans")).bearer_auth(token).json(&json!({
        "inventory": {"asset": {"id": "asset:round2", "name": "Round two", "kind": format!("token={secret}")}}
    })).send().await.unwrap();
    assert_eq!(bad_body.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    let bad_query = client
        .get(format!("{base}/v1/findings?severity=password%3D{secret}"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(bad_query.status(), reqwest::StatusCode::BAD_REQUEST);
    for response in [bad_body, bad_query] {
        assert!(response.headers().contains_key("x-request-id"));
        let text = response.text().await.unwrap();
        assert!(
            !text.contains(secret),
            "API errors must preserve credential redaction: {text}"
        );
        let body: Value = serde_json::from_str(&text).unwrap();
        assert!(body["error"]["code"].as_str().is_some());
    }
    assert_eq!(
        client
            .get(format!("{base}/ready"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
    );
    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
