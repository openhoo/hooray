//! Socket-level API smoke coverage with a persistent temporary history store.
use std::{collections::BTreeSet, time::Duration};

use hooray::{api, config::Config, store::Store};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{net::TcpListener, sync::oneshot};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

#[tokio::test]
async fn osv_crosses_the_batch_boundary_without_losing_matches_or_repeating_details() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(|request: &wiremock::Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            let queries = body["queries"].as_array().unwrap();
            assert!(!queries.is_empty() && queries.len() <= 1000);
            ResponseTemplate::new(200).set_body_json(json!({
                "results": queries.iter().map(|_| json!({"vulns": [{"id": "SMOKE-OSV-1"}]})).collect::<Vec<_>>()
            }))
        })
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/vulns/SMOKE-OSV-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "SMOKE-OSV-1", "summary": "Shared controlled advisory"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let mut inventory: hooray::model::Inventory = serde_json::from_value(json!({
        "asset": {"id": "asset:batch-smoke", "name": "Batch smoke", "kind": "repository"}
    }))
    .unwrap();
    for index in 0..1001 {
        let purl = format!("pkg:cargo/smoke-{index}@1.0.0");
        let identity = hooray::model::stable_component_id(&purl).unwrap();
        let component = serde_json::from_value(json!({
            "identity": identity, "name": format!("smoke-{index}"), "version": "1.0.0",
            "purl": purl, "scope": "runtime"
        }))
        .unwrap();
        inventory.components.insert(identity, component);
    }
    inventory.validate().unwrap();
    let findings = hooray::osv::OsvClient::new(&server.uri(), 4)
        .unwrap()
        .scan(&inventory)
        .await
        .unwrap();
    assert_eq!(findings.len(), 1001);
    assert_eq!(
        findings
            .values()
            .filter_map(|finding| finding.component_id.as_ref())
            .collect::<BTreeSet<_>>(),
        inventory.components.keys().collect::<BTreeSet<_>>()
    );
    assert!(
        findings
            .values()
            .all(|finding| finding.advisory_id.as_deref() == Some("SMOKE-OSV-1"))
    );
}

#[tokio::test]
async fn authenticated_http_scans_survive_concurrent_reads_and_database_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("history.sqlite3");
    let token = "smoke-test-auth";
    let digest = Sha256::digest(token.as_bytes());
    let digest = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let config = Config {
        offline: true,
        max_concurrency: 16,
        max_request_bytes: 1024,
        auth_bearer_sha256: Some(serde_json::from_value(json!(digest)).unwrap()),
        ..Config::default()
    };
    let state = api::ApiState::new(Store::open(&database).unwrap(), config).unwrap();
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

    let unauthorized = client.get(format!("{base}/health")).send().await.unwrap();
    assert_eq!(unauthorized.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(unauthorized.headers()["www-authenticate"], "Bearer");
    let authorized = client
        .get(format!("{base}/ready"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(authorized.status(), reqwest::StatusCode::OK);

    let malformed = client
        .post(format!("{base}/v1/scans"))
        .bearer_auth(token)
        .header("content-type", "application/json")
        .body("{")
        .send()
        .await
        .unwrap();
    assert_eq!(malformed.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(
        malformed.json::<Value>().await.unwrap()["error"]["code"],
        "invalid_json"
    );
    let oversized = client
        .post(format!("{base}/v1/scans"))
        .bearer_auth(token)
        .header("content-type", "application/json")
        .body("x".repeat(1025))
        .send()
        .await
        .unwrap();
    assert_eq!(oversized.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);

    let inventory = json!({
        "asset": {"id": "asset:socket-smoke", "name": "Socket smoke", "kind": "repository"},
        "components": {}, "locations": [], "dependencies": []
    });
    let scans = futures::future::join_all((0..12).map(|index| {
        let client = client.clone();
        let base = base.clone();
        let inventory = inventory.clone();
        async move {
            let request_id = format!("socket-scan-{index}");
            let response = client
                .post(format!("{base}/v1/scans"))
                .bearer_auth(token)
                .header("x-request-id", &request_id)
                .json(&json!({"inventory": inventory, "metadata": {"sequence": index}}))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::CREATED);
            assert_eq!(response.headers()["x-request-id"], request_id);
            response.json::<Value>().await.unwrap()["run_id"]
                .as_str()
                .unwrap()
                .to_owned()
        }
    }));
    let reads = futures::future::join_all((0..12).map(|_| {
        let client = client.clone();
        let base = base.clone();
        async move {
            let response = client
                .get(format!("{base}/v1/runs?limit=100"))
                .bearer_auth(token)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            assert!(
                response.json::<Value>().await.unwrap()["count"]
                    .as_u64()
                    .unwrap()
                    <= 12
            );
        }
    }));
    let (run_ids, _) = tokio::join!(scans, reads);
    assert_eq!(run_ids.iter().collect::<BTreeSet<_>>().len(), 12);
    let history = client
        .get(format!("{base}/v1/runs?limit=100"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(history["count"], 12);
    assert!(
        history["runs"]
            .as_array()
            .unwrap()
            .iter()
            .all(|run| run.get("inventory").is_none())
    );

    let report = client
        .get(format!("{base}/v1/reports/{}", run_ids[0]))
        .bearer_auth(token)
        .header("accept", "application/yaml")
        .send()
        .await
        .unwrap();
    assert_eq!(report.status(), reqwest::StatusCode::OK);
    assert_eq!(report.headers()["content-type"], "application/yaml");
    let report: Value = serde_yaml::from_str(&report.text().await.unwrap()).unwrap();
    assert_eq!(report["inventory"]["asset"]["id"], "asset:socket-smoke");
    let diff = client
        .get(format!("{base}/v1/runs/{}/diff/{}", run_ids[1], run_ids[0]))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(diff["introduced"], json!([]));
    assert_eq!(diff["resolved"], json!([]));
    let invalid_filter = client
        .get(format!("{base}/v1/inventory?scope=not-a-scope"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(invalid_filter.status(), reqwest::StatusCode::BAD_REQUEST);

    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let reopened = Store::open(&database).unwrap();
    assert_eq!(reopened.list_run_summaries(100, 0).unwrap().len(), 12);
    for run_id in run_ids {
        let report = reopened
            .get_run(&hooray::model::RunId::new(run_id).unwrap())
            .unwrap()
            .unwrap();
        report.validate().unwrap();
    }
}
