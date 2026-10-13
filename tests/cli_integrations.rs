//! Exercise tooling exports at the CLI boundary with persisted, validated scans.
use std::process::{Command, Output};

use hooray::{model::ScanReport, store::Store};
use serde_json::{Value, json};

fn report(id: &str, findings: &[&str], denied: Option<&str>) -> ScanReport {
    let findings: serde_json::Map<String, Value> = findings
        .iter()
        .map(|id| {
            (
                (*id).to_owned(),
                json!({
                    "id": id, "kind": "sast", "rule_id": "rule:example",
                    "summary": "Review unsafe evaluation", "severity": "high",
                    "confidence": "high", "status": "open", "location_id": "location:example"
                }),
            )
        })
        .collect();
    let decisions = denied.map(|finding| {
        let mut value =
            json!({"policy_id": "policy:test", "outcome": "deny", "reason": "Review required"});
        if !finding.is_empty() {
            value["finding_id"] = json!(finding);
        }
        value
    });
    serde_json::from_value(json!({
        "schema_version": "1",
        "run": {"id": id, "started_at": "2026-10-13T12:00:00Z", "completed_at": "2026-10-13T12:00:01Z"},
        "inventory": {
            "asset": {"id": "asset:example", "name": "example", "kind": "repository"},
            "locations": [{"id": "location:example", "asset_id": "asset:example", "path": "src/example.py", "start": {"line": 7, "column": 3}}]
        },
        "findings": findings,
        "policy_decisions": decisions.into_iter().collect::<Vec<_>>(),
        "policy_summary": {"allowed": 0, "warned": 0, "denied": u64::from(denied.is_some())}
    })).unwrap()
}

fn seed(temp: &tempfile::TempDir, reports: &[ScanReport]) {
    let mut store = Store::open(temp.path().join("history.db")).unwrap();
    for report in reports {
        store.save_report(report).unwrap();
    }
}

fn export(temp: &tempfile::TempDir, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hooray"))
        .current_dir(temp.path())
        .env("HOORAY_DATABASE_PATH", temp.path().join("history.db"))
        .args(["integrations", "export"])
        .args(arguments)
        .output()
        .unwrap()
}

fn payload(output: Output, status: i32) -> Value {
    assert_eq!(
        output.status.code(),
        Some(status),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn exports_produce_ready_payloads_without_rescanning_and_preserve_policy_status() {
    let temp = tempfile::tempdir().unwrap();
    seed(
        &temp,
        &[report(
            "run:denied",
            &["finding:example"],
            Some("finding:example"),
        )],
    );
    let sha = "0123456789012345678901234567890123456789";
    let check = payload(
        export(
            &temp,
            &["run:denied", "--kind", "github-check", "--head-sha", sha],
        ),
        1,
    );
    assert_eq!(check["head_sha"], sha);
    assert_eq!(check["external_id"], "run:denied");
    assert_eq!(check["conclusion"], "failure");
    assert_eq!(check["output"]["annotations"][0]["path"], "src/example.py");
    let slack = payload(export(&temp, &["run:denied", "--kind", "slack"]), 1);
    assert!(slack["text"].as_str().unwrap().contains("DENIED"));
    let vscode = payload(export(&temp, &["run:denied", "--kind", "vscode"]), 1);
    assert_eq!(vscode["diagnostics"].as_array().unwrap().len(), 1);
    let lsp = payload(
        export(
            &temp,
            &[
                "run:denied",
                "--kind",
                "lsp",
                "--document-uri",
                "file:///workspace/src/example.py",
                "--workspace-root",
                "/workspace",
            ],
        ),
        1,
    );
    assert_eq!(lsp["method"], "textDocument/publishDiagnostics");
    assert_eq!(lsp["params"]["diagnostics"].as_array().unwrap().len(), 1);
    let jira = payload(
        export(
            &temp,
            &["run:denied", "--kind", "jira", "--project-key", "SEC"],
        ),
        1,
    );
    assert_eq!(jira["fields"]["project"]["key"], "SEC");
    assert_eq!(jira["fields"]["issuetype"]["name"], "Bug");
    assert_eq!(
        Store::open(temp.path().join("history.db"))
            .unwrap()
            .list_run_summaries(10, 0)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn baseline_gate_blocks_new_and_unscoped_denials_but_can_accept_existing_findings() {
    let temp = tempfile::tempdir().unwrap();
    seed(
        &temp,
        &[
            report("run:baseline", &["finding:old"], Some("finding:old")),
            report("run:existing", &["finding:old"], Some("finding:old")),
            report(
                "run:new",
                &["finding:old", "finding:new"],
                Some("finding:new"),
            ),
            report("run:unscoped", &["finding:old"], Some("")),
        ],
    );
    let existing = payload(
        export(
            &temp,
            &[
                "run:existing",
                "--kind",
                "pr-gate",
                "--baseline",
                "run:baseline",
            ],
        ),
        0,
    );
    assert_eq!(existing["passed"], true);
    assert_eq!(existing["introduced_findings"], 0);
    assert_eq!(existing["unchanged_findings"], 1);
    let new = payload(
        export(
            &temp,
            &["run:new", "--kind", "pr-gate", "--baseline", "run:baseline"],
        ),
        1,
    );
    assert_eq!(new["passed"], false);
    assert_eq!(new["new_denied_decisions"][0]["finding_id"], "finding:new");
    let unscoped = payload(
        export(
            &temp,
            &[
                "run:unscoped",
                "--kind",
                "pr-gate",
                "--baseline",
                "run:baseline",
            ],
        ),
        1,
    );
    assert_eq!(unscoped["passed"], false);
    assert_eq!(
        unscoped["unscoped_denied_decisions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn gate_rejects_cross_asset_baselines_and_never_writes_partial_payloads() {
    let temp = tempfile::tempdir().unwrap();
    let mut foreign = report("run:foreign", &[], None);
    foreign.inventory.asset.id = hooray::model::AssetId::new("asset:foreign").unwrap();
    foreign.inventory.locations.clear();
    seed(&temp, &[report("run:current", &[], None), foreign]);
    for arguments in [
        vec![
            "run:current",
            "--kind",
            "pr-gate",
            "--baseline",
            "run:foreign",
        ],
        vec![
            "run:current",
            "--kind",
            "pr-gate",
            "--baseline",
            "run:missing",
        ],
        vec!["run:missing", "--kind", "slack"],
        vec![
            "run:current",
            "--kind",
            "slack",
            "--details-url",
            "http://example.invalid",
        ],
    ] {
        let output = export(&temp, &arguments);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn export_options_fail_early_for_missing_incompatible_or_invalid_inputs() {
    let temp = tempfile::tempdir().unwrap();
    for arguments in [
        vec!["run:test", "--kind", "github-check"],
        vec![
            "run:test",
            "--kind",
            "github-check",
            "--head-sha",
            "not-a-sha",
        ],
        vec!["run:test", "--kind", "jira"],
        vec!["run:test", "--kind", "jira", "--project-key", "bad\nkey"],
        vec!["run:test", "--kind", "lsp"],
        vec!["run:test", "--kind", "pr-gate"],
        vec!["run:test", "--kind", "slack", "--baseline", "run:old"],
        vec![
            "run:test",
            "--kind",
            "vscode",
            "--details-url",
            "https://example.invalid",
        ],
        vec![
            "run:test",
            "--kind",
            "slack",
            "--head-sha",
            "0123456789012345678901234567890123456789",
        ],
        vec![
            "run:test",
            "--kind",
            "slack",
            "--document-uri",
            "file:///example",
        ],
        vec!["run:test", "--kind", "slack", "--project-key", "SEC"],
        vec![
            "run:test",
            "--kind",
            "slack",
            "--workspace-root",
            "/workspace",
        ],
        vec![
            "run:test",
            "--kind",
            "vscode",
            "--workspace-root",
            "relative",
        ],
        vec![
            "run:test",
            "--kind",
            "vscode",
            "--workspace-root",
            "/workspace/../other",
        ],
        vec!["run:test", "--kind", "slack", "--max-items", "0"],
    ] {
        let output = export(&temp, &arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(output.stdout.is_empty());
        assert!(
            !temp.path().join("history.db").exists(),
            "invalid options must not open history"
        );
    }
}

#[test]
fn export_file_failure_remains_operational_even_for_a_denied_report() {
    let temp = tempfile::tempdir().unwrap();
    seed(&temp, &[report("run:denied", &[], Some(""))]);
    let output = export(
        &temp,
        &[
            "run:denied",
            "--kind",
            "slack",
            "--output",
            "missing/report.json",
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(!temp.path().join("missing").exists());
}

#[test]
fn selection_is_deterministic_and_payload_overflow_preserves_existing_output() {
    let temp = tempfile::tempdir().unwrap();
    let short = report("run:short", &["finding:one", "finding:two"], None);
    let ids: Vec<String> = (0..500)
        .map(|index| format!("finding:{index:04}"))
        .collect();
    let mut large = report(
        "run:large",
        &ids.iter().map(String::as_str).collect::<Vec<_>>(),
        None,
    );
    for finding in large.findings.values_mut() {
        finding.summary = Some("Review this warning. ".repeat(400));
    }
    seed(&temp, &[short, large]);
    let first = export(
        &temp,
        &["run:short", "--kind", "vscode", "--max-items", "1"],
    );
    let second = export(
        &temp,
        &["run:short", "--kind", "vscode", "--max-items", "1"],
    );
    assert_eq!(first.stdout, second.stdout);
    let value = payload(first, 0);
    assert_eq!(value["diagnostics"].as_array().unwrap().len(), 1);
    assert_eq!(value["truncation"]["total"], 2);
    std::fs::write(temp.path().join("preserved.json"), "existing output").unwrap();
    let oversized = export(
        &temp,
        &[
            "run:large",
            "--kind",
            "vscode",
            "--output",
            "preserved.json",
        ],
    );
    assert_eq!(oversized.status.code(), Some(2));
    assert!(oversized.stdout.is_empty());
    assert_eq!(
        std::fs::read_to_string(temp.path().join("preserved.json")).unwrap(),
        "existing output"
    );
}

#[test]
fn editor_projection_normalizes_relative_paths_without_changing_absolute_or_traversal_paths() {
    let temp = tempfile::tempdir().unwrap();
    let mut reports = Vec::new();
    for (run_id, path) in [
        ("run:relative", "./src/example.py"),
        ("run:absolute", "/original/src/example.py"),
        ("run:traversal", "../outside.py"),
    ] {
        let mut scan = report(run_id, &["finding:example"], None);
        let mut location = scan.inventory.locations.pop_first().unwrap();
        location.path = path.to_owned();
        scan.inventory.locations.insert(location);
        reports.push(scan);
    }
    seed(&temp, &reports);
    let relative = payload(
        export(
            &temp,
            &[
                "run:relative",
                "--kind",
                "vscode",
                "--workspace-root",
                "/workspace/client",
            ],
        ),
        0,
    );
    assert_eq!(
        relative["diagnostics"][0]["uri"],
        "file:///workspace/client/src/example.py"
    );
    let absolute = payload(
        export(
            &temp,
            &[
                "run:absolute",
                "--kind",
                "vscode",
                "--workspace-root",
                "/workspace",
            ],
        ),
        0,
    );
    assert_eq!(
        absolute["diagnostics"][0]["uri"],
        "file:///original/src/example.py"
    );
    let traversal = payload(
        export(
            &temp,
            &[
                "run:traversal",
                "--kind",
                "lsp",
                "--workspace-root",
                "/workspace",
                "--document-uri",
                "file:///outside.py",
            ],
        ),
        0,
    );
    assert!(
        traversal["params"]["diagnostics"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let stored = Store::open(temp.path().join("history.db"))
        .unwrap()
        .get_run(&hooray::model::RunId::new("run:relative").unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.inventory.locations.first().unwrap().path,
        "./src/example.py"
    );
}
