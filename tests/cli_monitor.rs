use std::{fs, path::Path, process::Command};

use serde_json::Value;

fn cli(directory: &Path, database: &Path, policy: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hooray"));
    command
        .current_dir(directory)
        .env("HOORAY_DATABASE_PATH", database)
        .env("HOORAY_POLICY_PATH", policy)
        .env("HOORAY_OFFLINE", "true");
    command
}

#[test]
fn relative_monitor_source_survives_a_different_working_directory() {
    let temp = tempfile::tempdir().unwrap();
    let registration = temp.path().join("registration");
    let service = temp.path().join("service");
    fs::create_dir_all(registration.join("project")).unwrap();
    fs::create_dir(&service).unwrap();
    let database = temp.path().join("history.db");
    let policy = temp.path().join("policy.yaml");
    fs::write(&policy, "version: 1\ndefault_outcome: allow\n").unwrap();
    let added = cli(&registration, &database, &policy)
        .args([
            "monitor",
            "targets",
            "add",
            "project",
            "--source",
            "project",
            "--interval-seconds",
            "60",
        ])
        .output()
        .unwrap();
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );

    let listed = cli(&service, &database, &policy)
        .args(["monitor", "targets", "list", "--format", "json"])
        .output()
        .unwrap();
    assert!(listed.status.success());
    let targets: Value = serde_json::from_slice(&listed.stdout).unwrap();
    let source = targets[0]["source"].as_str().unwrap();
    assert!(Path::new(source).is_absolute(), "stored source: {source}");
    assert_eq!(
        fs::canonicalize(source).unwrap(),
        fs::canonicalize(registration.join("project")).unwrap()
    );

    let monitored = cli(&service, &database, &policy)
        .args(["monitor", "--once"])
        .output()
        .unwrap();
    assert!(
        monitored.status.success(),
        "{}",
        String::from_utf8_lossy(&monitored.stderr)
    );
    let store = hooray::store::Store::open(&database).unwrap();
    let targets = store.list_monitor_targets(10, 0).unwrap();
    assert!(
        targets[0].inventory.is_some(),
        "monitor must evaluate the registered source"
    );
    assert!(targets[0].source_fingerprint.is_some());
}
