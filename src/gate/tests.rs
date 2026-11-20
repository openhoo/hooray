use super::*;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

const SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
const ALLOW: &str = "version: 1\ndefault_outcome: allow\n";

fn archive(dir: &Path, members: &[(&str, &str)]) -> PathBuf {
    let path = dir.join("artifact.zip");
    let mut zip = zip::ZipWriter::new(fs::File::create(&path).unwrap());
    for &(name, bytes) in members {
        zip.start_file(
            name,
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated),
        )
        .unwrap();
        zip.write_all(bytes.as_bytes()).unwrap();
    }
    zip.finish().unwrap();
    path
}

fn package(version: &str, source: &str) -> String {
    format!("[[package]]\nname='zip'\nversion='{version}'\nsource='{source}'\n")
}
fn policy(dir: &Path, data: &str) -> PathBuf {
    let p = dir.join("policy.yaml");
    fs::write(&p, data).unwrap();
    p
}

#[tokio::test]
async fn gate_native_decision_survives_reopen_pins_report_and_requires_both_digests() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("gate.sqlite");
    let mut store = Store::open(&db).unwrap();
    let policy = policy(dir.path(), ALLOW);
    let safe = package("9.8.1", SOURCE);
    let artifact = archive(dir.path(), &[("Cargo.lock", &safe)]);
    let d = evaluate(&Config::default(), &mut store, &artifact, &policy)
        .await
        .unwrap();
    assert!(d.allowed());
    assert_eq!(d.matched_advisories, Some(0));
    let (a, p) = input_digests(&artifact, &policy).unwrap();
    assert_eq!(a, crate::util::sha256_hex(&fs::read(&artifact).unwrap()));
    assert_eq!(p, crate::util::sha256_hex(ALLOW.as_bytes()));
    drop(store);
    let mut store = Store::open(&db).unwrap();
    assert_eq!(
        require_current_allow(&store, &format!("sha256:{a}"), &p).unwrap(),
        d
    );
    assert!(lookup(&store, &a.to_uppercase(), &p).is_err());
    assert!(require_current_allow(&store, &"0".repeat(64), &p).is_err());
    assert!(require_current_allow(&store, &a, &"0".repeat(64)).is_err());
    assert_eq!(store.delete_before("2099-01-01T00:00:00Z").unwrap(), 0);
    assert!(
        store
            .get_run(&crate::model::RunId::new(&d.run_id).unwrap())
            .unwrap()
            .is_some()
    );
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute_batch("PRAGMA recursive_triggers=OFF; PRAGMA foreign_keys=ON;")
        .unwrap();
    for query in [
        "UPDATE artifact_gate_attempts SET attempt_id=1",
        "DELETE FROM artifact_gate_attempts",
        "UPDATE artifact_gate_decisions SET outcome='deny'",
        "DELETE FROM artifact_gate_decisions",
        "INSERT OR REPLACE INTO artifact_gate_attempts SELECT * FROM artifact_gate_attempts",
        "REPLACE INTO artifact_gate_decisions SELECT * FROM artifact_gate_decisions",
    ] {
        assert!(conn.execute(query, []).is_err(), "{query}");
    }
    // A new attempt cannot take over the same native run via its UNIQUE key.
    store.start_gate_attempt(&a, &p).unwrap();
    let colliding_run = "INSERT OR REPLACE INTO artifact_gate_decisions
        SELECT (SELECT max(attempt_id) FROM artifact_gate_attempts), run_id, scope, scanner_version,
        publisher_source,publisher_revision,publisher_sha256,outcome,reason,component_purl,
        matched_advisories,policy_allowed,policy_warned,policy_denied,completed_at FROM artifact_gate_decisions";
    assert!(conn.execute(colliding_run, []).is_err());
    let restored = evaluate(&Config::default(), &mut store, &artifact, &policy)
        .await
        .unwrap();
    assert!(restored.allowed());
    // A later native evaluation that fails to scan cannot fall back to d.
    let strict = Config {
        max_input_bytes: 1,
        ..Config::default()
    };
    assert!(
        evaluate(&strict, &mut store, &artifact, &policy)
            .await
            .is_err()
    );
    assert!(require_current_allow(&store, &a, &p).is_err());
}

#[tokio::test]
async fn gate_denies_publisher_even_with_allow_policy_and_distinguishes_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open_memory().unwrap();
    let policy = policy(dir.path(), ALLOW);
    let old = package("8.6.0", SOURCE);
    let path = archive(dir.path(), &[("Cargo.lock", &old)]);
    let d = evaluate(&Config::default(), &mut store, &path, &policy)
        .await
        .unwrap();
    assert_eq!(d.outcome, Outcome::Deny);
    assert!(d.matched_advisories.unwrap() > 0);
    assert_eq!(d.policy_summary.denied, 0);
    assert!(require_current_allow(&store, &d.artifact_sha256, &d.policy_sha256).is_err());
    let safe = package("9.8.1", SOURCE);
    let other = "[[package]]\nname='other'\nversion='1.0.0'\n";
    let duplicate = format!(
        "{safe}{}",
        package("9.8.1", "git+https://example.invalid/fork")
    );
    for members in [
        vec![("Cargo.lock", other)],
        vec![("Cargo.lock", &duplicate)],
        vec![(
            "Cargo.lock",
            &package("9.8.1", "git+https://example.invalid/fork"),
        )],
        vec![(
            "Cargo.lock",
            &package("9.8.1", "registry+https://example.invalid"),
        )],
        vec![("Cargo.lock", "[[package]]\nname='zip'\nversion='9.8.1'\n")],
        vec![("Cargo.lock", &package("future", SOURCE))],
        vec![
            ("Cargo.lock", &safe),
            ("extra.txt", "not part of the profile"),
        ],
    ] {
        let path = archive(dir.path(), &members);
        let d = evaluate(&Config::default(), &mut store, &path, &policy)
            .await
            .unwrap();
        assert_eq!(d.outcome, Outcome::Unknown, "{members:?}: {d:?}");
        assert!(d.matched_advisories.is_none());
        assert!(require_current_allow(&store, &d.artifact_sha256, &d.policy_sha256).is_err());
    }
}

#[tokio::test]
async fn gate_rejects_policy_denials_and_time_sensitive_positive_coverage() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open_memory().unwrap();
    let safe = package("9.8.1", SOURCE);
    let manifest = "[package]\nname='app'\nversion='0.1.0'\nlicense='MIT'\n";
    let lock = format!("[[package]]\nname='app'\nversion='0.1.0'\n{safe}");
    let path = archive(
        dir.path(),
        &[("Cargo.lock", &lock), ("Cargo.toml", manifest)],
    );
    let p = policy(dir.path(), "version: 1\ndefault_outcome: deny\n");
    let d = evaluate(&Config::default(), &mut store, &path, &p)
        .await
        .unwrap();
    assert_eq!(d.outcome, Outcome::Deny);
    assert_eq!(d.matched_advisories, Some(0));
    assert!(d.policy_summary.denied > 0);
    let p = policy(
        dir.path(),
        "version: 1\ndefault_outcome: allow\nrules:\n  - id: risk\n    outcome: deny\n    reason: high risk\n    selectors:\n      rule_ids: [no-such-rule]\n      risk: {minimum: 100}\n",
    );
    let d = evaluate(&Config::default(), &mut store, &path, &p)
        .await
        .unwrap();
    assert_eq!(d.outcome, Outcome::Unknown);
    let p = policy(
        dir.path(),
        "version: 1\ndefault_outcome: allow\nexceptions:\n  - id: expiring\n    owner: ops\n    reason: review\n    ticket: SEC-1\n    expires_at: '2099-06-01T00:00:00Z'\n    selectors: {purl: 'pkg:cargo/zip@9.8.1'}\n",
    );
    let d = evaluate(&Config::default(), &mut store, &path, &p)
        .await
        .unwrap();
    assert_eq!(d.outcome, Outcome::Unknown);
    assert!(d.reason.contains("expiring"));
}

#[cfg(unix)]
#[test]
fn gate_snapshots_pin_bytes_reject_links_and_enforce_limits() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = tempfile::tempdir().unwrap();
    let p = policy(dir.path(), ALLOW);
    let a = dir.path().join("bounded.zip");
    fs::write(&a, b"123").unwrap();
    let x = snapshot::Snapshots::new(&a, &p, 3).unwrap();
    assert_eq!(
        x.artifact
            .parent()
            .unwrap()
            .metadata()
            .unwrap()
            .permissions()
            .mode()
            & 0o077,
        0
    );
    fs::write(&a, b"4567").unwrap();
    assert_eq!(fs::read(x.artifact).unwrap(), b"123");
    assert_eq!(x.artifact_sha256, crate::util::sha256_hex(b"123"));
    assert!(snapshot::Snapshots::new(&a, &p, 3).is_err());
    let link = dir.path().join("alias.yaml");
    symlink(&p, &link).unwrap();
    assert!(input_digests(&a, &link).is_err());
    assert!(input_digests(&link, &p).is_err());
}

// Exercise the public reader against the history left by old scanner versions
// and concurrent workers. Completing an old attempt later must never promote it.
#[tokio::test]
async fn gate_latest_attempt_wins_across_workers_and_provenance_changes() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("history.db");
    let mut writer = Store::open(&db).unwrap();
    let mut peer = Store::open(&db).unwrap();
    let path = archive(dir.path(), &[("Cargo.lock", &package("9.8.1", SOURCE))]);
    let p = policy(dir.path(), ALLOW);
    let first = evaluate(&Config::default(), &mut writer, &path, &p)
        .await
        .unwrap();
    let artifact = first.artifact_sha256.as_str();
    let policy = first.policy_sha256.as_str();
    let earlier = writer.start_gate_attempt(artifact, policy).unwrap();
    let later = peer.start_gate_attempt(artifact, policy).unwrap();
    let run = writer
        .get_run(&crate::model::RunId::new(&first.run_id).unwrap())
        .unwrap()
        .unwrap();
    let mut stale = first.clone();
    let mut old_run = run.clone();
    old_run.run.id = crate::model::RunId::new("run:old-scanner").unwrap();
    old_run.run.scanner_version = Some("old".into());
    writer.save_report(&old_run).unwrap();
    stale.run_id = old_run.run.id.to_string();
    stale.scanner_version = "old".into();
    peer.finish_gate_attempt(later, &stale).unwrap();
    assert!(lookup(&writer, artifact, policy).unwrap().is_none());
    let mut slow = first.clone();
    let mut other_run = run.clone();
    other_run.run.id = crate::model::RunId::new("run:slow").unwrap();
    writer.save_report(&other_run).unwrap();
    slow.run_id = other_run.run.id.to_string();
    writer.finish_gate_attempt(earlier, &slow).unwrap();
    assert!(lookup(&peer, artifact, policy).unwrap().is_none());

    let number = peer.start_gate_attempt(artifact, policy).unwrap();
    let mut denial = first.clone();
    let mut denied_run = run;
    denied_run.run.id = crate::model::RunId::new("run:deny").unwrap();
    peer.save_report(&denied_run).unwrap();
    denial.run_id = denied_run.run.id.to_string();
    denial.outcome = Outcome::Deny;
    denial.reason = "test decision".into();
    peer.finish_gate_attempt(number, &denial).unwrap();
    assert_eq!(lookup(&writer, artifact, policy).unwrap(), Some(denial));
    assert!(require_current_allow(&writer, artifact, policy).is_err());
}
