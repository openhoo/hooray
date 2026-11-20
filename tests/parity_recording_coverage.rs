#![cfg(feature = "parity")]

use std::{fs, path::Path, process::Command};

use serde_json::{Value, json};

fn check(corpus: &Path, recordings: &Path, strict: bool) -> (i32, Vec<Value>) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hooray-parity"));
    cmd.arg("check")
        .arg("--corpus")
        .arg(corpus)
        .arg("--recordings")
        .arg(recordings)
        .args(["--format", "json"]);
    if strict {
        cmd.arg("--require-recordings");
    }
    let out = cmd.output().unwrap();
    let code = out.status.code().unwrap();
    if code == 2 {
        assert!(String::from_utf8_lossy(&out.stderr).contains("non-empty corpus manifest"));
        return (code, vec![]);
    }
    (
        code,
        serde_json::from_slice(&out.stdout).expect("case results"),
    )
}

#[test]
fn coverage_gate_distinguishes_local_checks_from_complete_and_partial_replays() {
    let dir = tempfile::tempdir().unwrap();
    let corpus = dir.path().join("corpus");
    let recordings = dir.path().join("recordings");
    fs::create_dir(&corpus).unwrap();
    fs::create_dir(&recordings).unwrap();
    let manifest = corpus.join("manifest.json");
    assert_eq!(check(&corpus, &recordings, true).0, 2);
    fs::write(&manifest, r#"{"cases":[]}"#).unwrap();
    assert_eq!(check(&corpus, &recordings, true).0, 2);

    let case = corpus.join("tiny");
    fs::create_dir(&case).unwrap();
    let sbom = case.join("tiny.cdx.json");
    fs::write(&sbom, json!({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "components": [{"type":"library","name":"tiny","version":"1.0.0","purl":"pkg:cargo/tiny@1.0.0"}]
    }).to_string()).unwrap();
    let row = json!({"case_id":"tiny","kind":"cyclonedx-sbom","min_components":1});
    fs::write(&manifest, json!({"cases":[row]}).to_string()).unwrap();
    assert_eq!(check(&corpus, &recordings, false).0, 0);
    let (status, rows) = check(&corpus, &recordings, true);
    assert_eq!(status, 1);
    assert_eq!(rows[0]["notes"], json!(["missing Xray recording"]));

    // Synthetic data exercises the CLI contract only. It is not Xray evidence.
    let recording = recordings.join("tiny.recording.json");
    let out = Command::new(env!("CARGO_BIN_EXE_hooray-parity"))
        .args(["record", "--offline", "--case"])
        .arg(&case)
        .arg("--xray-sbom")
        .arg(&sbom)
        .arg("--out")
        .arg(&recording)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(check(&corpus, &recordings, true).0, 0);

    let second = corpus.join("second");
    fs::create_dir(&second).unwrap();
    fs::copy(&sbom, second.join("tiny.cdx.json")).unwrap();
    fs::write(
        &manifest,
        json!({"cases":[row,{"case_id":"second","kind":"cyclonedx-sbom","min_components":1}]})
            .to_string(),
    )
    .unwrap();
    fs::copy(&recording, recordings.join("duplicate.recording.json")).unwrap();
    let (status, rows) = check(&corpus, &recordings, true);
    assert_eq!(status, 1);
    assert!(
        rows.iter()
            .any(|r| r["case_id"] == "second" && r["notes"] == json!(["missing Xray recording"]))
    );
    assert!(rows.iter().any(|r| r["case_id"] == "tiny"
        && r["notes"] == json!(["duplicate Xray recording for this case"])));
}
