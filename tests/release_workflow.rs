use serde_yaml::Value;

const RELEASE_WORKFLOW: &str = include_str!("../.github/workflows/release.yml");

#[test]
fn manual_publication_is_limited_to_main_except_dry_run() {
    let workflow: Value = serde_yaml::from_str(RELEASE_WORKFLOW).expect("release workflow YAML");
    let condition = workflow["jobs"]["prepare"]["if"]
        .as_str()
        .expect("prepare job publication guard");

    assert_eq!(
        condition,
        "github.event_name != 'workflow_dispatch' || inputs.dry_run || github.ref_name == 'main'"
    );
}

#[cfg(unix)]
#[test]
fn setup_installs_verified_legacy_and_dual_binary_archives() {
    let status = std::process::Command::new("bash")
        .arg("tests/setup_release.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .expect("run setup action fixture");
    assert!(status.success(), "setup action fixture: {status}");
}

#[cfg(unix)]
#[test]
fn image_promotion_and_historical_provenance_follow_the_release_workflow() {
    let workflow: Value = serde_yaml::from_str(RELEASE_WORKFLOW).expect("release workflow YAML");
    let steps = workflow["jobs"]["ghcr"]["steps"]
        .as_sequence()
        .expect("GHCR release steps");
    let step = steps
        .iter()
        .find(|s| s["id"].as_str() == Some("image"))
        .expect("publish/recover step");
    let temp = tempfile::tempdir().expect("private workflow fixture");
    let script = temp.path().join("publish-or-recover.sh");
    std::fs::write(&script, step["run"].as_str().expect("Bash body")).unwrap();
    let run = std::process::Command::new("python3")
        .args(["-I", "tests/release_image_workflow.py"])
        .arg(script)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run isolated image release fixture");
    assert!(
        run.status.success(),
        "{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    // These uses: steps are executed by Actions, not by the Bash subprocess.
    // Historical verification must prevent re-signing or re-attesting the old image.
    for name in [
        "Log in to GHCR for signing",
        "Sign image digest",
        "Attest image digest",
    ] {
        let step = steps
            .iter()
            .find(|s| s["name"].as_str() == Some(name))
            .expect(name);
        assert_eq!(
            step["if"].as_str(),
            Some("steps.image.outputs.reuse_provenance != 'true'"),
            "{name}"
        );
    }
}
