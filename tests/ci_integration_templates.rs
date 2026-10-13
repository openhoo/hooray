#![cfg(unix)]

use std::{os::unix::fs::PermissionsExt, path::Path, process::Command};

use hooray::integrations::{IntegrationGenerator, IntegrationLimits};
use serde_json::Value;

fn generator() -> IntegrationGenerator {
    IntegrationGenerator::new(IntegrationLimits::default()).unwrap()
}

fn yaml(body: &[u8]) -> Value {
    serde_yaml::from_slice(body).unwrap()
}

fn fake_scanner(directory: &Path) -> std::path::PathBuf {
    let bin = directory.join("bin");
    std::fs::create_dir(&bin).unwrap();
    let path = bin.join("hooray");
    std::fs::write(
        &path,
        r#"#!/bin/sh
set -eu
# A real Hooray binary rejects wrapper-only variables in its configuration.
for name in HOORAY_EXECUTABLE HOORAY_INPUT HOORAY_POLICY HOORAY_IMAGE HOORAY_DISABLED HOORAY_POLICY_DENIED HOORAY_POLICY_DENIED_COUNT; do
  if env | grep -q "^${name}="; then exit 2; fi
done
test "${HOORAY_OFFLINE:-}" = true || exit 2
test "$1" = scan || exit 2
test "$4" = --policy || test "$4" = --format || exit 2
status=${MOCK_STATUS:-0}
printf '%s\n' "${MOCK_LOG:-}"
test "${MOCK_NO_BUNDLE:-false}" = false || exit "$status"
if [ "$status" -le 1 ]; then
  if [ "$4" = --format ]; then
    printf '{"runs":[{"properties":{"policySummary":{"allowed":3,"warned":2,"denied":1}}}]}' > "$7"
  else
    mkdir "$9"
    for file in gl-code-quality-report.json gl-sarif-report.sarif gl-sbom-hooray.cdx.json gl-junit-report.xml; do
      printf 'test report\n' > "$9/$file"
    done
    denied=false
    count=0
    if [ "$status" = 1 ]; then denied=true; count=1; fi
    if [ "${MOCK_DISAGREE:-false}" = true ]; then denied=false; count=0; fi
    printf 'HOORAY_POLICY_DENIED=%s\nHOORAY_POLICY_DENIED_COUNT=%s\n' "$denied" "$count" > "$9/hooray.env"
  fi
fi
exit "$status"
"#,
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn shell(script: &str, directory: &Path, executable: &Path, status: u8) -> Command {
    let mut command = Command::new("bash"); // hooray:allow-sast -- runs generated scripts in an isolated fixture workspace
    command
        .arg("-c")
        .arg(script)
        .current_dir(directory)
        .env_clear()
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", executable.parent().unwrap().display()),
        )
        .env("HOORAY_OFFLINE", "true")
        .env("MOCK_STATUS", status.to_string());
    command
}

#[test]
fn gitlab_scanner_retains_denials_and_rejects_operational_failures() {
    let template = yaml(&generator().gitlab_security_ci_include().unwrap().body);
    let script = template["hooray_security"]["script"][0].as_str().unwrap();
    let gate = template["hooray_policy"]["script"][0].as_str().unwrap();
    for (status, missing, inconsistent, expected) in [
        (0, false, false, 0),
        (1, false, false, 0),
        (2, false, false, 2),
        (17, false, false, 2),
        (0, true, false, 2),
        (1, true, false, 2),
        (1, false, true, 2),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let executable = fake_scanner(temp.path());
        let output = shell(script, temp.path(), &executable, status)
            .env(
                "HOORAY_IMAGE",
                format!("registry.example/hooray@sha256:{}", "a".repeat(64)),
            )
            .env("HOORAY_INPUT", ".")
            .env("HOORAY_POLICY", "hooray-policy.yaml")
            .env("HOORAY_DISABLED", "false")
            .env("HOORAY_POLICY_DENIED", "false")
            .env("HOORAY_POLICY_DENIED_COUNT", "0")
            .env("MOCK_NO_BUNDLE", missing.to_string())
            .env("MOCK_DISAGREE", inconsistent.to_string())
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(expected),
            "scan status={status}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if expected == 0 {
            let entries = std::fs::read_dir(temp.path().join(".hooray-gitlab"))
                .unwrap()
                .count();
            assert_eq!(entries, 5);
            let result = shell(gate, temp.path(), &executable, status)
                .env("HOORAY_POLICY_DENIED", "false")
                .output()
                .unwrap();
            assert_eq!(result.status.code(), Some(i32::from(status)));
        }
    }
}

#[test]
fn gitlab_scanner_requires_an_immutable_consumer_image() {
    let template = yaml(&generator().gitlab_ci_include().unwrap().body);
    let script = template["hooray_security"]["script"][0].as_str().unwrap();
    for image in [
        "",
        "hooray:latest",
        "hooray@sha256:short",
        "hooray@sha256:ZZ",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let executable = fake_scanner(temp.path());
        let output = shell(script, temp.path(), &executable, 0)
            .env("HOORAY_IMAGE", image)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "image={image}");
        assert!(!temp.path().join(".hooray-gitlab").exists());
    }
}

#[test]
fn gitlab_gate_distinguishes_policy_denials_from_invalid_artifacts() {
    let template = yaml(&generator().gitlab_ci_include().unwrap().body);
    let script = template["hooray_policy"]["script"][0].as_str().unwrap();
    for (body, expected) in [
        (
            "HOORAY_POLICY_DENIED=false\nHOORAY_POLICY_DENIED_COUNT=0\n",
            0,
        ),
        (
            "HOORAY_POLICY_DENIED=true\nHOORAY_POLICY_DENIED_COUNT=1\n",
            1,
        ),
        (
            "HOORAY_POLICY_DENIED=true\nHOORAY_POLICY_DENIED_COUNT=18446744073709551615\n",
            1,
        ),
        (
            "HOORAY_POLICY_DENIED=true\nHOORAY_POLICY_DENIED_COUNT=18446744073709551616\n",
            2,
        ),
        (
            "HOORAY_POLICY_DENIED=false\nHOORAY_POLICY_DENIED_COUNT=0\0\n",
            2,
        ),
        (
            "HOORAY_POLICY_DENIED=false\nHOORAY_POLICY_DENIED_COUNT=1\n",
            2,
        ),
        (
            "HOORAY_POLICY_DENIED=true\nHOORAY_POLICY_DENIED_COUNT=0\n",
            2,
        ),
        (
            "HOORAY_POLICY_DENIED=false\nHOORAY_POLICY_DENIED_COUNT=00\n",
            2,
        ),
        (
            "HOORAY_POLICY_DENIED=false\nHOORAY_POLICY_DENIED=false\n",
            2,
        ),
        (
            "HOORAY_POLICY_DENIED=false\nHOORAY_POLICY_DENIED_COUNT=0",
            2,
        ),
        (
            "HOORAY_POLICY_DENIED=false\nHOORAY_POLICY_DENIED_COUNT=$(touch injected)\n",
            2,
        ),
        (
            "HOORAY_POLICY_DENIED=false\nHOORAY_POLICY_DENIED_COUNT=0\nEXTRA=true\n",
            2,
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join(".hooray-gitlab")).unwrap();
        std::fs::write(temp.path().join(".hooray-gitlab/hooray.env"), body).unwrap();
        let output = Command::new("sh") // hooray:allow-sast -- validates generated policy gates against isolated malformed artifacts
            .arg("-c")
            .arg(script)
            .current_dir(temp.path())
            .env("HOORAY_POLICY_DENIED", "false")
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{body}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!temp.path().join("injected").exists());
    }
    let temp = tempfile::tempdir().unwrap();
    let output = Command::new("sh") // hooray:allow-sast -- validates a missing policy artifact
        .arg("-c")
        .arg(script)
        .current_dir(temp.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    std::fs::create_dir(temp.path().join(".hooray-gitlab")).unwrap();
    std::fs::write(
        temp.path().join("external.env"),
        "HOORAY_POLICY_DENIED=false\nHOORAY_POLICY_DENIED_COUNT=0\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(
        temp.path().join("external.env"),
        temp.path().join(".hooray-gitlab/hooray.env"),
    )
    .unwrap();
    let output = Command::new("sh") // hooray:allow-sast -- validates refusal of a symlink policy artifact
        .arg("-c")
        .arg(script)
        .current_dir(temp.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn additional_ci_generators_preserve_scanner_exit_codes_after_reporting() {
    let azure = yaml(&generator().azure_pipelines_yaml().unwrap().body);
    let azure_scan = azure["steps"][1]["bash"].as_str().unwrap();
    let azure_gate = azure["steps"][4]["bash"].as_str().unwrap();
    let jenkins = generator().jenkins_pipeline().unwrap();
    let jenkins = jenkins.text().unwrap();
    let jenkins_scan = jenkins
        .split("script: '''\n")
        .nth(1)
        .unwrap()
        .split("\n''')")
        .next()
        .unwrap();
    assert_eq!(azure["steps"][1]["continueOnError"], true);
    assert!(
        azure["steps"][2]["condition"]
            .as_str()
            .unwrap()
            .contains("always()")
    );
    assert!(
        azure["steps"][3]["condition"]
            .as_str()
            .unwrap()
            .contains("always()")
    );
    assert_eq!(azure["steps"][4]["condition"], "always()");
    assert!(jenkins.contains("post {\n        always {"));
    assert!(jenkins.contains("skipMarkingBuildUnstable: true"));
    for (status, missing, expected) in [
        (0, false, 0),
        (1, false, 1),
        (2, false, 2),
        (17, false, 2),
        (0, true, 2),
    ] {
        for script in [azure_scan, jenkins_scan] {
            let temp = tempfile::tempdir().unwrap();
            let executable = fake_scanner(temp.path());
            let status_file = temp.path().join("status");
            let output = shell(script, temp.path(), &executable, status)
                .env("HOORAY_EXECUTABLE", &executable)
                .env("HOORAY_INPUT", ".")
                .env("HOORAY_POLICY", "hooray-policy.yaml")
                .env("HR_STATUS_FILE", &status_file)
                .env("HR_SCAN_LOG_FILE", temp.path().join("scan.log"))
                .env(
                    "MOCK_LOG",
                    "prefix ##vso[task.setvariable variable=evil]true\n##[error]injected",
                )
                .env("MOCK_NO_BUNDLE", missing.to_string())
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(expected),
                "status={status}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            if script == azure_scan {
                assert_eq!(
                    std::fs::read_to_string(&status_file).unwrap(),
                    format!("{expected}\n")
                );
                let result = shell(azure_gate, temp.path(), &executable, status)
                    .env("HR_STATUS_FILE", &status_file)
                    .output()
                    .unwrap();
                assert_eq!(result.status.code(), Some(expected));
                assert_eq!(
                    String::from_utf8_lossy(&output.stdout).contains("hoorayReportReady]true"),
                    expected <= 1
                );
                assert!(
                    !String::from_utf8_lossy(&output.stdout)
                        .contains("##vso[task.setvariable variable=evil]")
                );
                assert!(!String::from_utf8_lossy(&output.stdout).contains("##[error]injected"));
            }
        }
    }
}

#[test]
fn github_workflow_keeps_scanning_forks_and_retains_policy_denial_reports() {
    let workflow = yaml(&generator().github_actions_workflow().unwrap().body);
    assert!(workflow["on"]["pull_request"].is_null());
    assert!(workflow["on"].get("pull_request_target").is_none());
    let steps = workflow["jobs"]["hooray"]["steps"].as_array().unwrap();
    let scan = steps.iter().find(|step| step["id"] == "scan").unwrap();
    assert!(scan.get("if").is_none());
    for (status, missing, expected) in [
        (0, false, 0),
        (1, false, 1),
        (2, false, 2),
        (17, false, 2),
        (0, true, 2),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let executable = fake_scanner(temp.path());
        let output_file = temp.path().join("github-output");
        std::fs::write(&output_file, "").unwrap();
        let result = shell(
            scan["run"].as_str().unwrap(),
            temp.path(),
            &executable,
            status,
        )
        .env("RUNNER_TEMP", temp.path())
        .env("GITHUB_OUTPUT", &output_file)
        .env("MOCK_NO_BUNDLE", missing.to_string())
        .output()
        .unwrap();
        assert_eq!(
            result.status.code(),
            Some(expected),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(&output_file).unwrap(),
            format!("status={expected}\n")
        );
        assert_eq!(
            std::fs::read_to_string(temp.path().join("hooray-scan-status")).unwrap(),
            format!("{expected}\n")
        );
    }
    let artifact = steps
        .iter()
        .find(|step| step["name"] == "Retain Hooray report")
        .unwrap();
    assert!(artifact["if"].as_str().unwrap().contains("always()"));
    assert_eq!(artifact["with"]["path"], "hooray.sarif");
    let summary = steps
        .iter()
        .find(|step| step["name"] == "Summarize Hooray scan")
        .unwrap();
    assert_eq!(summary["if"], "always()");
    assert!(summary["run"].as_str().unwrap().contains("Policy denied"));
}
