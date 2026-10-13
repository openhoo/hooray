#[cfg(unix)]
mod unix {
    use std::{collections::BTreeMap, path::Path, process::Command};

    use serde_json::{Value as JsonValue, json};
    use serde_yaml::Value;

    const SCAN_ACTION: &str = include_str!("../actions/scan/action.yml");
    const ACTION_README: &str = include_str!("../actions/README.md");
    const FAKE_CLI: &str = r#"#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['ACTION_CALLS'], 'a') as stream:
    stream.write(json.dumps(args) + '\n')
if args[:1] == ['--config']:
    args = args[2:]
status = int(os.environ.get('ACTION_SCAN_STATUS', '0'))
if args[:2] == ['policy', 'validate']:
    sys.exit(int(os.environ.get('ACTION_POLICY_STATUS', '0')))
if args[:2] == ['scan', 'project']:
    if '--output' in args and os.environ.get('ACTION_OMIT_REPORT') != 'true':
        destination = pathlib.Path(args[args.index('--output') + 1])
        if args[args.index('--format') + 1] == 'gitlab-artifacts':
            destination.mkdir()
            (destination / 'report.sarif').write_text('current bundle\n')
        else:
            destination.write_text('current primary\n')
    print('::error::repository-controlled CLI text')
    sys.exit(status)
if args[:2] == ['history', 'list']:
    destination = pathlib.Path(args[args.index('--output') + 1])
    mode = os.environ.get('ACTION_HISTORY_MODE', '')
    report = {
        'run': {'id': 'run:test-current'},
        'policy_summary': {'allowed': 3, 'warned': 2, 'denied': 1 if status == 1 else 0},
        'findings': {'finding:one': {}, 'finding:two': {}},
    }
    if mode == 'newline':
        report['run']['id'] = 'run:test\nreport=stale'
    elif mode == 'option':
        report['run']['id'] = '--help'
    elif mode == 'contradictory':
        report['policy_summary']['denied'] = 1 if status == 0 else 0
    elif mode == 'boolean':
        report['policy_summary']['allowed'] = True
    destination.write_text(json.dumps([] if mode == 'empty' else [report]))
    sys.exit(int(os.environ.get('ACTION_HISTORY_STATUS', '0')))
if args[:1] == ['report']:
    report_status = int(os.environ.get('ACTION_REPORT_STATUS', str(status)))
    destination = pathlib.Path(args[args.index('--output') + 1])
    if os.environ.get('ACTION_OMIT_EXTRA') != 'true':
        if args[args.index('--format') + 1] == 'gitlab-artifacts':
            destination.mkdir()
            (destination / 'report.sarif').write_text('persisted bundle\n')
        else:
            destination.write_text('persisted extra\n' + 'details ' * int(os.environ.get('ACTION_EXTRA_SIZE', '0')))
    sys.exit(report_status)
sys.exit(2)
"#;

    fn scan_script() -> String {
        let action: Value = serde_yaml::from_str(SCAN_ACTION).expect("scan action YAML");
        let step = action["runs"]["steps"]
            .as_sequence()
            .expect("composite action steps")
            .iter()
            .find(|step| step["id"].as_str() == Some("scan"))
            .expect("scan shell step");
        assert!(step["uses"].is_null(), "execute the scan run block");
        step["run"].as_str().expect("scan shell step").to_owned()
    }

    fn executable(path: &Path, script: &str) {
        use std::os::unix::fs::PermissionsExt;

        std::fs::write(path, script).expect("write fixture executable");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .expect("mark fixture executable");
    }

    struct Fixture {
        directory: tempfile::TempDir,
    }

    struct Result {
        status: i32,
        outputs: BTreeMap<String, String>,
        summary: String,
        stdout: String,
        stderr: String,
        calls: Vec<JsonValue>,
    }

    impl Fixture {
        fn new() -> Self {
            // macOS /var and /tmp can be system symlinks; fixtures use a
            // canonical parent so security checks target planted links only.
            let parent = std::env::temp_dir()
                .canonicalize()
                .expect("canonical temp root");
            let directory = tempfile::tempdir_in(parent).expect("action fixture directory");
            executable(
                &directory.path().join("scan.sh"),
                &format!("#!/usr/bin/env bash\n{}", scan_script()),
            );
            executable(&directory.path().join("fake-hooray"), FAKE_CLI);
            std::fs::write(directory.path().join("summary"), "").unwrap();
            std::fs::write(directory.path().join("calls"), "").unwrap();
            Self { directory }
        }

        fn path(&self, name: &str) -> std::path::PathBuf {
            self.directory.path().join(name)
        }

        fn run(&self, env: &[(&str, &str)]) -> Result {
            self.run_from(self.directory.path(), env)
        }

        fn run_from(&self, working_directory: &Path, env: &[(&str, &str)]) -> Result {
            let output = Command::new(self.path("scan.sh"))
                .current_dir(working_directory)
                .env("INPUT_CONFIG", "")
                .env("INPUT_EXECUTABLE", self.path("fake-hooray"))
                .env("INPUT_FORMAT", "sarif")
                .env("INPUT_PATH", ".")
                .env("INPUT_OFFLINE", "false")
                .env("INPUT_OUTPUT", "hooray.sarif")
                .env("INPUT_POLICY", "hooray-policy.yaml")
                .env("INPUT_FAIL_ON_POLICY", "true")
                .env("INPUT_SUMMARY", "true")
                .env("INPUT_ADDITIONAL_FORMATS", "")
                .env(
                    "GITHUB_ACTION_PATH",
                    Path::new(env!("CARGO_MANIFEST_DIR")).join("actions/scan"),
                )
                .env("GITHUB_OUTPUT", self.path("outputs"))
                .env("GITHUB_STEP_SUMMARY", self.path("summary"))
                .env("RUNNER_TEMP", self.directory.path())
                .env("ACTION_CALLS", self.path("calls"))
                .envs(env.iter().copied())
                .output()
                .expect("run actual composite action shell");
            Result {
                status: output.status.code().expect("action exit status"),
                outputs: std::fs::read_to_string(self.path("outputs"))
                    .unwrap()
                    .lines()
                    .map(|line| {
                        let (key, value) = line.split_once('=').expect("single-line output");
                        (key.to_owned(), value.to_owned())
                    })
                    .collect(),
                summary: std::fs::read_to_string(self.path("summary")).unwrap(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                calls: std::fs::read_to_string(self.path("calls"))
                    .unwrap()
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect(),
            }
        }
    }

    #[test]
    fn scan_action_rejects_stdout_newlines_and_option_injection() {
        for (name, value) in [
            ("INPUT_OUTPUT", "-"),
            ("INPUT_OUTPUT", "reports\nreport.sarif"),
            ("INPUT_OUTPUT", "reports\rreport.sarif"),
            ("INPUT_PATH", "--help"),
            ("INPUT_POLICY", "--help"),
            ("INPUT_CONFIG", "--help"),
            ("INPUT_FORMAT", "sarif\nexit-code=0"),
            ("INPUT_EXECUTABLE", "--help"),
            ("INPUT_ADDITIONAL_FORMATS", "json\nexit-code=0"),
        ] {
            let result = Fixture::new().run(&[(name, value)]);
            assert_eq!(result.status, 2, "{name}");
            assert_eq!(result.outputs["exit-code"], "2");
            assert_eq!(result.outputs["policy-status"], "error");
            assert_eq!(result.outputs["report"], "");
            assert!(result.calls.is_empty());
        }
    }

    #[test]
    fn scan_action_publishes_truthful_pass_and_deny_outputs_and_summaries() {
        for (scan_status, fail, action_status, policy_status) in [
            ("0", "true", 0, "passed"),
            ("1", "true", 1, "denied"),
            ("1", "false", 0, "denied"),
        ] {
            let fixture = Fixture::new();
            let result = fixture.run(&[
                ("ACTION_SCAN_STATUS", scan_status),
                ("INPUT_FAIL_ON_POLICY", fail),
            ]);
            assert_eq!(result.status, action_status);
            assert_eq!(result.outputs["exit-code"], action_status.to_string());
            assert_eq!(result.outputs["scan-exit-code"], scan_status);
            assert_eq!(result.outputs["policy-status"], policy_status);
            assert_eq!(result.outputs["run-id"], "run:test-current");
            assert_eq!(result.outputs["allowed"], "3");
            assert_eq!(result.outputs["warned"], "2");
            assert_eq!(result.outputs["denied"], scan_status);
            assert_eq!(result.outputs["finding-count"], "2");
            assert_eq!(
                result.outputs["report"],
                fixture.path("hooray.sarif").to_string_lossy()
            );
            assert_eq!(
                serde_json::from_str::<JsonValue>(&result.outputs["reports"]).unwrap(),
                json!({"sarif": fixture.path("hooray.sarif")})
            );
            assert_eq!(
                std::fs::read_to_string(fixture.path("hooray.sarif")).unwrap(),
                "current primary\n"
            );
            assert!(result.summary.contains(&format!("**{policy_status}**")));
            assert!(result.stdout.contains("::stop-commands::"));
            assert_eq!(result.calls.len(), 3);
        }
    }

    #[test]
    fn scan_action_never_suppresses_operational_errors_or_advertises_stale_reports() {
        for status in ["2", "127"] {
            let fixture = Fixture::new();
            std::fs::write(fixture.path("hooray.sarif"), "stale report\n").unwrap();
            let result = fixture.run(&[
                ("ACTION_SCAN_STATUS", status),
                ("INPUT_FAIL_ON_POLICY", "false"),
            ]);
            assert_eq!(result.status, 2);
            assert_eq!(result.outputs["exit-code"], "2");
            assert_eq!(result.outputs["scan-exit-code"], status);
            assert_eq!(result.outputs["policy-status"], "error");
            assert_eq!(result.outputs["report"], "");
            assert_eq!(result.outputs["reports"], "{}");
            assert_eq!(result.outputs["run-id"], "");
            assert_eq!(
                std::fs::read_to_string(fixture.path("hooray.sarif")).unwrap(),
                "stale report\n"
            );
        }
    }

    #[test]
    fn scan_action_policy_validation_errors_are_operational() {
        for status in ["1", "2"] {
            let result = Fixture::new().run(&[
                ("ACTION_POLICY_STATUS", status),
                ("INPUT_FAIL_ON_POLICY", "false"),
            ]);
            assert_eq!(result.status, 2);
            assert_eq!(result.outputs["scan-exit-code"], "");
            assert_eq!(result.outputs["policy-status"], "error");
            assert_eq!(result.outputs["run-id"], "");
            assert_eq!(result.calls.len(), 1);
        }
    }

    #[test]
    fn scan_action_renders_additional_formats_from_the_same_denied_run() {
        let fixture = Fixture::new();
        let result = fixture.run(&[
            ("ACTION_SCAN_STATUS", "1"),
            ("INPUT_ADDITIONAL_FORMATS", "json,junit,markdown"),
        ]);
        assert_eq!(result.status, 1);
        let reports: BTreeMap<String, String> =
            serde_json::from_str(&result.outputs["reports"]).unwrap();
        assert_eq!(reports.len(), 4);
        for format in ["json", "junit", "markdown"] {
            assert_eq!(
                std::fs::read_to_string(&reports[format]).unwrap(),
                "persisted extra\n"
            );
            assert!(
                Path::new(&reports[format]).starts_with(&result.outputs["artifacts-directory"])
            );
        }
        assert_eq!(
            result.calls.iter().filter(|args| args[0] == "scan").count(),
            1
        );
        for call in result.calls.iter().filter(|args| args[0] == "report") {
            assert_eq!(call[1], "run:test-current");
        }
        assert_eq!(result.calls.len(), 6);
        assert!(result.summary.contains("### Detailed report"));
        assert!(result.summary.contains("persisted extra"));
    }

    #[test]
    fn scan_action_report_errors_fail_and_retain_the_completed_primary_report() {
        for status in ["2", "0"] {
            let result = Fixture::new().run(&[
                ("ACTION_SCAN_STATUS", "1"),
                ("ACTION_REPORT_STATUS", status),
                ("INPUT_FAIL_ON_POLICY", "false"),
                ("INPUT_ADDITIONAL_FORMATS", "json"),
            ]);
            assert_eq!(result.status, 2);
            assert_eq!(result.outputs["policy-status"], "error");
            assert!(result.outputs["report"].ends_with("/hooray.sarif"));
            assert_eq!(result.outputs["denied"], "1");
            assert_eq!(result.outputs["artifacts-directory"], "");
        }
    }

    #[test]
    fn scan_action_preserves_empty_output_and_opt_out_summary_behavior() {
        let result = Fixture::new().run(&[("INPUT_OUTPUT", ""), ("INPUT_SUMMARY", "false")]);
        assert_eq!(result.status, 0);
        assert_eq!(result.outputs["report"], "");
        assert_eq!(result.outputs["run-id"], "run:test-current");
        assert!(result.summary.is_empty());
        let scan = result.calls.iter().find(|args| args[0] == "scan").unwrap();
        assert!(!scan.as_array().unwrap().contains(&json!("--output")));
    }

    #[test]
    fn scan_action_anchors_primary_outputs_to_the_working_directory() {
        let fixture = Fixture::new();
        std::fs::create_dir(fixture.path("subproject")).unwrap();
        let result = fixture.run_from(&fixture.path("subproject"), &[]);
        assert_eq!(result.status, 0);
        let expected = fixture.path("subproject/hooray.sarif");
        assert_eq!(result.outputs["report"], expected.to_string_lossy());
        assert_eq!(
            serde_json::from_str::<JsonValue>(&result.outputs["reports"]).unwrap(),
            json!({"sarif": expected})
        );
        assert!(!fixture.path("hooray.sarif").exists());
    }

    #[test]
    fn scan_action_bounds_detailed_summaries_and_checks_missing_additional_reports() {
        let result = Fixture::new().run(&[
            ("INPUT_ADDITIONAL_FORMATS", "markdown"),
            ("ACTION_EXTRA_SIZE", "150000"),
        ]);
        assert_eq!(result.status, 0);
        assert!(result.summary.len() < 1024 * 1024);
        assert!(result.summary.contains("Summary truncated"));
        let result = Fixture::new().run(&[
            ("INPUT_ADDITIONAL_FORMATS", "json"),
            ("ACTION_OMIT_EXTRA", "true"),
        ]);
        assert_eq!(result.status, 2);
        assert_eq!(result.outputs["artifacts-directory"], "");
        assert!(result.outputs["report"].ends_with("/hooray.sarif"));
    }

    #[test]
    fn scan_action_real_cli_persists_one_run_and_renders_policy_reports() {
        for (outcome, expected_status) in [("allow", 0), ("deny", 1)] {
            let fixture = Fixture::new();
            std::fs::create_dir(fixture.path("project")).unwrap();
            std::fs::write(fixture.path("project/example.py"), "eval(user_input)\n").unwrap();
            std::fs::write(
                fixture.path("hooray-policy.yaml"),
                format!("version: 1\ndefault_outcome: {outcome}\n"),
            )
            .unwrap();
            let result = fixture.run(&[
                ("INPUT_EXECUTABLE", env!("CARGO_BIN_EXE_hooray")),
                ("INPUT_PATH", "project"),
                ("INPUT_OFFLINE", "true"),
                ("INPUT_FORMAT", "json"),
                (
                    "INPUT_ADDITIONAL_FORMATS",
                    "junit,markdown,gitlab-artifacts",
                ),
            ]);
            assert_eq!(
                result.status, expected_status,
                "{}\n{}",
                result.stdout, result.stderr
            );
            assert!(!result.outputs["run-id"].is_empty());
            assert!(result.outputs["finding-count"].parse::<u64>().unwrap() > 0);
            let report: JsonValue =
                serde_json::from_slice(&std::fs::read(&result.outputs["report"]).unwrap()).unwrap();
            assert_eq!(report["report"]["run"]["id"], result.outputs["run-id"]);
            let reports: BTreeMap<String, String> =
                serde_json::from_str(&result.outputs["reports"]).unwrap();
            assert_eq!(reports.len(), 4);
            assert!(Path::new(&reports["gitlab-artifacts"]).is_dir());
            assert!(result.summary.contains("### Detailed report"));
            let listed = Command::new(env!("CARGO_BIN_EXE_hooray"))
                .current_dir(fixture.directory.path())
                .env("HOORAY_DATABASE_PATH", &result.outputs["database"])
                .args(["history", "list", "--format", "json"])
                .output()
                .unwrap();
            assert!(listed.status.success());
            let history: JsonValue = serde_json::from_slice(&listed.stdout).unwrap();
            assert_eq!(
                history.as_array().unwrap().len(),
                1,
                "additional reports must not rescan"
            );

            // Execute the documented follow-up shell with its actual environment
            // names: unknown HOORAY_* wrapper variables would fail CLI parsing.
            let example = ACTION_README
                .split("## Export a GitHub Check")
                .nth(1)
                .unwrap()
                .split("```yaml\n")
                .nth(1)
                .unwrap()
                .split("```")
                .next()
                .unwrap();
            let example: Value = serde_yaml::from_str(example).unwrap();
            let declared_environment = example[0]["env"].as_mapping().unwrap();
            assert_eq!(declared_environment.len(), 3);
            for key in declared_environment.keys() {
                let key = key.as_str().unwrap();
                assert!(!key.starts_with("HOORAY_") || key == "HOORAY_DATABASE_PATH");
            }
            let binary = Path::new(env!("CARGO_BIN_EXE_hooray"));
            let mut paths = vec![binary.parent().unwrap().to_owned()];
            paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
            let exported = Command::new("bash")
                .current_dir(fixture.directory.path())
                .env("PATH", std::env::join_paths(paths).unwrap())
                .env("HOORAY_DATABASE_PATH", &result.outputs["database"])
                .env("HR_RUN_ID", &result.outputs["run-id"])
                .env("HR_HEAD_SHA", "a".repeat(40))
                .args(["-e", "-c", example[0]["run"].as_str().unwrap()])
                .output()
                .unwrap();
            assert_eq!(
                exported.status.code(),
                Some(expected_status),
                "{}",
                String::from_utf8_lossy(&exported.stderr)
            );
            let check: JsonValue =
                serde_json::from_slice(&std::fs::read(fixture.path("hooray-check.json")).unwrap())
                    .unwrap();
            assert_eq!(check["head_sha"], "a".repeat(40));
            assert_eq!(check["external_id"], result.outputs["run-id"]);
        }
    }

    #[test]
    fn scan_action_rejects_missing_or_contradictory_persisted_metadata() {
        for mode in ["empty", "newline", "option", "contradictory", "boolean"] {
            let result = Fixture::new().run(&[("ACTION_HISTORY_MODE", mode)]);
            assert_eq!(result.status, 2, "{mode}");
            assert_eq!(result.outputs["run-id"], "");
            assert_eq!(result.outputs["report"], "");
        }
        let result = Fixture::new().run(&[("ACTION_HISTORY_STATUS", "2")]);
        assert_eq!(result.status, 2);
        assert_eq!(result.outputs["report"], "");
    }

    #[test]
    fn scan_action_rejects_symlink_destinations_and_ancestors_without_modification() {
        use std::os::unix::fs::symlink;

        for output in [
            "linked/report.sarif",
            "linked/../report.sarif",
            "hooray.sarif",
        ] {
            let fixture = Fixture::new();
            std::fs::create_dir(fixture.path("real")).unwrap();
            std::fs::write(fixture.path("real/report.sarif"), "protected\n").unwrap();
            symlink(fixture.path("real"), fixture.path("linked")).unwrap();
            symlink(
                fixture.path("real/report.sarif"),
                fixture.path("hooray.sarif"),
            )
            .unwrap();
            let result = fixture.run(&[("INPUT_OUTPUT", output)]);
            assert_eq!(result.status, 2, "{output}");
            assert_eq!(result.outputs["report"], "");
            assert!(result.calls.is_empty());
            assert_eq!(
                std::fs::read_to_string(fixture.path("real/report.sarif")).unwrap(),
                "protected\n"
            );
        }
    }

    #[test]
    fn scan_action_rejects_invalid_booleans_and_extra_format_lists_before_scanning() {
        for (key, value) in [
            ("INPUT_OFFLINE", "FALSE"),
            ("INPUT_FAIL_ON_POLICY", "yes"),
            ("INPUT_SUMMARY", "yes"),
            ("INPUT_ADDITIONAL_FORMATS", "json,json"),
            ("INPUT_ADDITIONAL_FORMATS", "json, junit"),
            ("INPUT_ADDITIONAL_FORMATS", "json,"),
            ("INPUT_ADDITIONAL_FORMATS", "unknown"),
        ] {
            let result = Fixture::new().run(&[(key, value)]);
            assert_eq!(result.status, 2, "{key}: {value}");
            assert!(result.calls.is_empty());
        }
    }

    #[test]
    fn scan_action_missing_report_is_operational_and_existing_regular_report_is_replaced() {
        let fixture = Fixture::new();
        std::fs::write(fixture.path("hooray.sarif"), "stale larger report\n").unwrap();
        let result = fixture.run(&[("ACTION_OMIT_REPORT", "true")]);
        assert_eq!(result.status, 2);
        assert_eq!(result.outputs["report"], "");
        assert_eq!(
            std::fs::read_to_string(fixture.path("hooray.sarif")).unwrap(),
            "stale larger report\n"
        );

        let fixture = Fixture::new();
        std::fs::write(fixture.path("hooray.sarif"), "stale larger report\n").unwrap();
        let result = fixture.run(&[]);
        assert_eq!(result.status, 0);
        assert_eq!(
            std::fs::read_to_string(fixture.path("hooray.sarif")).unwrap(),
            "current primary\n"
        );
    }

    #[test]
    fn scan_action_keeps_directory_bundle_compatibility_and_refuses_existing_bundle() {
        let fixture = Fixture::new();
        let result = fixture.run(&[
            ("INPUT_FORMAT", "gitlab-artifacts"),
            ("INPUT_OUTPUT", "bundle"),
        ]);
        assert_eq!(result.status, 0);
        assert_eq!(
            result.outputs["report"],
            fixture.path("bundle").to_string_lossy()
        );
        assert_eq!(
            std::fs::read_to_string(fixture.path("bundle/report.sarif")).unwrap(),
            "current bundle\n"
        );
        let fixture = Fixture::new();
        std::fs::create_dir(fixture.path("bundle")).unwrap();
        let result = fixture.run(&[
            ("INPUT_FORMAT", "gitlab-artifacts"),
            ("INPUT_OUTPUT", "bundle"),
        ]);
        assert_eq!(result.status, 2);
        assert!(result.calls.is_empty());
    }
}
