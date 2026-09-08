#[cfg(unix)]
mod unix {
    use std::process::Command;

    use serde_yaml::Value;

    const SCAN_ACTION: &str = include_str!("../actions/scan/action.yml");

    fn scan_script() -> String {
        let action: Value = serde_yaml::from_str(SCAN_ACTION).expect("scan action YAML");
        let step = action["runs"]["steps"]
            .as_sequence()
            .expect("composite action steps")
            .iter()
            .find(|step| step["id"].as_str() == Some("scan"))
            .expect("scan shell step");
        assert!(
            step["uses"].is_null(),
            "contract test must execute only the scan run block"
        );
        step["run"].as_str().expect("scan shell step").to_owned()
    }

    fn status_for_output(output: &str) -> Option<i32> {
        let directory = tempfile::tempdir().expect("action fixture directory");
        let script = directory.path().join("scan.sh");
        std::fs::write(&script, scan_script()).expect("write action scan script");
        Command::new("bash")
            .arg(script)
            .current_dir(directory.path())
            .env("INPUT_CONFIG", "")
            .env("INPUT_EXECUTABLE", "unused")
            .env("INPUT_FORMAT", "sarif")
            .env("INPUT_PATH", ".")
            .env("INPUT_OFFLINE", "false")
            .env("INPUT_OUTPUT", output)
            .env("INPUT_POLICY", "hooray-policy.yaml")
            .env("GITHUB_OUTPUT", "unused-output")
            .env("RUNNER_TEMP", directory.path())
            .status()
            .expect("run scan action shell")
            .code()
    }

    #[test]
    fn scan_action_rejects_stdout_and_newline_report_paths() {
        assert_eq!(status_for_output("-"), Some(2));
        assert_eq!(status_for_output("reports\nreport.sarif"), Some(2));
        assert_eq!(status_for_output("reports\rreport.sarif"), Some(2));
    }
}
