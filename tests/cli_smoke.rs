//! Process-level refusal checks: special input files must never hang the CLI.
#[cfg(unix)]
#[test]
fn fifo_config_and_policy_fail_promptly_without_creating_scan_history() {
    use std::{
        ffi::CString,
        fs,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    let temp = tempfile::tempdir().unwrap();
    let fifo = temp.path().join("blocked.yaml");
    let c_path = CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: c_path is a live NUL-terminated pathname and mode is owner-only.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
    let project = temp.path().join("project");
    fs::create_dir(&project).unwrap();
    let database = temp.path().join("history.db");
    for arguments in [
        vec!["--config", fifo.to_str().unwrap(), "history", "list"],
        vec!["policy", "validate", fifo.to_str().unwrap()],
        vec![
            "scan",
            "project",
            project.to_str().unwrap(),
            "--policy",
            fifo.to_str().unwrap(),
            "--offline",
        ],
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_hooray"))
            .current_dir(temp.path())
            .env("HOORAY_DATABASE_PATH", &database)
            .args(&arguments)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("CLI blocked on FIFO for {arguments:?}");
            }
            thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(
            status.code(),
            Some(2),
            "special-file inputs require operational refusal"
        );
    }
    if database.exists() {
        let store = hooray::store::Store::open(&database).unwrap();
        assert!(store.list_runs(10, 0).unwrap().is_empty());
    }
}
